// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package dnsserver implements a simple, authoritative DNS server.  It is
// built upon https://github.com/miekg/dns.
//
// See the top-level package for general documentation.
package dnsserver

import (
	"context"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/tsavola/indns"
)

const (
	defaultAddr = ":53"
)

// Config of DNS server.
type Config struct {
	// Addr defaults to ":53".  If a hostname is specified, all IP addresses it
	// resolves to will be listened on.
	Addr string

	NoTCP bool
	NoUDP bool

	ErrorLog Logger // Defaults to log package's standard logger
	DebugLog Logger // Defaults to nothingness

	// If the NS field of SOA is set, the name server will be authoritative and
	// NS and SOA records are returned.
	SOA SOA
}

// Serve DNS requests.  Resolver implementation effectively defines the zones.
func Serve(resolver Resolver, config Config) error {
	return new(Server).Serve(resolver, config)
}

// Server of DNS requests.
type Server struct {
	// If provided by the user, this channel will be closed once all listeners
	// are ready.
	Ready chan struct{}

	lock sync.Mutex
	stop chan struct{}
	done chan struct{}
}

// Serve DNS requests until Shutdown is called.  Resolver implementation
// effectively defines the zones.
func (s *Server) Serve(resolver Resolver, config Config) (err error) {
	s.lock.Lock()
	stop := s.stop
	done := s.done
	start := stop == nil
	if start {
		stop = make(chan struct{})
		done = make(chan struct{})
		s.stop = stop
		s.done = done
	}
	s.lock.Unlock()
	if !start {
		return
	}
	defer close(done)

	if config.ErrorLog == nil {
		config.ErrorLog = defaultLogger{}
	}

	if config.Addr == "" {
		config.Addr = defaultAddr
	}
	host, port, err := net.SplitHostPort(config.Addr)
	if err != nil {
		return
	}

	err = config.SOA.init()
	if err != nil {
		return
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		handle(w, m, resolver, &config.SOA, config.ErrorLog, config.DebugLog)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wait := func() {
		select {
		case <-stop:
		case <-ctx.Done():
		}
	}

	var addrs []string
	if host == "" {
		addrs = []string{host}
	} else {
		addrs, err = new(net.Resolver).LookupHost(ctx, host)
		if err != nil {
			return
		}
	}
	for i, host := range addrs {
		addrs[i] = net.JoinHostPort(host, port)
	}

	errors := make(chan error, 2*2*len(addrs)) // (tcp, udp) x (wait, listen) x addrs

	for _, addr := range addrs {
		addr := addr

		if !config.NoTCP {
			var l net.Listener

			l, err = net.Listen("tcp", addr)
			if err != nil {
				return
			}

			go func() {
				defer l.Close()
				wait()
				errors <- nil
			}()

			go func() {
				errors <- dns.ActivateAndServe(l, nil, handler)
			}()
		}

		if !config.NoUDP {
			var pc net.PacketConn

			pc, err = net.ListenPacket("udp", addr)
			if err != nil {
				return
			}

			go func() {
				defer pc.Close()
				wait()
				errors <- nil
			}()

			go func() {
				errors <- dns.ActivateAndServe(nil, pc, handler)
			}()
		}
	}

	if s.Ready != nil {
		close(s.Ready)
	}

	err = <-errors
	return
}

// Shutdown the server.  Serve call will return.
func (s *Server) Shutdown(ctx context.Context) (err error) {
	s.lock.Lock()
	stop := s.stop
	done := s.done
	if stop == nil {
		stop = make(chan struct{})
		s.stop = stop
	}
	s.lock.Unlock()
	close(stop)
	if done != nil {
		<-done
	}
	return
}

func handle(w dns.ResponseWriter, questMsg *dns.Msg, resolver Resolver, soa *SOA, errorLog, debugLog Logger) {
	defer func() {
		if x := recover(); x != nil {
			errorLog.Printf("panic: %v", x)
		}
	}()

	defer func() {
		if err := w.Close(); err != nil {
			errorLog.Printf("close: %v", err)
		}
	}()

	var replyMsg dns.Msg
	replyCode := dns.RcodeServerFailure

	defer func() {
		if debugLog != nil && replyCode != dns.RcodeSuccess {
			debugLog.Printf("dnsserver: %v %s", w.RemoteAddr(), dns.RcodeToString[replyCode])
		}

		if err := w.WriteMsg(replyMsg.SetRcode(questMsg, replyCode)); err != nil {
			errorLog.Printf("write: %v", err)
		}
	}()

	if len(questMsg.Question) != 1 {
		replyCode = dns.RcodeNotImplemented
		return
	}

	q := &questMsg.Question[0]

	if q.Qclass != dns.ClassINET {
		replyCode = dns.RcodeNotImplemented
		return
	}

	if debugLog != nil {
		debugLog.Printf("dnsserver: %v %s %q", w.RemoteAddr(), dns.TypeToString[q.Qtype], q.Name)
	}

	var (
		zone    string
		qIsApex bool
		nodes   []indns.NodeRecords
		serial  uint32
	)

	if transferReq(q) {
		if soa.authority() {
			nodes, serial = resolver.TransferZone(strings.ToLower(q.Name))
			if serial != 0 {
				zone = q.Name
				qIsApex = true
				replyMsg.Authoritative = true
				replyMsg.Answer = append(replyMsg.Answer, soaAnswer(q.Name, soa, serial))
				replyMsg.Answer = append(replyMsg.Answer, nsAnswer(q.Name, soa.NS, soa.TTL))
			}
		}
	} else {
		var nr indns.NodeRecords

		zone, nr.Name, nr.Records, serial = resolver.ResolveRecords(strings.ToLower(q.Name), indns.RecordType(q.Qtype))
		if zone != "" {
			zone = q.Name[len(q.Name)-len(zone):] // Preserve case.
			qIsApex = (nr.Name == indns.Apex)
			nodes = []indns.NodeRecords{nr}
			replyMsg.Authoritative = soa.authority()
		}
	}

	if nodes != nil {
		for _, node := range nodes {
			var name string

			switch node.Name {
			case indns.Apex:
				name = q.Name

			case indns.Wildcard:
				name = "*." + q.Name

			default:
				if qIsApex {
					name = node.Name + "." + q.Name
				} else {
					name = q.Name
				}
			}

			for _, x := range node.Records {
				switch t := x.Type(); t {
				case indns.TypeNS:
					if replyType(q, dns.TypeNS) {
						r := x.(indns.RecordNS)
						replyMsg.Answer = append(replyMsg.Answer, nsAnswer(name, r.Value, r.TTL))
					}

				case indns.TypeA:
					if replyType(q, dns.TypeA) {
						r := x.(indns.RecordA)
						replyMsg.Answer = append(replyMsg.Answer, &dns.A{
							Hdr: dns.RR_Header{
								Name:   name,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    r.TTL,
							},
							A: r.Value,
						})
					}

				case indns.TypeAAAA:
					if replyType(q, dns.TypeAAAA) {
						r := x.(indns.RecordAAAA)
						replyMsg.Answer = append(replyMsg.Answer, &dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   name,
								Rrtype: dns.TypeAAAA,
								Class:  dns.ClassINET,
								Ttl:    r.TTL,
							},
							AAAA: r.Value,
						})
					}

				case indns.TypeTXT:
					if replyType(q, dns.TypeTXT) {
						r := x.(indns.RecordTXT)
						replyMsg.Answer = append(replyMsg.Answer, &dns.TXT{
							Hdr: dns.RR_Header{
								Name:   name,
								Rrtype: dns.TypeTXT,
								Class:  dns.ClassINET,
								Ttl:    r.TTL,
							},
							Txt: r.Values,
						})
					}

				default:
					if debugLog != nil {
						debugLog.Printf("dnsserver: node %q has unknown record type: %v", name, t)
					}
				}
			}

			if q.Qtype == dns.TypeANY && len(replyMsg.Answer) == 0 {
				// Synthesize an HINFO record as resolution didn't yield ANY.
				replyMsg.Answer = append(replyMsg.Answer, &dns.HINFO{
					Hdr: dns.RR_Header{
						Name:   name,
						Rrtype: dns.TypeHINFO,
						Class:  dns.ClassINET,
						Ttl:    soa.TTL,
					},
				})
			}
		}

		// Zone transfer is concluded with repeated SOA record.
		if transferReq(q) || (q.Qtype == dns.TypeSOA && q.Name == zone && replyMsg.Authoritative) {
			replyMsg.Answer = append(replyMsg.Answer, soaAnswer(q.Name, soa, serial))
		}

		replyCode = dns.RcodeSuccess
	} else {
		replyCode = dns.RcodeNameError
	}

	if replyMsg.Authoritative {
		// RFC 2308, Section 3: SOA in Authority section also for negative answers.
		if negativeAnswer(&replyMsg, replyCode) {
			replyMsg.Ns = append(replyMsg.Ns, soaAnswer(zone, soa, serial))
		} else {
			replyMsg.Ns = append(replyMsg.Ns, nsAnswer(q.Name, soa.NS, soa.TTL))
		}
	}
}

// replyType returns true if records with recordType should be included in the
// reply message for the given question.
func replyType(q *dns.Question, recordType uint16) bool {
	switch q.Qtype {
	case dns.TypeAXFR, dns.TypeIXFR, dns.TypeANY, recordType:
		return true

	default:
		return false
	}
}

// transferReq returns true if question is some kind of zone transfer request.
func transferReq(q *dns.Question) bool {
	switch q.Qtype {
	case dns.TypeAXFR, dns.TypeIXFR:
		return true

	default:
		return false
	}
}

func negativeAnswer(replyMsg *dns.Msg, replyCode int) bool {
	return replyCode == dns.RcodeNameError || len(replyMsg.Answer) == 0
}

func nsAnswer(name, value string, ttl uint32) *dns.NS {
	return &dns.NS{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ns: value,
	}
}

func soaAnswer(name string, soa *SOA, serial uint32) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    soa.TTL,
		},
		Ns:      soa.NS,
		Mbox:    soa.Mbox,
		Serial:  serial,
		Refresh: soa.Refresh,
		Retry:   soa.Retry,
		Expire:  soa.Expire,
		Minttl:  soa.TTL,
	}
}
