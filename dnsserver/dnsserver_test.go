// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver_test

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/tsavola/indns"
	"github.com/tsavola/indns/dnsserver"
	"github.com/tsavola/indns/dnszone"
)

const (
	addr = "127.0.0.1:54311"
)

func TestServer(t *testing.T) {
	config := dnsserver.Config{
		Addr: addr,
	}

	orgZone := &dnszone.Zone{
		Domain: "example.org.",
		Nodes: map[string]indns.Records{
			indns.Apex: indns.Records{
				indns.RecordA{
					Value: net.ParseIP("93.184.216.34"),
					TTL:   1,
				},
				indns.RecordAAAA{
					Value: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
					TTL:   1,
				},
			},
		},
	}

	comZone := &dnszone.Zone{
		Domain: "example.com.",
	}

	zones := dnszone.Init(orgZone, comZone)

	ctx := context.Background()

	server := dnsserver.Server{
		Ready: make(chan struct{}),
	}

	served := make(chan error, 1)

	go func() {
		defer close(served)
		served <- server.Serve(zones, config)
	}()

	<-server.Ready

	client := &dns.Client{
		Net: "tcp",
	}

	for i, name := range []string{"_acme-challenge.example.org.", "example.org.", "www.example.com.", "www.example.net."} {
		for j, typ := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT} {
			msg := new(dns.Msg)
			msg.SetQuestion(name, typ)

			in, _, err := client.Exchange(msg, addr)
			if err != nil {
				t.Error(err)
			} else {
				t.Log(in)
			}

			if i == 0 && j == 0 {
				go zones.ModifyTXTRecord(ctx, "_acme-challenge.example.org.", []string{"asdf"}, 1)

				err = zones.ModifyTXTRecord(ctx, "_acme-challenge.example.org.", []string{"qwerty"}, 2)
				if err != nil {
					t.Error(err)
				}
			}
		}
	}

	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}

	if err := <-served; err != nil {
		t.Fatal(err)
	}
}
