// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnszone

import (
	"context"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/libdns/libdns"
	"github.com/tsavola/indns"
)

// AppendRecords creates the requested records in the given zone and returns
// the populated records that were created.
func (c *Container) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) (rets []libdns.Record, err error) {
	for _, lib := range recs {
		if lib.ID != "" {
			continue
		}

		var native indns.Record

		native, err = parseRecord(lib.Type, lib.Value, lib.TTL)
		if err != nil {
			break
		}

		err = c.modifyRecord(ctx, zone, lib.Name, native, true)
		if err != nil {
			break
		}

		rets = append(rets, lib)
	}

	return
}

// DeleteRecords deletes the given records from the zone if they exist.  It
// returns the records that were deleted.
func (c *Container) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) (rets []libdns.Record, err error) {
	for _, lib := range recs {
		if lib.ID != "" {
			continue
		}

		t, ok := parseRecordType(lib.Type)
		if !ok {
			continue
		}

		var forgotten bool

		forgotten, err = c.forgetRecord(zone, lib.Name, t)
		if err != nil {
			break
		}

		if forgotten {
			rets = append(rets, lib)
		}
	}

	return
}

func parseRecordType(t string) (_ indns.RecordType, ok bool) {
	switch t {
	case "A":
		return indns.TypeA, true
	case "NS":
		return indns.TypeNS, true
	case "TXT":
		return indns.TypeTXT, true
	case "AAAA":
		return indns.TypeAAAA, true
	}

	return
}

func parseRecord(t, value string, ttl time.Duration) (indns.Record, error) {
	switch t {
	case "A":
		return parseA(value, ttl)
	case "NS":
		return parseNS(value, ttl)
	case "TXT":
		return parseTXT(value, ttl)
	case "AAAA":
		return parseAAAA(value, ttl)
	}

	return nil, fmt.Errorf("DNS record type not supported: %s", t)
}

func parseA(s string, ttl time.Duration) (indns.Record, error) {
	if ip := net.ParseIP(s).To4(); ip != nil {
		return indns.RecordA{Value: ip, TTL: parseTTL(ttl)}, nil
	} else {
		return nil, fmt.Errorf("not an IPv4 address: %q", s)
	}
}

func parseNS(s string, ttl time.Duration) (indns.Record, error) {
	return indns.RecordNS{Value: s, TTL: parseTTL(ttl)}, nil
}

func parseTXT(s string, ttl time.Duration) (indns.Record, error) {
	return indns.RecordTXT{Values: []string{s}, TTL: parseTTL(ttl)}, nil
}

func parseAAAA(s string, ttl time.Duration) (indns.Record, error) {
	if ip := net.ParseIP(s); ip != nil {
		return indns.RecordAAAA{Value: ip, TTL: parseTTL(ttl)}, nil
	} else {
		return nil, fmt.Errorf("not an IP address: %q", s)
	}
}

func parseTTL(d time.Duration) (s uint32) {
	if d >= 0 {
		if n := d / time.Second; n <= math.MaxUint32 {
			s = uint32(n)
		}
	}
	return
}

var _ libdns.RecordAppender = new(Container)
var _ libdns.RecordDeleter = new(Container)
