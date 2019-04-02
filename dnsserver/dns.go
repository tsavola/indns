// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"github.com/tsavola/indns"
)

// Resolver can dump host and zone records.  It must be instantaneous.
type Resolver interface {
	// ResolveRecords copies a host's records.  It should return empty node
	// name if and only if the host name doesn't fall into any known zone:
	// unknown node names in known zones should be returned without records.
	//
	// The filter parameter selects a single record type, or some records if
	// indns.TypeANY is specified (see RFC 8482).  Unknown values must be
	// handled by returning an empty record set.
	//
	// serial is the current serial number of the node's zone.  It is non-zero
	// for known zones, and zero if zone wasn't found.
	ResolveRecords(hostname string, filter indns.RecordType) (node, zone string, rs indns.Records, serial uint32)

	// TransferZone copies the contents of a domain.  The apex node must be
	// first.
	//
	// serial is the current serial number of the zone.  It is non-zero if the
	// zone was found, and zero if not.
	TransferZone(domain string) (zone []indns.NodeRecords, serial uint32)
}
