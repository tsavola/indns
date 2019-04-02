// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package indns

import (
	"net"
)

type RecordType uint16

// Types of DNS records.  The values must match the standard ones.
const (
	TypeA    RecordType = 1
	TypeNS              = 2
	TypeTXT             = 16
	TypeAAAA            = 28

	TypeANY = 255 // Only for matching against actual resource types.
)

type Record interface {
	DeepCopy() Record
	IsZero() bool
	Type() RecordType
}

type RecordA IPRecord
type RecordNS StringRecord
type RecordTXT StringsRecord
type RecordAAAA IPRecord

func (r RecordA) DeepCopy() Record    { return RecordA((*IPRecord)(&r).DeepCopy()) }
func (r RecordNS) DeepCopy() Record   { return RecordNS((*StringRecord)(&r).DeepCopy()) }
func (r RecordTXT) DeepCopy() Record  { return RecordTXT((*StringsRecord)(&r).DeepCopy()) }
func (r RecordAAAA) DeepCopy() Record { return RecordAAAA((*IPRecord)(&r).DeepCopy()) }

func (r RecordA) IsZero() bool    { return len(r.Value) == 0 }
func (r RecordNS) IsZero() bool   { return r.Value == "" }
func (r RecordTXT) IsZero() bool  { return len(r.Values) == 0 }
func (r RecordAAAA) IsZero() bool { return len(r.Value) == 0 }

func (RecordA) Type() RecordType    { return TypeA }
func (RecordNS) Type() RecordType   { return TypeNS }
func (RecordTXT) Type() RecordType  { return TypeTXT }
func (RecordAAAA) Type() RecordType { return TypeAAAA }

// Records contains Record*-type items (values, not pointers).
type Records []Record

func (rs Records) Addressable() bool {
	for _, r := range rs {
		switch r.Type() {
		case TypeA, TypeAAAA:
			return true
		}
	}
	return false
}

func (rs Records) DeepCopy() Records {
	clone := make(Records, len(rs))
	for i, r := range rs {
		clone[i] = r.DeepCopy()
	}
	return clone
}

type IPRecord struct {
	Value net.IP
	TTL   uint32
}

func (r *IPRecord) DeepCopy() IPRecord {
	return IPRecord{
		Value: append(net.IP(nil), r.Value...),
		TTL:   r.TTL,
	}
}

type StringRecord struct {
	Value string
	TTL   uint32
}

func (r *StringRecord) DeepCopy() StringRecord {
	return *r
}

type StringsRecord struct {
	Values []string
	TTL    uint32
}

func (r *StringsRecord) DeepCopy() StringsRecord {
	return StringsRecord{
		Values: append([]string(nil), r.Values...),
		TTL:    r.TTL,
	}
}
