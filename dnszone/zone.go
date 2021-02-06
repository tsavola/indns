// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package dnszone implements a simple DNS zone container.
//
// See the top-level package for general documentation.
package dnszone

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/tsavola/indns"
)

// Container of zones.
type Container struct {
	mutex sync.RWMutex
	zones []*Zone

	changeReady chan struct{}
	changeZones map[*Zone]struct{}
}

// Init zones.
func Init(zones ...*Zone) *Container {
	return InitWithSerial(TimeSerial(time.Now()), zones...)
}

// Init zones with a custom initial serial number.
func InitWithSerial(serial uint32, zones ...*Zone) *Container {
	for _, z := range zones {
		z.serial = serial
	}

	return &Container{
		zones: zones,
	}
}

// Hosts lists fully-qualified-but-without-dot-suffix domain names of
// addressable nodes.  Wildcard entries are included as such
// (e.g. "*.example.net").
func (c *Container) Hosts() []string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var hosts []string

	for _, z := range c.zones {
		domain := strings.TrimSuffix(z.Domain, ".")
		for node, rs := range z.Nodes {
			if rs.Addressable() {
				host := domain
				if node != indns.Apex {
					host = node + "." + host
				}
				hosts = append(hosts, host)
			}
		}
	}

	return hosts
}

// ResolveRecords answers ANY queries by returning A and AAAA records.
func (c *Container) ResolveRecords(fqdn string, filter indns.RecordType) (zone, node string, results indns.Records, serial uint32) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	for _, z := range c.zones {
		node = z.matchResource(fqdn)
		if node != "" {
			if rs := z.resolveNode(node); rs != nil {
				switch filter {
				case indns.TypeANY:
					results = resolveANYRecords(rs)

				default:
					results = resolveRecordType(rs, filter)
				}
			}
			zone = z.Domain
			serial = z.serial
			return
		}
	}

	return
}

func resolveRecordType(rs indns.Records, t indns.RecordType) indns.Records {
	results := make(indns.Records, 0, len(rs))
	for _, r := range rs {
		if r.Type() == t {
			results = append(results, r.DeepCopy())
		}
	}
	return results
}

func resolveANYRecords(rs indns.Records) indns.Records {
	results := make(indns.Records, 0, len(rs))
	for _, r := range rs {
		switch r.Type() {
		case indns.TypeA, indns.TypeAAAA:
			results = append(results, r.DeepCopy())
		}
	}
	return results
}

// ResolveZone checks the existence of a zone.  It's ok if the zone exists but
// the node is unknown: the relative node name is still returned.
//
// Successful check of a nonexistent zone returns an error with a NotExist()
// method which returns true.
func (c *Container) ResolveZone(ctx context.Context, fqdn string) (zone, node string, err error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	for _, z := range c.zones {
		node = z.matchResource(fqdn)
		if node != "" {
			zone = z.Domain
			return
		}
	}

	err = newZoneError(fqdn)
	return
}

// TransferZone copies the contents of a domain.  The apex will be the first
// node.  serial is the current serial number of the zone.
//
// Zero values are returned if the zone is not found.
func (c *Container) TransferZone(name string) (results []indns.NodeRecords, serial uint32) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	for _, z := range c.zones {
		if z.Domain == name {
			results = z.transfer()
			serial = z.serial
			return
		}
	}

	return
}

// ModifyTXTRecord is a high-level interface for creating, updating or removing
// a TXT record.  It blocks until the modification is complete or the context
// is done.
func (c *Container) ModifyTXTRecord(ctx context.Context, fqdn string, values []string, ttl int) error {
	if ttl <= 0 || ttl > math.MaxInt32 {
		return errors.New("TTL value is invalid")
	}

	zone, node, err := c.ResolveZone(ctx, fqdn)
	if err != nil {
		return err
	}

	return c.ModifyRecord(ctx, zone, node, indns.RecordTXT{Values: values, TTL: uint32(ttl)})
}

// ForgetTXTRecord is a high-level interface for removing a TXT record.  It
// doesn't wait for the modification to be complete.  The record will disappear
// at some point in the future.
func (c *Container) ForgetTXTRecord(fqdn string) error {
	zone, node, err := c.ResolveZone(context.Background(), fqdn)
	if err != nil {
		return nil
	}

	return c.ForgetRecord(zone, node, indns.TypeTXT)
}

// ModifyRecord creates, updates or removes a record.  It blocks until the
// modification is complete or the context is done.
func (c *Container) ModifyRecord(ctx context.Context, zoneName, node string, r indns.Record) error {
	return c.modifyRecord(ctx, zoneName, node, r, false)
}

func (c *Container) modifyRecord(ctx context.Context, zoneName, node string, r indns.Record, strict bool) error {
	c.mutex.Lock()

	var targetZone *Zone

	for _, z := range c.zones {
		if z.Domain == zoneName {
			targetZone = z
			break
		}
	}

	if targetZone != nil {
		// Modify zone immediately without changing serial number.
		modified := targetZone.modifyRecord(node, r.Type(), r, strict)

		// Coalesce all serial number changes over a one-second period, and
		// increment each zone's serial number just once at the end of that
		// period.  That way they don't run ahead of Serial().
		var ready <-chan struct{}
		if modified {
			ready = c.scheduleChange(targetZone)
		}

		c.mutex.Unlock()

		if !modified {
			return errors.New("record already exists")
		}

		// Block until the serial number change is visible.
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-ready:
			return nil
		}
	} else {
		c.mutex.Unlock()

		return newZoneError(zoneName)
	}
}

// ForgetRecord is non-blocking ModifyRecord with zero-value record.  The
// record will disappear at an unspecified time in the future.
func (c *Container) ForgetRecord(zoneName, node string, rt indns.RecordType) error {
	_, err := c.forgetRecord(zoneName, node, rt)
	return err
}

func (c *Container) forgetRecord(zoneName, node string, rt indns.RecordType) (bool, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, z := range c.zones {
		if z.Domain == zoneName {
			// See the comments in Container.modifyRecord.
			if z.modifyRecord(node, rt, nil, true) {
				c.scheduleChange(z)
				return true, nil
			} else {
				return false, nil
			}
		}
	}

	return false, newZoneError(zoneName)
}

// scheduleChange must be called with write lock held.
func (c *Container) scheduleChange(z *Zone) <-chan struct{} {
	if c.changeReady == nil {
		c.changeReady = make(chan struct{})
		c.changeZones = make(map[*Zone]struct{})
		time.AfterFunc(time.Second, c.applyChanges)
	}

	c.changeZones[z] = struct{}{}
	return c.changeReady
}

func (c *Container) applyChanges() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for z := range c.changeZones {
		z.serial++
	}

	close(c.changeReady)
	c.changeReady = nil
	c.changeZones = nil
}

// Zone enumerates the nodes of a domain.
//
// Must not be modified directly after its Container has been used for
// resolving resources or transferring zones.
type Zone struct {
	Domain string
	Nodes  map[string]indns.Records

	serial uint32 // managed by Container
}

func (z *Zone) matchResource(name string) (node string) {
	switch {
	case z.Domain == name:
		node = indns.Apex

	case strings.HasSuffix(name, "."+z.Domain):
		node = name[:len(name)-1-len(z.Domain)]
	}

	return
}

func (z *Zone) resolveNode(node string) (rs indns.Records) {
	rs = z.Nodes[node]
	if rs == nil && node != indns.Apex { // wildcard doesn't apply to apex
		rs = z.Nodes[indns.Wildcard]
	}
	return
}

func (z *Zone) transfer() (results []indns.NodeRecords) {
	results = make([]indns.NodeRecords, 0, len(z.Nodes))

	if rs := z.Nodes[indns.Apex]; rs != nil {
		results = append(results, indns.NodeRecords{
			Name:    indns.Apex,
			Records: rs.DeepCopy(),
		})
	}

	for name, rs := range z.Nodes {
		if name != indns.Apex && name != indns.Wildcard {
			results = append(results, indns.NodeRecords{
				Name:    name,
				Records: rs.DeepCopy(),
			})
		}
	}

	if rs := z.Nodes[indns.Wildcard]; rs != nil {
		results = append(results, indns.NodeRecords{
			Name:    indns.Wildcard,
			Records: rs.DeepCopy(),
		})
	}

	return
}

func (z *Zone) modifyRecord(node string, rt indns.RecordType, r indns.Record, strict bool) bool {
	if r != nil && !r.IsZero() {
		if z.Nodes == nil {
			z.Nodes = make(map[string]indns.Records)
		}

		rs := z.Nodes[node]
		for i, x := range rs {
			if x.Type() == rt {
				if strict {
					return false
				} else {
					rs[i] = r
					return true
				}
			}
		}
		z.Nodes[node] = append(rs, r)
		return true
	} else {
		rs := z.Nodes[node]
		for i, x := range rs {
			if x.Type() == rt {
				rs = append(rs[:i], rs[i+1:]...)
				if len(rs) > 0 {
					z.Nodes[node] = rs
				} else {
					delete(z.Nodes, node)
				}
				return true
			}
		}

		return false
	}
}

func deepCopyStrings(values []string) []string {
	return append([]string(nil), values...)
}
