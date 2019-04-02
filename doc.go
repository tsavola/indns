// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*

Package indns provides a DNS server component.

Package indns/dnsserver provides a simple, authoritative DNS server.  It needs
a zone database.

Package indns/dnszone provides a static in-memory zone database.


Wildcard certificate renewal

While indns is generic, its intended use case is to support wildcard TLS
certificate verification.  It can be combined with
https://github.com/mholt/certmagic and https://github.com/tsavola/legodns to
achieve automatic ACME certificate renewal, integrated into a single Go
program.


DNS configuration

The idea is that there are fewer moving parts if the TLS server and its name
server are the same server (e.g. 192.0.2.0).  We just need some domain names:
one for the name server (example.net), and one for the TLS server with wildcard
needs (example.org).  One could also be a subdomain of the other, but that
would be messier to illustrate.

1. Zone ``example.net'' is hosted somewhere.

2. Name ``ns1.example.net'' is configured with address 192.0.2.0.

3. A server program with integrated indns is running at 192.0.2.0.

4. It configures dnsserver as ``ns1.example.net''.

5. It configures dnszone ``example.org'' with address 192.0.2.0 for all names.

6. ``ns1.example.net'' is registered as the primary name server of the
``example.org'' domain.

7. Another name server mirroring ``ns1.example.net'' should be registered as a
secondary name server of the ``example.org'' domain (but the setup works also
without one).

Steps 3, 4, and 5 as code:

	import (
		"log"
		"net"

		"github.com/tsavola/indns"
		"github.com/tsavola/indns/dnsserver"
		"github.com/tsavola/indns/dnszone"
	)

	// Step 5
	var zones = dnszone.Init(&dnszone.Zone{
		Domain: "example.org.",
		Nodes: map[string]indns.Records{
			indns.Apex: indns.Records{
				indns.RecordNS{
					Value: "ns1.example.net.",
					TTL:   7200,
				},
			},
			indns.Wildcard: indns.Records{
				indns.RecordA{
					Value: net.ParseIP("192.0.2.0"),
					TTL:   7200,
				},
			},
		},
	})

	var dnsServer = dnsserver.Server{
		Ready: make(chan struct{}),
	}

	func serveDNS() {
		// Step 4
		config := dnsserver.Config{
			SOA: dnsserver.SOA{
				NS:   "ns1.example.net.",
				Mbox: "hostmaster.example.net.",
			},
		}

		// Step 3
		log.Fatal(dnsServer.Serve(zones, config))
	}


ACME example

	import (
		"log"
		"net/http"

		"github.com/mholt/certmagic"
		"github.com/tsavola/legodns"
	)

	func main() {
		go serveDNS()
		<-dnsServer.Ready

		certmagic.Email = "hostmaster@example.net"
		certmagic.Agreed = true
		certmagic.DNSProvider = legodns.NewProvider(zones)

		tlsConfig, err := certmagic.TLS(zones.Hosts())
		if err != nil {
			log.Fatal(err)
		}

		httpServer := http.Server{
			Addr:      ":https",
			TLSConfig: tlsConfig,
		}

		log.Fatal(httpServer.ListenAndServeTLS("", ""))
	}

*/
package indns
