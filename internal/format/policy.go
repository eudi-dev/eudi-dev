// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package format

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
)

// FetchPolicy decides whether an outbound connection is allowed. It receives
// the network ("tcp4" or "tcp6") and the resolved "ip:port" address, so DNS
// rebinding and redirects to internal names cannot bypass it.
type FetchPolicy func(network, address string) error

var fetchPolicy atomic.Value // holds FetchPolicy

// SetFetchPolicy installs a policy for every outbound connection of this
// package's HTTP clients. Nil removes the policy.
func SetFetchPolicy(policy FetchPolicy) {
	fetchPolicy.Store(policy)
}

func dialControl(network, address string, _ syscall.RawConn) error {
	policy, _ := fetchPolicy.Load().(FetchPolicy)
	if policy == nil {
		return nil
	}
	return policy(network, address)
}

// AllowOwnOrigins permits requests to the configured issuer and verifier URLs. Each
// exception comes from operator configuration and matches the exact resolved
// address and port. Other private destinations stay blocked.
func AllowOwnOrigins(next FetchPolicy, urls ...string) FetchPolicy {
	allowed := make(map[string]bool)
	for _, raw := range urls {
		for _, addr := range resolveOriginAddresses(raw) {
			allowed[addr] = true
		}
	}
	if len(allowed) == 0 {
		return next
	}
	return func(network, address string) error {
		if allowed[address] {
			return nil
		}
		if next == nil {
			return nil
		}
		return next(network, address)
	}
}

func resolveOriginAddresses(raw string) []string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return nil
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		switch parsed.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return nil
		}
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, netip.AddrPortFrom(addr.Unmap(), portNumber(port)).String())
		}
	}
	return out
}

func portNumber(port string) uint16 {
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

// extraBlockedPrefixes adds the special-purpose ranges of the IANA IPv4 and
// IPv6 registries (RFC 6890) that the netip predicates do not cover.
var extraBlockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, broadcast included
	netip.MustParsePrefix("::/96"),           // IPv4-compatible (deprecated)
	netip.MustParsePrefix("100::/64"),        // discard-only
	netip.MustParsePrefix("2001::/32"),       // Teredo
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("3fff::/20"),       // documentation
	netip.MustParsePrefix("fc00::/7"),        // unique-local
	netip.MustParsePrefix("fec0::/10"),       // site-local (deprecated)
	// NAT64 (RFC 6052, RFC 8215) and 6to4 (RFC 3056) embed any IPv4
	// address, private ones too.
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
}

// AllowLoopback permits connections to loopback addresses and leaves every
// other address to next.
func AllowLoopback(next FetchPolicy) FetchPolicy {
	return func(network, address string) error {
		if addrPort, err := netip.ParseAddrPort(address); err == nil && addrPort.Addr().Unmap().IsLoopback() {
			return nil
		}
		return next(network, address)
	}
}

// BlockPrivateAddresses is a FetchPolicy that rejects connections to
// loopback, private (RFC 1918), link-local (including cloud metadata
// endpoints), CGNAT, unique-local, NAT64, unspecified and multicast addresses,
// and to the other special-purpose ranges in extraBlockedPrefixes.
// A host that fetches visitor-supplied URLs and can reach internal networks
// needs it.
func BlockPrivateAddresses(network, address string) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("blocked connection to unparseable address %q", address)
	}
	addr := addrPort.Addr().Unmap()
	blocked := addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsUnspecified() || addr.IsMulticast()
	for _, prefix := range extraBlockedPrefixes {
		blocked = blocked || prefix.Contains(addr)
	}
	if blocked {
		return fmt.Errorf("connections to internal address %s are not allowed", addr)
	}
	return nil
}
