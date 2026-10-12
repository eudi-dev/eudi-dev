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

// Package netaddr decides which hosts are local to the machine that runs
// eudi-dev.
package netaddr

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// DefaultListenHost keeps a server on this machine because the servers have
// no authentication (SECURITY.md).
const DefaultListenHost = "127.0.0.1"

// ParseListenHost checks a server's bind address. It takes an IP address,
// such as 0.0.0.0 for every interface. localhost stands for 127.0.0.1.
func ParseListenHost(host string) (string, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if normalize(host) == "localhost" {
		return DefaultListenHost, nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return "", fmt.Errorf("%q is not an IP address, use 127.0.0.1, ::1 or 0.0.0.0", host)
	}
	return addr.String(), nil
}

// ListenAddr is the address net.Listen takes for host and port.
func ListenAddr(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// LocalURL returns the URL for reaching a server on this machine. A server
// on loopback or on every interface answers at localhost.
func LocalURL(host string, port int) string {
	if addr, err := netip.ParseAddr(host); err == nil && !addr.IsLoopback() && !addr.IsUnspecified() {
		return "http://" + ListenAddr(host, port)
	}
	return "http://localhost:" + strconv.Itoa(port)
}

// DockerHost is the host machine's name inside a Docker container.
const DockerHost = "host.docker.internal"

// IsLoopback reports whether host is the name localhost or an address in
// 127.0.0.0/8 or ::1. Host names compare case insensitively (RFC 4343) and may
// end with the root dot. An IPv6 address may be bracketed.
func IsLoopback(host string) bool {
	host = normalize(host)
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && addr.Unmap().IsLoopback()
}

// IsLocal reports whether host is a loopback host or DockerHost. Both reach
// the machine itself, so local development uses them for wallet, issuer and
// verifier.
func IsLocal(host string) bool {
	return IsLoopback(host) || normalize(host) == DockerHost
}

func normalize(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}
