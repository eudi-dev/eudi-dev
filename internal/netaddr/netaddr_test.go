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

package netaddr

import "testing"

func TestIsLocal(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost":             true,
		"LOCALHOST":             true,
		"localhost.":            true,
		"127.0.0.1":             true,
		"127.0.0.2":             true,
		"127.255.255.254":       true,
		"::1":                   true,
		"[::1]":                 true,
		"::ffff:127.0.0.1":      true,
		"host.docker.internal":  true,
		"Host.Docker.Internal":  true,
		"10.0.0.1":              false,
		"192.168.1.1":           false,
		"example.com":           false,
		"localhost.example.com": false,
		"":                      false,
	} {
		if got := IsLocal(host); got != want {
			t.Errorf("IsLocal(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestIsLoopbackLeavesOutTheDockerHost(t *testing.T) {
	if IsLoopback("host.docker.internal") {
		t.Error("host.docker.internal counts as loopback")
	}
	if !IsLoopback("127.0.0.2") {
		t.Error("127.0.0.2 does not count as loopback")
	}
}

func TestParseListenHost(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1":   "127.0.0.1",
		"localhost":   "127.0.0.1",
		"LocalHost.":  "127.0.0.1",
		"0.0.0.0":     "0.0.0.0",
		"::1":         "::1",
		"[::]":        "::",
		" 10.0.0.5 ":  "10.0.0.5",
		"fd00::0:0:1": "fd00::1",
	} {
		got, err := ParseListenHost(in)
		if err != nil || got != want {
			t.Errorf("ParseListenHost(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
	// A host name binds at most one of its addresses, so only IP addresses
	// pick the interface.
	for _, in := range []string{"", "example.com", "fe80::1%en0", "127.0.0.1:8085"} {
		if got, err := ParseListenHost(in); err == nil {
			t.Errorf("ParseListenHost(%q) = %q, want an error", in, got)
		}
	}
}

func TestLocalURL(t *testing.T) {
	for _, tc := range []struct {
		host string
		want string
	}{
		{"127.0.0.1", "http://localhost:8085"},
		{"::1", "http://localhost:8085"},
		{"0.0.0.0", "http://localhost:8085"},
		{"::", "http://localhost:8085"},
		{"192.168.1.5", "http://192.168.1.5:8085"},
		{"fd00::1", "http://[fd00::1]:8085"},
	} {
		if got := LocalURL(tc.host, 8085); got != tc.want {
			t.Errorf("LocalURL(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}
