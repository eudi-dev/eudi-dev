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

package wallet

import (
	"net"
	"net/url"
	"testing"
	"time"
)

func listeningPort(t *testing.T, addr string) string {
	t.Helper()
	u, err := url.Parse(addr)
	if err != nil {
		t.Fatal(err)
	}
	return u.Port()
}

func reachable(host, port string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func requireIPv6Loopback(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	_ = ln.Close()
}

// The wallet API has no authentication, so a server binds the IPv4 loopback
// address unless told otherwise (SECURITY.md).
func TestServerBindsIPv4LoopbackByDefault(t *testing.T) {
	requireIPv6Loopback(t)
	srv := NewServer(generateTestWallet(t), 0, nil)
	addr, err := srv.ListenAndServeBackground()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()
	port := listeningPort(t, addr)
	if !reachable("127.0.0.1", port) {
		t.Error("the server does not answer on 127.0.0.1")
	}
	if reachable("::1", port) {
		t.Error("the server answers on ::1 although it binds 127.0.0.1 only")
	}
}

func TestServerBindsTheListenHost(t *testing.T) {
	requireIPv6Loopback(t)
	srv := NewServer(generateTestWallet(t), 0, nil)
	srv.SetListenHost("::1")
	addr, err := srv.ListenAndServeBackground()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()
	port := listeningPort(t, addr)
	if !reachable("::1", port) {
		t.Error("the server does not answer on ::1")
	}
	if reachable("127.0.0.1", port) {
		t.Error("the server answers on 127.0.0.1 although it binds ::1 only")
	}
}
