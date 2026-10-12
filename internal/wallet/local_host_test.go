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

import "testing"

// Plain http is secure exactly on the hosts treated as local by the HTTP client.
func TestSecureIssuerOriginOnLocalHosts(t *testing.T) {
	for issuer, want := range map[string]bool{
		"https://issuer.example":            true,
		"http://LOCALHOST:8080":             true,
		"http://127.0.0.2:8080":             true,
		"http://host.docker.internal:8080":  true,
		"http://issuer.example":             false,
		"http://192.168.1.10:8080":          false,
		"ftp://localhost/credential-issuer": false,
	} {
		if got := secureIssuerOrigin(issuer); got != want {
			t.Errorf("secureIssuerOrigin(%q) = %v, want %v", issuer, got, want)
		}
	}
}

func TestSameLoopbackHost(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"localhost", "127.0.0.1", true},
		{"LOCALHOST", "::1", true},
		{"127.0.0.2", "localhost", true},
		{"Issuer.Example", "issuer.example", true},
		{"host.docker.internal", "localhost", false},
		{"issuer.example", "localhost", false},
	} {
		if got := sameLoopbackHost(tc.a, tc.b); got != tc.want {
			t.Errorf("sameLoopbackHost(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
