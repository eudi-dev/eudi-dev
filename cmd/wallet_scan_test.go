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

package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestAcceptOID4URIRoutesToRemote(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		wantPath string
	}{
		{
			name:     "a credential offer",
			uri:      "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example%22%7D",
			wantPath: "/api/offers",
		},
		{
			name:     "a presentation request",
			uri:      "openid4vp://?client_id=x509_hash:abc&request_uri=https://verifier.example/req",
			wantPath: "/api/presentations",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetRemoteTestState(t)

			var (
				mu       sync.Mutex
				gotPath  string
				gotURI   string
				gotCalls int
			)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				gotCalls++
				gotPath = r.URL.Path
				var body struct {
					URI string `json:"uri"`
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				gotURI = body.URI
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"status":"completed"}`)
			}))
			defer ts.Close()

			remoteFlag = ts.URL
			t.Cleanup(func() { remoteFlag = "" })

			// autoAccept keeps it non-interactive so no consent browser opens.
			if err := acceptOID4URI(tt.uri, dispatchOID4Opts{autoAccept: true}); err != nil {
				t.Fatalf("acceptOID4URI: %v", err)
			}

			mu.Lock()
			defer mu.Unlock()
			if gotCalls != 1 {
				t.Fatalf("remote wallet received %d calls, want 1", gotCalls)
			}
			if gotPath != tt.wantPath {
				t.Errorf("routed to %q, want %q on the remote wallet", gotPath, tt.wantPath)
			}
			if gotURI != tt.uri {
				t.Errorf("remote received uri %q, want %q", gotURI, tt.uri)
			}
		})
	}
}

// A running wallet reports its flow like the local one: text without --json.
// It answers on its own address, so the local listener flags are refused.
func TestRemoteAcceptPrintsTextAndRefusesListenerFlags(t *testing.T) {
	resetRemoteTestState(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/offers" {
			fmt.Fprint(w, `{"credential_id":"c1","format":"dc+sd-jwt","issuer":"https://issuer.example"}`)
			return
		}
		fmt.Fprint(w, `{"status":"submitted","response":{"status_code":200}}`)
	}))
	defer ts.Close()
	remoteFlag = ts.URL

	vp := "openid4vp://?client_id=x509_hash:abc&request_uri=https://verifier.example/req"
	vci := "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example%22%7D"
	for uri, want := range map[string]string{vp: "submitted: HTTP 200", vci: "Received dc+sd-jwt credential from https://issuer.example (ID: c1)"} {
		var err error
		out := captureStdout(t, func() { err = acceptOID4URI(uri, dispatchOID4Opts{autoAccept: true}) })
		if err != nil || !strings.Contains(out, want) {
			t.Errorf("remote accept printed %q, %v, want %q", out, err, want)
		}
	}

	for _, opts := range []dispatchOID4Opts{{autoAccept: true, port: 9999, portExplicit: true}, {autoAccept: true, docker: true}, {autoAccept: true, listenHost: "0.0.0.0", listenExplicit: true}} {
		if err := acceptOID4URI(vp, opts); err == nil || !strings.Contains(err.Error(), "--remote local") {
			t.Errorf("remote accept with --port %v, --docker %v, --listen %v: %v, want a refusal", opts.portExplicit, opts.docker, opts.listenExplicit, err)
		}
	}
}
