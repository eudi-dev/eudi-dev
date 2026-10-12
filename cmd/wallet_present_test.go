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
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

func useStrictValidation(t *testing.T) {
	t.Helper()
	previous := walletValidationMode
	walletValidationMode = string(wallet.ValidationModeStrict)
	t.Cleanup(func() { walletValidationMode = previous })
}

func TestOneShotAcceptAppliesHAIPToPresentations(t *testing.T) {
	uri := `openid4vp://?client_id=redirect_uri:https://verifier.example/cb&response_type=vp_token&response_mode=direct_post&nonce=n-0` +
		`&response_uri=https://verifier.example/cb&dcql_query=` +
		url.QueryEscape(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:unheld"]}}]}`)

	for _, tc := range []struct {
		name    string
		haip    bool
		wantErr string
	}{
		{name: "without --haip", haip: false, wantErr: "no matching credentials"},
		{name: "with --haip", haip: true, wantErr: "HAIP 1.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetRemoteTestState(t)
			useStrictValidation(t)

			// An explicit free port keeps a wallet server running on the default port out of the flow.
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			_ = listener.Close()

			err = acceptOID4URI(uri, dispatchOID4Opts{
				port:         port,
				portExplicit: true,
				autoAccept:   true,
				haip:         tc.haip,
				mode:         walletValidationMode,
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestOneShotAcceptAppliesHAIPToOffers(t *testing.T) {
	for _, tc := range []struct {
		name          string
		haip          bool
		wantErr       string
		wantTokenCall bool
	}{
		{name: "without --haip", haip: false, wantTokenCall: true},
		{name: "with --haip", haip: true, wantErr: "must be an https URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetRemoteTestState(t)
			useStrictValidation(t)

			const issuerURL = "http://issuer.example"
			var tokenCalls atomic.Int32
			issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/openid-credential-issuer":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"credential_issuer":   issuerURL,
						"credential_endpoint": issuerURL + "/credential",
						"credential_configurations_supported": map[string]any{
							"pid": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:pid"},
						},
					})
				case "/.well-known/oauth-authorization-server":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"issuer":         issuerURL,
						"token_endpoint": issuerURL + "/token",
					})
				case "/token":
					tokenCalls.Add(1)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer issuer.Close()

			// HAIP exempts http on loopback, so the issuer sits behind a proxy under a public name.
			t.Setenv("HTTP_PROXY", "")
			t.Setenv("NO_PROXY", "")
			previousProxy, previousNoProxy := walletHTTPProxy, walletNoProxy
			walletHTTPProxy, walletNoProxy = issuer.URL, ""
			t.Cleanup(func() { walletHTTPProxy, walletNoProxy = previousProxy, previousNoProxy })

			offer, err := json.Marshal(map[string]any{
				"credential_issuer":            issuerURL,
				"credential_configuration_ids": []string{"pid"},
				"grants": map[string]any{
					"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
						"pre-authorized_code": "code",
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			uri := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offer))

			err = acceptOID4URI(uri, dispatchOID4Opts{haip: tc.haip, mode: walletValidationMode})
			if err == nil {
				t.Fatal("the offer was accepted, want the token or HAIP error")
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
			if got := tokenCalls.Load() > 0; got != tc.wantTokenCall {
				t.Errorf("token endpoint called = %v, want %v (err = %v)", got, tc.wantTokenCall, err)
			}
		})
	}
}
