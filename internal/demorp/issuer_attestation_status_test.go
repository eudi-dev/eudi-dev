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

package demorp

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/statuslist"
)

// serveProviderStatusLists serves the wallet provider's status lists. On
// /list, index 0 is valid and index 1 revoked. /expired is a list whose
// token has expired, and /moved names another uri as its subject.
func serveProviderStatusLists(t *testing.T, provider walletProvider) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(nil)
	t.Cleanup(srv.Close)
	serve := func(cfg statuslist.StatusListConfig) http.HandlerFunc {
		return func(rw http.ResponseWriter, _ *http.Request) {
			jwt, err := statuslist.GenerateStatusListJWT([]byte{0b00000010}, provider.key, cfg)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
				return
			}
			rw.Header().Set("Content-Type", statuslist.MediaTypeJWT)
			_, _ = rw.Write([]byte(jwt))
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/list", serve(statuslist.StatusListConfig{URI: srv.URL + "/list"}))
	mux.Handle("/expired", serve(statuslist.StatusListConfig{URI: srv.URL + "/expired", IssuedAt: time.Now().Add(-48 * time.Hour)}))
	mux.Handle("/moved", serve(statuslist.StatusListConfig{URI: srv.URL + "/elsewhere"}))
	srv.Config.Handler = mux
	return srv
}

func statusReference(uri string, idx int) map[string]any {
	return map[string]any{"status_list": map[string]any{"uri": uri, "idx": idx}}
}

// attestationStatusCases are status references on the lists of
// serveProviderStatusLists, with the words a refusal names.
var attestationStatusCases = []struct {
	name, path string
	idx        int
	want       string
}{
	{"a valid entry", "/list", 0, ""},
	{"a revoked entry", "/list", 1, "INVALID"},
	{"an index out of range", "/list", 100, "out of range"},
	{"an expired status list", "/expired", 0, "expired"},
	{"a status list of another uri", "/moved", 0, "subject"},
}

// ARF WUA_25: the PID Provider "SHALL validate that the WIA is not revoked".
// CIR (EU) 2024/2979 Annex Ib C_WIA-1 puts the reference in client_status.
func TestTheStatusOfAWalletInstanceAttestationIsChecked(t *testing.T) {
	d, _, _ := newDemoRP(t)
	provider := foreignWalletProvider(t)
	lists := serveProviderStatusLists(t, provider)

	for _, claim := range []string{"client_status", "status"} {
		for _, tc := range attestationStatusCases {
			t.Run(claim+"/"+tc.name, func(t *testing.T) {
				clientKey, err := mock.GenerateKey()
				if err != nil {
					t.Fatal(err)
				}
				payload := map[string]any{
					"sub": "wallet",
					"iat": time.Now().Unix(),
					"exp": time.Now().Add(5 * time.Minute).Unix(),
					"cnf": map[string]any{"jwk": holderJWK(t, clientKey)},
				}
				reference := statusReference(lists.URL+tc.path, tc.idx)
				if claim == "client_status" {
					payload[claim] = map[string]any{"status": reference, "exp": time.Now().Add(60 * 24 * time.Hour).Unix()}
				} else {
					payload[claim] = reference
				}
				attestation := signJWT(t, provider.key,
					map[string]any{"typ": "oauth-client-attestation+jwt", "x5c": []any{base64.StdEncoding.EncodeToString(provider.leaf.Raw)}},
					payload)
				rec := pushAuthorizationRequest(t, d.IssuerHandler(), "wallet", nil, "abc", map[string]string{
					"OAuth-Client-Attestation":     attestation,
					"OAuth-Client-Attestation-PoP": attestationPoP(t, clientKey, demoIssuerID),
				})
				switch {
				case tc.want == "" && rec.Code != http.StatusCreated:
					t.Errorf("status = %d, want 201: %s", rec.Code, rec.Body.String())
				case tc.want != "" && (rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.want)):
					t.Errorf("status = %d %s, want 400 naming %q", rec.Code, rec.Body.String(), tc.want)
				}
			})
		}
	}
}

// ARF WUA_11a: the provider "SHALL validate that the KA is not revoked". CIR
// (EU) 2024/2979 Annex Ib C_KA-1 puts the reference in key_storage_status.
func TestTheStatusOfAKeyAttestationIsChecked(t *testing.T) {
	d, _, _ := newDemoRP(t)
	provider := foreignWalletProvider(t)
	lists := serveProviderStatusLists(t, provider)
	keys := generateKeys(t, 1)

	for _, tc := range attestationStatusCases {
		t.Run(tc.name, func(t *testing.T) {
			attestation := provider.keyAttestation(t, d, keys, func(p map[string]any) {
				p["key_storage_status"] = map[string]any{"status": statusReference(lists.URL+tc.path, tc.idx), "exp": time.Now().Add(60 * 24 * time.Hour).Unix()}
			})
			code, doc := sendProofs(t, d, "credential=pid-sdjwt", "attestation", attestation)
			switch {
			case tc.want == "" && code != http.StatusOK:
				t.Errorf("status = %d %v, want 200", code, doc)
			case tc.want != "" && (code != http.StatusBadRequest || doc["error"] != "invalid_proof" || !strings.Contains(fmt.Sprint(doc["error_description"]), tc.want)):
				t.Errorf("status = %d %v, want 400 invalid_proof naming %q", code, doc, tc.want)
			}
		})
	}
}
