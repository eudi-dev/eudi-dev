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

package web

import (
	"crypto/ecdsa"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/statuslist"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

// The decoder of `wallet serve` fetches status lists, trusted lists and issuer
// metadata with the wallet's outbound settings. A host with a private CA is
// reachable with --tls-ca or --tls-verify=false and refused with verification on
// and no CA.
func TestDecoderValidationUsesTheWalletTLSSettings(t *testing.T) {
	store := wallet.NewWalletStore(t.TempDir())
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("loading wallet: %v", err)
	}
	metadataKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	defer srv.Close()
	srv.Config.Handler = issuerHostHandler(t, w, srv.URL, metadataKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	chain, err := w.DefaultSigningCertChain()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	claims := map[string]any{"given_name": "Erika"}
	withStatus, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer: srv.URL, VCT: "urn:test", ExpiresIn: time.Hour, Claims: claims,
		Key: w.IssuerKey, CertChain: chain, StatusListURI: srv.URL + "/statuslist",
	})
	if err != nil {
		t.Fatal(err)
	}
	withMetadataKey, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer: srv.URL, VCT: "urn:test", ExpiresIn: time.Hour, Claims: claims, Key: metadataKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	trustList, err := wallet.GenerateTrustListJWTForWallet(w, srv.URL)
	if err != nil {
		t.Fatalf("trusted list: %v", err)
	}

	mux := NewMuxWithOptions(MuxOptions{WalletStore: store, HTTPClient: w.HTTPClient})
	on, off := true, false
	for _, tc := range []struct {
		name     string
		cfg      wallet.OutboundConfig
		wantPass bool
	}{
		{"verification off", wallet.OutboundConfig{TLSVerify: &off}, true},
		{"private CA configured", wallet.OutboundConfig{TLSVerify: &on, TLSCAPEM: caPEM}, true},
		{"verification on without the CA", wallet.OutboundConfig{TLSVerify: &on}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := w.ConfigureOutbound(tc.cfg); err != nil {
				t.Fatalf("configuring outbound: %v", err)
			}
			for _, fetch := range []struct {
				name   string
				path   string
				body   map[string]any
				checks []string
			}{
				{"trusted list", "/api/validate", map[string]any{"input": withStatus, "trustListURL": srv.URL + "/trustlist", "checkStatus": true}, []string{"signature", "status", "status list signature"}},
				{"status list", "/api/validate", map[string]any{"input": withStatus, "trustListRaw": trustList, "checkStatus": true}, []string{"status", "status list signature"}},
				{"issuer metadata", "/api/validate", map[string]any{"input": withMetadataKey}, []string{"signature"}},
				{"issuer metadata on decode", "/api/decode", map[string]any{"input": withMetadataKey}, []string{"signature"}},
			} {
				checks := validateChecks(t, mux, fetch.path, fetch.body)
				for _, name := range fetch.checks {
					if passed := checks[name].Status == "pass"; passed != tc.wantPass {
						t.Errorf("%s: %s check = %+v, want pass %v", fetch.name, name, checks[name], tc.wantPass)
					}
				}
			}
		})
	}
}

// issuerHostHandler serves a status list with a valid first entry, the wallet's
// trusted list, and JWT VC issuer metadata that publishes metadataKey.
func issuerHostHandler(t *testing.T, w *wallet.Wallet, issuerURL string, metadataKey *ecdsa.PrivateKey) http.Handler {
	t.Helper()
	chain, err := w.DefaultSigningCertChain()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/statuslist", func(rw http.ResponseWriter, r *http.Request) {
		jwt, err := statuslist.GenerateStatusListJWT([]byte{0}, w.IssuerKey, statuslist.StatusListConfig{
			URI:       issuerURL + "/statuslist",
			Issuer:    issuerURL,
			CertChain: chain,
		})
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		rw.Header().Set("Content-Type", "application/statuslist+jwt")
		_, _ = rw.Write([]byte(jwt))
	})
	mux.HandleFunc("/trustlist", func(rw http.ResponseWriter, r *http.Request) {
		jwt, err := wallet.GenerateTrustListJWTForWallet(w, issuerURL)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = rw.Write([]byte(jwt))
	})
	mux.HandleFunc("/.well-known/jwt-vc-issuer", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]any{
			"issuer": issuerURL,
			"jwks":   map[string]any{"keys": []any{mock.SigningJWKMap(&metadataKey.PublicKey)}},
		})
	})
	return mux
}

func validateChecks(t *testing.T, h http.Handler, path string, body map[string]any) map[string]CheckResult {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: HTTP %d: %s", path, rec.Code, rec.Body.String())
	}
	var resp struct {
		Validation struct {
			Checks []CheckResult `json:"checks"`
		} `json:"validation"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	checks := map[string]CheckResult{}
	for _, c := range resp.Validation.Checks {
		checks[c.Name] = c
	}
	return checks
}
