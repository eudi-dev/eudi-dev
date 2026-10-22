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
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

func TestStrictTLSRequestFetch(t *testing.T) {
	verifier := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = io.WriteString(rw, "request-object")
	}))
	defer verifier.Close()
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	_, err := fetchRequestURIGET(w, verifier.URL)
	var certErr *tls.CertificateVerificationError
	if !errors.As(err, &certErr) {
		t.Fatalf("strict wallet must reject the untrusted TLS certificate: %v", err)
	}
}

func TestStrictTLSResponsePost(t *testing.T) {
	verifier := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(rw, `{}`)
	}))
	defer verifier.Close()
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	_, err := w.submitAuthorizationError("access_denied", "declined", "state", verifier.URL,
		&oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ResponseMode: "direct_post"}})
	var certErr *tls.CertificateVerificationError
	if !errors.As(err, &certErr) {
		t.Fatalf("strict wallet must reject the untrusted TLS certificate: %v", err)
	}
}

func TestWalletTLSModeAndOverrides(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/request" {
			w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
			_, _ = io.WriteString(w, "eyJhbGciOiJFUzI1NiJ9.eyJub25jZSI6InRlc3QifQ.c2ln")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"credential_issuer": "https://" + r.Host, "credential_configuration_ids": []string{"pid"}, "c_nonce": "nonce"})
	}))
	defer server.Close()
	for _, tc := range []struct {
		name   string
		mode   ValidationMode
		verify *bool
		trust  bool
		reject bool
	}{
		{name: "strict default", mode: ValidationModeStrict, reject: true},
		{name: "debug default", mode: ValidationModeDebug},
		{name: "strict disabled", mode: ValidationModeStrict, verify: tlsBool(false)},
		{name: "debug enabled", mode: ValidationModeDebug, verify: tlsBool(true), reject: true},
		{name: "strict trusted", mode: ValidationModeStrict, trust: true},
		{name: "debug enabled trusted", mode: ValidationModeDebug, verify: tlsBool(true), trust: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			w.ValidationMode = tc.mode
			var ca []byte
			if tc.trust {
				ca = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			}
			if err := w.ConfigureOutbound(OutboundConfig{TLSVerify: tc.verify, TLSCAPEM: ca}); err != nil {
				t.Fatal(err)
			}
			defer w.HTTPClient().CloseIdleConnections()
			for _, exchange := range []struct {
				name string
				run  func() error
			}{
				{"request GET", func() error { _, err := fetchRequestURIGET(w, server.URL+"/request"); return err }},
				{"request POST", func() error {
					_, err := fetchRequestURIPOST(w, server.URL+"/request", "", nil)
					return err
				}},
				{"response POST", func() error {
					_, err := w.submitAuthorizationError("access_denied", "declined", "state", server.URL, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ResponseMode: "direct_post"}})
					return err
				}},
				{"offer GET", func() error {
					_, err := w.resolveOffer("openid-credential-offer://?credential_offer_uri="+url.QueryEscape(server.URL), nil)
					return err
				}},
				{"issuer metadata", func() error {
					_, _, err := fetchIssuerMetadataDocument(w.HTTPClient(), server.URL, false, refuseMetadataProblem)
					return err
				}},
				{"OAuth metadata", func() error { _, err := fetchOAuthMetadata(w.HTTPClient(), server.URL); return err }},
				{"token POST", func() error {
					_, err := postFormWithDPoP(w.HTTPClient(), server.URL, url.Values{"grant_type": {"test"}}, nil, "", nil, nil, nil)
					return err
				}},
				{"nonce POST", func() error { _, _, err := nonceRequest(w.HTTPClient(), "POST", server.URL, nil); return err }},
				{"attestation challenge", func() error { _, err := fetchAttestationChallenge(server.URL, w.HTTPClient()); return err }},
			} {
				t.Run(exchange.name, func(t *testing.T) {
					err := exchange.run()
					if tc.reject {
						var certErr *tls.CertificateVerificationError
						if !errors.As(err, &certErr) {
							t.Fatalf("expected TLS rejection, got %v", err)
						}
					} else if err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

func tlsBool(value bool) *bool { return &value }

func TestTLSConformanceSettingsApplyToExistingClientsAndClones(t *testing.T) {
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer endpoint.Close()
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)
	client := w.HTTPClient()
	defer client.CloseIdleConnections()
	for _, tc := range []struct {
		body     string
		reject   bool
		override *bool
	}{
		{body: `{"validation_mode":"strict"}`, reject: true},
		{body: `{"tls_verify_override":false}`, override: tlsBool(false)},
		{body: `{"validation_mode":"debug"}`, override: tlsBool(false)},
		{body: `{"tls_verify_override":true}`, reject: true, override: tlsBool(true)},
		{body: `{"validation_mode":"strict"}`, reject: true, override: tlsBool(true)},
		{body: `{"tls_verify_override":null}`, reject: true},
		{body: `{"validation_mode":"debug"}`},
	} {
		t.Run(tc.body, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/api/config/conformance", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			srv.mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("config: %d %s", rec.Code, rec.Body.String())
			}
			config := decodeJSON(t, rec)
			if config["tls_verify"] != tc.reject {
				t.Fatalf("effective TLS setting: %v", config)
			}
			gotOverride := config["tls_verify_override"]
			if tc.override == nil {
				if gotOverride != nil {
					t.Fatalf("override = %v", gotOverride)
				}
			} else if gotOverride != *tc.override {
				t.Fatalf("override = %v", gotOverride)
			}
			for _, c := range []*http.Client{client} {
				resp, err := c.Get(endpoint.URL)
				if resp != nil {
					resp.Body.Close()
				}
				if tc.reject {
					var certErr *tls.CertificateVerificationError
					if !errors.As(err, &certErr) {
						t.Fatalf("expected TLS rejection, got %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	req := httptest.NewRequest(http.MethodPut, "/api/config/conformance", strings.NewReader(`{"validation_mode":"strict","tls_verify_override":"false"}`))
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || w.Mode() != ValidationModeDebug {
		t.Fatalf("invalid config changed state: %d %s", rec.Code, rec.Body.String())
	}
}

func TestTLSResetPreservesExplicitStartupOverride(t *testing.T) {
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	if err := w.ConfigureOutbound(OutboundConfig{TLSVerify: tlsBool(false)}); err != nil {
		t.Fatal(err)
	}
	defer w.HTTPClient().CloseIdleConnections()
	srv := NewServer(w, 0, nil)
	for _, tc := range []struct {
		method, body string
		want         bool
	}{
		{http.MethodPut, `{"tls_verify_override":true}`, true},
		{http.MethodDelete, "", false},
	} {
		req := httptest.NewRequest(tc.method, "/api/config/conformance", strings.NewReader(tc.body))
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || decodeJSON(t, rec)["tls_verify"] != tc.want {
			t.Fatalf("config reset: %d %s", rec.Code, rec.Body.String())
		}
	}
}

func TestTLSTrustSurvivesStoreReload(t *testing.T) {
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer endpoint.Close()
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: endpoint.Certificate().Raw})
	if err := w.ConfigureOutbound(OutboundConfig{TLSCAPEM: ca}); err != nil {
		t.Fatal(err)
	}
	defer w.HTTPClient().CloseIdleConnections()
	server := NewServer(w, 0, nil)
	server.applyPersistedWalletState(generateTestWallet(t))
	response, err := w.HTTPClient().Get(endpoint.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "ok" {
		t.Fatalf("response=%q err=%v", body, err)
	}
}

// The wallet CA signs the certificate of the wallet's own HTTPS listener. A
// strict wallet reaches it, for example for the status list of a credential
// it issued, and still refuses a certificate from another CA.
func TestStrictWalletTrustsItsOwnHTTPSListener(t *testing.T) {
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	caKey, chain := w.certificateAuthority()
	cert, err := generateIssuerTLSCertificate("localhost", caKey, caCertificate(chain))
	if err != nil {
		t.Fatal(err)
	}
	own := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(rw, "ok") }))
	own.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	own.StartTLS()
	defer own.Close()
	defer w.HTTPClient().CloseIdleConnections()

	response, err := w.HTTPClient().Get(strings.Replace(own.URL, "127.0.0.1", "localhost", 1))
	if err != nil {
		t.Fatalf("the wallet refused its own listener: %v", err)
	}
	_ = response.Body.Close()

	foreign := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {}))
	defer foreign.Close()
	_, err = w.HTTPClient().Get(foreign.URL)
	var certErr *tls.CertificateVerificationError
	if !errors.As(err, &certErr) {
		t.Fatalf("a certificate from another CA must be refused: %v", err)
	}
}
