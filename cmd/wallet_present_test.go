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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/config"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
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
				conformance:  walletConformance{settings: wallet.ConformanceSettings{ValidationMode: wallet.ValidationMode(walletValidationMode), RequireHAIP: tc.haip}},
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// A presentation runs on the wallet of its wallet directory. A server that the
// URL handler registered for another wallet does not take it over.
func TestPresentationStaysWithItsWalletDirectory(t *testing.T) {
	resetRemoteTestState(t)
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(`{"status":"submitted"}`))
	}))
	defer other.Close()
	if err := os.WriteFile(filepath.Join(config.BaseDir(), "url-handler.sh"), []byte(`LISTENER="`+other.URL+`"`), 0o755); err != nil {
		t.Fatal(err)
	}

	uri := `openid4vp://?client_id=redirect_uri:https://verifier.example/cb&response_type=vp_token&response_mode=direct_post&nonce=n-0` +
		`&response_uri=https://verifier.example/cb&dcql_query=` +
		url.QueryEscape(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:unheld"]}}]}`)
	err := acceptOID4URI(uri, dispatchOID4Opts{autoAccept: true, conformance: walletConformance{settings: wallet.ConformanceSettings{ValidationMode: wallet.ValidationMode(walletValidationMode)}}})
	if err == nil || !strings.Contains(err.Error(), "no matching credentials") {
		t.Fatalf("err = %v, want the local wallet to find no match", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the server of another wallet received %d requests", n)
	}
}

// The local accept runs the wallet's presentation flow, so a verifier whose
// query matches nothing gets access_denied (OpenID4VP 1.0 §8.5) as it does
// from a running wallet.
func TestOneShotPresentationTellsTheVerifierAboutNoMatch(t *testing.T) {
	resetRemoteTestState(t)
	received := make(chan url.Values, 1)
	verifier := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		received <- r.PostForm
	}))
	defer verifier.Close()
	cb := verifier.URL + "/cb"
	uri := "openid4vp://?client_id=" + url.QueryEscape("redirect_uri:"+cb) +
		"&response_type=vp_token&response_mode=direct_post&nonce=n-1&response_uri=" + url.QueryEscape(cb) +
		"&dcql_query=" + url.QueryEscape(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:unheld"]}}]}`)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	err = acceptOID4URI(uri, dispatchOID4Opts{port: port, portExplicit: true, autoAccept: true, conformance: walletConformance{settings: wallet.ConformanceSettings{ValidationMode: wallet.ValidationModeDebug}}})
	if err == nil || !strings.Contains(err.Error(), "no matching credentials") {
		t.Fatalf("err = %v, want no match", err)
	}
	select {
	case form := <-received:
		if form.Get("error") != "access_denied" {
			t.Errorf("the verifier received %v, want access_denied", form)
		}
	default:
		t.Error("the verifier received no response")
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

			err = acceptOID4URI(uri, dispatchOID4Opts{conformance: walletConformance{settings: wallet.ConformanceSettings{ValidationMode: wallet.ValidationMode(walletValidationMode), RequireHAIP: tc.haip}}})
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

func TestOneShotIssuancePrintsOnlyTheResultAsJSON(t *testing.T) {
	t.Cleanup(func() { jsonOutput = false })
	jsonOutput = true
	for _, result := range []*wallet.IssuanceResult{
		{CredentialID: "c1", Format: "dc+sd-jwt", Issuer: "https://issuer.example", VerificationDetail: "signature valid"},
		{Issuer: "https://issuer.example", Pending: true, TransactionID: "tx", RetryInterval: "5s"},
	} {
		out := captureStdout(t, func() { printIssuanceResult(result) })
		var doc wallet.IssuanceResult
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("stdout is not one JSON document: %v\n%s", err, out)
		}
		if doc.Issuer != result.Issuer || doc.Pending != result.Pending {
			t.Errorf("printed %+v, want %+v", doc, result)
		}
	}
}

func TestOneShotPresentationPrintsOnlyTheResultAsJSON(t *testing.T) {
	resetRemoteTestState(t)
	t.Cleanup(func() {
		jsonOutput = false
		resetFlags(rootCmd)
	})
	dir := walletDir
	rootCmd.SetArgs([]string{"issue", "sdjwt", "--pid", "--wallet"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt --pid --wallet: %v", err)
	}
	resetFlags(rootCmd)
	walletDir = dir

	var posts atomic.Int32
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer verifier.Close()
	cb := verifier.URL + "/cb"
	uri := "openid4vp://?client_id=" + url.QueryEscape("redirect_uri:"+cb) +
		"&response_type=vp_token&response_mode=direct_post&nonce=n-1&response_uri=" + url.QueryEscape(cb) +
		"&dcql_query=" + url.QueryEscape(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["given_name"]}]}]}`)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	jsonOutput = true
	var runErr error
	out := captureStdout(t, func() {
		runErr = acceptOID4URI(uri, dispatchOID4Opts{
			port:         port,
			portExplicit: true,
			autoAccept:   true,
			conformance:  walletConformance{settings: wallet.ConformanceSettings{ValidationMode: wallet.ValidationModeDebug}},
		})
	})
	if runErr != nil {
		t.Fatalf("accept: %v", runErr)
	}
	if posts.Load() != 1 {
		t.Fatalf("the verifier got %d responses, want 1", posts.Load())
	}
	var doc struct {
		Status      string   `json:"status"`
		VPTokenKeys []string `json:"vp_token_keys"`
		Response    struct {
			StatusCode int `json:"status_code"`
		} `json:"response"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, out)
	}
	if doc.Status != "submitted" || doc.Response.StatusCode != http.StatusOK || len(doc.VPTokenKeys) != 1 {
		t.Errorf("document %+v, want the running server's submitted document", doc)
	}
}

// Strict --arf answers a verifier that authenticated with a trusted access
// certificate with access_denied, as the wallet's /authorize endpoint does.
func TestOneShotPresentationSendsTheARFRefusalToTheVerifier(t *testing.T) {
	resetRemoteTestState(t)
	useStrictValidation(t)
	w, store, err := loadWallet()
	if err != nil {
		t.Fatal(err)
	}
	rp, err := w.Registrar().RegisterRelyingParty(registrar.WalletRelyingParty{
		TradeName:  "Example Shop",
		Identifier: []registrar.Identifier{{Type: "http://data.europa.eu/eudi/id/LEI", Identifier: "5299000J2N45DDNE4Y28"}},
		Services: []registrar.WalletRelyingPartyService{{IntendedUses: []registrar.IntendedUse{{
			Purpose:     []registrar.MultiLangString{{Lang: "en", Content: "Age check"}},
			Credentials: []registrar.RegisteredCredential{{Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []string{"urn:eudi:pid:1"}}, Claims: []registrar.RegisteredClaim{{Path: []any{"age_over_18"}}}}},
		}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	access, err := w.Registrar().IssueAccessCertificate(registrar.AccessCertificateRequest{Identifier: rp.Identifier[0].Identifier, CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))})
	if err != nil {
		t.Fatal(err)
	}
	registration, err := w.Registrar().IssueRegistrationCertificate(registrar.RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier, IntendedUseIdentifier: rp.Services[0].IntendedUses[0].IntendedUseIdentifier})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}
	chain, err := keys.ParseCertificatesPEM([]byte(access.Chain))
	if err != nil {
		t.Fatal(err)
	}

	received := make(chan url.Values, 1)
	verifier := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		received <- r.PostForm
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(verifier.Close)
	var info []any
	if err := json.Unmarshal([]byte(registration.VerifierInfo), &info); err != nil {
		t.Fatal(err)
	}
	clientID := oid4vp.X509HashClientID(chain[0])
	request, err := oid4vp.SignRequestObjectJWT(map[string]any{
		"client_id": clientID, "response_type": "vp_token", "response_mode": "direct_post",
		"response_uri": verifier.URL, "nonce": "n", "state": "s", "verifier_info": info,
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
			"claims": []any{map[string]any{"path": []any{"birthdate"}}},
		}}},
	}, key, chain)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	err = acceptOID4URI("openid4vp://authorize?"+url.Values{"client_id": {clientID}, "request": {request}}.Encode(), dispatchOID4Opts{
		port: port, portExplicit: true, autoAccept: true, conformance: walletConformance{settings: wallet.ConformanceSettings{ValidationMode: wallet.ValidationMode(walletValidationMode), RequireARF: true}},
	})
	if err == nil || !strings.Contains(err.Error(), "RPRC_21") {
		t.Fatalf("err = %v, want the RPRC_21 refusal", err)
	}
	select {
	case form := <-received:
		if form.Get("error") != "access_denied" || form.Get("state") != "s" {
			t.Errorf("the verifier received %v, want access_denied", form)
		}
	default:
		t.Error("the verifier received no response")
	}
}
