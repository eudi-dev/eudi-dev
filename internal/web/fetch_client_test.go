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
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/statuslist"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// verifyingWallet checks TLS certificates on every request. With ca it trusts
// that CA as well. Without a wallet, a loopback request skips verification,
// so only the wallet's client refuses an untrusted certificate.
func verifyingWallet(t *testing.T, ca *httptest.Server) *wallet.Wallet {
	t.Helper()
	holderKey, _ := mock.GenerateKey()
	issuerKey, _ := mock.GenerateKey()
	w := wallet.New(holderKey, issuerKey, false)
	verify := true
	cfg := wallet.OutboundConfig{TLSVerify: &verify}
	if ca != nil {
		cfg.TLSCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate().Raw})
	}
	if err := w.ConfigureOutbound(cfg); err != nil {
		t.Fatal(err)
	}
	return w
}

func countingTLSServer(t *testing.T, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestTheDecoderFetchesATrustedListWithTheWalletClient(t *testing.T) {
	srv, hits := countingTLSServer(t, "not a trusted list")

	trust := resolveTrust(ValidateOpts{Wallet: verifyingWallet(t, srv), TrustListURL: srv.URL})
	if trust.Err == nil || !strings.Contains(trust.Err.Error(), "parsing trusted list") || hits.Load() != 1 {
		t.Errorf("with the CA: %v after %d requests, want the fetched body parsed", trust.Err, hits.Load())
	}

	trust = resolveTrust(ValidateOpts{Wallet: verifyingWallet(t, nil), TrustListURL: srv.URL})
	if trust.Err == nil || !strings.Contains(trust.Err.Error(), "certificate") || hits.Load() != 1 {
		t.Errorf("without the CA: %v after %d requests, want a refused certificate", trust.Err, hits.Load())
	}
}

func statusCheck(t *testing.T, raw string, w *wallet.Wallet) CheckResult {
	t.Helper()
	result, err := Validate(raw, ValidateOpts{Wallet: w, CheckStatus: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range result["validation"].(map[string]any)["checks"].([]CheckResult) {
		if c.Name == validate.CheckStatus {
			return c
		}
	}
	t.Fatal("no status check")
	return CheckResult{}
}

func credentialWithStatus(t *testing.T, uri string) string {
	t.Helper()
	key, _ := mock.GenerateKey()
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer: "https://issuer.example", VCT: "urn:example:unknown:1", ExpiresIn: time.Hour,
		Claims: map[string]any{"a": 1}, Key: key, StatusListURI: uri,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestTheDecoderFetchesAStatusListWithTheWalletClient(t *testing.T) {
	key, _ := mock.GenerateKey()
	var uri string
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		token, err := statuslist.GenerateStatusListJWT(make([]byte, 16), key, statuslist.StatusListConfig{URI: uri})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		_, _ = w.Write([]byte(token))
	}))
	t.Cleanup(srv.Close)
	uri = srv.URL + "/status"
	raw := credentialWithStatus(t, uri)

	if check := statusCheck(t, raw, verifyingWallet(t, srv)); check.Status == "fail" || hits.Load() != 1 {
		t.Errorf("with the CA: %+v after %d requests, want the list read", check, hits.Load())
	}
	if check := statusCheck(t, raw, verifyingWallet(t, nil)); check.Status != "fail" || !strings.Contains(check.Detail, "certificate") || hits.Load() != 1 {
		t.Errorf("without the CA: %+v after %d requests, want a refused certificate", check, hits.Load())
	}
}

// The decoder blocks private networks unless --allow-private-networks is
// given. The policy covers the wallet's client as well.
func TestTheDecoderRefusesPrivateAddressesUnderThePolicy(t *testing.T) {
	format.SetFetchPolicy(format.AllowLoopback(format.BlockPrivateAddresses))
	t.Cleanup(func() { format.SetFetchPolicy(nil) })
	const private = "http://10.255.255.1:9/list"
	w := verifyingWallet(t, nil)

	if trust := resolveTrust(ValidateOpts{Wallet: w, TrustListURL: private}); trust.Err == nil || !strings.Contains(trust.Err.Error(), "not allowed") {
		t.Errorf("trusted list: %v, want the private address refused", trust.Err)
	}
	if check := statusCheck(t, credentialWithStatus(t, private), w); check.Status != "fail" || !strings.Contains(check.Detail, "not allowed") {
		t.Errorf("status list: %+v, want the private address refused", check)
	}
}
