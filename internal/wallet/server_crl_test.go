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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
)

func crlRequest(t *testing.T, srv *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func certificatePEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

var testProviderList = provider.CategoryList(credtemplate.CategoryEAA)

// providerChain creates the EAA provider CA and returns its chain: the signing
// certificate, the provider CA and the wallet CA.
func providerChain(t *testing.T, w *Wallet) []*x509.Certificate {
	t.Helper()
	w.IssuerURL = "https://wallet.example"
	_, chain, err := w.Signer().ForList(testProviderList, "DE", "dc+sd-jwt")
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 3 {
		t.Fatalf("chain has %d certificates, want the leaf, the provider CA and the wallet CA", len(chain))
	}
	return chain
}

func parsedCRL(t *testing.T, w *Wallet, path string) *x509.RevocationList {
	t.Helper()
	der, err := w.CRL(path)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	return crl
}

func lists(crl *x509.RevocationList, cert *x509.Certificate) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true
		}
	}
	return false
}

// A signing certificate goes on the CRL of its provider CA, and a provider CA
// on the CRL of the wallet CA (RFC 5280 §5).
func TestRevokedCertificateIsListedByItsIssuer(t *testing.T) {
	srv := newTestServer(t, true)
	chain := providerChain(t, srv.wallet)
	leaf, providerCA := chain[0], chain[1]
	leafCRL := provider.ProviderCRLPath(provider.Role(testProviderList), "DE")

	if rec := crlRequest(t, srv, http.MethodPost, "/api/certificates/revocations", map[string]any{"certificate": certificatePEM(leaf), "reason": 1}); rec.Code != http.StatusCreated {
		t.Fatalf("revoking the leaf: %d %s", rec.Code, rec.Body)
	}
	if rec := crlRequest(t, srv, http.MethodPost, "/api/certificates/revocations", map[string]any{"certificate": certificatePEM(providerCA)}); rec.Code != http.StatusCreated {
		t.Fatalf("revoking the provider CA: %d %s", rec.Code, rec.Body)
	}

	crl := parsedCRL(t, srv.wallet, leafCRL)
	if !lists(crl, leaf) || lists(crl, providerCA) {
		t.Errorf("provider CRL entries = %v", crl.RevokedCertificateEntries)
	}
	if crl.RevokedCertificateEntries[0].ReasonCode != 1 {
		t.Errorf("reason = %d, want 1", crl.RevokedCertificateEntries[0].ReasonCode)
	}
	if err := crl.CheckSignatureFrom(providerCA); err != nil {
		t.Errorf("provider CRL signature: %v", err)
	}
	if root := parsedCRL(t, srv.wallet, provider.RootCRLPath); !lists(root, providerCA) || lists(root, leaf) {
		t.Errorf("root CRL entries = %v", root.RevokedCertificateEntries)
	}
}

// RFC 5280 §3.3 keeps an entry on one CRL issued after the certificate expired.
func TestExpiredCertificateStaysOnOneMoreCRL(t *testing.T) {
	w := generateTestWallet(t)
	now := time.Now()
	w.RevokedCertificates = []RevokedCertificate{
		{Serial: "0a", CRLPath: provider.RootCRLPath, Revoked: 1, Expires: now.Add(-time.Hour).Unix()},
		{Serial: "0b", CRLPath: provider.RootCRLPath, Revoked: 1, Expires: now.Add(-2 * crlUpdateInterval).Unix()},
	}
	entries := w.revokedEntries(provider.RootCRLPath)
	if len(entries) != 1 || entries[0].SerialNumber.Text(16) != "a" {
		t.Errorf("entries = %v, want only the certificate that expired an hour ago", entries)
	}
}

func TestRevocationCanBeUndone(t *testing.T) {
	srv := newTestServer(t, true)
	leaf := providerChain(t, srv.wallet)[0]
	crlRequest(t, srv, http.MethodPost, "/api/certificates/revocations", map[string]any{"certificate": certificatePEM(leaf)})

	rec := crlRequest(t, srv, http.MethodGet, "/api/certificates/revocations", nil)
	var listed []RevokedCertificate
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || len(listed) != 1 {
		t.Fatalf("listed %s (%v)", rec.Body, err)
	}
	if rec := crlRequest(t, srv, http.MethodDelete, "/api/certificates/revocations/"+listed[0].Serial, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("undoing: %d %s", rec.Code, rec.Body)
	}
	if crl := parsedCRL(t, srv.wallet, provider.ProviderCRLPath(provider.Role(testProviderList), "DE")); lists(crl, leaf) {
		t.Error("the CRL still lists the certificate")
	}
	if rec := crlRequest(t, srv, http.MethodDelete, "/api/certificates/revocations/"+listed[0].Serial, nil); rec.Code != http.StatusNotFound {
		t.Errorf("undoing twice: %d", rec.Code)
	}
}

func TestOnlyCertificatesOfThisWalletCanBeRevoked(t *testing.T) {
	srv := newTestServer(t, true)
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := mock.GenerateRootCACert(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]map[string]any{
		"foreign":       {"certificate": certificatePEM(foreign)},
		"no pem":        {"certificate": "nonsense"},
		"unused reason": {"certificate": certificatePEM(providerChain(t, srv.wallet)[0]), "reason": 7},
		"delta reason":  {"certificate": certificatePEM(providerChain(t, srv.wallet)[0]), "reason": 8},
	} {
		if rec := crlRequest(t, srv, http.MethodPost, "/api/certificates/revocations", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

// A trust anchor has no issuer, so a trusted list withdraws it.
func TestSelfSignedCertificateCannotBeRevoked(t *testing.T) {
	srv := newTestServer(t, true)
	root := providerChain(t, srv.wallet)[2]
	rec := crlRequest(t, srv, http.MethodPost, "/api/certificates/revocations", map[string]any{"certificate": certificatePEM(root)})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "trusted list") {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
}

func TestRevocationSurvivesAReload(t *testing.T) {
	for name, store := range map[string]*WalletStore{
		"file":     NewWalletStore(t.TempDir()),
		"entities": NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), storage.NewMemory()),
	} {
		t.Run(name, func(t *testing.T) {
			w, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			w.RevokedCertificates = []RevokedCertificate{{Serial: "0a", CRLPath: provider.RootCRLPath, Revoked: 1, Expires: time.Now().Add(time.Hour).Unix()}}
			w.WithdrawnCertificates = []trustedlists.WithdrawnCertificate{{ID: "ab"}}
			if err := store.Save(w); err != nil {
				t.Fatal(err)
			}
			loaded, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			if len(loaded.RevokedCertificates) != 1 || loaded.RevokedCertificates[0].Serial != "0a" || len(loaded.WithdrawnCertificates) != 1 {
				t.Errorf("loaded %+v %+v", loaded.RevokedCertificates, loaded.WithdrawnCertificates)
			}
			loaded.RevokedCertificates, loaded.WithdrawnCertificates = nil, nil
			if err := store.Save(loaded); err != nil {
				t.Fatal(err)
			}
			if again, err := store.LoadOrCreate(); err != nil || len(again.RevokedCertificates)+len(again.WithdrawnCertificates) != 0 {
				t.Errorf("after undoing: %+v %+v (%v)", again.RevokedCertificates, again.WithdrawnCertificates, err)
			}
		})
	}
}

func TestCRLFaults(t *testing.T) {
	srv := newTestServer(t, true)
	get := func() *httptest.ResponseRecorder {
		return crlRequest(t, srv, http.MethodGet, provider.RootCRLPath, nil)
	}
	set := func(body map[string]any) {
		t.Helper()
		if rec := crlRequest(t, srv, http.MethodPut, "/api/crl/fault", body); rec.Code != http.StatusOK {
			t.Fatalf("setting %v: %d %s", body, rec.Code, rec.Body)
		}
	}
	parse := func(rec *httptest.ResponseRecorder) *x509.RevocationList {
		t.Helper()
		crl, err := x509.ParseRevocationList(rec.Body.Bytes())
		if err != nil {
			t.Fatalf("%d %s: %v", rec.Code, rec.Body, err)
		}
		return crl
	}
	ca := srv.wallet.Signer().TrustAnchor()

	set(map[string]any{"fault": "unavailable"})
	if rec := get(); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("unavailable: %d", rec.Code)
	}

	set(map[string]any{"fault": "expired"})
	if crl := parse(get()); !crl.NextUpdate.Before(time.Now()) {
		t.Errorf("expired CRL has nextUpdate %s", crl.NextUpdate)
	}

	set(map[string]any{"fault": "bad-signature"})
	if err := parse(get()).CheckSignatureFrom(ca); err == nil {
		t.Error("the CRL has a valid signature")
	}

	set(map[string]any{"next_update_seconds": 60})
	crl := parse(get())
	if left := time.Until(crl.NextUpdate); left <= 0 || left > time.Minute {
		t.Errorf("nextUpdate is %s away, want at most 60s", left)
	}
	if err := crl.CheckSignatureFrom(ca); err != nil {
		t.Errorf("signature: %v", err)
	}

	if rec := crlRequest(t, srv, http.MethodDelete, "/api/crl/fault", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("clearing: %d", rec.Code)
	}
	if left := time.Until(parse(get()).NextUpdate); left < 6*24*time.Hour {
		t.Errorf("nextUpdate after clearing is %s away", left)
	}
	if rec := crlRequest(t, srv, http.MethodPut, "/api/crl/fault", map[string]any{"fault": "melting"}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown fault: %d", rec.Code)
	}
	if rec := crlRequest(t, srv, http.MethodPut, "/api/crl/fault", map[string]any{}); rec.Code != http.StatusBadRequest {
		t.Errorf("empty fault: %d", rec.Code)
	}
}

// A hanging CRL ends when the client gives up.
func TestHangingCRLEndsWithTheRequest(t *testing.T) {
	srv := newTestServer(t, true)
	crlRequest(t, srv, http.MethodPut, "/api/crl/fault", map[string]any{"fault": "hang"})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, provider.RootCRLPath, nil).WithContext(ctx))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the request did not end")
	}
}

func TestDemoBlocksCRLControls(t *testing.T) {
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/certificates/revocations"},
		{http.MethodDelete, "/api/certificates/revocations/0a"},
		{http.MethodPut, "/api/crl/fault"},
		{http.MethodDelete, "/api/crl/fault"},
		{http.MethodGet, "/api/credentials/abc/certificates"},
		{http.MethodHead, "/api/credentials/abc/certificates"},
	} {
		if !demoBlockedRoute(httptest.NewRequest(tc.method, tc.path, nil)) {
			t.Errorf("%s %s is open on the demo", tc.method, tc.path)
		}
	}
}

// A CRL client sees a revocation and each fault over HTTP.
func TestCRLClientSeesRevocationAndFaults(t *testing.T) {
	srv := newTestServer(t, true)
	public := httptest.NewServer(srv.Handler())
	defer public.Close()
	srv.wallet.IssuerURL = public.URL
	_, chain, err := srv.wallet.Signer().ForList(testProviderList, "DE", "dc+sd-jwt")
	if err != nil {
		t.Fatal(err)
	}
	problem := func() string {
		t.Helper()
		problems := certchain.CheckRevocation(chain, public.Client(), time.Now())
		if len(problems) == 0 {
			return ""
		}
		return problems[0].Error()
	}
	if got := problem(); got != "" {
		t.Fatalf("clean chain: %s", got)
	}

	for fault, want := range map[string]string{
		"unavailable":   "503",
		"expired":       "expired",
		"bad-signature": "signature",
	} {
		crlRequest(t, srv, http.MethodPut, "/api/crl/fault", map[string]any{"fault": fault})
		if got := problem(); !strings.Contains(got, want) {
			t.Errorf("%s: problem = %q, want %q", fault, got, want)
		}
	}
	crlRequest(t, srv, http.MethodDelete, "/api/crl/fault", nil)

	crlRequest(t, srv, http.MethodPost, "/api/certificates/revocations", map[string]any{"certificate": certificatePEM(chain[0])})
	if got := problem(); !strings.Contains(got, "revoked") {
		t.Errorf("problem = %q, want the revocation", got)
	}
}

// A credential lists its chain with the actions of this wallet for each
// certificate, and a revocation shows on the next read.
func TestCredentialCertificatesOfferTheActionsOfThisWallet(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.IssuerURL = "https://wallet.example"
	srv.wallet.ClearCredentials()
	if err := srv.wallet.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatal(err)
	}
	path := "/api/credentials/" + srv.wallet.GetCredentials()[0].ID + "/certificates"
	var certificates []CredentialCertificate
	read := func() {
		t.Helper()
		rec := crlRequest(t, srv, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET = %d: %s", rec.Code, rec.Body)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &certificates); err != nil {
			t.Fatal(err)
		}
	}
	read()
	if len(certificates) == 0 || !certificates[0].Revocable || certificates[0].Revoked {
		t.Fatalf("certificates = %+v, want a revocable leaf", certificates)
	}
	if last := certificates[len(certificates)-1]; last.Revocable || last.Role != certificateRoleRoot {
		t.Errorf("the last certificate is %+v, want the root", last)
	}
	if certificates[0].Role != certificateRoleSigner || certificates[0].Withdrawable {
		t.Errorf("the first certificate is %+v, want a signer that can't be withdrawn", certificates[0])
	}
	rec := crlRequest(t, srv, http.MethodPost, certificateRevocationsPath, map[string]any{"certificate": certificates[0].Certificate})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body)
	}
	read()
	if !certificates[0].Revoked {
		t.Errorf("certificates = %+v, want the leaf revoked", certificates[0])
	}
	cred := srv.wallet.GetCredentials()[0]
	matches := []consent.Match{{CredentialID: cred.ID}}
	srv.wallet.flagRevokedCertificates(matches, nil)
	if len(matches[0].RevokedCertificates) != 1 || matches[0].RevokedCertificates[0] != certificates[0].Name {
		t.Errorf("consent match lists %v, want %q", matches[0].RevokedCertificates, certificates[0].Name)
	}
}

// Credentials under one CA share its revocation: both show it, both are flagged
// for consent, and undoing it clears both.
func TestCredentialsSharingACAShareItsRevocation(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.IssuerURL = "https://wallet.example"
	srv.wallet.ClearCredentials()
	if err := srv.wallet.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatal(err)
	}
	creds := srv.wallet.GetCredentials()
	if len(creds) < 2 {
		t.Fatalf("%d credentials, want at least 2", len(creds))
	}
	first, second := srv.wallet.credentialCertificates(creds[0]), srv.wallet.credentialCertificates(creds[1])
	ca, other := first[1], second[1]
	if ca.Role != certificateRoleIntermediate || ca.Serial != other.Serial || len(ca.Credentials) == 0 {
		t.Fatalf("first CA %+v, second CA %+v, want one shared CA", ca, other)
	}
	matches := []consent.Match{{CredentialID: creds[0].ID}, {CredentialID: creds[1].ID}}
	options := &consent.CredentialOptions{Queries: []consent.QueryOptions{{Candidates: matches}}}
	if rec := crlRequest(t, srv, http.MethodPost, certificateRevocationsPath, map[string]any{"certificate": ca.Certificate}); rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body)
	}
	if !srv.wallet.credentialCertificates(creds[1])[1].Revoked {
		t.Error("the second credential does not show the revoked CA")
	}
	srv.wallet.flagRevokedCertificates(matches, options)
	for _, match := range matches {
		if len(match.RevokedCertificates) != 1 || match.RevokedCertificates[0] != ca.Name {
			t.Errorf("match %s lists %v, want %q once", match.CredentialID, match.RevokedCertificates, ca.Name)
		}
	}
	for _, cred := range creds[:2] {
		if problems := srv.wallet.CertificateProblems(embeddedCertificates(cred)); !slices.ContainsFunc(problems, func(p certchain.RevocationProblem) bool { return p.Revoked }) {
			t.Errorf("%s: problems = %v, want the revoked CA", credentialLabel(cred), problems)
		}
	}
	if rec := crlRequest(t, srv, http.MethodDelete, certificateRevocationsPath+"/"+ca.Serial, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d: %s", rec.Code, rec.Body)
	}
	cleared := []consent.Match{{CredentialID: creds[0].ID}}
	srv.wallet.flagRevokedCertificates(cleared, nil)
	if cleared[0].RevokedCertificates != nil || srv.wallet.credentialCertificates(creds[1])[1].Revoked {
		t.Error("undoing the revocation left a credential flagged")
	}
}
