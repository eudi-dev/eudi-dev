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
	"crypto/x509"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
)

func listAnchors(t *testing.T, srv *Server) []*x509.Certificate {
	t.Helper()
	set := srv.wallet.TrustedLists()
	list, err := set.ReadList(set.OwnListURL(provider.ListID(testProviderList)))
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := lote.Anchors(list, lote.IssuanceServices, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return anchors
}

func hasAnchor(anchors []*x509.Certificate, cert *x509.Certificate) bool {
	for _, anchor := range anchors {
		if anchor.Equal(cert) {
			return true
		}
	}
	return false
}

func withdraw(t *testing.T, srv *Server, cert *x509.Certificate) trustedlists.WithdrawnCertificate {
	t.Helper()
	rec := crlRequest(t, srv, http.MethodPost, "/api/trust/withdrawals", map[string]any{"certificate": certificatePEM(cert)})
	if rec.Code != http.StatusCreated {
		t.Fatalf("withdrawing: %d %s", rec.Code, rec.Body)
	}
	var entry trustedlists.WithdrawnCertificate
	if err := json.Unmarshal(rec.Body.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	return entry
}

// A withdrawn anchor leaves its trusted list, and so does a certificate issued
// by it.
func TestWithdrawnAnchorLeavesTheTrustedList(t *testing.T) {
	srv := newTestServer(t, true)
	chain := providerChain(t, srv.wallet)
	leaf, providerCA := chain[0], chain[1]
	if anchors := listAnchors(t, srv); !hasAnchor(anchors, leaf) || !hasAnchor(anchors, providerCA) {
		t.Fatalf("the list holds %d anchors, want the leaf and the provider CA", len(anchors))
	}

	entry := withdraw(t, srv, leaf)
	if anchors := listAnchors(t, srv); hasAnchor(anchors, leaf) || !hasAnchor(anchors, providerCA) {
		t.Error("withdrawing the leaf should remove only the leaf")
	}
	if rec := crlRequest(t, srv, http.MethodDelete, "/api/trust/withdrawals/"+entry.ID, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("restoring: %d %s", rec.Code, rec.Body)
	}
	if !hasAnchor(listAnchors(t, srv), leaf) {
		t.Error("the restored leaf is not on the list")
	}
	if rec := crlRequest(t, srv, http.MethodDelete, "/api/trust/withdrawals/"+entry.ID, nil); rec.Code != http.StatusNotFound {
		t.Errorf("restoring twice: %d", rec.Code)
	}

	withdraw(t, srv, providerCA)
	if anchors := listAnchors(t, srv); hasAnchor(anchors, providerCA) || hasAnchor(anchors, leaf) {
		t.Error("withdrawing the provider CA should also remove its leaf")
	}
}

// The last anchor leaves the list without the list signer taking its place.
func TestListWithoutAnchorsNamesNoProvider(t *testing.T) {
	srv := newTestServer(t, true)
	chain := providerChain(t, srv.wallet)
	for _, cert := range listAnchors(t, srv) {
		if len(cert.CRLDistributionPoints) > 0 || cert.Equal(chain[1]) {
			withdraw(t, srv, cert)
		}
	}
	for _, cert := range listAnchors(t, srv) {
		if cert.Subject.CommonName == chain[0].Subject.CommonName {
			t.Errorf("anchor %s stays on the list", cert.Subject)
		}
	}
}

func TestOnlyListedCertificatesCanBeWithdrawn(t *testing.T) {
	srv := newTestServer(t, true)
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := mock.GenerateRootCACert(key)
	if err != nil {
		t.Fatal(err)
	}
	if rec := crlRequest(t, srv, http.MethodPost, "/api/trust/withdrawals", map[string]any{"certificate": certificatePEM(foreign)}); rec.Code != http.StatusBadRequest {
		t.Errorf("foreign certificate: %d %s", rec.Code, rec.Body)
	}
}

func TestWithdrawalsAreListedAndBlockedOnTheDemo(t *testing.T) {
	srv := newTestServer(t, true)
	withdraw(t, srv, providerChain(t, srv.wallet)[0])
	rec := crlRequest(t, srv, http.MethodGet, "/api/trust/withdrawals", nil)
	var listed []trustedlists.WithdrawnCertificate
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || len(listed) != 1 {
		t.Fatalf("listed %s (%v)", rec.Body, err)
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/trust/withdrawals"},
		{http.MethodDelete, "/api/trust/withdrawals/ab"},
	} {
		if !demoBlockedRoute(mustRequest(t, tc.method, tc.path)) {
			t.Errorf("%s %s is open on the demo", tc.method, tc.path)
		}
	}
}

func mustRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
