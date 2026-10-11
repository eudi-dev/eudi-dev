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
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/statuslist"
	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

func findCheck(t *testing.T, status map[string]any, name string) map[string]any {
	t.Helper()
	for _, entry := range status["checks"].([]any) {
		if check := entry.(map[string]any); check["name"] == name {
			return check
		}
	}
	t.Fatalf("no %q check in %v", name, status["checks"])
	return nil
}

// The shared credential checks run under their own names, with the detail of
// a passed check.
func TestVerifierRunsTheSharedCredentialChecks(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()
	id, params := startVerification(t, h, "ticket")
	postPresentation(t, h, id, "ticket", presentTicket(t, d, holderKey, params.Get("client_id"), params.Get("nonce")))

	_, status := requestStatus(t, d, id)
	if status["status"] != "verified" {
		t.Fatalf("status = %v (checks: %v)", status["status"], status["checks"])
	}
	for _, name := range []string{"type", "expiry", "integrity", "signature", "haip"} {
		if check := findCheck(t, status, name); check["ok"] != true || check["detail"] == nil {
			t.Errorf("%s: %v, want a passed check with its detail", name, check)
		}
	}
	if check := findCheck(t, status, "status"); check["skipped"] == nil {
		t.Errorf("status: %v, want it reported as skipped for a ticket without a status list", check)
	}
}

// HAIP 1.0 §6.1: "The status claim, if present, MUST contain status_list".
// The verifier reports another status mechanism as a HAIP finding.
func TestVerifierReportsEveryHAIPCredentialFinding(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()
	id, params := startVerification(t, h, "ticket")

	chain, err := d.wallet.DefaultSigningCertChain()
	if err != nil {
		t.Fatal(err)
	}
	claims := ticketTemplate(t, d).Claims
	claims["status"] = map[string]any{"type": "custom-revocation"}
	credential, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer: d.issuerID(), VCT: TicketVCT, ExpiresIn: time.Hour, Claims: claims,
		Key: d.wallet.IssuerKey, HolderKey: &holderKey.PublicKey, CertChain: chain,
		AlwaysDisclosed: []string{"status"},
	})
	if err != nil {
		t.Fatal(err)
	}
	postPresentation(t, h, id, "ticket", presentCredential(t, holderKey, credential, params.Get("client_id"), params.Get("nonce")))

	_, status := requestStatus(t, d, id)
	if status["status"] != "verified" {
		t.Fatalf("status = %v (checks: %v)", status["status"], status["checks"])
	}
	warning, _ := findCheck(t, status, "haip")["warning"].(string)
	if !strings.Contains(warning, "HAIP 1.0 §6.1") || !strings.Contains(warning, "custom-revocation") {
		t.Errorf("haip warning = %q, want the status finding", warning)
	}
}

// The verifier fetches status lists with the wallet's HTTP client, so the
// wallet's TLS settings apply.
func TestVerifierFetchesWithTheWalletsHTTPClient(t *testing.T) {
	d, w, holderKey := newDemoRP(t)
	w.ValidationMode = wallet.ValidationModeStrict
	key, chain, err := w.StatusListSigningMaterial()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(nil)
	srv.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		jwt, err := statuslist.GenerateStatusListJWT([]byte{0}, key, statuslist.StatusListConfig{URI: srv.URL + "/statuslist", Issuer: srv.URL, CertChain: chain})
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		rw.Header().Set("Content-Type", "application/statuslist+jwt")
		_, _ = rw.Write([]byte(jwt))
	})
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h := d.VerifierHandler()

	present := func() map[string]any {
		id, params := startVerification(t, h, "ticket")
		credential := signTicketWithStatus(t, d, holderKey, srv.URL+"/statuslist", 0)
		postPresentation(t, h, id, "ticket", presentCredential(t, holderKey, credential, params.Get("client_id"), params.Get("nonce")))
		_, status := requestStatus(t, d, id)
		return status
	}

	if status := present(); status["status"] != "failed" || findCheck(t, status, "status")["ok"] != false {
		t.Fatalf("the status list behind an untrusted certificate was read: %v", status["checks"])
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := w.ConfigureOutbound(wallet.OutboundConfig{TLSCAPEM: caPEM}); err != nil {
		t.Fatal(err)
	}
	if status := present(); status["status"] != "verified" {
		t.Fatalf("status = %v with the server CA in --tls-ca (checks: %v)", status["status"], status["checks"])
	}
}
