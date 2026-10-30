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
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
)

func TestTheWalletsOwnPIDsValidateWithThePIDTrustedList(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.RequireARF = true
	for _, c := range w.GetCredentials() {
		if got := w.trustAnchorFindings(receivedCredential(c.Raw)); len(got) != 0 {
			t.Errorf("%s %s: %v", c.Format, credentialLabel(c), got)
		}
	}
}

// A PID from another wallet's CA is not on this wallet's PID Provider LoTE
// (ARF ISSU_07). Strict mode refuses it and debug mode warns.
func TestAForeignPIDFailsTheTrustAnchorCheck(t *testing.T) {
	w := generateTestWallet(t)
	w.RequireARF = true
	for _, c := range generateTestWalletWithPID(t).GetCredentials() {
		findings := w.trustAnchorFindings(receivedCredential(c.Raw))
		if len(findings) != 1 || !strings.HasPrefix(findings[0].String(), "ARF ISSU_07: ") {
			t.Fatalf("%s: findings %v", c.Format, findings)
		}
		resp := map[string]any{"credentials": []any{map[string]any{"credential": c.Raw}}}
		w.ValidationMode = ValidationModeStrict
		if _, err := w.checkReceivedCredentials(resp, nil, "", "https://issuer.example"); err == nil {
			t.Errorf("%s: strict mode accepted the credential", c.Format)
		}
		w.ValidationMode = ValidationModeDebug
		if _, err := w.checkReceivedCredentials(resp, nil, "", "https://issuer.example"); err != nil {
			t.Errorf("%s: debug mode refused: %v", c.Format, err)
		}
	}
}

// Every copy of a batch is signed on its own, so every copy is checked.
func TestEveryCopyOfABatchIsChecked(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.RequireARF = true
	w.ValidationMode = ValidationModeStrict
	own := w.GetCredentials()[0].Raw
	foreign := generateTestWalletWithPID(t).GetCredentials()[0].Raw
	resp := map[string]any{"credentials": []any{map[string]any{"credential": own}, map[string]any{"credential": foreign}}}
	if _, err := w.checkReceivedCredentials(resp, nil, "", "https://issuer.example"); err == nil {
		t.Error("strict mode accepted a batch with a foreign copy")
	}
}

// An attestation entry can link any list of trusted entities. The wallet
// fetches it and checks that a trusted list operator signed it (ARF ISSU_08,
// PPNot_05).
func TestAnAttestationIsCheckedAgainstAFetchedList(t *testing.T) {
	const vct = "urn:example:diploma:1"
	issuer := generateTestWallet(t)
	result, err := issuer.IssueCredential(IssueOptions{Format: "sdjwt", VCT: vct, Claims: map[string]any{"degree": "MSc"}, Category: credtemplate.CategoryEAA})
	if err != nil {
		t.Fatal(err)
	}
	serveList := func(w *Wallet) string {
		group, _ := w.TrustedLists().FindGroup(credtemplate.CategoryEAA, "", "")
		list, err := w.TrustedLists().SignedGroupList(w.IssuerURL, group, "/api/trustlists/"+group.ID)
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte(list)) }))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	other := generateTestWallet(t)
	isLOTE := true
	for _, tc := range []struct {
		name, list string
		operator   *Wallet
		want       string
		// added puts the operator's CA on trusted-list-ca instead of
		// --trusted-list-ca.
		added bool
	}{
		{"the issuer's list", serveList(issuer), issuer, "", false},
		{"the issuer's list with its CA on trusted-list-ca", serveList(issuer), issuer, "", true},
		{"a list of an unknown operator", serveList(issuer), nil, "does not chain to a trusted list CA", false},
		{"another wallet's list", serveList(other), other, "does not validate", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			w.RequireARF = true
			if tc.operator != nil {
				anchor := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tc.operator.Signer().TrustAnchor().Raw})
				if tc.added {
					if _, err := addTrustedEntity(w, trustedlists.TrustedListCAID, "", string(anchor)); err != nil {
						t.Fatal(err)
					}
				} else {
					w.TrustSettings.ListCAPEM = anchor
				}
			}
			if _, err := w.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{
				Name:        "Diploma",
				Category:    credtemplate.CategoryQEAA,
				Credentials: []registrar.CatalogCredential{{Format: "dc+sd-jwt", Type: vct}},
				Schema:      registrar.AttestationSchema{TrustedAuthorities: []registrar.TrustAuthority{{FrameworkType: "etsi_tl", Value: tc.list, IsLOTE: &isLOTE}}},
			}); err != nil {
				t.Fatal(err)
			}
			findings := w.trustAnchorFindings(receivedCredential(result.Raw))
			if tc.want == "" && len(findings) != 0 || tc.want != "" && (len(findings) != 1 || !strings.Contains(findings[0].String(), tc.want)) {
				t.Errorf("findings %v, want %q", findings, tc.want)
			}
		})
	}
}

// eaaWithUntrustedList returns a wallet with --arf whose catalogue links an
// EAA type to a list signed by an unknown operator, and a credential of that
// type.
func eaaWithUntrustedList(t *testing.T) (*Wallet, string) {
	t.Helper()
	issuer := generateTestWallet(t)
	result, err := issuer.IssueCredential(IssueOptions{Format: "sdjwt", VCT: "urn:example:badge:1", Claims: map[string]any{"level": "gold"}})
	if err != nil {
		t.Fatal(err)
	}
	group, _ := issuer.TrustedLists().FindGroup(credtemplate.CategoryEAA, "", "")
	list, err := issuer.TrustedLists().SignedGroupList(issuer.IssuerURL, group, "/api/trustlists/eaa")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte(list)) }))
	t.Cleanup(srv.Close)
	w := generateTestWallet(t)
	w.RequireARF = true
	isLOTE := true
	if _, err := w.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{
		Name:        "Badge",
		Credentials: []registrar.CatalogCredential{{Format: "dc+sd-jwt", Type: "urn:example:badge:1"}},
		Schema:      registrar.AttestationSchema{TrustedAuthorities: []registrar.TrustAuthority{{FrameworkType: "etsi_tl", Value: srv.URL, IsLOTE: &isLOTE}}},
	}); err != nil {
		t.Fatal(err)
	}
	return w, result.Raw
}

// ISSU_10 asks for the check of an EAA only when the wallet has the anchors. A
// list signed by an unknown operator gives none.
func TestAnEAAWithAnUntrustedListIsNotChecked(t *testing.T) {
	w, raw := eaaWithUntrustedList(t)
	if findings := w.trustAnchorFindings(receivedCredential(raw)); len(findings) != 0 {
		t.Errorf("findings %v, want none", findings)
	}
}

// The catalogue check returns the untrusted EAA list as a warning. The
// issuance check writes it to the activity log.
func TestTheCatalogueCheckReturnsAnUntrustedEAAListAsAWarning(t *testing.T) {
	w, raw := eaaWithUntrustedList(t)
	logged := len(w.GetLog())
	anchoring, found := w.CheckCatalogueAnchoring(raw)
	if !found || len(anchoring.Warnings) != 1 || !strings.Contains(anchoring.Warnings[0], "has no trust anchors") {
		t.Fatalf("anchoring = %+v, want one warning for the untrusted list", anchoring)
	}
	if got := len(w.GetLog()); got != logged {
		t.Errorf("the catalogue check wrote %d log entries, want it to only return the warning", got-logged)
	}

	w.trustAnchorFindings(receivedCredential(raw))
	log := w.GetLog()
	if last := log[len(log)-1]; last.Severity != "warning" || last.Details["event"] != "trusted_list" {
		t.Errorf("last log entry %+v, want the trusted list warning", last)
	}
}

// A PID needs the list of its providers (ARF ISSU_07). A catalogue entry
// without a readable list is a finding.
func TestAPIDNeedsAReadableList(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.RequireARF = true
	if _, err := w.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{
		Name:        "Other PID",
		Category:    credtemplate.CategoryPID,
		Credentials: []registrar.CatalogCredential{{Format: "dc+sd-jwt", Type: "urn:example:pid:1"}},
		Schema:      registrar.AttestationSchema{TrustedAuthorities: []registrar.TrustAuthority{{FrameworkType: "aki", Value: "s9tIpPmhxdiuNkHMEWNpYim8S8Y"}}},
	}); err != nil {
		t.Fatal(err)
	}
	pid := StoredCredential{Format: "dc+sd-jwt", VCT: "urn:example:pid:1", Raw: "not checked"}
	if findings := w.trustAnchorFindings(pid); len(findings) != 1 || !strings.HasPrefix(findings[0].String(), "ARF ISSU_07: ") {
		t.Errorf("findings %v, want ISSU_07", findings)
	}
}

// ISSU_10 applies only when the wallet has the issuer's trust anchors. An
// EAA entry without a trusted list is not checked.
func TestAnAttestationWithoutATrustedListIsNotChecked(t *testing.T) {
	w := generateTestWallet(t)
	w.RequireARF = true
	const vct = "urn:example:diploma:1"
	if _, err := w.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{
		Name:        "Diploma",
		Credentials: []registrar.CatalogCredential{{Format: "dc+sd-jwt", Type: vct}},
		Schema:      registrar.AttestationSchema{TrustedAuthorities: []registrar.TrustAuthority{{FrameworkType: "aki", Value: "s9tIpPmhxdiuNkHMEWNpYim8S8Y"}}},
	}); err != nil {
		t.Fatal(err)
	}
	diploma := StoredCredential{Format: "dc+sd-jwt", VCT: vct, Raw: "not checked"}
	if got := w.trustAnchorFindings(diploma); len(got) != 0 {
		t.Errorf("findings %v", got)
	}
}

func TestTheTrustAnchorCheckNeedsARF(t *testing.T) {
	w := generateTestWallet(t)
	for _, c := range generateTestWalletWithPID(t).GetCredentials() {
		if got := w.trustAnchorFindings(receivedCredential(c.Raw)); len(got) != 0 {
			t.Errorf("findings without --arf: %v", got)
		}
	}
}

func TestAnOfferOutsideTheCatalogueWarns(t *testing.T) {
	w := generateTestWallet(t)
	metadata := map[string]any{"credential_configurations_supported": map[string]any{
		"pid":     map[string]any{"format": "dc+sd-jwt", "vct": credtype.PIDVCT},
		"unknown": map[string]any{"format": "dc+sd-jwt", "vct": "urn:example:unknown:1"},
	}}
	if got := w.catalogueFindings(metadata, []string{"pid", "unknown"}); len(got) != 0 {
		t.Errorf("findings without --arf: %v", got)
	}
	w.RequireARF = true
	got := w.catalogueFindings(metadata, []string{"pid", "unknown"})
	if len(got) != 1 || !strings.Contains(got[0].String(), "urn:example:unknown:1") {
		t.Fatalf("findings %v, want one for the unknown type", got)
	}
}

// A trusted list anchors an external credential. The revocation service of
// that list anchors the credential's status list.
func TestExternalCredentialStatusIsAnchoredByItsTrustedList(t *testing.T) {
	const vct = "urn:example:diploma:1"
	var issuerHandler http.Handler
	issuerSite := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { issuerHandler.ServeHTTP(rw, r) }))
	defer issuerSite.Close()
	issuer := generateTestWallet(t)
	issuer.BaseURL = issuerSite.URL
	issuerHandler = NewServer(issuer, 0, nil).Handler()
	issued, err := issuer.IssueCredential(IssueOptions{Format: "sdjwt", VCT: vct, Claims: map[string]any{"degree": "MSc"}, Category: credtemplate.CategoryEAA})
	if err != nil {
		t.Fatal(err)
	}
	group, _ := issuer.TrustedLists().FindGroup(credtemplate.CategoryEAA, "", "")
	list, err := issuer.TrustedLists().SignedGroupList(issuer.BaseURL, group, "/api/trustlists/"+group.ID)
	if err != nil {
		t.Fatal(err)
	}
	listSite := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte(list)) }))
	defer listSite.Close()

	for _, tc := range []struct {
		name     string
		anchored bool
	}{
		{"a catalogue entry links the issuer's list", true},
		{"no catalogue entry for the type", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			if tc.anchored {
				w.TrustSettings.ListCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Signer().TrustAnchor().Raw})
				isLOTE := true
				if _, err := w.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{
					Name:        "Diploma",
					Category:    credtemplate.CategoryEAA,
					Credentials: []registrar.CatalogCredential{{Format: "dc+sd-jwt", Type: vct}},
					Schema:      registrar.AttestationSchema{TrustedAuthorities: []registrar.TrustAuthority{{FrameworkType: "etsi_tl", Value: listSite.URL, IsLOTE: &isLOTE}}},
				}); err != nil {
					t.Fatal(err)
				}
			}
			if got := len(w.StatusListAnchors(issued.Raw)) > 0; got != tc.anchored {
				t.Fatalf("status list anchors found = %v, want %v", got, tc.anchored)
			}
			imported, err := w.ImportCredential(issued.Raw)
			if err != nil {
				t.Fatal(err)
			}
			resp := serverRequest(t, NewServer(w, 0, nil), http.MethodGet, "/api/credentials/"+imported.ID+"/status", "")
			if resp.Code != http.StatusOK {
				t.Fatalf("status check: %d %s", resp.Code, resp.Body.String())
			}
			status := decodeJSON(t, resp)
			if status["managed"] != false || status["source"] != "remote" || status["status"] != float64(0) {
				t.Errorf("status = %v, want the issuer's valid entry", status)
			}
			if status["trustAnchored"] != tc.anchored {
				t.Errorf("trustAnchored = %v, want %v", status["trustAnchored"], tc.anchored)
			}
		})
	}
}
