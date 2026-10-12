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
	"crypto/ecdsa"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
)

func signTestRegistrationCertificate(t *testing.T, w *Wallet, purpose any) string {
	t.Helper()
	chain, err := w.DefaultSigningCertChain()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	now := time.Now()
	claims := map[string]any{
		"sub":  "LEIEU-TEST-VERIFIER",
		"name": "Test Verifier",
		"iat":  now.Unix(),
	}
	if purpose != nil {
		claims["purpose"] = purpose
	}
	raw, err := SignRegistrationCertificateJWT(claims, w.IssuerKey, chain)
	if err != nil {
		t.Fatalf("signing registration certificate: %v", err)
	}
	return raw
}

func verifierInfoPayload(entries ...map[string]any) map[string]any {
	list := make([]any, 0, len(entries))
	for _, entry := range entries {
		list = append(list, entry)
	}
	return map[string]any{"verifier_info": list}
}

func TestVerifierInfoPurposes(t *testing.T) {
	w := generateTestWallet(t)

	t.Run("a plain purpose string is read", func(t *testing.T) {
		cert := signTestRegistrationCertificate(t, w, "Checking your ticket")
		purposes, findings := verifierInfoPurposes(verifierInfoPayload(
			map[string]any{"format": "registration_cert", "data": cert},
		))
		if len(findings) != 0 {
			t.Errorf("findings = %v, want none", findings)
		}
		if len(purposes) != 1 || purposes[0] != "Checking your ticket" {
			t.Errorf("purposes = %v, want the certificate's purpose", purposes)
		}
	})

	t.Run("a localized purpose prefers English", func(t *testing.T) {
		cert := signTestRegistrationCertificate(t, w, []any{
			map[string]any{"lang": "de", "value": "Ticketpruefung"},
			map[string]any{"lang": "en", "value": "Ticket check"},
		})
		purposes, _ := verifierInfoPurposes(verifierInfoPayload(
			map[string]any{"format": "registration_cert", "data": cert},
		))
		if len(purposes) != 1 || purposes[0] != "Ticket check" {
			t.Errorf("purposes = %v, want the English content", purposes)
		}
	})

	t.Run("a localized purpose without English falls back to the first", func(t *testing.T) {
		cert := signTestRegistrationCertificate(t, w, []any{
			map[string]any{"lang": "de", "value": "Ticketpruefung"},
			map[string]any{"lang": "fr", "value": "Verification du billet"},
		})
		purposes, _ := verifierInfoPurposes(verifierInfoPayload(
			map[string]any{"format": "registration_cert", "data": cert},
		))
		if len(purposes) != 1 || purposes[0] != "Ticketpruefung" {
			t.Errorf("purposes = %v, want the first content", purposes)
		}
	})

	t.Run("the sub is the registered entity, not the client_id", func(t *testing.T) {
		// ETSI TS 119 475 uses sub for the legal entity identifier, which need not
		// match client_id.
		cert := signTestRegistrationCertificate(t, w, "Checking your ticket")
		purposes, findings := verifierInfoPurposes(verifierInfoPayload(
			map[string]any{"format": "registration_cert", "data": cert},
		))
		if len(findings) != 0 {
			t.Errorf("findings = %v, want none", findings)
		}
		if len(purposes) != 1 {
			t.Errorf("purposes = %v, want the purpose shown for a foreign sub", purposes)
		}
	})

	t.Run("a broken signature is not shown", func(t *testing.T) {
		cert := signTestRegistrationCertificate(t, w, "Checking your ticket")
		parts := strings.Split(cert, ".")
		tampered := parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-4] + "AAAA"
		purposes, findings := verifierInfoPurposes(verifierInfoPayload(
			map[string]any{"format": "registration_cert", "data": tampered},
		))
		if len(purposes) != 0 {
			t.Errorf("purposes = %v, want none for a tampered certificate", purposes)
		}
		if len(findings) != 1 || !strings.Contains(findings[0], "signature") {
			t.Errorf("findings = %v, want one naming the signature", findings)
		}
	})

	t.Run("a JWT of another type is passed over", func(t *testing.T) {
		other, err := SignRequestObjectJWT(map[string]any{"purpose": "not a certificate"}, w.IssuerKey, nil)
		if err != nil {
			t.Fatalf("signing JWT: %v", err)
		}
		purposes, findings := verifierInfoPurposes(verifierInfoPayload(
			map[string]any{"format": "jwt", "data": other},
		))
		if len(purposes) != 0 || len(findings) != 0 {
			t.Errorf("purposes = %v findings = %v, want a foreign JWT ignored", purposes, findings)
		}
	})

	t.Run("verifier_info arriving as a JSON string is read", func(t *testing.T) {
		cert := signTestRegistrationCertificate(t, w, "Checking your ticket")
		encoded, err := json.Marshal([]map[string]any{{"format": "registration_cert", "data": cert}})
		if err != nil {
			t.Fatalf("encoding verifier_info: %v", err)
		}
		purposes, _ := verifierInfoPurposes(map[string]any{"verifier_info": string(encoded)})
		if len(purposes) != 1 || purposes[0] != "Checking your ticket" {
			t.Errorf("purposes = %v, want the certificate's purpose", purposes)
		}
	})

	t.Run("duplicate purposes are shown once", func(t *testing.T) {
		cert := signTestRegistrationCertificate(t, w, "Checking your ticket")
		purposes, _ := verifierInfoPurposes(verifierInfoPayload(
			map[string]any{"format": "registration_cert", "data": cert},
			map[string]any{"format": "registration_cert", "data": cert},
		))
		if len(purposes) != 1 {
			t.Errorf("purposes = %v, want the duplicate collapsed", purposes)
		}
	})

	t.Run("a request without verifier_info has no purposes", func(t *testing.T) {
		purposes, findings := verifierInfoPurposes(map[string]any{"client_id": "x509_hash:test-verifier"})
		if len(purposes) != 0 || len(findings) != 0 {
			t.Errorf("purposes = %v findings = %v, want nothing", purposes, findings)
		}
	})
}

// A concurrent demo reset must not cause DefaultSigningMaterial to return a mismatched
// key and chain.
func TestDefaultSigningMaterialPairsKeyAndChain(t *testing.T) {
	w := generateTestWallet(t)
	key, chain, err := w.DefaultSigningMaterial()
	if err != nil {
		t.Fatalf("DefaultSigningMaterial() error = %v", err)
	}
	if key == nil || len(chain) == 0 {
		t.Fatal("expected a key and a chain")
	}
	leafKey, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("leaf certificate does not hold an EC key")
	}
	if !leafKey.Equal(&key.PublicKey) {
		t.Error("the leaf certificate does not wrap the returned signing key")
	}
}

func TestPlainParameterRequestShowsThePurpose(t *testing.T) {
	srv := newTestServer(t, false)
	cert := signTestRegistrationCertificate(t, srv.wallet, "Checking who you are")
	verifierInfo, err := json.Marshal([]map[string]any{{"format": "registration_cert", "data": cert}})
	if err != nil {
		t.Fatalf("encoding verifier_info: %v", err)
	}

	dcql, err := json.Marshal(map[string]any{
		"credentials": []any{map[string]any{
			"id":     "pid",
			"format": "dc+sd-jwt",
			"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
			"claims": []any{map[string]any{"path": []any{"given_name"}}},
		}},
	})
	if err != nil {
		t.Fatalf("encoding dcql: %v", err)
	}

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"purpose-nonce"},
		"response_uri":  {"https://verifier.example/response"},
		"dcql_query":    {string(dcql)},
		"verifier_info": {string(verifierInfo)},
	}

	done := make(chan struct{})
	go func() {
		req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
		srv.mux.ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()

	var pending []*ConsentRequest
	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		if pending = srv.wallet.GetPendingRequests(); len(pending) > 0 {
			break
		}
	}
	if len(pending) == 0 {
		t.Fatal("no pending consent request appeared")
	}
	if len(pending[0].Purposes) != 1 || pending[0].Purposes[0] != "Checking who you are" {
		t.Errorf("Purposes = %v, want the certificate's purpose", pending[0].Purposes)
	}

	denyReq := httptest.NewRequest("POST", "/api/requests/"+pending[0].ID+"/deny", nil)
	srv.mux.ServeHTTP(httptest.NewRecorder(), denyReq)
	<-done
}

// Without a readable x5c, the purpose cannot be signature-checked and must remain
// hidden.
func TestVerifierInfoPurposesHidesAnUncheckableCertificate(t *testing.T) {
	w := generateTestWallet(t)
	cert, err := SignRegistrationCertificateJWT(map[string]any{
		"sub":     "LEIEU-TEST-VERIFIER",
		"purpose": "Checking your ticket",
	}, w.IssuerKey, nil)
	if err != nil {
		t.Fatalf("signing certificate: %v", err)
	}
	purposes, findings := verifierInfoPurposes(verifierInfoPayload(
		map[string]any{"format": "registration_cert", "data": cert},
	))
	if len(purposes) != 0 {
		t.Errorf("purposes = %v, want none for a certificate without x5c", purposes)
	}
	if len(findings) != 1 || !strings.Contains(findings[0], "cannot be checked") {
		t.Errorf("findings = %v, want one saying the signature cannot be checked", findings)
	}
}

// Includes the required ARF fields and registers given_name for urn:eudi:pid:1.
func conformantRegistrationCert() map[string]any {
	return map[string]any{
		"name":                  "Test Verifier",
		"sub":                   "LEIEU-TEST",
		"country":               "EU",
		"registry_uri":          "https://registrar.example",
		"srv_description":       []any{map[string]any{"lang": "en", "value": "Test service"}},
		"entitlements":          []any{"https://uri.etsi.org/19475/Entitlement/Service_Provider"},
		"privacy_policy":        "https://example/privacy",
		"support_uri":           "https://example/support",
		"supervisory_authority": map[string]any{"email": "dpa@example"},
		"iat":                   float64(time.Now().Unix()),
		"credentials": []any{map[string]any{
			"format": "dc+sd-jwt",
			"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
			"claim":  []any{map[string]any{"path": []any{"given_name"}}},
		}},
	}
}

func TestRegistrationCertificateContentFindings(t *testing.T) {
	if findings := registrationCertificateContentFindings(conformantRegistrationCert()); len(findings) != 0 {
		t.Errorf("a conformant certificate should have no findings, got %v", findings)
	}

	sparse := map[string]any{"name": "X", "sub": "Y", "iat": float64(time.Now().Unix())}
	findings := registrationCertificateContentFindings(sparse)
	for _, want := range []string{"privacy_policy", "srv_description", "entitlements", "support_uri", "supervisory_authority", "credentials"} {
		if !containsSubstring(findings, want) {
			t.Errorf("findings %v should name the missing %s", findings, want)
		}
	}
}

func TestRegistrationValidityFindings(t *testing.T) {
	now := time.Now()
	longLived := map[string]any{"iat": float64(now.Unix()), "exp": float64(now.AddDate(2, 0, 0).Unix())}
	if !containsSubstring(registrationValidityFindings(longLived), "more than 12 months") {
		t.Error("a certificate valid for two years should be flagged")
	}
	expired := map[string]any{"iat": float64(now.AddDate(0, -2, 0).Unix()), "exp": float64(now.AddDate(0, -1, 0).Unix())}
	if !containsSubstring(registrationValidityFindings(expired), "expired") {
		t.Error("an expired certificate should be flagged")
	}
	if findings := registrationValidityFindings(map[string]any{"iat": float64(now.Unix())}); len(findings) != 0 {
		t.Errorf("a certificate with iat and no exp should pass, got %v", findings)
	}
}

func TestOverAskingFindings(t *testing.T) {
	cert := conformantRegistrationCert()

	asksGivenName := map[string]any{"credentials": []any{map[string]any{
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
		"claims": []any{map[string]any{"path": []any{"given_name"}}},
	}}}
	if findings := overAskingFindings(cert, asksGivenName); len(findings) != 0 {
		t.Errorf("asking a registered claim should not be over-asking, got %v", findings)
	}

	asksFamilyName := map[string]any{"credentials": []any{map[string]any{
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
		"claims": []any{map[string]any{"path": []any{"family_name"}}},
	}}}
	if !containsSubstring(overAskingFindings(cert, asksFamilyName), "family_name") {
		t.Error("asking an unregistered claim should be over-asking")
	}

	parent := map[string]any{"credentials": []any{map[string]any{
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
		"claim":  []any{map[string]any{"path": []any{"address"}}},
	}}}
	asksChild := map[string]any{"credentials": []any{map[string]any{
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
		"claims": []any{map[string]any{"path": []any{"address", "street_address"}}},
	}}}
	if findings := overAskingFindings(parent, asksChild); len(findings) != 0 {
		t.Errorf("a registered parent path should cover a child, got %v", findings)
	}

	// An unregistered credential type is one finding however many claims it
	// requests.
	asksUnregisteredType := map[string]any{"credentials": []any{map[string]any{
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{"urn:eudi:other:1"}},
		"claims": []any{
			map[string]any{"path": []any{"given_name"}},
			map[string]any{"path": []any{"family_name"}},
		},
	}}}
	if findings := overAskingFindings(cert, asksUnregisteredType); len(findings) != 1 {
		t.Errorf("an unregistered type should be one finding for the query, got %v", findings)
	}

	// A missing credentials list already has a content finding.
	noCredentials := map[string]any{"name": "X"}
	if findings := overAskingFindings(noCredentials, asksGivenName); len(findings) != 0 {
		t.Errorf("a certificate with no credentials should produce no over-asking findings, got %v", findings)
	}
}

// ARF RPRC_19 requires a registration certificate even though OpenID4VP makes
// verifier_info optional.
func TestConsentPurposesWarnsOnMissingRegistrationCertificate(t *testing.T) {
	w := generateTestWallet(t)
	authReq := &AuthorizationRequestParams{RequestPayload: map[string]any{"dcql_query": map[string]any{}}}
	w.consentPurposes("presentation", authReq)
	found := false
	for _, entry := range w.GetLog() {
		if strings.Contains(entry.Detail, "RPRC_19") {
			found = true
		}
	}
	if !found {
		t.Error("a request without a registration certificate should log the RPRC_19 warning")
	}
}

// Several certificate findings share one activity log entry.
func TestConsentPurposesSummarizesCertificateFindings(t *testing.T) {
	w := generateTestWallet(t)
	cert := signTestRegistrationCertificate(t, w, "Checking your ticket")
	authReq := &AuthorizationRequestParams{
		RequestPayload: verifierInfoPayload(map[string]any{"format": "registration_cert", "data": cert}),
	}
	w.consentPurposes("presentation", authReq)

	summaries := 0
	var details map[string]any
	for _, entry := range w.GetLog() {
		if strings.Contains(entry.Detail, "findings, see details") {
			summaries++
			details = entry.Details
		}
	}
	if summaries != 1 {
		t.Fatalf("want exactly one summarized registration certificate warning, got %d", summaries)
	}
	if list, _ := details["findings"].([]string); len(list) < 2 {
		t.Errorf("the summary should carry the findings list in its details, got %v", details)
	}
}
