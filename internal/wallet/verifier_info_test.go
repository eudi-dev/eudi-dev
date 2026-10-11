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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
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
	raw, err := registrar.SignRegistrationCertificateJWT(claims, w.IssuerKey, chain)
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

// purposesOf returns the purposes of the registration certificates in
// verifier_info that verify, and the problems of the others.
func purposesOf(payload map[string]any) ([]string, []string) {
	certs, problems := verifiedRegistrationCertificates(payload)
	purposes, _ := registrationPurposes(certs)
	return purposes, problems
}

func TestVerifierInfoPurposes(t *testing.T) {
	w := generateTestWallet(t)

	t.Run("a plain purpose string is read", func(t *testing.T) {
		cert := signTestRegistrationCertificate(t, w, "Checking your ticket")
		purposes, findings := purposesOf(verifierInfoPayload(
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
		purposes, _ := purposesOf(verifierInfoPayload(
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
		purposes, _ := purposesOf(verifierInfoPayload(
			map[string]any{"format": "registration_cert", "data": cert},
		))
		if len(purposes) != 1 || purposes[0] != "Ticketpruefung" {
			t.Errorf("purposes = %v, want the first content", purposes)
		}
	})

	t.Run("a broken signature is not shown", func(t *testing.T) {
		cert := signTestRegistrationCertificate(t, w, "Checking your ticket")
		parts := strings.Split(cert, ".")
		tampered := parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-4] + "AAAA"
		purposes, findings := purposesOf(verifierInfoPayload(
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
		purposes, findings := purposesOf(verifierInfoPayload(
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
		purposes, _ := purposesOf(map[string]any{"verifier_info": string(encoded)})
		if len(purposes) != 1 || purposes[0] != "Checking your ticket" {
			t.Errorf("purposes = %v, want the certificate's purpose", purposes)
		}
	})

	t.Run("duplicate purposes are shown once", func(t *testing.T) {
		cert := signTestRegistrationCertificate(t, w, "Checking your ticket")
		purposes, _ := purposesOf(verifierInfoPayload(
			map[string]any{"format": "registration_cert", "data": cert},
			map[string]any{"format": "registration_cert", "data": cert},
		))
		if len(purposes) != 1 {
			t.Errorf("purposes = %v, want the duplicate collapsed", purposes)
		}
	})

	t.Run("a request without verifier_info has no purposes", func(t *testing.T) {
		purposes, findings := purposesOf(map[string]any{"client_id": "x509_hash:test-verifier"})
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

// Without a readable x5c, the purpose cannot be signature-checked and must remain
// hidden.
func TestVerifierInfoPurposesHidesAnUncheckableCertificate(t *testing.T) {
	w := generateTestWallet(t)
	cert, err := registrar.SignRegistrationCertificateJWT(map[string]any{
		"sub":     "LEIEU-TEST-VERIFIER",
		"purpose": "Checking your ticket",
	}, w.IssuerKey, nil)
	if err != nil {
		t.Fatalf("signing certificate: %v", err)
	}
	purposes, findings := purposesOf(verifierInfoPayload(
		map[string]any{"format": "registration_cert", "data": cert},
	))
	if len(purposes) != 0 {
		t.Errorf("purposes = %v, want none for a certificate without x5c", purposes)
	}
	if len(findings) != 1 || !strings.Contains(findings[0], "no readable x5c certificate") {
		t.Errorf("findings = %v, want one about the missing x5c certificate", findings)
	}
}

// Includes the required ARF fields and registers given_name for urn:eudi:pid:1.
func conformantRegistrationCert() map[string]any {
	return map[string]any{
		"name":                  "Test Verifier",
		"sub":                   "LEIEU-TEST",
		"country":               "EU",
		"registry_uri":          "https://registrar.example",
		"policy_id":             []any{"0.4.0.19475.3.1"},
		"certificate_policy":    "https://registrar.example/policy",
		"srv_description":       []any{map[string]any{"lang": "en", "value": "Test service"}},
		"entitlements":          []any{"https://uri.etsi.org/19475/Entitlement/Service_Provider"},
		"privacy_policy":        "https://example/privacy",
		"support_uri":           "https://example/support",
		"supervisory_authority": map[string]any{"email": "dpa@example"},
		"iat":                   float64(time.Now().Unix()),
		"status":                map[string]any{"status_list": map[string]any{"idx": float64(7), "uri": "https://registrar.example/status"}},
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
	for _, want := range []string{"privacy_policy", "srv_description", "entitlements", "support_uri", "supervisory_authority", "credentials", "status", "country", "registry_uri", "policy_id", "certificate_policy"} {
		if !containsSubstring(findings, want) {
			t.Errorf("findings %v should name the missing %s", findings, want)
		}
	}
}

func TestRegistrationValidityFindings(t *testing.T) {
	now := time.Now()
	longLived := map[string]any{"iat": float64(now.Unix()), "exp": float64(now.AddDate(2, 0, 0).Unix())}
	if !containsSubstring(registrationValidityFindings(longLived, "ARF RPRC_17"), "more than 12 months") {
		t.Error("a certificate valid for two years should be flagged")
	}
	expired := map[string]any{"iat": float64(now.AddDate(0, -2, 0).Unix()), "exp": float64(now.AddDate(0, -1, 0).Unix())}
	if !containsSubstring(registrationValidityFindings(expired, "ARF RPRC_17"), "expired") {
		t.Error("an expired certificate should be flagged")
	}
	if findings := registrationValidityFindings(map[string]any{"iat": float64(now.Unix())}, "ARF RPRC_17"); len(findings) != 0 {
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

	// An entry without a claim list declares no attributes (ETSI TS 119 475
	// V1.2.1 Annex B.2.9), so every requested claim over-asks.
	typeOnly := map[string]any{"credentials": []any{map[string]any{
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
	}}}
	if !containsSubstring(overAskingFindings(typeOnly, asksGivenName), "given_name") {
		t.Errorf("a type registered without claims should make given_name over-asking, got %v", overAskingFindings(typeOnly, asksGivenName))
	}

	// A missing credentials list already has a content finding.
	noCredentials := map[string]any{"name": "X"}
	if findings := overAskingFindings(noCredentials, asksGivenName); len(findings) != 0 {
		t.Errorf("a certificate with no credentials should produce no over-asking findings, got %v", findings)
	}
}

// ARF RPRC_19 requires a registration certificate even though OpenID4VP makes
// verifier_info optional. RPRC_17 has the wallet warn the user without one.
func TestARFRequiresARegistrationCertificate(t *testing.T) {
	findings := ARFFindings(&AuthorizationRequestParams{RequestPayload: map[string]any{"dcql_query": map[string]any{}}})
	if !containsSubstring(findings, "ARF RPRC_17 and RPRC_19: the request carries no registration certificate") {
		t.Errorf("findings %v, want the RPRC_17 and RPRC_19 finding", findings)
	}
}

// Several certificate findings share one activity log entry.
func TestARFFindingsShareOneLogEntry(t *testing.T) {
	w := generateTestWallet(t)
	cert := signTestRegistrationCertificate(t, w, "Checking your ticket")
	findings := ARFFindings(&AuthorizationRequestParams{
		RequestPayload: verifierInfoPayload(map[string]any{"format": "registration_cert", "data": cert}),
	})
	w.warnFindings("presentation", specCitedSummary("The request", findings), findings)

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

// --arf checks over-asking (ARF RPRC_21). Strict mode refuses it, debug mode
// warns, and without --arf the wallet does not check it.
func TestARFChecksOverAsking(t *testing.T) {
	w := generateTestWallet(t)
	chain, err := w.DefaultSigningCertChain()
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	registered := []map[string]any{{
		"id":     "pid",
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
		"claims": []any{map[string]any{"path": []any{"given_name"}}},
	}}
	cert, err := registrar.SignRegistrationCertificateJWT(map[string]any{
		"sub": "LEIEU-TEST-VERIFIER", "name": "Test Verifier", "iat": time.Now().Unix(),
		"credentials": registrar.RegisteredCredentials(registered),
	}, w.IssuerKey, chain)
	if err != nil {
		t.Fatalf("signing registration certificate: %v", err)
	}
	request := func(claim string) *AuthorizationRequestParams {
		return &AuthorizationRequestParams{
			ClientID:     "redirect_uri:https://verifier.example/response",
			ResponseType: "vp_token",
			ResponseMode: "direct_post",
			ResponseURI:  "https://verifier.example/response",
			Nonce:        "n",
			DCQLQuery: map[string]any{"credentials": []any{map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
				"claims": []any{map[string]any{"path": []any{claim}}},
			}}},
			RequestPayload: verifierInfoPayload(map[string]any{"format": "registration_cert", "data": cert}),
		}
	}

	if _, err := ValidateAuthorizationRequest(ConformanceSettings{ValidationMode: ValidationModeStrict, RequireARF: true}, request("birthdate")); err == nil || !strings.Contains(err.Error(), "RPRC_21") {
		t.Errorf("strict mode with --arf: err = %v, want the RPRC_21 refusal", err)
	}
	if findings, err := ValidateAuthorizationRequest(ConformanceSettings{ValidationMode: ValidationModeDebug, RequireARF: true}, request("birthdate")); err != nil || !containsSubstring(findings, "RPRC_21") {
		t.Errorf("debug mode with --arf: findings %v (%v), want the RPRC_21 warning", findings, err)
	}
	if findings, err := ValidateAuthorizationRequest(ConformanceSettings{ValidationMode: ValidationModeStrict}, request("birthdate")); err != nil || containsSubstring(findings, "RPRC") {
		t.Errorf("strict mode without --arf: findings %v (%v), want no ARF check", findings, err)
	}
}

// The consent dialog shows the purposes of a registration certificate only
// when the certificate is bound to the access certificate that signed the
// request (OpenID4VP 1.0 §5.1).
func TestTheConsentShowsOnlyBoundRegistrations(t *testing.T) {
	reg := generateTestWallet(t)
	key, chain, verifierInfo := registeredVerifier(t, reg)
	if purposes, _ := consentRegistration(signedARFRequest(t, reg, key, chain, verifierInfo)); !slices.Equal(purposes, []string{"Age check"}) {
		t.Errorf("bound certificate: purposes %v, want Age check", purposes)
	}
	otherKey, otherChain, _ := registeredVerifier(t, reg)
	if purposes, _ := consentRegistration(signedARFRequest(t, reg, otherKey, otherChain, verifierInfo)); len(purposes) != 0 {
		t.Errorf("certificate of another relying party: purposes %v, want none", purposes)
	}
	unsigned := &AuthorizationRequestParams{FullParams: map[string]string{"verifier_info": verifierInfo}}
	if purposes, _ := consentRegistration(unsigned); len(purposes) != 0 {
		t.Errorf("unsigned request: purposes %v, want none", purposes)
	}
}
