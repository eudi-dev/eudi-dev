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
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/regcert"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

func signTestRegistrationCertificate(t *testing.T, w *Wallet, purpose any) string {
	t.Helper()
	_, chain, err := w.Signer().Default()
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

// purposesOf returns the purposes of the valid registration certificates in
// verifier_info and the problems of the others.
func purposesOf(payload map[string]any) ([]string, []string) {
	certs, problems := verifiedRegistrationCertificates(payload)
	purposes, _ := regcert.Purposes(certs)
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
		other, err := oid4vp.SignRequestObjectJWT(map[string]any{"purpose": "not a certificate"}, w.IssuerKey, nil)
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
	key, chain, err := w.Signer().Default()
	if err != nil {
		t.Fatalf("Default() error = %v", err)
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

// Several certificate findings share one activity log entry.
func TestARFFindingsShareOneLogEntry(t *testing.T) {
	w := generateTestWallet(t)
	cert := signTestRegistrationCertificate(t, w, "Checking your ticket")
	findings := oid4vp.ARFFindings(&oid4vp.Request{
		RequestPayload: verifierInfoPayload(map[string]any{"format": "registration_cert", "data": cert}),
	})
	w.warnFindings("presentation", "authorization_request_finding", subjectRequest, specCitedSummary("The request", findings), findings, nil)

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
	_, chain, err := w.Signer().Default()
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
	request := func(claim string) *oid4vp.Request {
		return &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: "redirect_uri:https://verifier.example/response", ResponseType: "vp_token", ResponseMode: "direct_post", ResponseURI: "https://verifier.example/response", Nonce: "n", DCQLQuery: map[string]any{"credentials": []any{map[string]any{
			"id":     "pid",
			"format": "dc+sd-jwt",
			"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
			"claims": []any{map[string]any{"path": []any{claim}}},
		}}}}, RequestPayload: verifierInfoPayload(map[string]any{"format": "registration_cert", "data": cert})}
	}

	if _, err := oid4vp.ValidateAuthorizationRequest(oid4vp.Checks{Strict: true, ARF: true}, request("birthdate")); err == nil || !strings.Contains(err.Error(), "RPRC_21") {
		t.Errorf("strict mode with --arf: err = %v, want the RPRC_21 refusal", err)
	}
	if findings, err := oid4vp.ValidateAuthorizationRequest(oid4vp.Checks{ARF: true}, request("birthdate")); err != nil || !containsSubstring(findings.Texts(), "RPRC_21") {
		t.Errorf("debug mode with --arf: findings %v (%v), want the RPRC_21 warning", findings, err)
	}
	if findings, err := oid4vp.ValidateAuthorizationRequest(oid4vp.Checks{Strict: true}, request("birthdate")); err != nil || containsSubstring(findings.Texts(), "RPRC") {
		t.Errorf("strict mode without --arf: findings %v (%v), want no ARF check", findings, err)
	}
}

// The consent dialog shows the purposes of a registration certificate only
// when the certificate is bound to the access certificate that signed the
// request (OpenID4VP 1.0 §5.1).
func TestTheConsentShowsOnlyBoundRegistrations(t *testing.T) {
	reg := generateTestWallet(t)
	key, chain, verifierInfo := registeredVerifier(t, reg)
	if purposes, _ := oid4vp.ConsentRegistration(signedARFRequest(t, reg, key, chain, verifierInfo)); !slices.Equal(purposes, []string{"Age check"}) {
		t.Errorf("bound certificate: purposes %v, want Age check", purposes)
	}
	otherKey, otherChain, _ := registeredVerifier(t, reg)
	if purposes, _ := oid4vp.ConsentRegistration(signedARFRequest(t, reg, otherKey, otherChain, verifierInfo)); len(purposes) != 0 {
		t.Errorf("certificate of another relying party: purposes %v, want none", purposes)
	}
	unsigned := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{FullParams: map[string]string{"verifier_info": verifierInfo}}}
	if purposes, _ := oid4vp.ConsentRegistration(unsigned); len(purposes) != 0 {
		t.Errorf("unsigned request: purposes %v, want none", purposes)
	}
}

// ETSI TS 119 475 V1.2.1 GEN-5.1.1-03 links the two certificates "solely on
// the matching identifier" when other attributes differ, so the consent shows
// the purposes of a certificate for another service. --arf compares the
// service too (ARF RPRC_17a).
func TestTheConsentBindsByTheRelyingPartyIdentifier(t *testing.T) {
	reg := generateTestWallet(t)
	key, chain, verifierInfo := registeredVerifier(t, reg)
	var info []map[string]any
	if err := json.Unmarshal([]byte(verifierInfo), &info); err != nil {
		t.Fatal(err)
	}
	certificate, err := base64.RawURLEncoding.DecodeString(info[0]["data"].(string))
	if err != nil {
		t.Fatal(err)
	}
	_, payload, _, err := format.ParseJWTParts(string(certificate))
	if err != nil {
		t.Fatal(err)
	}
	payload[registrar.ServiceIdentifierClaim] = "another-service"
	otherService, err := registrar.SignRegistrationCertificateJWT(payload, key, chain)
	if err != nil {
		t.Fatal(err)
	}
	request := signedARFRequest(t, reg, key, chain, `[{"format":"registration_cert","data":"`+otherService+`"}]`)
	if purposes, _ := oid4vp.ConsentRegistration(request); !slices.Equal(purposes, []string{"Age check"}) {
		t.Errorf("purposes %v, want Age check", purposes)
	}
	if findings := oid4vp.ARFFindings(request); !containsSubstring(findings.Texts(), "RPRC_17a") {
		t.Errorf("findings %v, want RPRC_17a for another service", findings)
	}
}
