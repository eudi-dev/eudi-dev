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
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/certinfo"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

func buildTestJWT(t *testing.T, header, payload map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + ".fakesig"
}

func buildTestSDJWT(t *testing.T, payload map[string]any, disclosures [][]any) string {
	t.Helper()
	header := map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"}
	h, _ := json.Marshal(header)

	if _, has := payload["_sd"]; has && len(disclosures) > 0 {
		var digests []string
		for _, d := range disclosures {
			dJSON, _ := json.Marshal(d)
			dB64 := base64.RawURLEncoding.EncodeToString(dJSON)
			hash := sha256.Sum256([]byte(dB64))
			digests = append(digests, base64.RawURLEncoding.EncodeToString(hash[:]))
		}
		payload["_sd"] = digests
	}

	p, _ := json.Marshal(payload)
	jwt := base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + ".fakesig"

	result := jwt
	for _, d := range disclosures {
		dJSON, _ := json.Marshal(d)
		result += "~" + base64.RawURLEncoding.EncodeToString(dJSON)
	}
	result += "~"
	return result
}

func TestDecode_JWT(t *testing.T) {
	jwt := buildTestJWT(t,
		map[string]any{"alg": "none", "typ": "JWT"},
		map[string]any{"sub": "user123", "iss": "https://example.com"},
	)

	result, err := Decode(jwt)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	if result["format"] != "jwt" {
		t.Errorf("format = %v, want jwt", result["format"])
	}

	header, ok := result["header"].(map[string]any)
	if !ok {
		t.Fatalf("header is not a map")
	}
	if header["alg"] != "none" {
		t.Errorf("header.alg = %v, want none", header["alg"])
	}

	payload, ok := result["payload"].(map[string]any)
	if !ok {
		t.Fatalf("payload is not a map")
	}
	if payload["sub"] != "user123" {
		t.Errorf("payload.sub = %v, want user123", payload["sub"])
	}
	if payload["iss"] != "https://example.com" {
		t.Errorf("payload.iss = %v, want https://example.com", payload["iss"])
	}
}

func TestDecode_SDJWT(t *testing.T) {
	disclosures := [][]any{
		{"salt1", "given_name", "Erika"},
		{"salt2", "family_name", "Mustermann"},
	}
	payload := map[string]any{
		"iss":     "https://issuer.example",
		"vct":     "urn:eudi:pid:1",
		"_sd_alg": "sha-256",
		"_sd":     nil,
	}
	raw := buildTestSDJWT(t, payload, disclosures)

	result, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	if result["format"] != "dc+sd-jwt" {
		t.Errorf("format = %v, want dc+sd-jwt", result["format"])
	}

	discs, ok := result["disclosures"].([]map[string]any)
	if !ok {
		t.Fatalf("disclosures is not []map[string]any, got %T", result["disclosures"])
	}
	if len(discs) != 2 {
		t.Fatalf("got %d disclosures, want 2", len(discs))
	}
	if discs[0]["name"] != "given_name" {
		t.Errorf("disclosures[0].name = %v, want given_name", discs[0]["name"])
	}
	if discs[0]["value"] != "Erika" {
		t.Errorf("disclosures[0].value = %v, want Erika", discs[0]["value"])
	}

	resolved, ok := result["resolvedClaims"].(map[string]any)
	if !ok {
		t.Fatalf("resolvedClaims is not a map")
	}
	if resolved["given_name"] != "Erika" {
		t.Errorf("resolvedClaims.given_name = %v, want Erika", resolved["given_name"])
	}
	if resolved["family_name"] != "Mustermann" {
		t.Errorf("resolvedClaims.family_name = %v, want Mustermann", resolved["family_name"])
	}
}

func TestDecode_SDJWTPreservesPayloadFields(t *testing.T) {
	disclosures := [][]any{
		{"salt1", "name", "Alice"},
	}
	payload := map[string]any{
		"iss":     "https://issuer.example",
		"exp":     1742592000.0,
		"_sd_alg": "sha-256",
		"_sd":     nil,
	}
	raw := buildTestSDJWT(t, payload, disclosures)

	result, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	p, ok := result["payload"].(map[string]any)
	if !ok {
		t.Fatalf("payload is not a map")
	}
	if p["iss"] != "https://issuer.example" {
		t.Errorf("payload.iss = %v, want https://issuer.example", p["iss"])
	}
}

func TestDecode_UnknownFormat(t *testing.T) {
	_, err := Decode("this-is-not-a-credential")
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestDecode_EmptyInput(t *testing.T) {
	_, err := Decode("")
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestDecode_MalformedJWT(t *testing.T) {
	_, err := Decode("!!!.!!!.!!!")
	if err == nil {
		t.Fatal("expected error for malformed JWT")
	}
}

func TestDecode_JWTResultHasNoDisclosures(t *testing.T) {
	jwt := buildTestJWT(t,
		map[string]any{"alg": "RS256"},
		map[string]any{"sub": "test"},
	)

	result, err := Decode(jwt)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	if _, ok := result["disclosures"]; ok {
		t.Error("JWT result should not have disclosures")
	}
	if _, ok := result["resolvedClaims"]; ok {
		t.Error("JWT result should not have resolvedClaims")
	}
}

func TestDecode_SDJWTIncludesIssuerMetadataValidation(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	var issuer string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwt-vc-issuer" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer,
			"jwks": map[string]any{
				"keys": []any{mock.SigningJWKMap(&key.PublicKey)},
			},
		})
	}))
	defer srv.Close()
	issuer = srv.URL

	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    issuer,
		VCT:       "urn:test",
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "Erika"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	result, err := Validate(raw, ValidateOpts{})
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}

	validation, ok := result["validation"].(map[string]any)
	if !ok {
		t.Fatalf("expected validation object, got %T", result["validation"])
	}
	checks, ok := validation["checks"].([]CheckResult)
	if !ok {
		t.Fatalf("expected validation checks array, got %T", validation["checks"])
	}
	var signature *CheckResult
	for i := range checks {
		check := checks[i]
		if check.Name == "signature" {
			signature = &check
			break
		}
	}
	if signature == nil {
		t.Fatal("expected signature check")
	}
	if signature.Status != "pass" {
		t.Fatalf("expected signature pass, got %v", signature)
	}
}

func newCA(t *testing.T, name string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := mock.GenerateNamedCACert(key, name)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func der(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}

func listCertificateSubjects(t *testing.T, raw string) []string {
	t.Helper()
	result, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}
	certs, _ := result["listCertificates"].([]certinfo.Certificate)
	subjects := make([]string, 0, len(certs))
	for _, cert := range certs {
		subjects = append(subjects, cert.Subject)
	}
	return subjects
}

// The decoder shows the certificates of a list's services (ETSI TS 119 602
// V1.1.1 §6.6.3) next to its signer chain, so each one opens in place.
func TestDecodeListsTheCertificatesOfATrustedListsServices(t *testing.T) {
	key, signer := newCA(t, "Acme List Operator")
	_, issuance := newCA(t, "Bolt PID CA")
	_, revocation := newCA(t, "Bolt Status CA")
	raw, err := lote.Sign(key, signer, lote.Options{
		OperatorName: "Acme",
		Entities:     []lote.Entity{{Name: "Bolt", Issuance: []string{der(issuance), der(issuance)}, Revocation: []string{der(revocation)}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	subjects := listCertificateSubjects(t, raw)
	if want := []string{subject(signer), subject(issuance), subject(revocation)}; !slices.Equal(subjects, want) {
		t.Errorf("list certificates = %v, want %v", subjects, want)
	}
}

// A pointer to another list carries the certificate of that list's signer
// (ETSI TS 119 602 V1.1.1 §6.3.13).
func TestDecodeListsTheCertificateOfAPointedToList(t *testing.T) {
	key, signer := newCA(t, "Acme List Operator")
	_, pointed := newCA(t, "Crate List Operator")
	raw, err := lote.SignList(key, signer, time.Now(), map[string]any{"ListAndSchemeInformation": map[string]any{
		"PointersToOtherLoTE": []map[string]any{lote.PointerEntry("https://lists.example/pid", lote.PIDProvidersListType, "Crate", "EU", der(pointed))},
	}})
	if err != nil {
		t.Fatal(err)
	}

	if subjects := listCertificateSubjects(t, raw); len(subjects) != 1 || subjects[0] != subject(pointed) {
		t.Errorf("list certificates = %v, want the pointed-to list's signer", subjects)
	}
}

func TestDecodeListsNoCertificatesForAPlainJWT(t *testing.T) {
	jwt := buildTestJWT(t, map[string]any{"alg": "none"}, map[string]any{"sub": "alice"})
	result, err := Decode(jwt)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result["listCertificates"]; ok {
		t.Errorf("a plain JWT has list certificates: %v", result["listCertificates"])
	}
}

func subject(cert *x509.Certificate) string {
	return certinfo.Describe(cert).Subject
}
