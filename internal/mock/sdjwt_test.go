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

package mock

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
)

// ETSI TS 119 182-1 V1.2.1 §5.1.11 defines the header iat as the signing time.
func TestGenerateSDJWT_SigningTimeIsIndependentOfIssuanceTime(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := GenerateCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := GenerateLeafCertWithOptions(caKey, ca, &key.PublicKey, LeafCertOptions{})
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	issuedAt := before.Add(-3 * time.Hour).Truncate(time.Hour)
	raw, err := GenerateSDJWT(SDJWTConfig{
		CertificateIssuer: "https://issuer.example", Issuer: "https://issuer.example",
		VCT: DefaultPIDVCT, Key: key, IssuedAt: &issuedAt,
		CertChain: []*x509.Certificate{leaf, ca},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	signedAt, ok := parsed.Header["iat"].(float64)
	if !ok || signedAt < float64(before.Unix()) || signedAt > float64(time.Now().Unix()) {
		t.Errorf("signature time = %v, want the current signing time", parsed.Header["iat"])
	}
	if parsed.Payload["iat"] != float64(issuedAt.Unix()) {
		t.Errorf("issuance time = %v, want %d", parsed.Payload["iat"], issuedAt.Unix())
	}
}

func TestGenerateSDJWT_DefaultClaims(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "urn:eudi:pid:1",
		ExpiresIn: 24 * time.Hour,
		Claims:    DefaultClaims,
		Key:       key,
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	if !strings.HasSuffix(result, "~") {
		t.Error("SD-JWT should end with ~")
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	if alg, _ := token.Header["alg"].(string); alg != "ES256" {
		t.Errorf("expected alg ES256, got %s", alg)
	}
	if typ, _ := token.Header["typ"].(string); typ != "dc+sd-jwt" {
		t.Errorf("expected typ dc+sd-jwt, got %s", typ)
	}
	if kid, _ := token.Header["kid"].(string); kid != KeyIDForPublicKey(&key.PublicKey) {
		t.Errorf("expected kid %s, got %s", KeyIDForPublicKey(&key.PublicKey), kid)
	}

	if iss, _ := token.Payload["iss"].(string); iss != "https://issuer.example" {
		t.Errorf("expected iss https://issuer.example, got %s", iss)
	}
	if vct, _ := token.Payload["vct"].(string); vct != "urn:eudi:pid:1" {
		t.Errorf("expected vct urn:eudi:pid:1, got %s", vct)
	}

	if len(token.Disclosures) != len(DefaultClaims) {
		t.Errorf("expected %d disclosures, got %d", len(DefaultClaims), len(token.Disclosures))
	}

	for name, expected := range DefaultClaims {
		val, ok := token.ResolvedClaims[name]
		if !ok {
			t.Errorf("missing resolved claim %q", name)
			continue
		}
		if val != expected {
			t.Errorf("claim %q: expected %v, got %v", name, expected, val)
		}
	}

	verifyResult := sdjwt.Verify(token, &key.PublicKey)
	if !verifyResult.SignatureValid {
		t.Errorf("signature verification failed: %v", verifyResult.Errors)
	}
}

// The German PID lists the country-independent type in aka_vcts. SD-JWT VC
// §2.2.2.3 forbids disclosing it, and a verifier matches its request before
// the holder discloses anything.
func TestGenerateSDJWT_GermanPIDCarriesAkaVCTsPlainly(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	result, err := GenerateSDJWT(SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "urn:eudi:pid:de:1",
		ExpiresIn: 24 * time.Hour,
		Claims:    SDJWTGermanPIDClaims,
		Key:       key,
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}
	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	aka, ok := token.Payload["aka_vcts"].([]any)
	if !ok {
		t.Fatalf("aka_vcts missing from the payload: %v", token.Payload["aka_vcts"])
	}
	if len(aka) != 1 || aka[0] != DefaultPIDVCT {
		t.Errorf("aka_vcts = %v, want [%q]", aka, DefaultPIDVCT)
	}
	for _, d := range token.Disclosures {
		if d.Name == "aka_vcts" {
			t.Error("aka_vcts must not be selectively disclosable")
		}
	}
}

func TestGenerateSDJWT_PIDClaims(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "urn:eudi:pid:1",
		ExpiresIn: 24 * time.Hour,
		Claims:    SDJWTPIDClaims,
		Key:       key,
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	// One disclosure per top-level claim, plus one per nested property and array element.
	expectedTotal := len(SDJWTPIDClaims)
	for _, value := range SDJWTPIDClaims {
		switch v := value.(type) {
		case map[string]any:
			expectedTotal += len(v)
		case []any:
			expectedTotal += len(v)
		}
	}
	if len(token.Disclosures) != expectedTotal {
		t.Errorf("expected %d disclosures, got %d", expectedTotal, len(token.Disclosures))
	}

	addr, ok := token.ResolvedClaims["address"].(map[string]any)
	if !ok {
		t.Fatal("expected address to be a map in resolved claims")
	}
	for _, field := range []string{"street_address", "locality", "postal_code", "country"} {
		if _, ok := addr[field]; !ok {
			t.Errorf("address missing subclaim %q", field)
		}
	}

	pob, ok := token.ResolvedClaims["place_of_birth"].(map[string]any)
	if !ok {
		t.Fatal("expected place_of_birth to be a map in resolved claims")
	}
	if pob["locality"] != "Amsterdam" {
		t.Errorf("expected place_of_birth.locality Amsterdam, got %v", pob["locality"])
	}
	if pob["country"] != "NL" {
		t.Errorf("expected place_of_birth.country NL, got %v", pob["country"])
	}
	if len(pob) != 2 {
		t.Errorf("expected place_of_birth to contain locality and country, got %d entries", len(pob))
	}

	var foundPOB bool
	var foundLocality bool
	for _, disclosure := range token.Disclosures {
		switch disclosure.Name {
		case "place_of_birth":
			foundPOB = true
			value, ok := disclosure.Value.(map[string]any)
			if !ok {
				t.Fatalf("place_of_birth disclosure should contain an object, got %T", disclosure.Value)
			}
			sdEntries, ok := value["_sd"].([]any)
			if !ok || len(sdEntries) != 2 {
				t.Fatalf("place_of_birth disclosure should carry _sd digests for locality and country, got %v", value["_sd"])
			}
		case "locality":
			if disclosure.Value == "Amsterdam" {
				foundLocality = true
			}
		}
	}
	if !foundPOB {
		t.Fatal("expected a place_of_birth disclosure")
	}
	if !foundLocality {
		t.Fatal("expected a locality disclosure for place_of_birth")
	}

	nats, ok := token.ResolvedClaims["nationalities"].([]any)
	if !ok {
		t.Fatal("expected nationalities to be an array in resolved claims")
	}
	if len(nats) != 1 || nats[0] != "NL" {
		t.Errorf("expected nationalities=[NL], got %v", nats)
	}
	if _, ok := token.ResolvedClaims["trust_anchor"]; ok {
		t.Fatal("did not expect trust_anchor in resolved SD-JWT claims")
	}

	verifyResult := sdjwt.Verify(token, &key.PublicKey)
	if !verifyResult.SignatureValid {
		t.Errorf("signature verification failed: %v", verifyResult.Errors)
	}
}

func TestGenerateSDJWT_CustomClaims(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	claims := map[string]any{"name": "Test", "score": float64(42)}

	cfg := SDJWTConfig{
		Issuer:    "https://test.example",
		VCT:       "test-type",
		ExpiresIn: time.Hour,
		Claims:    claims,
		Key:       key,
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	if len(token.Disclosures) != 2 {
		t.Errorf("expected 2 disclosures, got %d", len(token.Disclosures))
	}

	verifyResult := sdjwt.Verify(token, &key.PublicKey)
	if !verifyResult.SignatureValid {
		t.Errorf("signature verification failed: %v", verifyResult.Errors)
	}
}

func TestGenerateSDJWT_EmptyClaims(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "urn:eudi:pid:1",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{},
		Key:       key,
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	if len(token.Disclosures) != 0 {
		t.Errorf("expected 0 disclosures, got %d", len(token.Disclosures))
	}

	verifyResult := sdjwt.Verify(token, &key.PublicKey)
	if !verifyResult.SignatureValid {
		t.Errorf("signature verification failed: %v", verifyResult.Errors)
	}
}

func TestGenerateSDJWT_CustomIssuerAndVCT(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := SDJWTConfig{
		Issuer:    "https://custom-issuer.de",
		VCT:       "urn:custom:type:2",
		ExpiresIn: 48 * time.Hour,
		Claims:    map[string]any{"foo": "bar"},
		Key:       key,
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	if iss, _ := token.Payload["iss"].(string); iss != "https://custom-issuer.de" {
		t.Errorf("expected iss https://custom-issuer.de, got %s", iss)
	}
	if vct, _ := token.Payload["vct"].(string); vct != "urn:custom:type:2" {
		t.Errorf("expected vct urn:custom:type:2, got %s", vct)
	}

	iat, _ := token.Payload["iat"].(float64)
	exp, _ := token.Payload["exp"].(float64)
	diff := exp - iat
	if diff < 47*3600 || diff > 49*3600 {
		t.Errorf("expected ~48h between iat and exp, got %.0fs", diff)
	}
}

func TestGenerateSDJWT_WrongKeyFailsVerify(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "urn:eudi:pid:1",
		ExpiresIn: 24 * time.Hour,
		Claims:    DefaultClaims,
		Key:       key1,
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	verifyResult := sdjwt.Verify(token, &key2.PublicKey)
	if verifyResult.SignatureValid {
		t.Error("signature should not verify with a different key")
	}
}

func TestGenerateSDJWT_NestedClaimValues(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	claims := map[string]any{
		"address": map[string]any{
			"street": "Main St",
			"city":   "Berlin",
		},
		"tags": []any{"admin", "user"},
	}

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "test",
		ExpiresIn: time.Hour,
		Claims:    claims,
		Key:       key,
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	// 2 top-level + 2 address subclaims + 2 array elements = 6 disclosures
	if len(token.Disclosures) != 6 {
		t.Errorf("expected 6 disclosures, got %d", len(token.Disclosures))
	}

	addr, ok := token.ResolvedClaims["address"].(map[string]any)
	if !ok {
		t.Fatal("expected address to be a map")
	}
	if addr["street"] != "Main St" {
		t.Errorf("expected street=Main St, got %v", addr["street"])
	}
	if addr["city"] != "Berlin" {
		t.Errorf("expected city=Berlin, got %v", addr["city"])
	}

	tags, ok := token.ResolvedClaims["tags"].([]any)
	if !ok {
		t.Fatal("expected tags to be an array")
	}
	if len(tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(tags))
	}

	verifyResult := sdjwt.Verify(token, &key.PublicKey)
	if !verifyResult.SignatureValid {
		t.Errorf("signature verification failed: %v", verifyResult.Errors)
	}
}

func TestGenerateSDJWT_UniqueDisclosures(t *testing.T) {
	key, _ := GenerateKey()

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "test",
		ExpiresIn: time.Hour,
		Claims:    SDJWTPIDClaims,
		Key:       key,
	}

	result, _ := GenerateSDJWT(cfg)
	token, _ := sdjwt.Parse(result)

	seen := make(map[string]bool)
	for _, d := range token.Disclosures {
		if seen[d.Digest] {
			t.Errorf("duplicate disclosure digest: %s", d.Digest)
		}
		seen[d.Digest] = true
	}

	seenSalts := make(map[string]bool)
	for _, d := range token.Disclosures {
		if seenSalts[d.Salt] {
			t.Errorf("duplicate disclosure salt: %s", d.Salt)
		}
		seenSalts[d.Salt] = true
	}
}

func TestGenerateSDJWT_WithNotBefore(t *testing.T) {
	key, _ := GenerateKey()
	nbf := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "test",
		ExpiresIn: 24 * time.Hour,
		NotBefore: &nbf,
		Claims:    map[string]any{"name": "test"},
		Key:       key,
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatal(err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatal(err)
	}

	nbfVal, ok := token.Payload["nbf"].(float64)
	if !ok {
		t.Fatal("expected nbf in payload")
	}
	if int64(nbfVal) != nbf.Unix() {
		t.Errorf("expected nbf=%d, got %d", nbf.Unix(), int64(nbfVal))
	}
}

func TestGenerateSDJWT_WithoutNotBefore(t *testing.T) {
	key, _ := GenerateKey()

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "test",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"name": "test"},
		Key:       key,
	}

	result, _ := GenerateSDJWT(cfg)
	token, _ := sdjwt.Parse(result)

	if _, ok := token.Payload["nbf"]; ok {
		t.Error("nbf should not be present when NotBefore is nil")
	}
}

func TestGenerateSDJWT_WithCertChainOmitsSelfSignedTrustAnchor(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	caKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey CA: %v", err)
	}
	caCert, err := GenerateCACert(caKey)
	if err != nil {
		t.Fatalf("GenerateCACert: %v", err)
	}
	leafCert, err := GenerateLeafCertWithOptions(caKey, caCert, &key.PublicKey, LeafCertOptions{})
	if err != nil {
		t.Fatalf("GenerateLeafCertWithOptions: %v", err)
	}

	result, err := GenerateSDJWT(SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "test",
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"name": "test"},
		Key:       key,
		CertChain: []*x509.Certificate{leafCert, caCert},
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	x5c, ok := token.Header["x5c"].([]any)
	if !ok {
		t.Fatal("expected x5c in header")
	}
	if len(x5c) != 1 {
		t.Fatalf("expected only leaf certificate in x5c, got %d entries", len(x5c))
	}
}

func TestGenerateSDJWT_AlwaysDisclosedTopLevel(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "urn:eudi:pid:1",
		ExpiresIn: 24 * time.Hour,
		Claims: map[string]any{
			"given_name":    "ERIKA",
			"family_name":   "MUSTERMANN",
			"nationalities": []any{"DE"},
		},
		Key:             key,
		AlwaysDisclosed: []string{"family_name", "nationalities", "no_such_claim"},
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}
	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	if got, _ := token.Payload["family_name"].(string); got != "MUSTERMANN" {
		t.Errorf("expected plain family_name in payload, got %v", token.Payload["family_name"])
	}
	nats, ok := token.Payload["nationalities"].([]any)
	if !ok || len(nats) != 1 || nats[0] != "DE" {
		t.Errorf("expected plain nationalities [DE] in payload, got %v", token.Payload["nationalities"])
	}
	if _, ok := token.Payload["given_name"]; ok {
		t.Error("given_name must not be plainly in the payload")
	}
	if len(token.Disclosures) != 1 {
		t.Errorf("expected 1 disclosure (given_name), got %d", len(token.Disclosures))
	}
	for _, name := range []string{"given_name", "family_name", "nationalities"} {
		if _, ok := token.ResolvedClaims[name]; !ok {
			t.Errorf("missing resolved claim %q", name)
		}
	}

	verifyResult := sdjwt.Verify(token, &key.PublicKey)
	if !verifyResult.SignatureValid {
		t.Errorf("signature verification failed: %v", verifyResult.Errors)
	}
}

func TestGenerateSDJWT_AlwaysDisclosedNestedPath(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "urn:eudi:pid:1",
		ExpiresIn: 24 * time.Hour,
		Claims: map[string]any{
			"address": map[string]any{
				"country":  "DE",
				"locality": "KÖLN",
			},
		},
		Key:             key,
		AlwaysDisclosed: []string{"address.country"},
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}
	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	if _, ok := token.Payload["address"]; ok {
		t.Error("address must not be plainly in the payload")
	}

	// country stays plain in the address value, so only address and locality are disclosures.
	if len(token.Disclosures) != 2 {
		t.Fatalf("expected 2 disclosures (address, locality), got %d", len(token.Disclosures))
	}
	var addressValue map[string]any
	for _, d := range token.Disclosures {
		if d.Name == "address" {
			addressValue, _ = d.Value.(map[string]any)
		}
	}
	if addressValue == nil {
		t.Fatal("address disclosure not found")
	}
	if got, _ := addressValue["country"].(string); got != "DE" {
		t.Errorf("expected plain country inside address disclosure, got %v", addressValue["country"])
	}
	if _, ok := addressValue["locality"]; ok {
		t.Error("locality must not be plain inside the address disclosure")
	}

	addr, ok := token.ResolvedClaims["address"].(map[string]any)
	if !ok {
		t.Fatalf("resolved address missing: %v", token.ResolvedClaims)
	}
	if addr["country"] != "DE" || addr["locality"] != "KÖLN" {
		t.Errorf("resolved address incomplete: %v", addr)
	}
}
