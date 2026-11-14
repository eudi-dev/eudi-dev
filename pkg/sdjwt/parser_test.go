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

package sdjwt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func buildTestSDJWT(t *testing.T, payload map[string]any, disclosures [][]any) string {
	t.Helper()

	header := map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	if _, has := payload["_sd"]; has && len(disclosures) > 0 {
		var digests []string
		for _, d := range disclosures {
			dJSON, _ := json.Marshal(d)
			dB64 := base64.RawURLEncoding.EncodeToString(dJSON)
			h := sha256.Sum256([]byte(dB64))
			digests = append(digests, base64.RawURLEncoding.EncodeToString(h[:]))
		}
		payload["_sd"] = digests
	}

	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	jwt := headerB64 + "." + payloadB64 + ".fakesig"

	result := jwt
	for _, d := range disclosures {
		dJSON, _ := json.Marshal(d)
		dB64 := base64.RawURLEncoding.EncodeToString(dJSON)
		result += "~" + dB64
	}
	result += "~"

	return result
}

func TestParse_BasicSDJWT(t *testing.T) {
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

	token, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if token.Header["alg"] != "ES256" {
		t.Errorf("header alg = %v, want ES256", token.Header["alg"])
	}

	if len(token.Disclosures) != 2 {
		t.Fatalf("got %d disclosures, want 2", len(token.Disclosures))
	}

	if token.Disclosures[0].Name != "given_name" {
		t.Errorf("disclosure[0].Name = %q, want %q", token.Disclosures[0].Name, "given_name")
	}
	if token.Disclosures[0].Value != "Erika" {
		t.Errorf("disclosure[0].Value = %v, want %q", token.Disclosures[0].Value, "Erika")
	}
	if token.Disclosures[1].Name != "family_name" {
		t.Errorf("disclosure[1].Name = %q, want %q", token.Disclosures[1].Name, "family_name")
	}

	if token.ResolvedClaims["given_name"] != "Erika" {
		t.Errorf("resolved given_name = %v, want Erika", token.ResolvedClaims["given_name"])
	}
	if token.ResolvedClaims["family_name"] != "Mustermann" {
		t.Errorf("resolved family_name = %v, want Mustermann", token.ResolvedClaims["family_name"])
	}
}

// RFC 9901 §4 requires the tilde after the last disclosure. Without it the
// last component is read as a disclosure, and Parse records a warning.
func TestParse_MissingTrailingTilde(t *testing.T) {
	payload := map[string]any{
		"iss":     "https://issuer.example",
		"vct":     "urn:eudi:pid:1",
		"_sd_alg": "sha-256",
		"_sd":     nil,
	}
	raw := buildTestSDJWT(t, payload, [][]any{
		{"salt1", "given_name", "Erika"},
		{"salt2", "family_name", "Mustermann"},
	})
	raw = strings.TrimSuffix(raw, "~")

	token, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(token.Disclosures) != 2 {
		t.Fatalf("got %d disclosures, want 2", len(token.Disclosures))
	}
	found := false
	for _, w := range token.Warnings {
		if strings.Contains(w, "tilde") {
			found = true
		}
	}
	if !found {
		t.Errorf("Warnings = %v, want one naming the missing tilde", token.Warnings)
	}
}

func TestParse_PlainJWT(t *testing.T) {
	payload := map[string]any{
		"iss": "https://issuer.example",
		"sub": "user123",
	}

	headerJSON, _ := json.Marshal(map[string]any{"alg": "ES256"})
	payloadJSON, _ := json.Marshal(payload)
	raw := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON) + ".fakesig"

	token, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(token.Disclosures) != 0 {
		t.Errorf("got %d disclosures, want 0", len(token.Disclosures))
	}
	if token.ResolvedClaims["iss"] != "https://issuer.example" {
		t.Errorf("resolved iss = %v, want https://issuer.example", token.ResolvedClaims["iss"])
	}
}

func TestParse_InvalidJWT(t *testing.T) {
	_, err := Parse("not-a-jwt")
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

func TestParse_EmptyInput(t *testing.T) {
	_, err := Parse("")
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestParse_UnsupportedHashAlg(t *testing.T) {
	headerJSON, _ := json.Marshal(map[string]any{"alg": "ES256"})
	payloadJSON, _ := json.Marshal(map[string]any{
		"iss":     "test",
		"_sd_alg": "sha3-256",
		"_sd":     []string{"abc"},
	})
	discJSON, _ := json.Marshal([]any{"salt", "name", "value"})
	discB64 := base64.RawURLEncoding.EncodeToString(discJSON)

	raw := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON) + ".sig~" + discB64 + "~"

	_, err := Parse(raw)
	if err == nil {
		t.Error("expected error for unsupported _sd_alg")
	}
}

func TestSDAlgFromPayload(t *testing.T) {
	if got := SDAlgFromPayload(map[string]any{}); got != "sha-256" {
		t.Errorf("no _sd_alg: got %q, want the sha-256 default", got)
	}
	if got := SDAlgFromPayload(map[string]any{"_sd_alg": "sha-384"}); got != "sha-384" {
		t.Errorf("_sd_alg sha-384: got %q, want sha-384", got)
	}
}

// The KB-JWT sd_hash follows the credential's _sd_alg. A credential issued
// under SHA-384 hashes with SHA-384.
func TestSDHash_FollowsSDAlg(t *testing.T) {
	h256, err := SDHash("data~", "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	h384, err := SDHash("data~", "sha-384")
	if err != nil {
		t.Fatal(err)
	}
	if h256 == h384 {
		t.Error("SHA-256 and SHA-384 produced the same sd_hash")
	}
}

func TestComputeDigest_SHA256(t *testing.T) {
	digest, err := computeDigest("test", "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	if digest == "" {
		t.Error("expected non-empty digest")
	}
}

func TestComputeDigest_SHA384(t *testing.T) {
	digest, err := computeDigest("test", "sha-384")
	if err != nil {
		t.Fatal(err)
	}
	if digest == "" {
		t.Error("expected non-empty digest")
	}
}

func TestComputeDigest_SHA512(t *testing.T) {
	digest, err := computeDigest("test", "sha-512")
	if err != nil {
		t.Fatal(err)
	}
	if digest == "" {
		t.Error("expected non-empty digest")
	}
}

func TestComputeDigest_Unsupported(t *testing.T) {
	_, err := computeDigest("test", "sha3-256")
	if err == nil {
		t.Error("expected error for unsupported alg")
	}
}

func TestParse_ArrayDisclosure(t *testing.T) {
	// An array element disclosure is [salt, value].
	arrDisc, digest := disclosureOf(t, "saltyy", "array-value")
	raw := assembleSDJWT(t, map[string]any{
		"iss":    "test",
		"values": []any{map[string]any{"...": digest}},
	}, arrDisc)

	token := mustParse(t, raw)

	if len(token.Disclosures) != 1 {
		t.Fatalf("got %d disclosures, want 1", len(token.Disclosures))
	}

	d := token.Disclosures[0]
	if !d.IsArrayEntry {
		t.Error("expected IsArrayEntry=true")
	}
	if d.Value != "array-value" {
		t.Errorf("Value = %v, want array-value", d.Value)
	}
	if d.Name != "" {
		t.Errorf("Name = %q, want empty", d.Name)
	}

	values, ok := token.ResolvedClaims["values"].([]any)
	if !ok || len(values) != 1 || values[0] != "array-value" {
		t.Errorf("resolved values = %v, want [array-value]", token.ResolvedClaims["values"])
	}
}

func TestCheckFullyUndisclosedChildren(t *testing.T) {
	warnings := checkFullyUndisclosedChildren([]Disclosure{
		{Name: "name", Value: "Max", Digest: "d1"},
	})
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}

	warnings = checkFullyUndisclosedChildren([]Disclosure{
		{
			Name: "addresses",
			Value: []any{
				map[string]any{"...": "unknown_digest1"},
				map[string]any{"...": "unknown_digest2"},
			},
			Digest: "d1",
		},
	})
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(warnings))
	}

	warnings = checkFullyUndisclosedChildren([]Disclosure{
		{
			Name:   "addresses",
			Value:  []any{"visible_value"},
			Digest: "d1",
		},
	})
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for partially disclosed array, got %v", warnings)
	}

	warnings = checkFullyUndisclosedChildren([]Disclosure{
		{
			Name: "address",
			Value: map[string]any{
				"_sd": []any{"unknown_digest1", "unknown_digest2"},
			},
			Digest: "d1",
		},
	})
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning for fully undisclosed map, got %d", len(warnings))
	}

	warnings = checkFullyUndisclosedChildren([]Disclosure{
		{
			Name: "address",
			Value: map[string]any{
				"_sd":  []any{"unknown"},
				"city": "Berlin",
			},
			Digest: "d1",
		},
	})
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for map with visible claims, got %v", warnings)
	}

	warnings = checkFullyUndisclosedChildren([]Disclosure{
		{IsArrayEntry: true, Value: []any{map[string]any{"...": "x"}}, Digest: "d1"},
	})
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for array entries, got %v", warnings)
	}
}
