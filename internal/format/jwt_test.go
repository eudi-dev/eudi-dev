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

package format

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func makeJWT(header, payload map[string]any, sig string) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(sig))
}

func TestParseJWTParts_Valid(t *testing.T) {
	jwt := makeJWT(
		map[string]any{"alg": "ES256", "typ": "JWT"},
		map[string]any{"sub": "user123", "iss": "https://example.com"},
		"test-sig",
	)

	header, payload, sig, err := ParseJWTParts(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if header["alg"] != "ES256" {
		t.Errorf("header.alg = %v, want ES256", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("header.typ = %v, want JWT", header["typ"])
	}
	if payload["sub"] != "user123" {
		t.Errorf("payload.sub = %v, want user123", payload["sub"])
	}
	if payload["iss"] != "https://example.com" {
		t.Errorf("payload.iss = %v, want https://example.com", payload["iss"])
	}
	if len(sig) == 0 {
		t.Error("expected non-empty signature bytes")
	}
}

func TestParseJWTParts_EmptySignature(t *testing.T) {
	h, _ := json.Marshal(map[string]any{"alg": "none"})
	p, _ := json.Marshal(map[string]any{"sub": "test"})
	jwt := base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + "."

	header, payload, _, err := ParseJWTParts(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if header["alg"] != "none" {
		t.Errorf("header.alg = %v, want none", header["alg"])
	}
	if payload["sub"] != "test" {
		t.Errorf("payload.sub = %v, want test", payload["sub"])
	}
}

func TestParseJWTParts_TwoParts(t *testing.T) {
	_, _, _, err := ParseJWTParts("part1.part2")
	if err == nil {
		t.Error("expected error for 2-part input")
	}
}

// RFC 7515 §7.1: a JWS Compact Serialization has exactly three parts.
func TestParseJWTParts_FourParts(t *testing.T) {
	jwt := makeJWT(map[string]any{"alg": "ES256"}, map[string]any{"sub": "x"}, "sig")
	if _, _, _, err := ParseJWTParts(jwt + ".extra"); err == nil {
		t.Error("expected error for 4-part input")
	}
}

func TestParseJWTParts_InvalidHeaderBase64(t *testing.T) {
	_, _, _, err := ParseJWTParts("!!!.aGVsbG8.c2ln")
	if err == nil {
		t.Error("expected error for invalid header base64url")
	}
}

func TestParseJWTParts_InvalidPayloadBase64(t *testing.T) {
	h, _ := json.Marshal(map[string]any{"alg": "ES256"})
	jwt := base64.RawURLEncoding.EncodeToString(h) + ".!!!.c2ln"
	_, _, _, err := ParseJWTParts(jwt)
	if err == nil {
		t.Error("expected error for invalid payload base64url")
	}
}

func TestParseJWTParts_InvalidHeaderJSON(t *testing.T) {
	notJSON := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	p, _ := json.Marshal(map[string]any{"sub": "test"})
	jwt := notJSON + "." + base64.RawURLEncoding.EncodeToString(p) + ".c2ln"
	_, _, _, err := ParseJWTParts(jwt)
	if err == nil {
		t.Error("expected error for non-JSON header")
	}
}

func TestParseJWTParts_InvalidPayloadJSON(t *testing.T) {
	h, _ := json.Marshal(map[string]any{"alg": "ES256"})
	notJSON := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	jwt := base64.RawURLEncoding.EncodeToString(h) + "." + notJSON + ".c2ln"
	_, _, _, err := ParseJWTParts(jwt)
	if err == nil {
		t.Error("expected error for non-JSON payload")
	}
}

func TestParseJWTParts_NestedPayload(t *testing.T) {
	jwt := makeJWT(
		map[string]any{"alg": "ES256"},
		map[string]any{
			"iss":    "https://example.com",
			"nested": map[string]any{"key": "value"},
			"arr":    []any{1, 2, 3},
		},
		"sig",
	)

	_, payload, _, err := ParseJWTParts(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nested, ok := payload["nested"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested map, got %T", payload["nested"])
	}
	if nested["key"] != "value" {
		t.Errorf("nested.key = %v, want value", nested["key"])
	}
	arr, ok := payload["arr"].([]any)
	if !ok {
		t.Fatalf("expected arr slice, got %T", payload["arr"])
	}
	if len(arr) != 3 {
		t.Errorf("arr length = %d, want 3", len(arr))
	}
}

func TestParseJWTParts_EmptyInput(t *testing.T) {
	_, _, _, err := ParseJWTParts("")
	if err == nil {
		t.Error("expected error for empty input")
	}
}

// RFC 7515 §4.1.9.
func TestJOSETypeIs(t *testing.T) {
	tests := []struct {
		typ, want string
		match     bool
	}{
		{"kb+jwt", "kb+jwt", true},
		{"application/kb+jwt", "kb+jwt", true},
		{"KB+JWT", "kb+jwt", true},
		{"statuslist+jwt", "application/statuslist+jwt", true},
		{"text/kb+jwt", "kb+jwt", false},
		{"jwt", "kb+jwt", false},
		{"", "kb+jwt", false},
	}
	for _, tt := range tests {
		if got := JOSETypeIs(tt.typ, tt.want); got != tt.match {
			t.Errorf("JOSETypeIs(%q, %q) = %v, want %v", tt.typ, tt.want, got, tt.match)
		}
	}
}
