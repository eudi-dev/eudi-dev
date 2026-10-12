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
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
)

func TestGenerateJWT_DefaultClaims(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := JWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "urn:eudi:pid:1",
		ExpiresIn: 24 * time.Hour,
		Claims:    DefaultClaims,
		Key:       key,
	}

	result, err := GenerateJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	if strings.Contains(result, "~") {
		t.Error("JWT should not contain ~")
	}

	parts := strings.Split(result, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	if alg, _ := token.Header["alg"].(string); alg != "ES256" {
		t.Errorf("expected alg ES256, got %s", alg)
	}
	if typ, _ := token.Header["typ"].(string); typ != "vc+jwt" {
		t.Errorf("expected typ vc+jwt, got %s", typ)
	}

	if iss, _ := token.Payload["iss"].(string); iss != "https://issuer.example" {
		t.Errorf("expected iss https://issuer.example, got %s", iss)
	}
	if vct, _ := token.Payload["vct"].(string); vct != "urn:eudi:pid:1" {
		t.Errorf("expected vct urn:eudi:pid:1, got %s", vct)
	}

	if len(token.Disclosures) != 0 {
		t.Errorf("expected 0 disclosures, got %d", len(token.Disclosures))
	}

	if _, ok := token.Payload["_sd"]; ok {
		t.Error("JWT payload should not contain _sd")
	}
	if _, ok := token.Payload["_sd_alg"]; ok {
		t.Error("JWT payload should not contain _sd_alg")
	}

	for name, expected := range DefaultClaims {
		val, ok := token.Payload[name]
		if !ok {
			t.Errorf("missing claim %q in payload", name)
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

func TestGenerateJWT_NilKey(t *testing.T) {
	cfg := JWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "test",
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"name": "Test"},
		Key:       nil,
	}

	_, err := GenerateJWT(cfg)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
	if !strings.Contains(err.Error(), "signing key is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGenerateJWT_WrongKeyFailsVerify(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	cfg := JWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "urn:eudi:pid:1",
		ExpiresIn: 24 * time.Hour,
		Claims:    DefaultClaims,
		Key:       key1,
	}

	result, err := GenerateJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
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

func TestGenerateJWT_StatusList(t *testing.T) {
	key, _ := GenerateKey()

	cfg := JWTConfig{
		Issuer:        "https://issuer.example",
		VCT:           "test",
		ExpiresIn:     time.Hour,
		Claims:        map[string]any{"name": "Test"},
		Key:           key,
		StatusListURI: "https://issuer.example/statuslist",
		StatusListIdx: 42,
	}

	result, err := GenerateJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	status, ok := token.Payload["status"].(map[string]any)
	if !ok {
		t.Fatal("expected status in payload")
	}
	sl, ok := status["status_list"].(map[string]any)
	if !ok {
		t.Fatal("expected status_list in status")
	}
	if uri, _ := sl["uri"].(string); uri != "https://issuer.example/statuslist" {
		t.Errorf("expected status list URI, got %s", uri)
	}
	if idx, _ := sl["idx"].(float64); int(idx) != 42 {
		t.Errorf("expected status list idx 42, got %v", sl["idx"])
	}
}

func TestGenerateJWT_WithNotBefore(t *testing.T) {
	key, _ := GenerateKey()
	nbf := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	cfg := JWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "test",
		ExpiresIn: 24 * time.Hour,
		NotBefore: &nbf,
		Claims:    map[string]any{"name": "test"},
		Key:       key,
	}

	result, err := GenerateJWT(cfg)
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

func TestGenerateJWT_WithoutNotBefore(t *testing.T) {
	key, _ := GenerateKey()

	cfg := JWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "test",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"name": "test"},
		Key:       key,
	}

	result, _ := GenerateJWT(cfg)
	token, _ := sdjwt.Parse(result)

	if _, ok := token.Payload["nbf"]; ok {
		t.Error("nbf should not be present when NotBefore is nil")
	}
}
