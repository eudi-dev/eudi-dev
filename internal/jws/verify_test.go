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

package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"
)

func key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func signed(t *testing.T, k *ecdsa.PrivateKey, payload any) string {
	t.Helper()
	compact, err := Sign(map[string]any{"alg": "ES256", "typ": "JWT"}, payload, k)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func TestVerifyReturnsThePayload(t *testing.T) {
	k := key(t)
	compact := signed(t, k, map[string]any{"iss": "https://issuer.example", "n": 1})

	payload, err := Verify(compact, &k.PublicKey)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("payload is not the JSON that was signed: %v", err)
	}
	if claims["iss"] != "https://issuer.example" {
		t.Errorf("iss = %v, want https://issuer.example", claims["iss"])
	}
}

func TestVerifyRejectsAnotherKey(t *testing.T) {
	compact := signed(t, key(t), map[string]any{"sub": "alice"})

	if _, err := Verify(compact, &key(t).PublicKey); err == nil {
		t.Error("a signature made by another key verified")
	}
}

func TestVerifyRejectsATamperedPayload(t *testing.T) {
	k := key(t)
	compact := signed(t, k, map[string]any{"sub": "alice"})

	parts := strings.Split(compact, ".")
	rewritten, err := json.Marshal(map[string]any{"sub": "attacker"})
	if err != nil {
		t.Fatal(err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(rewritten)

	if _, err := Verify(strings.Join(parts, "."), &k.PublicKey); err == nil {
		t.Error("a rewritten payload verified")
	}
}

func TestVerifyErrors(t *testing.T) {
	k := key(t)
	compact := signed(t, k, map[string]any{"sub": "alice"})

	tests := []struct {
		name    string
		compact string
		key     any
		want    string
	}{
		{"no key", compact, nil, "requires a public key"},
		{"not a JWS", "not.a.jws", &k.PublicKey, "parsing JWS"},
		{"empty", "", &k.PublicKey, "parsing JWS"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(tt.compact, tt.key)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

// A token with alg "none" must never verify.
func TestVerifyRefusesTheNoneAlgorithm(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker"}`))
	unsigned := header + "." + payload + "."

	if _, err := Verify(unsigned, &key(t).PublicKey); err == nil {
		t.Error("an unsigned token was accepted")
	}
}

// Verify must refuse an HMAC token. The caller passes a public key, and it
// must never serve as an HMAC secret.
func TestVerifyRefusesASymmetricAlgorithm(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	signer, err := josev4.NewSigner(josev4.SigningKey{Algorithm: josev4.HS256, Key: secret}, nil)
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign([]byte(`{"sub":"attacker"}`))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Verify(compact, secret); err == nil {
		t.Error("an HS256 token was accepted")
	}
}

func TestVerifyAcceptsRSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := josev4.NewSigner(josev4.SigningKey{Algorithm: josev4.RS256, Key: rsaKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign([]byte(`{"sub":"alice"}`))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	payload, err := Verify(compact, &rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("Verify with an RSA key: %v", err)
	}
	if string(payload) != `{"sub":"alice"}` {
		t.Errorf("payload = %s", payload)
	}
}

func TestValid(t *testing.T) {
	k := key(t)
	compact := signed(t, k, map[string]any{"sub": "alice"})

	if !Valid(compact, &k.PublicKey) {
		t.Error("Valid reported a good signature as bad")
	}
	if Valid(compact, &key(t).PublicKey) {
		t.Error("Valid reported another key's signature as good")
	}
	if Valid("garbage", &k.PublicKey) {
		t.Error("Valid accepted something that is not a JWS")
	}
	if Valid(compact, nil) {
		t.Error("Valid accepted a missing key")
	}
}
