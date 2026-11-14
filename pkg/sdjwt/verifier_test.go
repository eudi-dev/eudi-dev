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
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

func testToken(t *testing.T, cfg mock.SDJWTConfig) *Token {
	t.Helper()
	cfg.Issuer, cfg.VCT, cfg.Claims = "https://issuer.example", "urn:test:1", credtemplate.DefaultClaims
	raw, err := mock.GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}
	token, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return token
}

func TestVerify(t *testing.T) {
	key, _ := mock.GenerateKey()
	other, _ := mock.GenerateKey()
	token := testToken(t, mock.SDJWTConfig{ExpiresIn: time.Hour, Key: key})

	if err := Verify(token, &key.PublicKey); err != nil {
		t.Errorf("Verify with the issuer key: %v", err)
	}
	if err := Verify(token, &other.PublicKey); !errors.Is(err, ErrSignature) {
		t.Errorf("Verify with another key = %v, want ErrSignature", err)
	}

	malformed := &Token{Raw: "not-a-jwt", Header: map[string]any{"alg": "ES256"}}
	if err := Verify(malformed, &key.PublicKey); err == nil || errors.Is(err, ErrSignature) {
		t.Errorf("Verify of a token without 3 JWT parts = %v, want a structure error", err)
	}

	if err := Verify(token, nil); err == nil || errors.Is(err, ErrSignature) || err.Error() != ErrSignature.Error() {
		t.Errorf("Verify without a key = %v, want the text of ErrSignature without ErrSignature", err)
	}
}

// The issuer signed the token. Only its header is changed to alg none, and
// Verify must not accept the signature under that header.
func TestVerifyRefusesAlgNone(t *testing.T) {
	key, _ := mock.GenerateKey()
	signed := testToken(t, mock.SDJWTConfig{ExpiresIn: time.Hour, Key: key})
	jwt, rest, _ := strings.Cut(signed.Raw, "~")
	parts := strings.Split(jwt, ".")
	parts[0] = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"dc+sd-jwt"}`))
	token, err := Parse(strings.Join(parts, ".") + "~" + rest)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(token, &key.PublicKey); err == nil || errors.Is(err, ErrSignature) || !strings.Contains(err.Error(), "unsupported algorithm: none") {
		t.Errorf("Verify with alg none = %v, want an unsupported algorithm error", err)
	}
}

func TestValidAt(t *testing.T) {
	key, _ := mock.GenerateKey()
	now := time.Now()
	notBefore := now.Add(time.Hour)

	tests := []struct {
		name string
		cfg  mock.SDJWTConfig
		at   time.Time
		want error
	}{
		{"inside the validity period", mock.SDJWTConfig{ExpiresIn: time.Hour}, now, nil},
		{"after exp", mock.SDJWTConfig{ExpiresIn: time.Hour}, now.Add(2 * time.Hour), ErrExpired},
		{"within the clock skew after exp", mock.SDJWTConfig{ExpiresIn: time.Hour}, now.Add(time.Hour + 30*time.Second), nil},
		{"before nbf", mock.SDJWTConfig{ExpiresIn: 2 * time.Hour, NotBefore: &notBefore}, now, ErrNotYetValid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.Key = key
			err := testToken(t, tt.cfg).ValidAt(tt.at)
			if !errors.Is(err, tt.want) {
				t.Errorf("ValidAt = %v, want %v", err, tt.want)
			}
		})
	}
}

// Each rejected value is a JSON type or number that RFC 7519 §2 does not allow
// for a NumericDate.
func TestValidAtRejectsUnreadableTimeClaims(t *testing.T) {
	for _, claim := range []string{"exp", "nbf", "iat"} {
		for name, value := range map[string]any{
			"text":            "2030-01-01T00:00:00Z",
			"numeric text":    "1893456000",
			"boolean":         true,
			"null":            nil,
			"negative":        float64(-1),
			"after year 9999": float64(1e15),
		} {
			t.Run(claim+" as "+name, func(t *testing.T) {
				token := &Token{ResolvedClaims: map[string]any{claim: value}}
				err := token.ValidAt(time.Now())
				if err == nil || !strings.Contains(err.Error(), claim+" is not a NumericDate") {
					t.Errorf("ValidAt = %v, want an error about %s", err, claim)
				}
			})
		}
	}
	if err := (&Token{}).ValidAt(time.Now()); err == nil {
		t.Error("ValidAt accepted a token without a processed payload")
	}
}

func TestIssuerCertificates(t *testing.T) {
	caKey, _ := mock.GenerateKey()
	ca, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := mock.GenerateKey()
	leaf, err := mock.GenerateLeafCertWithOptions(caKey, ca, &key.PublicKey, mock.LeafCertOptions{})
	if err != nil {
		t.Fatal(err)
	}

	token := testToken(t, mock.SDJWTConfig{ExpiresIn: time.Hour, Key: key, CertChain: []*x509.Certificate{leaf, ca}})
	certs, err := token.IssuerCertificates()
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 || !certs[0].Equal(leaf) {
		t.Fatalf("IssuerCertificates = %d certificates, want the leaf first", len(certs))
	}
	if err := Verify(token, certs[0].PublicKey); err != nil {
		t.Errorf("Verify with the key of the leaf: %v", err)
	}

	certs, err = testToken(t, mock.SDJWTConfig{ExpiresIn: time.Hour, Key: key}).IssuerCertificates()
	if err != nil || len(certs) != 0 {
		t.Errorf("IssuerCertificates without x5c = %d certificates, %v", len(certs), err)
	}
	token.Header["x5c"] = []any{"not a certificate"}
	if _, err := token.IssuerCertificates(); err == nil {
		t.Error("IssuerCertificates accepted an x5c entry that is not a certificate")
	}
}

var presentationNow = time.Unix(1794571200, 0)

// presenter builds presentations of one credential bound to the holder key.
type presenter struct {
	t                     *testing.T
	issuer, holder, other *ecdsa.PrivateKey
}

func newPresenter(t *testing.T) *presenter {
	t.Helper()
	p := &presenter{t: t}
	for _, key := range []**ecdsa.PrivateKey{&p.issuer, &p.holder, &p.other} {
		generated, err := mock.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		*key = generated
	}
	return p
}

func (p *presenter) sign(typ string, payload map[string]any, key *ecdsa.PrivateKey) string {
	p.t.Helper()
	jwt, err := jws.Sign(map[string]any{"typ": typ, "alg": jws.AlgES256}, payload, key)
	if err != nil {
		p.t.Fatal(err)
	}
	return jwt
}

// credential is an SD-JWT that ends with a tilde. change edits the payload
// before signing.
func (p *presenter) credential(change func(payload map[string]any)) string {
	p.t.Helper()
	jwk, err := keys.PublicJWK(&p.holder.PublicKey)
	if err != nil {
		p.t.Fatal(err)
	}
	payload := map[string]any{
		"iss": "https://issuer.example", "vct": "urn:test:1",
		"exp": presentationNow.Add(time.Hour).Unix(), "cnf": map[string]any{"jwk": jwk},
	}
	if change != nil {
		change(payload)
	}
	return p.sign("dc+sd-jwt", payload, p.issuer) + "~"
}

// keyBinding is a Key Binding JWT over credential. change edits the payload
// before signing.
func (p *presenter) keyBinding(credential string, key *ecdsa.PrivateKey, change func(payload map[string]any)) string {
	p.t.Helper()
	sdHash, err := SDHash(credential, "sha-256")
	if err != nil {
		p.t.Fatal(err)
	}
	payload := map[string]any{
		"iat": presentationNow.Unix(), "aud": "https://verifier.example", "nonce": "n-2", "sd_hash": sdHash,
	}
	if change != nil {
		change(payload)
	}
	return p.sign(TypeKeyBinding, payload, key)
}

func TestVerifyKeyBinding(t *testing.T) {
	expected := KeyBinding{Audience: "https://verifier.example", Nonce: "n-2", Now: presentationNow}
	changed := func(change func(payload map[string]any)) func(p *presenter, credential string) string {
		return func(p *presenter, credential string) string {
			return credential + p.keyBinding(credential, p.holder, change)
		}
	}
	set := func(name string, value any) func(p *presenter, credential string) string {
		return changed(func(payload map[string]any) { payload[name] = value })
	}
	unix := func(offset time.Duration) int64 { return presentationNow.Add(offset).Unix() }
	with := func(change func(k *KeyBinding)) KeyBinding {
		k := expected
		change(&k)
		return k
	}

	tests := []struct {
		name     string
		build    func(p *presenter, credential string) string
		expected KeyBinding
		wantErr  string
		wantIs   error
	}{
		{name: "valid key binding", build: changed(nil), expected: expected},
		{
			name:     "no Key Binding JWT",
			build:    func(_ *presenter, credential string) string { return credential },
			expected: expected,
			wantErr:  "no Key Binding JWT",
		},
		{
			name: "signed with another key",
			build: func(p *presenter, credential string) string {
				return credential + p.keyBinding(credential, p.other, nil)
			},
			expected: expected,
			wantIs:   ErrSignature,
		},
		{
			name: "sd_hash of another presentation",
			build: func(p *presenter, credential string) string {
				return credential + p.keyBinding(p.credential(func(payload map[string]any) { payload["vct"] = "urn:test:2" }), p.holder, nil)
			},
			expected: expected,
			wantErr:  "sd_hash does not match the presentation",
			wantIs:   ErrSDHash,
		},
		{
			name: "credential without cnf",
			build: func(p *presenter, _ string) string {
				credential := p.credential(func(payload map[string]any) { delete(payload, "cnf") })
				return credential + p.keyBinding(credential, p.holder, nil)
			},
			expected: expected,
			wantErr:  "the credential has no cnf claim",
		},

		{
			name:     "another audience",
			build:    changed(nil),
			expected: with(func(k *KeyBinding) { k.Audience = "https://other.example" }),
			wantErr:  `aud does not match: got "https://verifier.example"`,
			wantIs:   ErrAudience,
		},
		{
			name:     "another nonce",
			build:    changed(nil),
			expected: with(func(k *KeyBinding) { k.Nonce = "n-3" }),
			wantErr:  `nonce does not match: got "n-2"`,
			wantIs:   ErrNonce,
		},
		{
			name:     "no expected audience and no aud claim",
			build:    changed(func(payload map[string]any) { delete(payload, "aud") }),
			expected: with(func(k *KeyBinding) { k.Audience = "" }),
			wantIs:   ErrAudience,
		},
		{
			name:     "no expected nonce and no nonce claim",
			build:    changed(func(payload map[string]any) { delete(payload, "nonce") }),
			expected: with(func(k *KeyBinding) { k.Nonce = "" }),
			wantIs:   ErrNonce,
		},
		{
			name:     "no expected audience and an empty aud claim",
			build:    set("aud", ""),
			expected: with(func(k *KeyBinding) { k.Audience = "" }),
			wantIs:   ErrAudience,
		},

		{name: "iat missing", build: changed(func(payload map[string]any) { delete(payload, "iat") }), expected: expected, wantErr: "iat is missing"},
		{name: "iat as text", build: set("iat", "1794571200"), expected: expected, wantErr: "iat is not a NumericDate"},
		{name: "iat within the clock skew ahead", build: set("iat", unix(30*time.Second)), expected: expected},
		{name: "iat in the future", build: set("iat", unix(2*time.Minute)), expected: expected, wantErr: "iat 2026-11-13T12:02:00Z is in the future"},
		{name: "iat within the clock skew behind", build: set("iat", unix(-30*time.Second)), expected: expected},
		{name: "iat older than the clock skew without MaxAge", build: set("iat", unix(-2*time.Minute)), expected: expected, wantErr: "is older than 0s"},
		{
			name:     "iat within MaxAge",
			build:    set("iat", unix(-4*time.Minute)),
			expected: with(func(k *KeyBinding) { k.MaxAge = 5 * time.Minute }),
		},
		{
			name:     "iat older than MaxAge",
			build:    set("iat", unix(-7*time.Minute)),
			expected: with(func(k *KeyBinding) { k.MaxAge = 5 * time.Minute }),
			wantErr:  "iat 2026-11-13T11:53:00Z is older than 5m0s",
		},

		{name: "exp ahead", build: set("exp", unix(time.Minute)), expected: expected},
		{name: "expired", build: set("exp", unix(-2*time.Minute)), expected: expected, wantIs: ErrExpired},
		{name: "exp as text", build: set("exp", "soon"), expected: expected, wantErr: "exp is not a NumericDate"},
		{name: "nbf reached", build: set("nbf", unix(0)), expected: expected},
		{name: "before nbf", build: set("nbf", unix(2*time.Minute)), expected: expected, wantIs: ErrNotYetValid},
		{name: "nbf as text", build: set("nbf", "later"), expected: expected, wantErr: "nbf is not a NumericDate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPresenter(t)
			token, err := Parse(tt.build(p, p.credential(nil)))
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(token, &p.issuer.PublicKey); err != nil {
				t.Fatal(err)
			}
			err = VerifyKeyBinding(token, tt.expected)
			switch {
			case tt.wantErr == "" && tt.wantIs == nil:
				if err != nil {
					t.Fatal(err)
				}
			case err == nil:
				t.Fatal("VerifyKeyBinding succeeded")
			case !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("error = %v, want it to contain %q", err, tt.wantErr)
			case tt.wantIs != nil && !errors.Is(err, tt.wantIs):
				t.Errorf("error = %v, want it to match %v", err, tt.wantIs)
			}
		})
	}
}

// RFC 9901 §4.3.1: sd_hash covers the Issuer-signed JWT and every Disclosure
// of the presentation, so a presentation without one of them fails.
func TestKeyBindingCoversTheDisclosures(t *testing.T) {
	p := newPresenter(t)
	disclose := func(salt, name, value string) (disclosure, digest string) {
		disclosure = base64.RawURLEncoding.EncodeToString([]byte(`["` + salt + `","` + name + `","` + value + `"]`))
		sum := sha256.Sum256([]byte(disclosure))
		return disclosure, base64.RawURLEncoding.EncodeToString(sum[:])
	}
	given, givenDigest := disclose("salt-1", "given_name", "Erika")
	family, familyDigest := disclose("salt-2", "family_name", "Mustermann")
	issued := strings.TrimSuffix(p.credential(func(payload map[string]any) {
		payload["_sd"] = []any{givenDigest, familyDigest}
		payload["_sd_alg"] = "sha-256"
	}), "~")
	presentation := issued + "~" + given + "~" + family + "~"
	expected := KeyBinding{Audience: "https://verifier.example", Nonce: "n-2", Now: presentationNow}

	token, err := Parse(presentation + p.keyBinding(presentation, p.holder, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeyBinding(token, expected); err != nil {
		t.Fatalf("VerifyKeyBinding: %v", err)
	}
	if token.ResolvedClaims["given_name"] != "Erika" || token.ResolvedClaims["family_name"] != "Mustermann" {
		t.Errorf("claims = %v, want both disclosed names", token.ResolvedClaims)
	}

	withoutFamily := issued + "~" + given + "~"
	token, err = Parse(withoutFamily + p.keyBinding(presentation, p.holder, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeyBinding(token, expected); !errors.Is(err, ErrSDHash) {
		t.Errorf("VerifyKeyBinding without a Disclosure = %v, want ErrSDHash", err)
	}
}

// RFC 9901 §4.3 gives a Key Binding JWT the typ kb+jwt. A trailing JWT with
// another typ is not a Key Binding JWT.
func TestATrailingJWTWithAnotherTypIsNotAKeyBinding(t *testing.T) {
	p := newPresenter(t)
	credential := p.credential(nil)
	sdHash, err := SDHash(credential, "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"iat": presentationNow.Unix(), "aud": "https://verifier.example", "nonce": "n-2", "sd_hash": sdHash}
	raw := credential + p.sign("JWT", payload, p.holder)

	if _, err := Parse(raw); err == nil {
		t.Error("Parse accepted a trailing JWT with the typ JWT")
	}
	token, err := ParseLenient(raw)
	if err != nil {
		t.Fatal(err)
	}
	expected := KeyBinding{Audience: "https://verifier.example", Nonce: "n-2", Now: presentationNow}
	if err := VerifyKeyBinding(token, expected); err == nil {
		t.Error("VerifyKeyBinding accepted a trailing JWT with the typ JWT")
	}
}

func TestConfirmationKey(t *testing.T) {
	p := newPresenter(t)
	token, err := Parse(p.credential(nil))
	if err != nil {
		t.Fatal(err)
	}
	key, err := token.ConfirmationKey()
	if err != nil {
		t.Fatal(err)
	}
	if !p.holder.PublicKey.Equal(key) {
		t.Error("ConfirmationKey is not the holder key")
	}
	for name, cnf := range map[string]any{
		"absent":         nil,
		"text":           "key",
		"without a jwk":  map[string]any{"kid": "1"},
		"unreadable jwk": map[string]any{"jwk": map[string]any{"kty": "EC"}},
	} {
		t.Run(name, func(t *testing.T) {
			token := &Token{ResolvedClaims: map[string]any{"cnf": cnf}}
			if _, err := token.ConfirmationKey(); err == nil {
				t.Error("ConfirmationKey returned a key")
			}
		})
	}
}
