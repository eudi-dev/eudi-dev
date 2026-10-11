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

package jwe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// sealed builds a JWE with the standard library alone, so the test is
// independent of the package under test.
type sealed struct {
	compact   string
	recipient *ecdh.PrivateKey
	cek       []byte
	protected string
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func seal(t *testing.T, enc string, plaintext []byte, apu, apv []byte) sealed {
	t.Helper()

	recipient, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	z, err := ephemeral.ECDH(recipient.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	bits, err := EncKeyBitLen(enc)
	if err != nil {
		t.Fatal(err)
	}
	cek := ConcatKDF(z, enc, apu, apv, bits)

	// An uncompressed point is 0x04 followed by the two coordinates.
	point := ephemeral.PublicKey().Bytes()
	header := map[string]any{
		"alg": "ECDH-ES",
		"enc": enc,
		"epk": map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   b64(point[1:33]),
			"y":   b64(point[33:65]),
		},
	}
	if len(apu) > 0 {
		header["apu"] = b64(apu)
	}
	if len(apv) > 0 {
		header["apv"] = b64(apv)
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	protected := b64(headerJSON)

	block, err := aes.NewCipher(cek)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, aead.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	// The AAD is the ASCII of the encoded header.
	out := aead.Seal(nil, iv, plaintext, []byte(protected))
	ciphertext, tag := out[:len(out)-16], out[len(out)-16:]

	return sealed{
		compact:   strings.Join([]string{protected, "", b64(iv), b64(ciphertext), b64(tag)}, "."),
		recipient: recipient,
		cek:       cek,
		protected: protected,
	}
}

func TestDecryptRoundTrip(t *testing.T) {
	for _, enc := range []string{"A128GCM", "A256GCM"} {
		t.Run(enc, func(t *testing.T) {
			want := []byte(`{"vp_token":"presented"}`)
			s := seal(t, enc, want, nil, nil)

			got, err := Decrypt(s.compact, s.recipient)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if string(got) != string(want) {
				t.Errorf("plaintext = %q, want %q", got, want)
			}
		})
	}
}

// ISO 18013-7 includes apu and apv in key derivation.
func TestDecryptRoundTripWithAPUAndAPV(t *testing.T) {
	want := []byte("mdoc response")
	s := seal(t, "A256GCM", want, []byte("mdoc-generated-nonce"), []byte("verifier-nonce"))

	got, err := Decrypt(s.compact, s.recipient)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("plaintext = %q, want %q", got, want)
	}
}

func TestDecryptWithCEK(t *testing.T) {
	want := []byte("read from a key log")
	s := seal(t, "A256GCM", want, nil, nil)

	got, err := DecryptWithCEK(s.compact, s.cek)
	if err != nil {
		t.Fatalf("DecryptWithCEK: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("plaintext = %q, want %q", got, want)
	}

	if _, err := DecryptWithCEK(s.compact, make([]byte, 32)); err == nil {
		t.Error("a wrong content encryption key decrypted the payload")
	}
}

// The tag authenticates the encoded header. A header rewritten after
// encryption must fail.
func TestDecryptRejectsATamperedHeader(t *testing.T) {
	s := seal(t, "A256GCM", []byte("payload"), nil, nil)
	parts := strings.Split(s.compact, ".")

	var header map[string]any
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatal(err)
	}
	header["cty"] = "smuggled"
	rewritten, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	parts[0] = b64(rewritten)

	if _, err := Decrypt(strings.Join(parts, "."), s.recipient); err == nil {
		t.Error("a rewritten protected header was accepted")
	}
}

func TestDecryptRejectsATamperedCiphertext(t *testing.T) {
	s := seal(t, "A256GCM", []byte("payload"), nil, nil)
	parts := strings.Split(s.compact, ".")
	ct, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 0xff
	parts[3] = b64(ct)

	if _, err := Decrypt(strings.Join(parts, "."), s.recipient); err == nil {
		t.Error("a flipped ciphertext bit was accepted")
	}
}

// A JWE encrypted for another key must fail decryption.
func TestDecryptWithTheWrongRecipientKey(t *testing.T) {
	s := seal(t, "A256GCM", []byte("payload"), nil, nil)
	other, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Decrypt(s.compact, other); err == nil {
		t.Error("a JWE addressed to another key was decrypted")
	}
}

func TestDecryptErrors(t *testing.T) {
	valid := seal(t, "A256GCM", []byte("payload"), nil, nil)
	key := valid.recipient

	headerOnly := func(h map[string]any) string {
		raw, err := json.Marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		return b64(raw) + "..AAAA.AAAA.AAAA"
	}

	// A well-formed epk lets each case reach the check it targets.
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point := ephemeral.PublicKey().Bytes()
	goodEPK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64(point[1:33]),
		"y":   b64(point[33:65]),
	}

	tests := []struct {
		name    string
		compact string
		key     *ecdh.PrivateKey
		want    string
	}{
		{"no key", valid.compact, nil, "requires a private key"},
		{"too few parts", "a.b.c", key, "expected 5 parts"},
		{"header not base64", "!!!..AAAA.AAAA.AAAA", key, "decoding JWE header"},
		{"header not json", b64([]byte("not json")) + "..AAAA.AAAA.AAAA", key, "parsing JWE header"},
		{"missing enc", headerOnly(map[string]any{"alg": "ECDH-ES"}), key, "missing enc"},
		{"missing epk", headerOnly(map[string]any{"enc": "A256GCM"}), key, "missing epk"},
		{
			"epk on an unsupported curve",
			headerOnly(map[string]any{"enc": "A256GCM", "epk": map[string]any{"crv": "P-384", "x": "aa", "y": "bb"}}),
			key,
			"unsupported curve",
		},
		{
			"epk without coordinates",
			headerOnly(map[string]any{"enc": "A256GCM", "epk": map[string]any{"crv": "P-256"}}),
			key,
			"missing x or y",
		},
		{
			"unsupported enc",
			headerOnly(map[string]any{"enc": "A192GCM", "epk": goodEPK}),
			key,
			"unsupported content encryption algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decrypt(tt.compact, tt.key)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestDecryptWithCEKRejectsUnsupportedEnc(t *testing.T) {
	header, err := json.Marshal(map[string]any{"enc": "A192GCM"})
	if err != nil {
		t.Fatal(err)
	}
	compact := b64(header) + "..AAAA.AAAA.AAAA"

	_, err = DecryptWithCEK(compact, make([]byte, 32))
	if err == nil || !strings.Contains(err.Error(), "unsupported content encryption algorithm") {
		t.Errorf("error = %v, want unsupported content encryption algorithm", err)
	}
}

func TestDecryptWithCEKRejectsMalformedSegments(t *testing.T) {
	header, err := json.Marshal(map[string]any{"enc": "A256GCM"})
	if err != nil {
		t.Fatal(err)
	}
	h := b64(header)

	tests := []struct {
		name    string
		compact string
		want    string
	}{
		{"too few parts", "a.b.c.d", "expected 5 parts"},
		{"bad iv", h + "..!!!.AAAA.AAAA", "decoding IV"},
		{"wrong-length iv", h + "..AAAA.AAAA.AAAA", "IV must be"},
		{"bad ciphertext", h + "..AAAA.!!!.AAAA", "decoding ciphertext"},
		{"bad tag", h + "..AAAA.AAAA.!!!", "decoding tag"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptWithCEK(tt.compact, make([]byte, 32))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestParseHeader(t *testing.T) {
	s := seal(t, "A128GCM", []byte("payload"), []byte("apu-value"), []byte("apv-value"))

	h, err := ParseHeader(s.compact)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h.Enc != "A128GCM" {
		t.Errorf("Enc = %q, want A128GCM", h.Enc)
	}
	if string(h.APU) != "apu-value" {
		t.Errorf("APU = %q, want apu-value", h.APU)
	}
	if string(h.APV) != "apv-value" {
		t.Errorf("APV = %q, want apv-value", h.APV)
	}
	if h.EPK == nil {
		t.Error("EPK was not parsed")
	}
	if h.Raw["alg"] != "ECDH-ES" {
		t.Errorf("Raw[alg] = %v, want ECDH-ES", h.Raw["alg"])
	}
}

// A malformed apu stays empty. Decryption then fails on the derived key.
func TestParseHeaderLeavesAMalformedAPUEmpty(t *testing.T) {
	header, err := json.Marshal(map[string]any{"enc": "A256GCM", "apu": "!!!not base64!!!"})
	if err != nil {
		t.Fatal(err)
	}

	h, err := ParseHeader(b64(header) + "..AAAA.AAAA.AAAA")
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if len(h.APU) != 0 {
		t.Errorf("APU = %q, want it left empty", h.APU)
	}
}

func TestOpenAESGCMDoesNotCorruptTheCallersBuffer(t *testing.T) {
	s := seal(t, "A256GCM", []byte("payload"), nil, nil)
	parts := strings.Split(s.compact, ".")
	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	ct, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		t.Fatal(err)
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatal(err)
	}

	// Spare capacity makes an append write into the caller's backing array.
	roomy := make([]byte, len(ct), len(ct)+len(tag)+16)
	copy(roomy, ct)
	before := string(roomy)

	if _, err := OpenAESGCM(s.cek, iv, roomy, tag, []byte(parts[0])); err != nil {
		t.Fatalf("OpenAESGCM: %v", err)
	}
	if string(roomy) != before {
		t.Error("OpenAESGCM wrote the tag into the caller's ciphertext buffer")
	}
}

func TestOpenAESGCMRejectsABadKeyLength(t *testing.T) {
	if _, err := OpenAESGCM(make([]byte, 7), make([]byte, 12), []byte("x"), make([]byte, 16), nil); err == nil {
		t.Error("a 7-byte AES key was accepted")
	}
}

func TestParsePublicKeyJWK(t *testing.T) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point := key.PublicKey().Bytes()
	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64(point[1:33]),
		"y":   b64(point[33:65]),
	}

	parsed, err := ParsePublicKeyJWK(jwk)
	if err != nil {
		t.Fatalf("ParsePublicKeyJWK: %v", err)
	}
	if !parsed.Equal(key.PublicKey()) {
		t.Error("parsed key does not match the original")
	}
}

func TestParsePublicKeyJWKErrors(t *testing.T) {
	tests := []struct {
		name string
		jwk  map[string]any
		want string
	}{
		{"no curve", map[string]any{"x": "aa", "y": "bb"}, "unsupported curve"},
		{"wrong curve", map[string]any{"crv": "P-521", "x": "aa", "y": "bb"}, "unsupported curve"},
		{"no x", map[string]any{"crv": "P-256", "y": "bb"}, "missing x or y"},
		{"no y", map[string]any{"crv": "P-256", "x": "aa"}, "missing x or y"},
		{"coordinates not base64", map[string]any{"crv": "P-256", "x": "!!!", "y": "!!!"}, ""},
		{"point not on the curve", map[string]any{"kty": "EC", "crv": "P-256", "x": b64(make([]byte, 32)), "y": b64(make([]byte, 32))}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePublicKeyJWK(tt.jwk)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tt.want != "" && !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}
