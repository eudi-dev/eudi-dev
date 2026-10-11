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

// Package jwe encrypts and decrypts compact JWEs for the wallet, the verifier
// and the proxy (ADR-0008).
package jwe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
)

// JWE algorithm and encryption identifiers of RFC 7518 that the wallet and
// the demo verifier name.
const (
	AlgECDHES  = "ECDH-ES"
	EncA128GCM = "A128GCM"
	EncA256GCM = "A256GCM"
)

type Header struct {
	Enc string
	EPK map[string]any
	APU []byte
	APV []byte
	Raw map[string]any
}

func ParseHeader(compact string) (Header, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return Header{}, fmt.Errorf("invalid JWE: expected 5 parts, got %d", len(parts))
	}
	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		return Header{}, fmt.Errorf("decoding JWE header: %w", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(headerBytes, &raw); err != nil {
		return Header{}, fmt.Errorf("parsing JWE header: %w", err)
	}
	h := Header{Raw: raw}
	h.Enc, _ = raw["enc"].(string)
	if h.Enc == "" {
		return Header{}, fmt.Errorf("missing enc in JWE header")
	}
	h.EPK, _ = raw["epk"].(map[string]any)
	// A malformed apu or apv stays empty. The derived key then differs, so
	// decryption fails.
	if b64, ok := raw["apu"].(string); ok {
		h.APU, _ = format.DecodeBase64URL(b64)
	}
	if b64, ok := raw["apv"].(string); ok {
		h.APV, _ = format.DecodeBase64URL(b64)
	}
	return h, nil
}

func Decrypt(compact string, key *ecdh.PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("decryption requires a private key")
	}
	header, err := ParseHeader(compact)
	if err != nil {
		return nil, err
	}
	// RFC 7518 §4.6: "The "alg" (algorithm) Header Parameter value "ECDH-ES"
	// is used in the Direct Key Agreement mode."
	if alg, _ := header.Raw["alg"].(string); alg != AlgECDHES {
		return nil, fmt.Errorf("unsupported JWE alg %q, want %s", alg, AlgECDHES)
	}
	// RFC 7516 §5.2 step 10: "verify that the JWE Encrypted Key value is an
	// empty octet sequence."
	if strings.Split(compact, ".")[1] != "" {
		return nil, fmt.Errorf("the JWE encrypted key must be empty under %s", AlgECDHES)
	}
	if header.EPK == nil {
		return nil, fmt.Errorf("missing epk in JWE header")
	}
	epk, err := ParsePublicKeyJWK(header.EPK)
	if err != nil {
		return nil, fmt.Errorf("parsing epk: %w", err)
	}
	z, err := key.ECDH(epk)
	if err != nil {
		return nil, fmt.Errorf("ECDH key agreement: %w", err)
	}
	keyBitLen, err := EncKeyBitLen(header.Enc)
	if err != nil {
		return nil, err
	}
	return DecryptWithCEK(compact, ConcatKDF(z, header.Enc, header.APU, header.APV, keyBitLen))
}

// DecryptWithCEK decrypts a compact JWE with a known content encryption key.
// The proxy uses it to read traffic from a key log.
func DecryptWithCEK(compact string, cek []byte) ([]byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid JWE: expected 5 parts, got %d", len(parts))
	}
	header, err := ParseHeader(compact)
	if err != nil {
		return nil, err
	}

	iv, err := format.DecodeBase64URL(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decoding IV: %w", err)
	}
	ciphertext, err := format.DecodeBase64URL(parts[3])
	if err != nil {
		return nil, fmt.Errorf("decoding ciphertext: %w", err)
	}
	tag, err := format.DecodeBase64URL(parts[4])
	if err != nil {
		return nil, fmt.Errorf("decoding tag: %w", err)
	}
	keyBitLen, err := EncKeyBitLen(header.Enc)
	if err != nil {
		return nil, err
	}
	if len(cek)*8 != keyBitLen {
		return nil, fmt.Errorf("%s requires a %d-bit key, got %d bits", header.Enc, keyBitLen, len(cek)*8)
	}
	// The AAD is the ASCII of the encoded protected header (RFC 7516 §5.1).
	switch header.Enc {
	case EncA128GCM, EncA256GCM:
		return OpenAESGCM(cek, iv, ciphertext, tag, []byte(parts[0]))
	case "A128CBC-HS256":
		return openAESCBCHS256(cek, iv, ciphertext, tag, []byte(parts[0]))
	default:
		return nil, fmt.Errorf("unsupported content encryption algorithm: %s", header.Enc)
	}
}

// openAESCBCHS256 checks the tag before it decrypts (RFC 7518 §5.2.2.2).
func openAESCBCHS256(key, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("A128CBC-HS256 requires 256-bit key, got %d bits", len(key)*8)
	}
	if !hmac.Equal(tag, cbcHS256Tag(key[:16], aad, iv, ciphertext)) {
		return nil, fmt.Errorf("A128CBC-HS256 authentication tag does not match")
	}
	if len(iv) != aes.BlockSize || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("A128CBC-HS256 IV or ciphertext has the wrong length")
	}
	block, err := aes.NewCipher(key[16:])
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	padding := int(plaintext[len(plaintext)-1])
	if padding == 0 || padding > aes.BlockSize {
		return nil, fmt.Errorf("A128CBC-HS256 plaintext has invalid padding")
	}
	return plaintext[:len(plaintext)-padding], nil
}

// OpenAESGCM opens an AES-GCM ciphertext given the tag separately, the way
// JWE carries it.
func OpenAESGCM(key, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	// aead.Open panics on a wrong-length nonce. The IV comes from an untrusted JWE.
	if len(iv) != aead.NonceSize() {
		return nil, fmt.Errorf("AES-GCM IV must be %d bytes, got %d", aead.NonceSize(), len(iv))
	}
	// Appending to ciphertext can write the tag into the caller's backing array.
	plaintext, err := aead.Open(nil, iv, slices.Concat(ciphertext, tag), aad)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}
	return plaintext, nil
}

// ConcatKDF derives a content encryption key for ECDH-ES as JWA specifies
// (NIST SP 800-56A, one round of SHA-256).
func ConcatKDF(z []byte, enc string, apu, apv []byte, keyBitLen int) []byte {
	h := sha256.New()

	var round [4]byte
	binary.BigEndian.PutUint32(round[:], 1)
	h.Write(round[:])

	h.Write(z)
	writeWithLength(h, []byte(enc)) // AlgorithmID
	writeWithLength(h, apu)         // PartyUInfo
	writeWithLength(h, apv)         // PartyVInfo

	// SuppPubInfo = keyBitLen (4-byte big-endian)
	var suppPub [4]byte
	binary.BigEndian.PutUint32(suppPub[:], uint32(keyBitLen))
	h.Write(suppPub[:])

	return h.Sum(nil)[:keyBitLen/8]
}

func writeWithLength(h io.Writer, data []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	h.Write(lenBuf[:])
	if len(data) > 0 {
		h.Write(data)
	}
}

func EncKeyBitLen(enc string) (int, error) {
	switch enc {
	case EncA128GCM:
		return 128, nil
	case EncA256GCM:
		return 256, nil
	case "A128CBC-HS256":
		return 256, nil // 128-bit MAC key plus 128-bit encryption key
	default:
		return 0, fmt.Errorf("unsupported content encryption algorithm: %s", enc)
	}
}

// ParsePublicKeyJWK reads a P-256 public key from a JWK map, such as an epk
// header. It uses the toolkit's JWK decoding, which includes the go-jose
// off-curve check.
func ParsePublicKeyJWK(m map[string]any) (*ecdh.PublicKey, error) {
	if crv, _ := m["crv"].(string); crv != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}
	if x, _ := m["x"].(string); x == "" {
		return nil, fmt.Errorf("missing x or y coordinate")
	}
	if y, _ := m["y"].(string); y == "" {
		return nil, fmt.Errorf("missing x or y coordinate")
	}
	doc, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("re-encoding epk: %w", err)
	}
	parsed, err := keys.ParseJWK(doc)
	if err != nil {
		return nil, err
	}
	ecKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("epk is not an EC key")
	}
	return ecKey.ECDH()
}
