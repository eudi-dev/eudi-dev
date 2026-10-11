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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RSA-OAEP (JWA "RSA-OAEP", RFC 7518 §4.2) requires SHA-1 for encryption padding. This is not a signature hash
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
)

// EncryptECDHES encrypts payload to the recipient's P-256 key as a compact JWE
// with ECDH-ES direct key agreement (RFC 7518 §4.6). The header alg is
// ECDH-ES. It returns the compact serialization and the derived content
// encryption key. apu and apv go into the key derivation and the header, as
// ISO 18013-7 Annex B requires for mdoc responses (ADR-0008).
func EncryptECDHES(payload []byte, recipient *ecdsa.PublicKey, kid, enc, cty string, apu, apv []byte) (string, []byte, error) {
	keyBitLen, err := EncKeyBitLen(enc)
	if err != nil {
		return "", nil, err
	}

	ephemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("generating ephemeral key: %w", err)
	}
	ephemeralECDH, err := ephemeral.ECDH()
	if err != nil {
		return "", nil, fmt.Errorf("converting ephemeral key to ECDH: %w", err)
	}
	recipientECDH, err := recipient.ECDH()
	if err != nil {
		return "", nil, fmt.Errorf("converting recipient key to ECDH: %w", err)
	}
	z, err := ephemeralECDH.ECDH(recipientECDH)
	if err != nil {
		return "", nil, fmt.Errorf("ECDH key agreement: %w", err)
	}
	cek := ConcatKDF(z, enc, apu, apv, keyBitLen)

	epk, err := keys.PublicJWK(&ephemeral.PublicKey)
	if err != nil {
		return "", nil, err
	}
	header := map[string]any{
		"alg": AlgECDHES,
		"enc": enc,
		"kid": kid,
		"epk": epk,
	}
	if apu != nil {
		header["apu"] = format.EncodeBase64URL(apu)
	}
	if apv != nil {
		header["apv"] = format.EncodeBase64URL(apv)
	}
	if cty != "" {
		header["cty"] = cty
	}
	// Direct key agreement leaves the encrypted key empty (RFC 7516 §5.1).
	compact, err := sealCompact(header, nil, cek, payload)
	return compact, cek, err
}

// EncryptRSAOAEP encrypts payload to the recipient's RSA key as a compact JWE.
// It wraps a random content encryption key with RSA-OAEP (RFC 7518 §4.2) or
// RSA-OAEP-256 (§4.3) and returns the compact serialization and that key.
func EncryptRSAOAEP(payload []byte, recipient *rsa.PublicKey, kid, alg, enc string) (string, []byte, error) {
	keyBitLen, err := EncKeyBitLen(enc)
	if err != nil {
		return "", nil, err
	}

	var oaepHash hash.Hash
	switch alg {
	case "RSA-OAEP":
		oaepHash = sha1.New() //nolint:gosec // RSA-OAEP is defined with SHA-1 (RFC 7518 §4.2)
	case "RSA-OAEP-256":
		oaepHash = sha256.New()
	default:
		return "", nil, fmt.Errorf("unsupported RSA key management alg: %s", alg)
	}

	cek := make([]byte, keyBitLen/8)
	if _, err := rand.Read(cek); err != nil {
		return "", nil, fmt.Errorf("generating content encryption key: %w", err)
	}
	encryptedKey, err := rsa.EncryptOAEP(oaepHash, rand.Reader, recipient, cek, nil)
	if err != nil {
		return "", nil, fmt.Errorf("RSA-OAEP wrapping the content encryption key: %w", err)
	}

	compact, err := sealCompact(map[string]any{"alg": alg, "enc": enc, "kid": kid}, encryptedKey, cek, payload)
	return compact, cek, err
}

// sealCompact encrypts payload under cek and returns the compact serialization. The
// AAD is the ASCII of the encoded protected header (RFC 7516 §5.1).
func sealCompact(header map[string]any, encryptedKey, cek, payload []byte) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling header: %w", err)
	}
	headerB64 := format.EncodeBase64URL(headerJSON)

	var iv, ciphertext, tag []byte
	switch enc, _ := header["enc"].(string); enc {
	case EncA128GCM, EncA256GCM:
		iv, ciphertext, tag, err = sealAESGCM(cek, payload, []byte(headerB64))
	case "A128CBC-HS256":
		iv, ciphertext, tag, err = sealAESCBCHS256(cek, payload, []byte(headerB64))
	default:
		return "", fmt.Errorf("unsupported enc algorithm: %s", enc)
	}
	if err != nil {
		return "", err
	}

	return headerB64 + "." +
		format.EncodeBase64URL(encryptedKey) + "." +
		format.EncodeBase64URL(iv) + "." +
		format.EncodeBase64URL(ciphertext) + "." +
		format.EncodeBase64URL(tag), nil
}

func sealAESGCM(key, plaintext, aad []byte) (iv, ciphertext, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating GCM: %w", err)
	}

	iv = make([]byte, aead.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, nil, fmt.Errorf("generating IV: %w", err)
	}

	sealed := aead.Seal(nil, iv, plaintext, aad)
	return iv, sealed[:len(sealed)-aead.Overhead()], sealed[len(sealed)-aead.Overhead():], nil
}

// sealAESCBCHS256 encrypts with AES-128-CBC and HMAC-SHA-256 (RFC 7518
// §5.2.2). The key is MAC_KEY (16 bytes) followed by ENC_KEY (16 bytes).
func sealAESCBCHS256(key, plaintext, aad []byte) (iv, ciphertext, tag []byte, err error) {
	if len(key) != 32 {
		return nil, nil, nil, fmt.Errorf("A128CBC-HS256 requires 256-bit key, got %d bits", len(key)*8)
	}

	iv = make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, nil, fmt.Errorf("generating IV: %w", err)
	}

	block, err := aes.NewCipher(key[16:])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext = make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	return iv, ciphertext, cbcHS256Tag(key[:16], aad, iv, ciphertext), nil
}

// cbcHS256Tag is the first half of HMAC-SHA-256 over AAD || IV || ciphertext
// || AL, where AL is the AAD length in bits as a 64-bit big-endian number
// (RFC 7518 §5.2.2.1).
func cbcHS256Tag(macKey, aad, iv, ciphertext []byte) []byte {
	var al [8]byte
	binary.BigEndian.PutUint64(al[:], uint64(len(aad)*8))
	mac := hmac.New(sha256.New, macKey)
	mac.Write(aad)
	mac.Write(iv)
	mac.Write(ciphertext)
	mac.Write(al[:])
	return mac.Sum(nil)[:16]
}

// pkcs7Pad pads to a whole number of blocks. Input that already is one gets a
// whole block of padding, so the padding is always removable.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}
