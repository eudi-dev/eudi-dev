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

// Package jws signs credentials, presentations, trust lists, status lists,
// metadata and attestations with one ES256 implementation.
package jws

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
)

// AlgES256 is the JWS algorithm of every signature this tool makes.
const AlgES256 = "ES256"

// RegisteredClaims are the registered claim names of RFC 7519 §4.1.
var RegisteredClaims = []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}

// SigningInput returns the base64url header and payload joined by a dot. A JWS
// signature is computed over these bytes.
func SigningInput(header map[string]any, payload any) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling header: %w", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling payload: %w", err)
	}
	return format.EncodeBase64URL(headerJSON) + "." + format.EncodeBase64URL(payloadJSON), nil
}

// Sign returns the compact serialization of header and payload signed with
// key. The payload can be a map or any JSON-marshalable value.
func Sign(header map[string]any, payload any, key *ecdsa.PrivateKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("signing requires a private key")
	}
	signingInput, err := SigningInput(header, payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := Signature(key, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + format.EncodeBase64URL(sig), nil
}

// Signature signs a digest and returns r and s in the fixed width form of
// JOSE and COSE (RFC 7518 §3.4). crypto/ecdsa returns integers of varying byte
// length, so both are left padded to the curve size.
func Signature(key *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("signing requires a private key")
	}
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*size)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])
	return sig, nil
}
