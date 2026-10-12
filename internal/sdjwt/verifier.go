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
	"crypto"
	"fmt"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/validity"
)

// ErrSignatureInvalid is recorded by Verify when the signature does not verify
// with the key.
const ErrSignatureInvalid = "signature verification failed"

// VerifyResult uses the camelCase keys of the validate --json document.
type VerifyResult struct {
	SignatureValid bool       `json:"signatureValid"`
	Expired        bool       `json:"expired"`
	NotYetValid    bool       `json:"notYetValid"`
	Algorithm      string     `json:"algorithm,omitempty"`
	KeyID          string     `json:"keyId,omitempty"`
	Issuer         string     `json:"issuer,omitempty"`
	ExpiresAt      *time.Time `json:"expiresAt,omitempty"`
	IssuedAt       *time.Time `json:"issuedAt,omitempty"`
	NotBefore      *time.Time `json:"notBefore,omitempty"`
	Errors         []string   `json:"errors,omitempty"`
}

func Verify(token *Token, pubKey crypto.PublicKey) *VerifyResult {
	result := &VerifyResult{}

	result.KeyID = jsonutil.GetString(token.Header, "kid")
	result.Algorithm = jsonutil.GetString(token.Header, "alg")
	result.Issuer = jsonutil.GetString(token.Payload, "iss")

	now := time.Now()
	if exp, ok := jsonutil.GetFloat64(token.Payload, "exp"); ok {
		t := time.Unix(int64(exp), 0)
		result.ExpiresAt = &t
		result.Expired = validity.Expired(&t, now)
	}
	if iat, ok := jsonutil.GetFloat64(token.Payload, "iat"); ok {
		t := time.Unix(int64(iat), 0)
		result.IssuedAt = &t
	}
	if nbf, ok := jsonutil.GetFloat64(token.Payload, "nbf"); ok {
		t := time.Unix(int64(nbf), 0)
		result.NotBefore = &t
		result.NotYetValid = validity.NotYet(&t, now)
	}

	jwtRaw := strings.SplitN(token.Raw, "~", 2)[0]
	if strings.Count(jwtRaw, ".") != 2 {
		result.Errors = append(result.Errors, "invalid JWT structure")
		return result
	}

	if !isSupportedAlgorithm(result.Algorithm) {
		result.Errors = append(result.Errors, fmt.Sprintf("unsupported algorithm: %s", result.Algorithm))
		return result
	}

	result.SignatureValid = jws.Valid(jwtRaw, pubKey)
	if !result.SignatureValid {
		result.Errors = append(result.Errors, ErrSignatureInvalid)
	}

	return result
}

// isSupportedAlgorithm lets callers report an unsupported algorithm before verification.
func isSupportedAlgorithm(alg string) bool {
	for _, supported := range jws.SupportedAlgorithms {
		if string(supported) == alg {
			return true
		}
	}
	return false
}
