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

// Package verifyreport verifies a credential signature and reports the outcome
// in the shape of the validate --json document.
package verifyreport

import (
	"crypto"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/validity"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt"
)

type SDJWTResult struct {
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

func SDJWT(token *sdjwt.Token, pubKey crypto.PublicKey) *SDJWTResult {
	result := &SDJWTResult{
		KeyID:     jsonutil.GetString(token.Header, "kid"),
		Algorithm: jsonutil.GetString(token.Header, "alg"),
		Issuer:    jsonutil.GetString(token.Payload, "iss"),
	}

	now := time.Now()
	if exp, ok := jsonutil.GetFloat64(token.Payload, "exp"); ok {
		t := time.Unix(int64(exp), 0)
		result.ExpiresAt = &t
		result.Expired = validity.Expired(&t, now)
	}
	// A PID discloses iat (CIR (EU) 2024/2977 Annex section 4.2, as replaced
	// by CIR (EU) 2026/1731), so iat falls back to the resolved claims.
	iat, ok := jsonutil.GetFloat64(token.Payload, "iat")
	if !ok {
		iat, ok = jsonutil.GetFloat64(token.ResolvedClaims, "iat")
	}
	if ok {
		t := time.Unix(int64(iat), 0)
		result.IssuedAt = &t
	}
	if nbf, ok := jsonutil.GetFloat64(token.Payload, "nbf"); ok {
		t := time.Unix(int64(nbf), 0)
		result.NotBefore = &t
		result.NotYetValid = validity.NotYet(&t, now)
	}

	if err := sdjwt.Verify(token, pubKey); err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	result.SignatureValid = true
	return result
}
