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

package mdoc

import (
	"crypto"
	"fmt"
	"time"

	"github.com/veraison/go-cose"

	"github.com/dominikschlosser/eudi-dev/v3/internal/validity"
)

// VerifyResult uses the camelCase keys of the validate --json document.
type VerifyResult struct {
	SignatureValid bool       `json:"signatureValid"`
	Expired        bool       `json:"expired"`
	NotYetValid    bool       `json:"notYetValid"`
	Algorithm      string     `json:"algorithm,omitempty"`
	DocType        string     `json:"docType,omitempty"`
	ValidFrom      *time.Time `json:"validFrom,omitempty"`
	ValidUntil     *time.Time `json:"validUntil,omitempty"`
	Signed         *time.Time `json:"signed,omitempty"`
	Errors         []string   `json:"errors,omitempty"`
	// Warnings list spec deviations that signature verification accepted.
	Warnings []string `json:"warnings,omitempty"`
}

func Verify(doc *Document, pubKey crypto.PublicKey) *VerifyResult {
	if doc == nil {
		return &VerifyResult{Errors: []string{"no document to verify"}}
	}

	result := &VerifyResult{
		DocType: doc.DocType,
	}

	if doc.IssuerAuth == nil {
		result.Errors = append(result.Errors, "no issuerAuth found")
		return result
	}

	mso := doc.IssuerAuth.MSO
	if mso != nil {
		if mso.DigestAlgorithm == "" {
			// ISO 18013-5 requires digestAlgorithm. Digest verification assumes SHA-256.
			result.Warnings = append(result.Warnings, "the MSO carries no digestAlgorithm, which ISO 18013-5 requires (assuming SHA-256)")
		}
		if mso.ValidityInfo != nil {
			result.ValidFrom = mso.ValidityInfo.ValidFrom
			result.ValidUntil = mso.ValidityInfo.ValidUntil
			result.Signed = mso.ValidityInfo.Signed

			now := time.Now()
			result.Expired = validity.Expired(mso.ValidityInfo.ValidUntil, now)
			result.NotYetValid = validity.NotYet(mso.ValidityInfo.ValidFrom, now)
		}
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(doc.IssuerAuth.RawCOSE); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("parsing COSE_Sign1: %v", err))
		return result
	}
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		result.Errors = append(result.Errors, "cannot determine COSE algorithm from protected header")
		return result
	}
	result.Algorithm = COSEAlgorithmName(alg)

	verifier, err := NewCOSEVerifier(alg, pubKey)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("creating verifier: %v", err))
		return result
	}

	if err := msg.Verify(nil, verifier); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("signature verification failed: %v", err))
		return result
	}

	result.SignatureValid = true
	return result
}
