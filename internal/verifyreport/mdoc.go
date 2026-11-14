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

package verifyreport

import (
	"crypto"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/validity"
	"github.com/eudi-dev/eudi-dev/v3/pkg/mdoc"
)

type MDOCResult struct {
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

// MDOC verifies the issuer signature of doc with pubKey and reports the
// validity of its MSO.
func MDOC(doc *mdoc.Document, pubKey crypto.PublicKey) *MDOCResult {
	result := &MDOCResult{DocType: doc.DocType}
	if doc.IssuerAuth != nil && doc.IssuerAuth.MSO != nil {
		mso := doc.IssuerAuth.MSO
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

	algorithm, err := doc.SignatureAlgorithm()
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	result.Algorithm = algorithm

	if err := mdoc.Verify(doc, pubKey); err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	result.SignatureValid = true
	return result
}
