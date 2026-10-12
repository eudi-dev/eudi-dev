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

package web

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/eudi-dev/eudi-dev/v2/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
)

type CheckResult struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "pass", "fail", "skipped"
	Detail string `json:"detail"`
	// NeedsNetwork marks a skipped check that needs a network lookup. The UI
	// requests it after offline decoding.
	NeedsNetwork bool `json:"needsNetwork,omitempty"`
}

// CheckSDJWTIntegrity checks digests in payload _sd arrays, array placeholders and nested
// disclosures.
func CheckSDJWTIntegrity(token *sdjwt.Token) CheckResult {
	if len(token.Disclosures) == 0 {
		return CheckResult{
			Name:   "integrity",
			Status: "skipped",
			Detail: "No disclosures to verify",
		}
	}

	// A disclosure can contain further digests, such as address fields within an
	// address disclosure.
	allDigests := collectDigests(token.Payload)
	for _, d := range token.Disclosures {
		collectDigestsRecursive(d.Value, allDigests)
	}

	matched := 0
	total := len(token.Disclosures)
	for _, d := range token.Disclosures {
		if allDigests[d.Digest] {
			matched++
		}
	}

	if matched == total {
		return CheckResult{
			Name:   "integrity",
			Status: "pass",
			Detail: fmt.Sprintf("%d/%d disclosure digests verified", matched, total),
		}
	}

	return CheckResult{
		Name:   "integrity",
		Status: "fail",
		Detail: fmt.Sprintf("%d/%d disclosure digests matched", matched, total),
	}
}

// CheckSDJWTType verifies the typ header parameter of the Issuer-signed JWT.
// draft-ietf-oauth-sd-jwt-vc-19 §2.2.1: "The Issuer MUST include the typ
// header parameter in the SD-JWT. The typ value MUST use dc+sd-jwt". A
// vc+sd-jwt token decodes but fails this check.
func CheckSDJWTType(token *sdjwt.Token) CheckResult {
	if err := sdjwt.ValidateVCType(token.Header); err != nil {
		return CheckResult{
			Name:   "type",
			Status: "fail",
			Detail: err.Error(),
		}
	}
	typ, _ := token.Header["typ"].(string)
	if typ == sdjwt.TypeSDJWTVCLegacy {
		return CheckResult{
			Name:   "type",
			Status: "fail",
			Detail: fmt.Sprintf("the typ header is %s, draft-ietf-oauth-sd-jwt-vc-19 §2.2.1 requires %s", typ, sdjwt.TypeSDJWTVC),
		}
	}
	return CheckResult{
		Name:   "type",
		Status: "pass",
		Detail: typ,
	}
}

func collectDigests(obj map[string]any) map[string]bool {
	result := make(map[string]bool)
	collectDigestsRecursive(obj, result)
	return result
}

func collectDigestsRecursive(val any, result map[string]bool) {
	switch v := val.(type) {
	case map[string]any:
		if sdArr, ok := v["_sd"].([]any); ok {
			for _, d := range sdArr {
				if s, ok := d.(string); ok {
					result[s] = true
				}
			}
		}
		// RFC 9901 §4.2.4.2: "The key MUST always be the string ... (three
		// dots). The value MUST be the digest of the Disclosure ... There MUST
		// NOT be any other keys in the object."
		if dots, ok := v["..."].(string); ok && len(v) == 1 {
			result[dots] = true
		}
		for _, child := range v {
			collectDigestsRecursive(child, result)
		}
	case []any:
		for _, item := range v {
			collectDigestsRecursive(item, result)
		}
	}
}

// CheckMDOCIntegrity hashes the complete IssuerSignedItem encodings and compares them
// with MSO.ValueDigests.
func CheckMDOCIntegrity(doc *mdoc.Document) CheckResult {
	if doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
		return CheckResult{
			Name:   "integrity",
			Status: "skipped",
			Detail: "No MSO available for digest verification",
		}
	}

	mso := doc.IssuerAuth.MSO
	if len(mso.ValueDigests) == 0 {
		return CheckResult{
			Name:   "integrity",
			Status: "skipped",
			Detail: "No value digests in MSO",
		}
	}

	hashFn := hashForAlgorithm(mso.DigestAlgorithm)
	if hashFn == nil {
		return CheckResult{
			Name:   "integrity",
			Status: "skipped",
			Detail: fmt.Sprintf("Unsupported digest algorithm: %s", mso.DigestAlgorithm),
		}
	}

	matched := 0
	total := 0
	for ns, items := range doc.NameSpaces {
		nsDigests, ok := mso.ValueDigests[ns]
		if !ok {
			continue
		}
		for _, item := range items {
			if len(item.RawCBOR) == 0 {
				continue
			}
			total++
			expected, ok := nsDigests[item.DigestID]
			if !ok {
				continue
			}

			h := hashFn()
			h.Write(item.RawCBOR)
			computed := h.Sum(nil)

			if bytes.Equal(computed, expected) {
				matched++
			}
		}
	}

	if total == 0 {
		return CheckResult{
			Name:   "integrity",
			Status: "skipped",
			Detail: "No claims with raw CBOR available for verification",
		}
	}

	if matched == total {
		return CheckResult{
			Name:   "integrity",
			Status: "pass",
			Detail: fmt.Sprintf("%d/%d claim digests verified", matched, total),
		}
	}

	return CheckResult{
		Name:   "integrity",
		Status: "fail",
		Detail: fmt.Sprintf("%d/%d claim digests matched", matched, total),
	}
}

func hashForAlgorithm(alg string) func() hash.Hash {
	switch alg {
	case "SHA-256":
		return sha256.New
	case "SHA-384":
		return sha512.New384
	case "SHA-512":
		return sha512.New
	default:
		return nil
	}
}
