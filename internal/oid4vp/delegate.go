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

package oid4vp

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/delegatepayload"
	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt/delegate"
)

// DelegateTransactionDataType is the transaction data type of
// draft-ietf-oauth-delegate-sd-jwt-00 §7.1. The wallet answers it with a
// Delegate SD-JWT.
const DelegateTransactionDataType = "delegate"

// Delegation holds the members that §7.1 adds to a delegate entry.
type Delegation struct {
	// Format is dSD-JWT or dSD-JWT+KB.
	Format string
	// PayloadDisclosure is delegate_payload_disclosure as received.
	PayloadDisclosure string
	// Disclosures is delegate_disclosures as received.
	Disclosures []string
}

// Delegation reads a delegate entry. ok is false for another type and for an
// entry without a delegate_payload_disclosure string.
func (e TransactionData) Delegation() (delegation Delegation, ok bool) {
	disclosure, _ := e.Data["delegate_payload_disclosure"].(string)
	if e.Type != DelegateTransactionDataType || disclosure == "" {
		return Delegation{}, false
	}
	return Delegation{
		Format:            jsonutil.GetString(e.Data, "format"),
		PayloadDisclosure: disclosure,
		Disclosures:       jsonutil.Strings(e.Data["delegate_disclosures"]),
	}, true
}

// PreferredHashAlg is the hash algorithm for the entry when it is the only
// entry in a presentation.
func (e TransactionData) PreferredHashAlg() string {
	return TransactionDataHashAlg([]TransactionData{e})
}

// DelegateFindings checks a delegate entry against §7.1. sdAlg is the _sd_alg
// of the KB-SD-JWT. §7.1: "_sd_alg may use any hash algorithm specified for
// hashing the transaction_data." The digests inside the Delegate Payload must
// match under it.
func (e TransactionData) DelegateFindings(sdAlg string) findings.List {
	label := e.Label()
	var list findings.List
	delegateFormat, _ := e.Data["format"].(string)
	if delegateFormat != delegate.FormatDSDJWT && delegateFormat != delegate.FormatDSDJWTKB {
		list = append(list, findings.DelegateSDJWT.Protocol("§7.1").Newf("format of %s must be %s or %s", label, delegate.FormatDSDJWT, delegate.FormatDSDJWTKB))
	}
	if value, present := e.Data["delegate_disclosures"]; present && jsonutil.Strings(value) == nil {
		list = append(list, findings.DelegateSDJWT.Protocol("§7.1").Newf("delegate_disclosures of %s must be an array of strings", label))
	}
	delegation, ok := e.Delegation()
	if !ok {
		return append(list, findings.DelegateSDJWT.Protocol("§7.1").Newf("%s has no delegate_payload_disclosure string", label))
	}
	inspection, err := inspectDelegatePayload(delegation.PayloadDisclosure, delegation.Disclosures, sdAlg)
	if err != nil {
		return append(list, findings.DelegateSDJWT.Protocol("§5.1.3").Newf("%s: %v", label, err))
	}
	// §7.1: "The delegate payload MUST NOT contain any disclosures not
	// provided in delegate_disclosures."
	for _, digest := range inspection.MissingDigests {
		list = append(list, findings.DelegateSDJWT.Protocol("§7.1").Newf("the Delegate Payload of %s contains the %s digest %s, but delegate_disclosures has no disclosure for it", label, sdAlg, digest))
	}
	// A verifier rejects the chain for such a disclosure (RFC 9901 §7.1 step 5).
	for _, index := range inspection.Unreferenced {
		list = append(list, findings.RFC(9901).Protocol("§7.1").Newf("delegate_disclosures[%d] of %s does not match any %s digest in the Delegate Payload", index, label, sdAlg))
	}
	// §5.1.4: "If the typ is KB-SD-JWT+KB then the Delegate Payload MUST
	// include a cnf claim."
	if delegateFormat == delegate.FormatDSDJWTKB && jsonutil.GetMap(inspection.Claims, "cnf") == nil {
		list = append(list, findings.DelegateSDJWT.Protocol("§5.1.4").Newf("%s asks for a %s, but its Delegate Payload has no cnf claim", label, delegate.FormatDSDJWTKB))
	}
	// RFC 7519 §4.1.4: exp is a NumericDate. The wallet stores it as a time
	// in RFC 3339, which ends at the year 9999.
	if value, present := inspection.Claims["exp"]; present {
		if exp, isNumber := value.(float64); !isNumber || exp < 0 || exp > delegatepayload.MaxNumericDate {
			list = append(list, findings.RFC(7519).Protocol("§4.1.4").Newf("the exp of the Delegate Payload of %s must be a NumericDate from 0 to %d", label, delegatepayload.MaxNumericDate))
		}
	}
	return list
}

// delegatePayloadInspection is the result of inspectDelegatePayload.
type delegatePayloadInspection struct {
	// Claims is the Delegate Payload with its Disclosures applied.
	Claims map[string]any
	// MissingDigests are the digests in the Delegate Payload without a
	// Disclosure.
	MissingDigests []string
	// Unreferenced are the positions of the Disclosures without a digest in
	// the Delegate Payload.
	Unreferenced []int
}

// inspectDelegatePayload decodes a Delegate Payload Disclosure and matches it
// with disclosures under sdAlg. §5.1.3: "The delegate payload disclosure is an
// Array disclosure, which is the base64url encoding of [salt, JSON Object
// Payload]."
//
// It reads the payload in its KB-SD-JWT form, as an unsigned SD-JWT with
// delegate_payload as its only claim.
func inspectDelegatePayload(payloadDisclosure string, disclosures []string, sdAlg string) (*delegatePayloadInspection, error) {
	decoded, err := format.DecodeBase64URL(payloadDisclosure)
	if err != nil {
		return nil, fmt.Errorf("delegate_payload_disclosure does not decode: %w", err)
	}
	var elements []any
	if err := json.Unmarshal(decoded, &elements); err != nil {
		return nil, fmt.Errorf("delegate_payload_disclosure does not decode: %w", err)
	}
	if len(elements) != 2 {
		return nil, fmt.Errorf("delegate_payload_disclosure must decode to [salt, JSON object]")
	}
	if _, isObject := elements[1].(map[string]any); !isObject {
		return nil, fmt.Errorf("delegate_payload_disclosure must decode to [salt, JSON object]")
	}
	payloadDigest, err := sdjwt.SDHash(payloadDisclosure, sdAlg)
	if err != nil {
		return nil, err
	}
	header, _ := json.Marshal(map[string]any{"alg": "none"})
	payload, _ := json.Marshal(map[string]any{
		"_sd_alg": sdAlg, "delegate_payload": []any{map[string]any{"...": payloadDigest}},
	})
	components := append([]string{format.EncodeBase64URL(header) + "." + format.EncodeBase64URL(payload) + ".", payloadDisclosure}, disclosures...)
	token, err := sdjwt.ParseLenient(strings.Join(components, "~") + "~")
	if err != nil {
		return nil, fmt.Errorf("the disclosures of the Delegate Payload do not decode: %w", err)
	}

	inspection := &delegatePayloadInspection{}
	referenced := sdjwt.ReferencedDigests(token)
	delete(referenced, payloadDigest)
	for i, disclosure := range token.Disclosures[1:] {
		if !referenced[disclosure.Digest] {
			inspection.Unreferenced = append(inspection.Unreferenced, i)
		}
		delete(referenced, disclosure.Digest)
	}
	inspection.MissingDigests = slices.Sorted(maps.Keys(referenced))
	if disclosed, _ := token.ResolvedClaims["delegate_payload"].([]any); len(disclosed) == 1 {
		inspection.Claims, _ = disclosed[0].(map[string]any)
	}
	return inspection, nil
}

// DelegatePayload is the decoded Delegate Payload of a delegate entry. It is
// nil when the entry has none.
func (e TransactionData) DelegatePayload() map[string]any {
	delegation, ok := e.Delegation()
	if !ok {
		return nil
	}
	inspection, err := inspectDelegatePayload(delegation.PayloadDisclosure, delegation.Disclosures, e.PreferredHashAlg())
	if err != nil {
		return nil
	}
	return inspection.Claims
}
