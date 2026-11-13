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
	"fmt"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
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
	if delegateFormat != sdjwt.FormatDelegate && delegateFormat != sdjwt.FormatDelegateKB {
		list = append(list, findings.DelegateSDJWT.Protocol("§7.1").Newf("format of %s must be %s or %s", label, sdjwt.FormatDelegate, sdjwt.FormatDelegateKB))
	}
	if value, present := e.Data["delegate_disclosures"]; present && jsonutil.Strings(value) == nil {
		list = append(list, findings.DelegateSDJWT.Protocol("§7.1").Newf("delegate_disclosures of %s must be an array of strings", label))
	}
	delegation, ok := e.Delegation()
	if !ok {
		return append(list, findings.DelegateSDJWT.Protocol("§7.1").Newf("%s has no delegate_payload_disclosure string", label))
	}
	inspection, err := sdjwt.InspectDelegatePayload(delegation.PayloadDisclosure, delegation.Disclosures, sdAlg)
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
	if delegateFormat == sdjwt.FormatDelegateKB && jsonutil.GetMap(inspection.Claims, "cnf") == nil {
		list = append(list, findings.DelegateSDJWT.Protocol("§5.1.4").Newf("%s asks for a %s, but its delegate payload has no cnf claim", label, sdjwt.FormatDelegateKB))
	}
	return list
}

// DelegatePayload is the decoded Delegate Payload of a delegate entry. It is
// nil when the entry has none.
func (e TransactionData) DelegatePayload() map[string]any {
	delegation, ok := e.Delegation()
	if !ok {
		return nil
	}
	inspection, err := sdjwt.InspectDelegatePayload(delegation.PayloadDisclosure, delegation.Disclosures, e.PreferredHashAlg())
	if err != nil {
		return nil
	}
	return inspection.Claims
}

// DelegateSummary describes a Delegate Payload in one sentence. It shows the
// receiving key and when the delegation ends. It is empty without a payload.
func DelegateSummary(payload map[string]any) string {
	if payload == nil {
		return ""
	}
	summary := "Delegate this credential"
	if jwk := jsonutil.GetMap(jsonutil.GetMap(payload, "cnf"), "jwk"); jwk != nil {
		if thumbprint, err := keys.Thumbprint(jwk); err == nil {
			summary += " to the key " + format.EncodeBase64URL(thumbprint)
		}
	}
	if exp, ok := jsonutil.GetFloat64(payload, "exp"); ok {
		summary += fmt.Sprintf(" until %s", time.Unix(int64(exp), 0).UTC().Format("2006-01-02 15:04 UTC"))
	}
	return summary
}
