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

package demorp

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

// encodeTransactionData base64url-encodes the page's transaction data entries
// for the transaction_data parameter (OpenID4VP 1.0 §5.1). The verifier sends
// them as given, so a test can also send invalid entries.
func encodeTransactionData(entries []map[string]any) ([]oid4vp.TransactionData, error) {
	var out []oid4vp.TransactionData
	for i, entry := range entries {
		if entry == nil {
			return nil, fmt.Errorf("transaction_data[%d] must be a JSON object", i)
		}
		data, err := json.Marshal(entry)
		if err != nil {
			return nil, fmt.Errorf("transaction_data[%d]: %w", i, err)
		}
		out = append(out, oid4vp.NewTransactionData(format.EncodeBase64URL(data), entry))
	}
	return out, nil
}

func (r *requestState) responseMode() string {
	if r.dcAPIOrigin != "" {
		return "dc_api.jwt"
	}
	return "direct_post.jwt"
}

func (r *requestState) transactionDataParam() []string {
	raw := make([]string, 0, len(r.transactionData))
	for _, entry := range r.transactionData {
		raw = append(raw, entry.Raw)
	}
	return raw
}

// checkTransactionDataHashes checks the transaction_data_hashes of the Key
// Binding JWT for query queryID (OpenID4VP 1.0 Appendix B.3.3.1), marks the
// covered entries in bound and returns them. §5.1 lets only one credential
// authorize an entry, so an entry already covered by another presentation is
// refused.
func checkTransactionDataHashes(entries []oid4vp.TransactionData, queryID string, kb map[string]any, bound []bool) ([]oid4vp.TransactionData, error) {
	hashes, present := kb["transaction_data_hashes"]
	if !present {
		return nil, nil
	}
	got := jsonutil.Strings(hashes)
	if len(got) == 0 {
		return nil, fmt.Errorf("transaction_data_hashes must be a non-empty array of strings")
	}
	rawAlg, algPresent := kb["transaction_data_hashes_alg"]
	alg := "sha-256"
	if algPresent {
		var ok bool
		if alg, ok = rawAlg.(string); !ok {
			return nil, fmt.Errorf("transaction_data_hashes_alg must be a string")
		}
	}
	var covered []oid4vp.TransactionData
	for _, hash := range got {
		matches := func(entry oid4vp.TransactionData) bool {
			want, err := sdjwt.SDHash(entry.Raw, alg)
			return err == nil && want == hash && slices.Contains(entry.CredentialIDs, queryID)
		}
		i := -1
		for j, entry := range entries {
			if !bound[j] && matches(entry) {
				i = j
				break
			}
		}
		if i < 0 {
			if slices.ContainsFunc(entries, matches) {
				return nil, fmt.Errorf("the %s hash %s belongs to a transaction_data entry already authorized by another presentation", alg, hash)
			}
			return nil, fmt.Errorf("the %s hash %s matches no transaction_data entry for %s", alg, hash, queryID)
		}
		entry := entries[i]
		switch {
		case entry.HashAlgs != nil && !algPresent:
			return nil, fmt.Errorf("transaction_data[%d] has transaction_data_hashes_alg, but the key binding JWT has none", i)
		case entry.HashAlgs != nil && !slices.Contains(entry.HashAlgs, alg):
			return nil, fmt.Errorf("transaction_data[%d] accepts %s, but the key binding JWT uses %s", i, strings.Join(entry.HashAlgs, ", "), alg)
		case entry.HashAlgs == nil && alg != "sha-256":
			return nil, fmt.Errorf("transaction_data[%d] lists no algorithm, so the hash must use sha-256, but the key binding JWT uses %s", i, alg)
		}
		bound[i] = true
		covered = append(covered, entry)
	}
	return covered, nil
}

func hasTS12Type(entries []oid4vp.TransactionData) bool {
	return slices.ContainsFunc(entries, func(entry oid4vp.TransactionData) bool {
		return slices.Contains(oid4vp.TS12TransactionDataTypes, entry.Type)
	})
}

// amrMethods are the authentication categories and methods of EUDI TS12
// v1.0.1 §3.6.
var amrMethods = map[string][]string{
	"knowledge": {"pin_less_than_6_digits", "pin_6_or_more_digits", "passphrase_less_than_8_chars",
		"passphrase_8_to_11_chars", "passphrase_12_or_more_chars", "pattern", "other"},
	"possession": {"key_in_remote_wscd", "key_in_local_external_wscd", "key_in_local_internal_wscd",
		"key_in_local_native_wscd", "other"},
	"inherence": {"fingerprint_device", "fingerprint_external", "face_device", "face_external", "other"},
}

// checkTS12Claims checks the Key Binding JWT claims required by EUDI TS12
// v1.0.1 §3.6.
func checkTS12Claims(kb map[string]any, responseMode string) error {
	if jti, _ := kb["jti"].(string); jti == "" {
		return fmt.Errorf("the key binding JWT has no jti")
	}
	if got := kb["response_mode"]; got != responseMode {
		return fmt.Errorf("the key binding JWT has the response_mode %v, but the request used %s", got, responseMode)
	}
	amr, _ := kb["amr"].([]any)
	categories := map[string]bool{}
	for i, method := range amr {
		object, _ := method.(map[string]any)
		if len(object) != 1 {
			return fmt.Errorf("amr[%d] of the key binding JWT must be an object with one authentication category", i)
		}
		for category, value := range object {
			name, _ := value.(string)
			if !slices.Contains(amrMethods[category], name) {
				return fmt.Errorf("amr[%d] of the key binding JWT has %s: %v, but TS12 §3.6 does not define it", i, category, value)
			}
			categories[category] = true
		}
	}
	// §3.6: "The amr array SHALL contain at least two different objects
	// representing authentication categories."
	return errIf(len(categories) < 2, "the amr of the key binding JWT needs at least 2 authentication categories, and it has %d", len(categories))
}

// unboundTransactionData lists the entries not covered by any presentation.
func unboundTransactionData(bound []bool) error {
	var missing []string
	for i, ok := range bound {
		if !ok {
			missing = append(missing, fmt.Sprintf("transaction_data[%d]", i))
		}
	}
	return errIf(len(missing) > 0, "no key binding JWT carries the hash of %s", strings.Join(missing, ", "))
}
