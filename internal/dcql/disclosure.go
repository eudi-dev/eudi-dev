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

package dcql

import (
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

// alwaysDisclosed returns the keys that every presentation of cred sends. A
// jwt_vc_json credential is presented whole (OpenID4VP 1.0 Appendix B.1). An
// SD-JWT claim that needs none of the credential's disclosures is in the
// issuer-signed payload (RFC 9901 §4.1). An mdoc has no such claims, because
// each data element is selected on its own.
func alwaysDisclosed(cred Credential, keys []string) []string {
	var out []string
	switch cred.Format {
	case credtype.FormatJWTVC:
		for _, key := range keys {
			if _, ok := claimValueBySelector(cred, key); ok {
				out = append(out, key)
			}
		}
	case credtype.FormatSDJWT:
		_, payload, _, err := format.ParseJWTParts(strings.Split(cred.Raw, "~")[0])
		if err != nil {
			return nil
		}
		digestMap := make(map[string]*sdjwt.Disclosure, len(cred.Disclosures))
		for i := range cred.Disclosures {
			digestMap[cred.Disclosures[i].Digest] = &cred.Disclosures[i]
		}
		for _, key := range keys {
			path, ok := ParseSDJWTSelector(key)
			if !ok || len(path) == 0 {
				continue
			}
			if _, ok := claimValueBySelector(cred, key); !ok {
				continue
			}
			digests := map[string]bool{}
			CollectPathDisclosureDigests(payload, path, digestMap, digests)
			if !heldDisclosure(digests, digestMap) {
				out = append(out, key)
			}
		}
	}
	return out
}

// heldDisclosure reports whether one of digests belongs to a disclosure of the
// credential. Other digests are decoys (RFC 9901 §4.2.5).
func heldDisclosure(digests map[string]bool, digestMap map[string]*sdjwt.Disclosure) bool {
	for digest := range digests {
		if digestMap[digest] != nil {
			return true
		}
	}
	return false
}

func collectAllNestedDisclosureDigests(value any, digestMap map[string]*sdjwt.Disclosure, digests map[string]bool) {
	switch v := value.(type) {
	case map[string]any:
		if sdArr, ok := v["_sd"].([]any); ok {
			for _, item := range sdArr {
				digest, ok := item.(string)
				if !ok {
					continue
				}
				digests[digest] = true
				if disc := digestMap[digest]; disc != nil {
					collectAllNestedDisclosureDigests(disc.Value, digestMap, digests)
				}
			}
		}
		for k, item := range v {
			if k == "_sd" {
				continue
			}
			collectAllNestedDisclosureDigests(item, digestMap, digests)
		}
	case []any:
		for _, item := range v {
			if obj, ok := item.(map[string]any); ok {
				if _, ok := obj["..."].(string); ok {
					// OID4VP 1.0 §7.1 selects array elements with a null or an
					// index. §6.4 forbids sending unselected claims.
					// An unselected disclosable element stays undisclosed. A path
					// that ends at the array discloses none of its elements.
					continue
				}
			}
			collectAllNestedDisclosureDigests(item, digestMap, digests)
		}
	}
}

func CollectPathDisclosureDigests(value any, path []any, digestMap map[string]*sdjwt.Disclosure, digests map[string]bool) {
	if len(path) == 0 {
		collectAllNestedDisclosureDigests(value, digestMap, digests)
		return
	}

	switch segment := path[0].(type) {
	case string:
		obj, ok := value.(map[string]any)
		if !ok {
			return
		}
		if next, ok := obj[segment]; ok {
			CollectPathDisclosureDigests(next, path[1:], digestMap, digests)
			return
		}
		if sdArr, ok := obj["_sd"].([]any); ok {
			for _, item := range sdArr {
				digest, ok := item.(string)
				if !ok {
					continue
				}
				disc := digestMap[digest]
				if disc == nil || disc.IsArrayEntry || disc.Name != segment {
					continue
				}
				digests[digest] = true
				CollectPathDisclosureDigests(disc.Value, path[1:], digestMap, digests)
			}
		}
	case int:
		arr, ok := value.([]any)
		if !ok || segment < 0 || segment >= len(arr) {
			return
		}
		collectArrayItemDisclosureDigests(arr[segment], path[1:], digestMap, digests)
	case nil:
		arr, ok := value.([]any)
		if !ok {
			return
		}
		for _, item := range arr {
			collectArrayItemDisclosureDigests(item, path[1:], digestMap, digests)
		}
	}
}

func collectArrayItemDisclosureDigests(item any, path []any, digestMap map[string]*sdjwt.Disclosure, digests map[string]bool) {
	if ref, ok := item.(map[string]any); ok {
		if digest, ok := ref["..."].(string); ok {
			digests[digest] = true
			if disc := digestMap[digest]; disc != nil {
				CollectPathDisclosureDigests(disc.Value, path, digestMap, digests)
			}
			return
		}
	}
	CollectPathDisclosureDigests(item, path, digestMap, digests)
}
