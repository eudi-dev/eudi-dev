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

package typemetadata

import (
	"fmt"

	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

// node is a claim selected by a path in the SD-JWT as issued.
type node struct {
	value any
	// sd marks a claim that is itself a Disclosure. A claim inside a
	// disclosed object is not selectively disclosable on its own (§5.6).
	sd bool
	// undisclosed marks an array element without a Disclosure. It was issued
	// and is selectively disclosable, but its contents are unknown.
	undisclosed bool
}

// Validate checks an SD-JWT VC against the claim metadata (§5.6). payload is
// the issuer-signed JWT payload and disclosures are all Disclosures of the
// credential, so the holder sees every issued claim. Each problem fails the
// validation (§5.7).
func (m *Metadata) Validate(payload map[string]any, disclosures []sdjwt.Disclosure) findings.List {
	return m.validate(payload, disclosures, true)
}

// ValidatePresentation checks a presented SD-JWT VC. A verifier can't tell an
// undisclosed claim from a missing one, so it skips the mandatory check
// (§5.6.3).
func (m *Metadata) ValidatePresentation(payload map[string]any, disclosures []sdjwt.Disclosure) findings.List {
	return m.validate(payload, disclosures, false)
}

func (m *Metadata) validate(payload map[string]any, disclosures []sdjwt.Disclosure, mandatory bool) findings.List {
	byDigest := make(map[string]sdjwt.Disclosure, len(disclosures))
	for _, d := range disclosures {
		byDigest[d.Digest] = d
	}
	var problems findings.List
	for _, claim := range m.Claims {
		name := PathString(claim.Path)
		selected, err := selectIssued(payload, claim.Path, byDigest)
		if err != nil {
			problems = append(problems, findings.SDJWTVC.Protocol("§5.6.1.2").Newf("the claim path %s: %v", name, err))
			continue
		}
		if mandatory && claim.Mandatory != nil && *claim.Mandatory && len(selected) == 0 {
			problems = append(problems, findings.SDJWTVC.Protocol("§5.6.3").Newf("the mandatory claim %s is missing", name))
		}
		if violatesSD(claim.SD, selected) {
			problems = append(problems, findings.SDJWTVC.Protocol("§5.6.4").Newf("the claim %s has sd %q, and the credential does not follow it", name, claim.SD))
		}
	}
	return problems
}

func violatesSD(sd string, selected []node) bool {
	for _, n := range selected {
		if (sd == SDAlways && !n.sd) || (sd == SDNever && n.sd) {
			return true
		}
	}
	return false
}

// selectIssued processes a claim path (§5.6.1.2) against the SD-JWT as
// issued. Array indexes count elements that are not disclosed.
func selectIssued(payload map[string]any, path []any, byDigest map[string]sdjwt.Disclosure) ([]node, error) {
	current := []node{{value: payload}}
	for _, component := range path {
		var next []node
		for _, n := range current {
			if n.undisclosed {
				continue
			}
			switch c := component.(type) {
			case string:
				object, ok := n.value.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("%q selects a key in a value that is not an object", c)
				}
				if value, ok := object[c]; ok {
					next = append(next, node{value: value})
				} else if d, ok := disclosedProperty(object, c, byDigest); ok {
					next = append(next, node{value: d.Value, sd: true})
				}
			case nil:
				array, ok := n.value.([]any)
				if !ok {
					return nil, fmt.Errorf("null selects the elements of a value that is not an array")
				}
				for _, item := range array {
					next = append(next, element(item, byDigest))
				}
			case float64:
				array, ok := n.value.([]any)
				if !ok {
					return nil, fmt.Errorf("%v selects an element of a value that is not an array", c)
				}
				if i := int(c); i < len(array) {
					next = append(next, element(array[i], byDigest))
				}
			}
		}
		current = next
	}
	return current, nil
}

func disclosedProperty(object map[string]any, name string, byDigest map[string]sdjwt.Disclosure) (sdjwt.Disclosure, bool) {
	digests, _ := object["_sd"].([]any)
	for _, digest := range digests {
		text, _ := digest.(string)
		if d, ok := byDigest[text]; ok && !d.IsArrayEntry && d.Name == name {
			return d, true
		}
	}
	return sdjwt.Disclosure{}, false
}

// element resolves an array element. RFC 9901 §4.2.4.2 writes a selectively
// disclosable element as {"...": "<digest>"}.
func element(item any, byDigest map[string]sdjwt.Disclosure) node {
	placeholder, ok := item.(map[string]any)
	if !ok || len(placeholder) != 1 {
		return node{value: item}
	}
	digest, ok := placeholder["..."].(string)
	if !ok {
		return node{value: item}
	}
	if d, ok := byDigest[digest]; ok && d.IsArrayEntry {
		return node{value: d.Value, sd: true}
	}
	return node{sd: true, undisclosed: true}
}
