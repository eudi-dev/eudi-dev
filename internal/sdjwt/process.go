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
	"fmt"
	"sort"
)

// processor holds the state for RFC 9901 §7.1 step 3. It walks the
// Issuer-signed JWT payload and every Disclosure value reached from it.
type processor struct {
	byDigest map[string]*Disclosure
	// seen records every embedded digest in the credential, for step 4.
	seen map[string]bool
	// used records the digests that resolved to a Disclosure, for step 5.
	used map[string]bool
	// deviations holds recoverable violations. Lenient parsing continues past them
	// and strict parsing rejects them.
	deviations []string
	// A repeated digest is reported once, even when many claims are mirrored.
	reportedDuplicateDigest bool
}

// processPayload resolves claims under RFC 9901 §7.1 steps 3 to 5 and records
// recoverable violations. Parse rejects every violation. Lenient callers inspect the
// remaining claims.
func processPayload(payload map[string]any, disclosures []Disclosure) (map[string]any, []string, error) {
	p := &processor{
		byDigest: make(map[string]*Disclosure, len(disclosures)),
		seen:     make(map[string]bool),
		used:     make(map[string]bool),
	}
	for i := range disclosures {
		d := &disclosures[i]
		// RFC 9901 §4: "A Holder MUST NOT send a Disclosure that was not
		// included in the issued SD-JWT or send a Disclosure more than once."
		// The duplicate resolves to the same claim, so the extra copy is ignored.
		if _, duplicate := p.byDigest[d.Digest]; duplicate {
			p.deviations = append(p.deviations, fmt.Sprintf("disclosure %s is present more than once, so the extra copy is ignored", shortDigest(d.Digest)))
			continue
		}
		p.byDigest[d.Digest] = d
	}

	resolved := p.object(payload, true)

	// Step 5: "If any Disclosure was not referenced by digest value in the
	// Issuer-signed JWT (directly or recursively via other Disclosures), the
	// SD-JWT MUST be rejected." An unreferenced disclosure is never inserted,
	// so lenient parsing ignores it.
	for i := range disclosures {
		d := &disclosures[i]
		if !p.used[d.Digest] {
			p.deviations = append(p.deviations, fmt.Sprintf("disclosure %s (%s) is not referenced by any digest in the credential, so it is ignored", shortDigest(d.Digest), disclosureLabel(d)))
		}
	}

	return resolved, p.deviations, nil
}

// object processes one JSON object of the payload. It keeps the existing
// claims, inserts the claims disclosed by the digests in its "_sd" array and
// drops the "_sd" key (§7.1 steps 3.b.i, 3.c.ii and 3.e). top marks the
// SD-JWT payload, the only object where _sd_alg belongs.
// The object's own digests resolve before its nested values, and nested values
// resolve in key order, so the first occurrence of a repeated digest is the
// same on every run.
func (p *processor) object(obj map[string]any, top bool) map[string]any {
	result := make(map[string]any, len(obj))
	p.disclose(obj, result)

	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch k {
		case "_sd":
			// Step 3.e: "Remove all _sd keys and their contents from the
			// Issuer-signed JWT payload."
			continue
		case "_sd_alg":
			// RFC 9901 §7.1 step 3.f removes _sd_alg. Section 4.1.1 forbids nested
			// copies, so a nested copy is a deviation.
			if !top {
				p.deviations = append(p.deviations, "_sd_alg is inside a nested object. RFC 9901 §4.1.1 allows it only at the top level.")
			}
			continue
		}
		result[k] = p.value(obj[k])
	}
	return result
}

// disclose inserts into result the claims that the "_sd" array of obj discloses.
func (p *processor) disclose(obj map[string]any, result map[string]any) {
	rawSD, present := obj["_sd"]
	if !present {
		return
	}
	// RFC 9901 §4.2.4.1: "The _sd key MUST refer to an array of strings, each
	// string being a digest of a Disclosure or a decoy digest".
	entries, ok := rawSD.([]any)
	if !ok {
		p.deviations = append(p.deviations, `the "_sd" value is not an array, which RFC 9901 §4.2.4.1 requires, so its disclosures are skipped`)
		return
	}

	for _, entry := range entries {
		digest, ok := entry.(string)
		if !ok {
			p.deviations = append(p.deviations, `an "_sd" array entry is not a string, which RFC 9901 §4.2.4.1 requires, so it is skipped`)
			continue
		}
		if !p.markSeen(digest) {
			continue
		}
		disc, found := p.byDigest[digest]
		if !found {
			// Step 3.c.i: "If no such Disclosure can be found, the digest
			// MUST be ignored." That covers decoy digests (§4.2.5) and
			// claims the Holder withheld.
			continue
		}
		if disc.IsArrayEntry {
			// Step 3.c.ii.1 wants three elements (salt, claim name, value) here.
			p.deviations = append(p.deviations, fmt.Sprintf("disclosure %s in an _sd array holds two elements, but RFC 9901 §7.1 expects three (salt, claim name, value), so it is skipped", shortDigest(digest)))
			continue
		}
		if disc.Name == "_sd" || disc.Name == "..." {
			// Step 3.c.ii.2: a disclosure MUST NOT be named _sd or ...
			p.deviations = append(p.deviations, fmt.Sprintf("disclosure %s discloses a claim named %q, which RFC 9901 §7.1 does not allow, so it is skipped", shortDigest(digest), disc.Name))
			continue
		}
		_, signed := obj[disc.Name]
		if _, disclosed := result[disc.Name]; signed || disclosed {
			// Step 3.c.ii.3: a disclosure MUST NOT redefine a claim that already
			// exists at this level, such as a signed vct. The existing value stays.
			p.deviations = append(p.deviations, fmt.Sprintf("disclosure %s discloses claim %q, which already exists at this level (RFC 9901 §7.1 does not let a disclosure redefine an existing claim), so the existing value stays", shortDigest(digest), disc.Name))
			continue
		}
		p.used[digest] = true
		// Step 3.c.ii.5 recurses into the disclosed value, then 3.c.ii.4 inserts
		// it under the claim name.
		result[disc.Name] = p.value(disc.Value)
	}
}

// array processes one JSON array. Each {"...": digest} placeholder becomes its
// disclosed value. A placeholder with no Disclosure is dropped (§7.1 steps
// 3.c.iii and 3.d).
func (p *processor) array(arr []any) []any {
	result := make([]any, 0, len(arr))

	for _, item := range arr {
		digest, isPlaceholder, err := arrayElementDigest(item)
		if err != nil {
			p.deviations = append(p.deviations, err.Error()+", so the element is dropped")
			continue
		}
		if !isPlaceholder {
			result = append(result, p.value(item))
			continue
		}

		if !p.markSeen(digest) {
			continue
		}
		disc, found := p.byDigest[digest]
		if !found {
			// Step 3.d: "Remove all array elements for which the digest was
			// not found in the previous step."
			continue
		}
		if !disc.IsArrayEntry {
			// Step 3.c.iii.1 wants two elements (salt, value) here.
			p.deviations = append(p.deviations, fmt.Sprintf("disclosure %s holds three elements but sits in an array element, where RFC 9901 §7.1 expects two (salt, value), so the element is dropped", shortDigest(digest)))
			continue
		}
		p.used[digest] = true
		// Step 3.c.iii.3 recurses into the value, then 3.c.iii.2 replaces the
		// array element with it.
		result = append(result, p.value(disc.Value))
	}

	return result
}

func (p *processor) value(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return p.object(val, false)
	case []any:
		return p.array(val)
	default:
		return v
	}
}

// markSeen records an embedded digest and reports whether it is the first
// occurrence. RFC 9901 §7.1 step 4: "If any digest value is encountered more
// than once in the Issuer-signed JWT payload (directly or recursively via other
// Disclosures), the SD-JWT MUST be rejected." Lenient parsing resolves only the
// first occurrence. Resolving every occurrence lets a few kilobytes of
// disclosures that reference each other twice per level expand exponentially.
func (p *processor) markSeen(digest string) bool {
	if p.seen[digest] {
		if !p.reportedDuplicateDigest {
			p.reportedDuplicateDigest = true
			p.deviations = append(p.deviations, "the same disclosure digest appears more than once, which RFC 9901 §4.1 does not allow, so only its first occurrence is resolved")
		}
		return false
	}
	p.seen[digest] = true
	return true
}

// arrayElementDigest returns the digest of an array element that is a digest
// placeholder. RFC 9901 §4.2.4.2: "For each digest, an object
// of the form {"...": "<digest>"} is added to the array. The key MUST always
// be the string ... (three dots). The value MUST be the digest of the
// Disclosure created as described in Section 4.2.3. There MUST NOT be any
// other keys in the object."
func arrayElementDigest(item any) (digest string, isPlaceholder bool, err error) {
	obj, isObject := item.(map[string]any)
	if !isObject {
		return "", false, nil
	}
	raw, present := obj["..."]
	if !present {
		return "", false, nil
	}
	if len(obj) != 1 {
		return "", false, fmt.Errorf(`array element carries a "..." key alongside %d other keys`, len(obj)-1)
	}
	value, isString := raw.(string)
	if !isString {
		return "", false, fmt.Errorf(`array element "..." does not refer to a string`)
	}
	return value, true, nil
}

// shortDigest keeps enough of a digest to find it in the payload.
func shortDigest(digest string) string {
	const shown = 12
	if len(digest) <= shown {
		return digest
	}
	return digest[:shown] + "..."
}

func disclosureLabel(d *Disclosure) string {
	if d.IsArrayEntry {
		return "array element"
	}
	return "claim " + d.Name
}
