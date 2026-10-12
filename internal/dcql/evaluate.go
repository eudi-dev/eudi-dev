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
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
)

// Credential is a stored credential as the matcher sees it.
type Credential struct {
	ID, Format, VCT, DocType, Raw string
	Claims                        map[string]any
	// Disclosures are the disclosures of an SD-JWT VC.
	Disclosures []sdjwt.Disclosure
	// Bound is set when the holder can prove holder binding: a KB-JWT for an
	// SD-JWT VC, deviceKey for an mdoc. A jwt_vc_json credential is presented
	// without a Verifiable Presentation, so it has none (OpenID4VP 1.0
	// Appendix B.1).
	Bound bool
	// IssuedAt orders renewed credentials first. A zero time sorts last.
	IssuedAt time.Time
}

// Options holds the wallet settings for evaluating a query.
type Options struct {
	// Strict answers only with matching credentials. Otherwise debug mode
	// also offers credentials that do not match, so verifiers can be tested
	// with wrong answers. They never become the automatic selection.
	Strict          bool
	PreferredFormat string
	// Anchors are the anchors of each etsi_tl trusted list by URL (§6.1.1.2).
	// A list without anchors matches nothing.
	Anchors map[string][]*x509.Certificate
	// Collapse reduces the matches before they are ordered, such as the copies
	// of one batch to one.
	Collapse func([]consent.Match) []consent.Match
}

// Evaluate matches credentials against a DCQL query (OID4VP 1.0 §6). It
// returns the matching credentials and the satisfiable set options for
// consent. The first candidate and option are the automatic selection.
//
// The request validation reports QueryFindings. Debug mode evaluates a query
// with findings as far as it can.
func Evaluate(query map[string]any, credentials []Credential, opts Options) ([]consent.Match, *consent.CredentialOptions) {
	credQueries, _ := query["credentials"].([]any)
	preferredFormat := opts.PreferredFormat

	log.Printf("[DCQL] Evaluating query: %d credential queries against %d stored credentials", len(credQueries), len(credentials))

	var matches []consent.Match
	// Debug mode offers credentials that do not match, so verifiers can be tested
	// with wrong answers. They never become the automatic selection.
	var nonMatching []consent.Match
	debug := !opts.Strict
	// Strict mode never presents an mdoc without deviceKey (ISO 18013-5 makes
	// deviceKeyInfo mandatory), so in strict mode such an mdoc matches no
	// query.
	strict := opts.Strict

	for _, cq := range credQueries {
		cqMap, ok := cq.(map[string]any)
		if !ok {
			continue
		}

		queryID, _ := cqMap["id"].(string)
		queryFormat, _ := cqMap["format"].(string)
		taList, _ := cqMap["trusted_authorities"].([]any)
		// Log skipped credentials by reason only when nothing matches.
		matched := 0
		skipped := make(map[string]int)

		for _, cred := range credentials {
			typeLabel := cred.VCT
			if typeLabel == "" {
				typeLabel = cred.DocType
			}

			var mismatches []string
			if !matchesFormat(cred, queryFormat) {
				skipped[fmt.Sprintf("format %s (want %s)", cred.Format, queryFormat)]++
				mismatches = append(mismatches, fmt.Sprintf("format %s, the query asks for %s", cred.Format, queryFormat))
			}
			if !matchesMeta(cred, cqMap) {
				skipped["meta mismatch"]++
				mismatches = append(mismatches, metaMismatch(cred, cqMap))
			}
			// Strict mode answers a query that requires binding only with a
			// bound credential. Debug mode offers an unbound one too, flagged
			// and after the bound ones.
			unbound := false
			switch {
			case cred.Bound:
			case requiresHolderBinding(cqMap) && debug:
				unbound = true
			case requiresHolderBinding(cqMap):
				skipped["no holder binding"]++
				mismatches = append(mismatches, "has no holder binding, and the query requires one")
			case strict && cred.Format == credtype.FormatMDOC:
				skipped["no deviceKey"]++
				mismatches = append(mismatches, "is an mdoc without deviceKey, which strict mode does not present")
			}

			selection := selectClaims(cred, cqMap)
			if len(mismatches) == 0 && len(selection.missingRequired) > 0 {
				if debug && len(selection.selectedKeys) > 0 {
					log.Printf("[DCQL] Warning: query=%s: credential %s (%s) missing required claims %v in debug mode, continuing with selected claims %v",
						queryID, typeLabel, cred.Format, selection.missingRequired, selection.selectedKeys)
				} else {
					skipped[fmt.Sprintf("required claims not found %v", selection.missingRequired)]++
					mismatches = append(mismatches, "lacks "+strings.Join(selection.missingRequired, ", "))
				}
			}
			if len(mismatches) == 0 && !selection.match {
				skipped["no requested claims matched"]++
				mismatches = append(mismatches, "satisfies none of the claim sets")
			}
			if len(mismatches) > 0 {
				if debug {
					nonMatching = append(nonMatching, consent.Match{
						QueryID:      queryID,
						CredentialID: cred.ID,
						Format:       cred.Format,
						VCT:          cred.VCT,
						DocType:      cred.DocType,
						Claims:       FilterClaims(cred, selection.selectedKeys),
						SelectedKeys: selection.selectedKeys,
						Mismatches:   mismatches,
					})
				}
				continue
			}

			untrustedAuthority := false
			if len(taList) > 0 {
				if !checkTrustedAuthorities(cred, taList, opts.Anchors) {
					if !debug {
						skipped["not trusted by any trusted_authority"]++
						continue
					}
					// Debug mode offers the credential anyway, flagged for the
					// consent dialog.
					untrustedAuthority = true
					log.Printf("[DCQL] Warning: query=%s: credential %s (%s) is not trusted by any trusted_authority, offered in debug mode",
						queryID, typeLabel, cred.Format)
				}
			}

			// §6.4.1: "the Wallet SHOULD return the first option that it can
			// satisfy". Debug mode lets the user choose another one.
			var claimSets []consent.ClaimSet
			if debug {
				if sets := satisfiableClaimSets(cred, cqMap); len(sets) > 1 {
					claimSets = sets
				}
			}

			if unbound {
				log.Printf("[DCQL] Warning: query=%s: credential %s (%s) has no holder binding, and the query requires one (OpenID4VP 1.0 §6.1). Offered in debug mode",
					queryID, typeLabel, cred.Format)
			}
			matched++
			log.Printf("[DCQL]   query=%s: credential %s (%s) matched, selected claims: %v", queryID, typeLabel, cred.Format, selection.selectedKeys)
			matches = append(matches, consent.Match{
				QueryID:            queryID,
				CredentialID:       cred.ID,
				Format:             cred.Format,
				VCT:                cred.VCT,
				DocType:            cred.DocType,
				Claims:             FilterClaims(cred, selection.selectedKeys),
				SelectedKeys:       selection.selectedKeys,
				UntrustedAuthority: untrustedAuthority,
				Unbound:            unbound,
				EmptyArrayClaims:   selection.emptyArrays,
				MissingClaims:      selection.missingRequired,
				ClaimSets:          claimSets,
			})
		}
		if matched == 0 {
			log.Printf("[DCQL]   query=%s: no match among %d credentials: %s", queryID, len(credentials), skipReasons(skipped))
		}
	}

	if opts.Collapse != nil {
		matches = opts.Collapse(matches)
		nonMatching = opts.Collapse(nonMatching)
	}
	sortMatchesNewestFirst(nonMatching, credentials)

	sortMatchesNewestFirst(matches, credentials)

	if preferredFormat != "" {
		sortMatchesByPreferredFormat(matches, preferredFormat)
	}

	sortMatchesTrustedFirst(matches)

	// Apply completeness last so a full claim match wins automatic selection.
	sortMatchesCompleteFirst(matches)

	// Keep candidates in preference order. The first per query becomes the automatic
	// choice.
	candidates := append([]consent.Match(nil), matches...)

	multiple := multipleQueries(credQueries)
	matches = keepOnePresentationPerQuery(matches, multiple)

	// OID4VP 1.0 §6.4.2: "If credential_sets is not provided, the Verifier
	// requests presentations for all Credentials in credentials to be
	// returned."
	credSets, _ := query["credential_sets"].([]any)
	if len(credSets) > 0 {
		log.Printf("[DCQL] Applying credential_sets constraints: %d sets, %d matches before", len(credSets), len(matches))
		matches = applyCredentialSets(matches, credSets, preferredFormat)
		if matches == nil {
			log.Printf("[DCQL] credential_sets: no option of any set can be satisfied, returning no credentials")
		} else {
			log.Printf("[DCQL] credential_sets: %d matches after filtering", len(matches))
		}
	} else if missing := unmatchedCredentialQueries(credQueries, matches); len(missing) > 0 {
		// §6.4.2: "If the Wallet cannot deliver all non-optional Credentials
		// requested by the Verifier according to these rules, it MUST NOT
		// return any Credential(s)." Without credential_sets every entry is
		// non-optional.
		log.Printf("[DCQL] Result: 0 matches (no credential answers %v, and every credential query is required without credential_sets)", missing)
		matches = nil
	}

	log.Printf("[DCQL] Result: %d matches", len(matches))
	if matches == nil && len(nonMatching) == 0 {
		return nil, nil
	}
	return matches, buildConsentCredentialOptions(candidates, nonMatching, credQueries, credSets, multiple, preferredFormat)
}

// multipleQueries returns the ids of the credential queries that set multiple
// (OID4VP 1.0 §6.1: "A boolean which indicates whether multiple Credentials can be
// returned for this Credential Query. If omitted, the default value is false").
func multipleQueries(credQueries []any) map[string]bool {
	multiple := map[string]bool{}
	for _, cq := range credQueries {
		cqMap, _ := cq.(map[string]any)
		if id, _ := cqMap["id"].(string); id != "" && cqMap["multiple"] == true {
			multiple[id] = true
		}
	}
	return multiple
}

// Preserve candidate order so the first credential and option remain the automatic
// selection.
func buildConsentCredentialOptions(candidates, nonMatching []consent.Match, credQueries, credSets []any, multiple map[string]bool, preferredFormat string) *consent.CredentialOptions {
	if len(candidates) == 0 && len(nonMatching) == 0 {
		return nil
	}
	byQuery := make(map[string][]consent.Match)
	var order []string
	for _, m := range candidates {
		if _, ok := byQuery[m.QueryID]; !ok {
			order = append(order, m.QueryID)
		}
		byQuery[m.QueryID] = append(byQuery[m.QueryID], m)
	}
	nonMatchingByQuery := make(map[string][]consent.Match)
	for _, m := range nonMatching {
		nonMatchingByQuery[m.QueryID] = append(nonMatchingByQuery[m.QueryID], m)
	}
	// Queries answered only by non-matching credentials come last, in request
	// order.
	for _, cq := range credQueries {
		cqMap, _ := cq.(map[string]any)
		id, _ := cqMap["id"].(string)
		if _, ok := byQuery[id]; !ok && len(nonMatchingByQuery[id]) > 0 && !slices.Contains(order, id) {
			order = append(order, id)
		}
	}

	options := &consent.CredentialOptions{}
	for _, id := range order {
		options.Queries = append(options.Queries, consent.QueryOptions{
			ID:          id,
			Multiple:    multiple[id],
			Candidates:  append([]consent.Match{}, byQuery[id]...),
			NonMatching: nonMatchingByQuery[id],
		})
	}
	answerable := make(map[string][]consent.Match, len(byQuery)+len(nonMatchingByQuery))
	for id, list := range byQuery {
		answerable[id] = list
	}
	for id, list := range nonMatchingByQuery {
		answerable[id] = append(answerable[id], list...)
	}

	for _, cs := range credSets {
		csMap, ok := cs.(map[string]any)
		if !ok {
			continue
		}
		required := true
		if r, ok := csMap["required"].(bool); ok {
			required = r
		}
		rawOptions, ok := csMap["options"].([]any)
		if !ok {
			continue
		}
		set := consent.SetOptions{Optional: !required}
		ordered := orderOptionsByPreferredFormat(rawOptions, byQuery, preferredFormat)
		for _, opt := range ordered {
			if ids, ok := satisfiableOption(opt, byQuery); ok {
				set.Options = append(set.Options, ids)
			}
		}
		// Options answered only by non-matching credentials come after the
		// satisfiable ones, so the automatic choice stays a matching option.
		for _, opt := range ordered {
			if _, ok := satisfiableOption(opt, byQuery); ok {
				continue
			}
			if ids, ok := satisfiableOption(opt, answerable); ok {
				set.Unmatched = append(set.Unmatched, len(set.Options))
				set.Options = append(set.Options, ids)
			}
		}
		if len(set.Options) > 0 {
			options.Sets = append(options.Sets, set)
		}
	}
	return options
}

func satisfiableOption(opt any, byQuery map[string][]consent.Match) ([]string, bool) {
	optArr, ok := opt.([]any)
	if !ok {
		return nil, false
	}
	ids := make([]string, 0, len(optArr))
	for _, qid := range optArr {
		qidStr, ok := qid.(string)
		if !ok {
			return nil, false
		}
		if _, has := byQuery[qidStr]; !has {
			return nil, false
		}
		ids = append(ids, qidStr)
	}
	return ids, true
}

func orderOptionsByPreferredFormat(options []any, byQuery map[string][]consent.Match, preferredFormat string) []any {
	if preferredFormat == "" {
		return options
	}
	queryFormat := make(map[string]string, len(byQuery))
	for qid, ms := range byQuery {
		if len(ms) > 0 {
			queryFormat[qid] = ms[0].Format
		}
	}
	ordered := make([]any, len(options))
	copy(ordered, options)
	sort.SliceStable(ordered, func(i, j int) bool {
		return optionMatchesFormat(ordered[i], queryFormat, preferredFormat) &&
			!optionMatchesFormat(ordered[j], queryFormat, preferredFormat)
	})
	return ordered
}

// Report malformed queries by array position when no query ID is available.
func unmatchedCredentialQueries(credQueries []any, matches []consent.Match) []string {
	matched := make(map[string]bool, len(matches))
	for _, m := range matches {
		matched[m.QueryID] = true
	}

	var missing []string
	for i, cq := range credQueries {
		cqMap, ok := cq.(map[string]any)
		if !ok {
			missing = append(missing, fmt.Sprintf("credentials[%d]", i))
			continue
		}
		id, _ := cqMap["id"].(string)
		if id == "" {
			missing = append(missing, fmt.Sprintf("credentials[%d]", i))
			continue
		}
		if !matched[id] {
			missing = append(missing, id)
		}
	}
	return missing
}

// Sort by issuance time so renewed credentials take precedence. Undated credentials
// come last and ties keep their order.
func sortMatchesNewestFirst(matches []consent.Match, credentials []Credential) {
	matched := make(map[string]bool, len(matches))
	for _, m := range matches {
		matched[m.CredentialID] = true
	}
	issued := make(map[string]time.Time, len(matches))
	for _, c := range credentials {
		if matched[c.ID] {
			issued[c.ID] = c.IssuedAt
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].QueryID != matches[j].QueryID {
			return false
		}
		a, b := issued[matches[i].CredentialID], issued[matches[j].CredentialID]
		if a.IsZero() != b.IsZero() {
			return b.IsZero()
		}
		return a.After(b)
	})
}

// Prefer credentials that match trusted_authorities. Preserve the existing order
// within matched and debug-only groups.
func sortMatchesTrustedFirst(matches []consent.Match) {
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].QueryID != matches[j].QueryID {
			return false
		}
		if matches[i].UntrustedAuthority != matches[j].UntrustedAuthority {
			return !matches[i].UntrustedAuthority
		}
		return !matches[i].Unbound && matches[j].Unbound
	})
}

// Prefer complete claim matches over partial matches allowed in debug mode. Apply this
// priority last.
func sortMatchesCompleteFirst(matches []consent.Match) {
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].QueryID != matches[j].QueryID {
			return false
		}
		return len(matches[i].MissingClaims) == 0 && len(matches[j].MissingClaims) > 0
	})
}

// keepOnePresentationPerQuery reduces the candidates for each query id to the
// one credential that will be presented. A query that sets multiple keeps every
// candidate. OID4VP 1.0 §8.1: "When multiple is omitted, or set to false, the
// array MUST contain only one Presentation."
func keepOnePresentationPerQuery(matches []consent.Match, multiple map[string]bool) []consent.Match {
	if len(matches) == 0 {
		return matches
	}
	seen := make(map[string]bool, len(matches))
	dropped := make(map[string]int)
	kept := matches[:0]
	for _, m := range matches {
		if seen[m.QueryID] && !multiple[m.QueryID] {
			dropped[m.QueryID]++
			continue
		}
		seen[m.QueryID] = true
		kept = append(kept, m)
	}
	for _, queryID := range slices.Sorted(maps.Keys(dropped)) {
		log.Printf("[DCQL]   query=%s: %d other candidates not presented: the query asks for one credential", queryID, dropped[queryID])
	}
	return kept
}

func skipReasons(skipped map[string]int) string {
	reasons := slices.Sorted(maps.Keys(skipped))
	slices.SortStableFunc(reasons, func(a, b string) int { return skipped[b] - skipped[a] })
	parts := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		parts = append(parts, fmt.Sprintf("%d %s", skipped[reason], reason))
	}
	if len(parts) == 0 {
		return "no credentials held"
	}
	return strings.Join(parts, ", ")
}

func sortMatchesByPreferredFormat(matches []consent.Match, preferred string) {
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].QueryID != matches[j].QueryID {
			return false
		}
		return matches[i].Format == preferred && matches[j].Format != preferred
	})
}

type claimSelection struct {
	selectedKeys    []string
	missingRequired []string
	// emptyArrays holds the claim paths that select an array of selectively
	// disclosable elements without selecting the elements, so presenting them
	// discloses an empty array (see disclosesEmptyArray).
	emptyArrays []string
	match       bool
}

// matchesFormat treats a missing format as a wildcard. §6.1 makes format
// REQUIRED, so QueryFindings reports it and strict mode refuses the query
// before matching.
func matchesFormat(cred Credential, queryFormat string) bool {
	if queryFormat == "" {
		return true
	}
	return cred.Format == queryFormat
}

// matchesMeta checks format-specific metadata (vct_values, doctype_value).
// QueryFindings reports a missing meta. Debug mode treats it as
// unconstrained. A vct_values entry matches that type and every type extending
// it (internal/credtype). ISO/IEC 18013-5 has no inheritance, so doctype_value
// matches exactly.
func matchesMeta(cred Credential, cqMap map[string]any) bool {
	meta, ok := cqMap["meta"].(map[string]any)
	if !ok {
		return true
	}

	if vctValues, ok := meta["vct_values"].([]any); ok {
		if cred.VCT == "" {
			return false
		}
		types := credtype.Chain(cred.VCT, credtype.AkaVCTs(cred.Claims))
		found := ""
		for _, v := range vctValues {
			s, ok := v.(string)
			if !ok {
				continue
			}
			for _, t := range types {
				if t == s {
					found = s
					break
				}
			}
			if found != "" {
				break
			}
		}
		if found == "" {
			return false
		}
		if found != cred.VCT {
			log.Printf("[DCQL]   credential %s: vct %s answers the requested %s (an extending type answers for the type it extends)",
				cred.ID, cred.VCT, found)
		}
	}

	if docType, ok := meta["doctype_value"].(string); ok {
		if cred.DocType != docType {
			return false
		}
	}

	if typeValues, ok := meta["type_values"].([]any); ok && cred.Format == credtype.FormatJWTVC {
		return matchesTypeValues(w3cCredentialTypes(cred.Claims), typeValues)
	}

	return true
}

// matchesTypeValues applies OID4VP 1.0 Appendix B.1.1: "Each inner array
// specifies a set of fully expanded types that MUST be present in the fully
// expanded types in the type property of the Verifiable Credential".
func matchesTypeValues(types []string, typeValues []any) bool {
	for _, alternative := range typeValues {
		required, ok := alternative.([]any)
		if !ok || len(required) == 0 {
			continue
		}
		all := true
		for _, r := range required {
			iri, _ := r.(string)
			if !slices.ContainsFunc(types, func(t string) bool { return typeExpandsTo(t, iri) }) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// typeExpandsTo reports whether a credential type equals a fully expanded type.
// The wallet does no JSON-LD processing. The W3C credential contexts define
// each type term as an IRI ending in #term, so a term matches an IRI with that
// fragment. B.1.1 keeps an undefined type as the relative IRI itself.
func typeExpandsTo(credentialType, iri string) bool {
	if credentialType == iri {
		return true
	}
	return !strings.Contains(credentialType, ":") && strings.HasSuffix(iri, "#"+credentialType)
}

// w3cCredentialTypes reads the type property of a W3C credential in JWT form.
// A VCDM 1.1 JWT carries the credential in the vc claim.
func w3cCredentialTypes(payload map[string]any) []string {
	raw := payload["type"]
	if vc, ok := payload["vc"].(map[string]any); ok && vc["type"] != nil {
		raw = vc["type"]
	}
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []any:
		return jsonutil.Strings(v)
	}
	return nil
}

// requiresHolderBinding reads require_cryptographic_holder_binding. It
// defaults to true (OpenID4VP 1.0 §6.1). The Verifier then expects a
// Cryptographic Holder Binding proof. An unbound credential cannot give one.
func requiresHolderBinding(cqMap map[string]any) bool {
	required, ok := cqMap["require_cryptographic_holder_binding"].(bool)
	return !ok || required
}

// metaMismatch describes how the credential type differs from the types in the
// query's meta.
func metaMismatch(cred Credential, cqMap map[string]any) string {
	meta, _ := cqMap["meta"].(map[string]any)
	if values, ok := meta["vct_values"].([]any); ok {
		var want []string
		for _, v := range values {
			if s, ok := v.(string); ok {
				want = append(want, s)
			}
		}
		have := cred.VCT
		if have == "" {
			have = cred.DocType
		}
		return fmt.Sprintf("type %s, the query asks for %s", have, strings.Join(want, " or "))
	}
	if values, ok := meta["type_values"].([]any); ok && cred.Format == credtype.FormatJWTVC {
		return fmt.Sprintf("type %v, the query asks for one of the type sets %v", w3cCredentialTypes(cred.Claims), values)
	}
	docType, ok := meta["doctype_value"].(string)
	if !ok {
		return "meta does not match"
	}
	have := cred.DocType
	if have == "" {
		have = cred.VCT
	}
	return fmt.Sprintf("type %s, the query asks for %s", have, docType)
}

func selectClaims(cred Credential, cqMap map[string]any) claimSelection {
	claimsQuery, ok := cqMap["claims"].([]any)
	if !ok || len(claimsQuery) == 0 {
		return claimSelection{match: true}
	}

	if claimSets, ok := cqMap["claim_sets"].([]any); ok && len(claimSets) > 0 {
		selected := selectFromClaimSets(cred, claimsQuery, claimSets)
		return claimSelection{
			selectedKeys: selected,
			match:        len(selected) > 0,
		}
	}

	return selectAllRequestedClaims(cred, claimsQuery)
}

// selectFromClaimSets picks the first satisfiable claim_set (preference order).
// claim_sets entries reference claims by their "id" property (string).
func selectFromClaimSets(cred Credential, claimsQuery []any, claimSets []any) []string {
	claimByID := buildClaimByID(claimsQuery)
	for _, cs := range claimSets {
		if selected, ok := claimSetSelectors(cred, claimByID, cs); ok {
			return selected
		}
	}
	return nil
}

// satisfiableClaimSets lists the matching claim_sets options of a credential, in
// the verifier's order. Debug mode offers them in the consent dialog.
func satisfiableClaimSets(cred Credential, cqMap map[string]any) []consent.ClaimSet {
	claimsQuery, _ := cqMap["claims"].([]any)
	claimSets, _ := cqMap["claim_sets"].([]any)
	if len(claimsQuery) == 0 || len(claimSets) == 0 {
		return nil
	}
	claimByID := buildClaimByID(claimsQuery)
	var out []consent.ClaimSet
	for i, cs := range claimSets {
		if selected, ok := claimSetSelectors(cred, claimByID, cs); ok {
			out = append(out, consent.ClaimSet{Index: i, Keys: selected, Claims: FilterClaims(cred, selected)})
		}
	}
	return out
}

// claimSetSelectors resolves one claim_sets option. ok is false when the credential
// cannot answer one of its claims.
func claimSetSelectors(cred Credential, claimByID map[string]map[string]any, claimSet any) ([]string, bool) {
	ids, ok := claimSet.([]any)
	if !ok {
		return nil, false
	}
	var selected []string
	for _, ref := range ids {
		id, ok := ref.(string)
		if !ok || claimByID[id] == nil {
			return nil, false
		}
		selector := claimSelectorFor(cred, claimByID[id])
		if selector == "" {
			return nil, false
		}
		selected = append(selected, selector)
	}
	return selected, len(selected) > 0
}

func buildClaimByID(claimsQuery []any) map[string]map[string]any {
	byID := make(map[string]map[string]any)
	for _, cq := range claimsQuery {
		cqMap, ok := cq.(map[string]any)
		if !ok {
			continue
		}
		id, _ := cqMap["id"].(string)
		if id == "" {
			continue
		}
		if _, ok := cqMap["path"].([]any); !ok {
			continue
		}
		byID[id] = cqMap
	}
	return byID
}

// claimSelectorFor resolves one Claims Query against a credential and returns
// the selector to disclose, or "" when the credential does not answer it.
// §6.4.1 treats a value mismatch "the same as if it did not exist in the
// Credential".
func claimSelectorFor(cred Credential, cqMap map[string]any) string {
	path, ok := cqMap["path"].([]any)
	if !ok {
		return ""
	}

	selector := claimSelectorFromPath(cred, path)
	if selector == "" {
		return ""
	}

	if values, ok := cqMap["values"].([]any); ok && len(values) > 0 {
		if !valuesConstraintSatisfied(claimValuesAtPath(cred, path), values) {
			return ""
		}
	}
	return selector
}

// selectAllRequestedClaims returns all requested claims that exist in the
// credential, plus the paths of the ones it cannot answer. §6.4.1: "If claims
// is present, but claim_sets is absent, the Verifier requests all claims
// listed in claims". None of them is optional.
func selectAllRequestedClaims(cred Credential, claimsQuery []any) claimSelection {
	var selected []string
	var missingRequired []string
	var emptyArrays []string
	for _, cq := range claimsQuery {
		cqMap, ok := cq.(map[string]any)
		if !ok {
			continue
		}
		path, ok := cqMap["path"].([]any)
		if !ok {
			continue
		}

		if selector := claimSelectorFor(cred, cqMap); selector != "" {
			selected = append(selected, selector)
			if disclosesEmptyArray(cred, path) {
				emptyArrays = append(emptyArrays, ClaimPathString(path))
			}
		} else {
			missingRequired = append(missingRequired, missingClaimLabel(cred, path))
		}
	}

	if len(selected) == 0 {
		return claimSelection{missingRequired: missingRequired}
	}
	return claimSelection{
		selectedKeys:    selected,
		missingRequired: missingRequired,
		emptyArrays:     emptyArrays,
		match:           true,
	}
}

func claimSelectorFromPath(cred Credential, path []any) string {
	if len(path) == 0 {
		return ""
	}

	if cred.Format == credtype.FormatMDOC {
		return claimKeyFromPath(cred, path)
	}

	key := claimKeyFromPath(cred, path)
	if key == "" {
		return ""
	}

	return ClaimPathString(path)
}

func missingClaimLabel(cred Credential, path []any) string {
	if cred.Format == credtype.FormatMDOC && len(path) == 2 {
		ns, nsOK := path[0].(string)
		el, elOK := path[1].(string)
		if nsOK && elOK {
			return ns + ":" + el
		}
	}
	return ClaimPathString(path)
}

// ClaimPathString writes a claims path as a selector such as
// address.locality or degrees[0]. A name that contains '.', '[', ']' or '"'
// is written as a quoted segment, ["a.b"], so ParseSDJWTSelector reads back
// the same path.
func ClaimPathString(path []any) string {
	if len(path) == 0 {
		return "<empty>"
	}

	var b strings.Builder
	for i, segment := range path {
		switch v := segment.(type) {
		case string:
			if v == "" || strings.ContainsAny(v, `.[]"`) {
				quoted, _ := json.Marshal(v)
				b.WriteByte('[')
				b.Write(quoted)
				b.WriteByte(']')
				continue
			}
			if i > 0 {
				b.WriteByte('.')
			}
			b.WriteString(v)
		case float64:
			b.WriteString("[")
			b.WriteString(strconv.FormatFloat(v, 'f', -1, 64))
			b.WriteString("]")
		case nil:
			b.WriteString("[*]")
		default:
			if i > 0 {
				b.WriteByte('.')
			}
			b.WriteString("?")
		}
	}
	return b.String()
}

// claimKeyFromPath resolves a DCQL claim path to a credential claim key.
// For SD-JWT: path is like ["given_name"] → key "given_name"
//
//	nested object: ["address", "street_address"] → validates subclaim exists, returns "address"
//	array wildcard: ["nationalities", null] → validates value is array, returns "nationalities"
//	array index:    ["nationalities", 0] → validates array has enough elements, returns "nationalities"
//
// For mdoc: path is like ["eu.europa.ec.eudi.pid.1", "given_name"] → key "eu.europa.ec.eudi.pid.1:given_name"
func claimKeyFromPath(cred Credential, path []any) string {
	if len(path) == 0 {
		return ""
	}

	if cred.Format == credtype.FormatMDOC {
		return mdocClaimKeyFromPath(cred, path)
	}

	key, ok := path[0].(string)
	if !ok {
		return ""
	}
	if _, ok := SelectClaims(cred.Claims, path); !ok {
		return ""
	}
	return key
}

// mdocClaimKeyFromPath applies a claims path pointer to an mdoc, per §7.2.1.
// The data element identifier is matched exactly: "If the data element does
// not exist in the Credential then abort processing and return an error."
func mdocClaimKeyFromPath(cred Credential, path []any) string {
	// §7.2.1: "If the claims path pointer does not contain exactly two
	// components or one of the components is not a string then abort
	// processing and return an error."
	if len(path) != 2 {
		return ""
	}
	namespace, ok := path[0].(string)
	if !ok {
		return ""
	}
	element, ok := path[1].(string)
	if !ok {
		return ""
	}

	key := namespace + ":" + element
	if _, exists := cred.Claims[key]; !exists {
		return ""
	}
	return key
}

// claimValuesAtPath returns the claims selected by a claims path pointer
// (§7). An array wildcard selects every element, so it adds one entry per
// element.
func claimValuesAtPath(cred Credential, path []any) []any {
	if len(path) == 0 {
		return nil
	}

	if cred.Format == credtype.FormatMDOC {
		key := mdocClaimKeyFromPath(cred, path)
		if key == "" {
			return nil
		}
		return []any{mdocValueAsJSON(cred.Claims[key])}
	}

	selected, _ := SelectClaims(cred.Claims, path)
	return selected
}

// mdocValueAsJSON converts an mdoc data element value to JSON for values
// matching. §6.3 requires the conversion of RFC 8949 §6.1. It encodes a byte
// string as base64url and a CBOR integer as a number.
func mdocValueAsJSON(value any) any {
	switch v := value.(type) {
	case []byte:
		return format.EncodeBase64URL(v)
	case time.Time:
		return v.UTC().Format(time.RFC3339)
	default:
		if n, ok := numericClaimValue(value); ok {
			return n
		}
		return value
	}
}

// valuesConstraintSatisfied reports whether a claim answers a values
// restriction.
//
// §6.3: "If the values property is present, the Wallet SHOULD return the claim
// only if the type and value of the claim both match exactly for at least one
// of the elements in the array."
func valuesConstraintSatisfied(selected []any, values []any) bool {
	for _, claim := range selected {
		for _, want := range values {
			if claimValueEquals(claim, want) {
				return true
			}
		}
	}
	return false
}

// claimValueEquals compares a claim against one entry of a values array. §6.3
// allows "strings, integers or boolean values" there. Type and value must both
// match, so the string "1" and the boolean true never match the integer 1.
func claimValueEquals(claim, want any) bool {
	switch expected := want.(type) {
	case string:
		got, ok := claim.(string)
		return ok && got == expected
	case bool:
		got, ok := claim.(bool)
		return ok && got == expected
	default:
		wantNum, ok := numericClaimValue(want)
		if !ok {
			return false
		}
		gotNum, ok := numericClaimValue(claim)
		return ok && gotNum == wantNum
	}
}

// numericClaimValue reports the numeric value of a claim or of a values entry.
// A JSON decoder returns float64. A CBOR decoder returns signed and unsigned
// integer types for mdoc data elements.
func numericClaimValue(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	default:
		return 0, false
	}
}

func FilterClaims(cred Credential, selectedKeys []string) map[string]any {
	filtered := make(map[string]any, len(selectedKeys))
	for _, k := range selectedKeys {
		if v, ok := claimValueBySelector(cred, k); ok {
			filtered[k] = v
		}
	}
	return filtered
}

func claimValueBySelector(cred Credential, selector string) (any, bool) {
	if cred.Format == credtype.FormatMDOC {
		v, ok := cred.Claims[selector]
		return v, ok
	}

	path, ok := ParseSDJWTSelector(selector)
	if !ok {
		return nil, false
	}
	selected, ok := SelectClaims(cred.Claims, path)
	if !ok {
		return nil, false
	}
	// A null component selects every element, so the value is the list.
	if slices.Contains(path, nil) {
		return selected, true
	}
	return selected[0], true
}

func ParseSDJWTSelector(selector string) ([]any, bool) {
	if selector == "" {
		return nil, false
	}

	var path []any
	var name strings.Builder

	flushName := func() bool {
		if name.Len() == 0 {
			return false
		}
		path = append(path, name.String())
		name.Reset()
		return true
	}

	for i := 0; i < len(selector); {
		switch selector[i] {
		case '.':
			if name.Len() == 0 {
				if len(path) == 0 {
					return nil, false
				}
				i++
				continue
			}
			if !flushName() {
				return nil, false
			}
			i++
		case '[':
			flushName()
			if strings.HasPrefix(selector[i:], `["`) {
				segment, n, ok := quotedSelectorSegment(selector[i+1:])
				if !ok {
					return nil, false
				}
				path = append(path, segment)
				i += n + 1
				continue
			}
			end := strings.IndexByte(selector[i:], ']')
			if end <= 1 {
				return nil, false
			}
			content := selector[i+1 : i+end]
			if content == "*" {
				path = append(path, nil)
			} else {
				idx, err := strconv.Atoi(content)
				if err != nil {
					return nil, false
				}
				path = append(path, idx)
			}
			i += end + 1
		default:
			name.WriteByte(selector[i])
			i++
		}
	}

	if name.Len() > 0 {
		path = append(path, name.String())
	}

	return path, len(path) > 0
}

// quotedSelectorSegment reads a JSON string followed by ']' from the start of
// s and returns the name and the number of bytes read.
func quotedSelectorSegment(s string) (string, int, bool) {
	for end := 1; end < len(s); end++ {
		switch s[end] {
		case '\\':
			end++
		case '"':
			var name string
			if err := json.Unmarshal([]byte(s[:end+1]), &name); err != nil || end+1 >= len(s) || s[end+1] != ']' {
				return "", 0, false
			}
			return name, end + 2, true
		}
	}
	return "", 0, false
}

// applyCredentialSets filters matches to satisfy credential_sets constraints,
// trying options containing the preferred format first. It returns nil when
// nothing may be returned: §6.4.2 requires a set to match "one of the options
// inside the Credential Set Query", and a wallet that "cannot deliver all
// non-optional Credentials [...] MUST NOT return any Credential(s)".
func applyCredentialSets(matches []consent.Match, credSets []any, preferredFormat string) []consent.Match {
	byQuery := make(map[string][]consent.Match)
	for _, m := range matches {
		byQuery[m.QueryID] = append(byQuery[m.QueryID], m)
	}

	needed := make(map[string]bool)

	for _, cs := range credSets {
		csMap, ok := cs.(map[string]any)
		if !ok {
			continue
		}

		required := true
		if r, ok := csMap["required"].(bool); ok {
			required = r
		}

		options, ok := csMap["options"].([]any)
		if !ok {
			continue
		}

		satisfied := false
		for _, opt := range orderOptionsByPreferredFormat(options, byQuery, preferredFormat) {
			ids, ok := satisfiableOption(opt, byQuery)
			if !ok {
				continue
			}
			for _, qid := range ids {
				needed[qid] = true
			}
			satisfied = true
			break
		}

		if required && !satisfied {
			return nil
		}
	}

	if len(needed) == 0 {
		return nil
	}

	var result []consent.Match
	for _, m := range matches {
		if needed[m.QueryID] {
			result = append(result, m)
		}
	}
	return result
}

func optionMatchesFormat(opt any, queryFormat map[string]string, format string) bool {
	optArr, ok := opt.([]any)
	if !ok {
		return false
	}
	for _, qid := range optArr {
		qidStr, ok := qid.(string)
		if !ok {
			return false
		}
		if queryFormat[qidStr] == format {
			return true
		}
	}
	return false
}

// checkTrustedAuthorities validates that the credential's issuer certificate chain
// is trusted by at least one of the given trusted authorities.
// Each entry must have "type" and "values" (array) fields. listAnchors holds
// the anchors of each etsi_tl list by URL.
func checkTrustedAuthorities(cred Credential, taList []any, listAnchors map[string][]*x509.Certificate) bool {
	for _, taRaw := range taList {
		taMap, ok := taRaw.(map[string]any)
		if !ok {
			continue
		}
		taType, _ := taMap["type"].(string)

		var urls []string
		if valuesRaw, ok := taMap["values"].([]any); ok {
			for _, v := range valuesRaw {
				if s, ok := v.(string); ok && s != "" {
					urls = append(urls, s)
				}
			}
		}

		switch taType {
		case "aki":
			if len(urls) == 0 {
				log.Printf("[DCQL]   trusted_authorities: aki entry missing values")
				continue
			}
			if checkAuthorityKeyIdentifiers(cred, urls) {
				return true
			}
		case "etsi_tl":
			if len(urls) == 0 {
				log.Printf("[DCQL]   trusted_authorities: etsi_tl entry missing values")
				continue
			}
			for _, u := range urls {
				if checkETSITrustList(cred, u, listAnchors[u]) {
					return true
				}
			}
		default:
			log.Printf("[DCQL]   trusted_authorities: unsupported type %q", taType)
		}
	}
	return false
}

func checkAuthorityKeyIdentifiers(cred Credential, values []string) bool {
	certs, err := extractCredentialCertificates(cred)
	if err != nil {
		log.Printf("[DCQL]   trusted_authorities: failed to extract certificate chain: %v", err)
		return false
	}
	if len(certs) == 0 {
		log.Printf("[DCQL]   trusted_authorities: credential contains no certificate chain")
		return false
	}

	allowed := make(map[string]struct{}, len(values))
	for _, v := range values {
		allowed[v] = struct{}{}
	}

	for _, cert := range certs {
		if len(cert.AuthorityKeyId) == 0 {
			continue
		}
		if _, ok := allowed[format.EncodeBase64URL(cert.AuthorityKeyId)]; ok {
			return true
		}
	}

	log.Printf("[DCQL]   trusted_authorities: no certificate in credential chain matched any requested aki")
	return false
}

func extractCredentialCertificates(cred Credential) ([]*x509.Certificate, error) {
	switch cred.Format {
	case credtype.FormatSDJWT:
		token, err := sdjwt.ParseLenient(cred.Raw)
		if err != nil {
			return nil, err
		}
		return validate.X5CCertificates(token.Header)
	case credtype.FormatMDOC:
		doc, err := mdoc.Parse(cred.Raw)
		if err != nil {
			return nil, err
		}
		return validate.ExtractMDOCX5ChainCertificates(doc)
	default:
		return nil, nil
	}
}

func checkETSITrustList(cred Credential, trustListURL string, anchors []*x509.Certificate) bool {
	if len(anchors) == 0 {
		return false
	}
	if _, err := ChainKey(cred, anchors); err != nil {
		log.Printf("[DCQL]   trusted_authorities: %s: %v", trustListURL, err)
		return false
	}
	return true
}

// ChainKey checks that the issuer certificate chain of cred (x5c of
// an SD-JWT, x5chain of an mdoc) ends in one of the anchors. It returns the
// key of the chain's leaf.
func ChainKey(cred Credential, anchors []*x509.Certificate) (crypto.PublicKey, error) {
	var key crypto.PublicKey
	var err error
	switch cred.Format {
	case credtype.FormatSDJWT:
		token, parseErr := sdjwt.ParseLenient(cred.Raw)
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse SD-JWT: %w", parseErr)
		}
		if key, err = validate.ExtractAndValidateX5C(token.Header, lote.CertInfos(anchors)); err != nil {
			return nil, fmt.Errorf("x5c chain validation failed: %w", err)
		}
	case credtype.FormatMDOC:
		doc, parseErr := mdoc.Parse(cred.Raw)
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse mdoc: %w", parseErr)
		}
		if key, err = validate.ExtractAndValidateMDOCX5Chain(doc, lote.CertInfos(anchors)); err != nil {
			return nil, fmt.Errorf("x5chain validation failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported credential format %q for chain validation", cred.Format)
	}
	if key == nil {
		return nil, fmt.Errorf("the credential carries no certificate chain")
	}
	return key, nil
}

// A path ending at a selectively disclosed array reveals the array without its
// elements. Only a trailing null or index selects elements. Arrays with always-visible
// elements are unaffected.
func disclosesEmptyArray(cred Credential, path []any) bool {
	if cred.Format != credtype.FormatSDJWT || len(path) == 0 {
		return false
	}
	switch path[len(path)-1].(type) {
	case nil, float64, int:
		return false
	}
	parts := strings.Split(cred.Raw, "~")
	_, payload, _, err := format.ParseJWTParts(parts[0])
	if err != nil {
		return false
	}
	digestMap := make(map[string]*sdjwt.Disclosure, len(cred.Disclosures))
	for i := range cred.Disclosures {
		digestMap[cred.Disclosures[i].Digest] = &cred.Disclosures[i]
	}
	arr, ok := placeholderValueAtPath(payload, path, digestMap).([]any)
	if !ok || len(arr) == 0 {
		return false
	}
	for _, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			return false
		}
		if _, ok := obj["..."].(string); !ok {
			return false
		}
	}
	return true
}

// placeholderValueAtPath walks a claims path (string components only) to its
// value in the credential's placeholder form. A selectively disclosable member
// resolves to its disclosure value. For an array of disclosable elements that
// value is a list of {"...": digest} references.
func placeholderValueAtPath(value any, path []any, digestMap map[string]*sdjwt.Disclosure) any {
	if len(path) == 0 {
		return value
	}
	segment, ok := path[0].(string)
	if !ok {
		return nil
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	if next, ok := obj[segment]; ok {
		return placeholderValueAtPath(next, path[1:], digestMap)
	}
	sdArr, _ := obj["_sd"].([]any)
	for _, item := range sdArr {
		digest, ok := item.(string)
		if !ok {
			continue
		}
		disc := digestMap[digest]
		if disc == nil || disc.IsArrayEntry || disc.Name != segment {
			continue
		}
		return placeholderValueAtPath(disc.Value, path[1:], digestMap)
	}
	return nil
}
