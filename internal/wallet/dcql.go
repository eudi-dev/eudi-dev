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

package wallet

import (
	"crypto/x509"
	"fmt"
	"log"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v2/internal/trustlist"
	"github.com/eudi-dev/eudi-dev/v2/internal/validate"
)

// EvaluateDCQL matches stored credentials against a DCQL query (OID4VP 1.0 Section 6).
// It returns matched credentials grouped by query credential ID.
func (w *Wallet) EvaluateDCQL(query map[string]any) []CredentialMatch {
	matches, _ := w.EvaluateDCQLWithOptions(query)
	return matches
}

// EvaluateDCQLWithOptions returns matching credentials and satisfiable set options for
// consent. The first candidate and option are the automatic selection.
func (w *Wallet) EvaluateDCQLWithOptions(query map[string]any) ([]CredentialMatch, *ConsentCredentialOptions) {
	credentials := w.GetCredentials()
	credQueries, _ := query["credentials"].([]any)

	log.Printf("[DCQL] Evaluating query: %d credential queries against %d stored credentials", len(credQueries), len(credentials))

	if findings := DCQLQueryFindings(query); len(findings) > 0 {
		for _, finding := range findings {
			log.Printf("[DCQL] Warning: %s", finding)
		}
		if w.ValidationMode == ValidationModeStrict {
			log.Printf("[DCQL] Result: 0 matches (strict mode treats a malformed query as an error)")
			return nil, nil
		}
	}

	var matches []CredentialMatch

	for _, cq := range credQueries {
		cqMap, ok := cq.(map[string]any)
		if !ok {
			continue
		}

		queryID, _ := cqMap["id"].(string)
		queryFormat, _ := cqMap["format"].(string)
		// Log skipped credentials by reason only when nothing matches.
		matched := 0
		skipped := make(map[string]int)

		for _, cred := range credentials {
			typeLabel := cred.VCT
			if typeLabel == "" {
				typeLabel = cred.DocType
			}

			if !matchesFormat(cred, queryFormat) {
				skipped[fmt.Sprintf("format %s (want %s)", cred.Format, queryFormat)]++
				continue
			}
			if !matchesMeta(cred, cqMap) {
				skipped["meta mismatch"]++
				continue
			}

			selection := w.selectClaims(cred, cqMap)
			if len(selection.missingRequired) > 0 {
				if w.ValidationMode == ValidationModeDebug && len(selection.selectedKeys) > 0 {
					log.Printf("[DCQL] Warning: query=%s: credential %s (%s) missing required claims %v in debug mode, continuing with selected claims %v",
						queryID, typeLabel, cred.Format, selection.missingRequired, selection.selectedKeys)
				} else {
					skipped[fmt.Sprintf("required claims not found %v", selection.missingRequired)]++
					continue
				}
			}
			if !selection.match {
				skipped["no requested claims matched"]++
				continue
			}

			untrustedAuthority := false
			if taList, ok := cqMap["trusted_authorities"].([]any); ok && len(taList) > 0 {
				if !checkTrustedAuthorities(cred, taList, w.HTTPClient()) {
					if w.ValidationMode != ValidationModeDebug {
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

			matched++
			log.Printf("[DCQL]   query=%s: credential %s (%s) matched, selected claims: %v", queryID, typeLabel, cred.Format, selection.selectedKeys)
			matches = append(matches, CredentialMatch{
				QueryID:            queryID,
				CredentialID:       cred.ID,
				Format:             cred.Format,
				VCT:                cred.VCT,
				DocType:            cred.DocType,
				Claims:             filterClaims(cred, selection.selectedKeys),
				SelectedKeys:       selection.selectedKeys,
				UntrustedAuthority: untrustedAuthority,
				EmptyArrayClaims:   selection.emptyArrays,
				MissingClaims:      selection.missingRequired,
			})
		}
		if matched == 0 {
			log.Printf("[DCQL]   query=%s: no match among %d credentials: %s", queryID, len(credentials), skipReasons(skipped))
		}
	}

	// Keep one unused batch copy so consent and presentation treat the batch as one
	// credential.
	matches = w.collapseBatchMatches(matches, credentials)

	sortMatchesNewestFirst(matches, credentials)

	if w.PreferredFormat != "" {
		sortMatchesByPreferredFormat(matches, w.PreferredFormat)
	}

	sortMatchesTrustedFirst(matches)

	// Apply completeness last so a full claim match wins automatic selection.
	sortMatchesCompleteFirst(matches)

	// Keep candidates in preference order. The first per query becomes the automatic
	// choice.
	candidates := append([]CredentialMatch(nil), matches...)

	multiple := multipleQueries(credQueries)
	matches = keepOnePresentationPerQuery(matches, multiple)

	// OID4VP 1.0 §6.4.2: "If credential_sets is not provided, the Verifier
	// requests presentations for all Credentials in credentials to be
	// returned."
	credSets, _ := query["credential_sets"].([]any)
	if len(credSets) > 0 {
		log.Printf("[DCQL] Applying credential_sets constraints: %d sets, %d matches before", len(credSets), len(matches))
		matches = applyCredentialSets(matches, credSets, w.PreferredFormat)
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
		return nil, nil
	}

	log.Printf("[DCQL] Result: %d matches", len(matches))
	if matches == nil {
		return nil, nil
	}
	return matches, buildConsentCredentialOptions(candidates, credSets, multiple, w.PreferredFormat)
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
func buildConsentCredentialOptions(candidates []CredentialMatch, credSets []any, multiple map[string]bool, preferredFormat string) *ConsentCredentialOptions {
	if len(candidates) == 0 {
		return nil
	}
	byQuery := make(map[string][]CredentialMatch)
	var order []string
	for _, m := range candidates {
		if _, ok := byQuery[m.QueryID]; !ok {
			order = append(order, m.QueryID)
		}
		byQuery[m.QueryID] = append(byQuery[m.QueryID], m)
	}

	options := &ConsentCredentialOptions{}
	for _, id := range order {
		options.Queries = append(options.Queries, ConsentQueryOptions{ID: id, Multiple: multiple[id], Candidates: byQuery[id]})
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
		set := ConsentSetOptions{Optional: !required}
		for _, opt := range orderOptionsByPreferredFormat(rawOptions, byQuery, preferredFormat) {
			if ids, ok := satisfiableOption(opt, byQuery); ok {
				set.Options = append(set.Options, ids)
			}
		}
		if len(set.Options) > 0 {
			options.Sets = append(options.Sets, set)
		}
	}
	return options
}

func satisfiableOption(opt any, byQuery map[string][]CredentialMatch) ([]string, bool) {
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

func orderOptionsByPreferredFormat(options []any, byQuery map[string][]CredentialMatch, preferredFormat string) []any {
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
func unmatchedCredentialQueries(credQueries []any, matches []CredentialMatch) []string {
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

// DCQLQueryFindings reports where a DCQL query departs from OID4VP 1.0 §6.
// Strict mode refuses the query. Debug mode logs the findings and evaluates
// the query as far as it can.
func DCQLQueryFindings(query map[string]any) []string {
	if query == nil {
		return nil
	}

	// §6: "credentials: REQUIRED. A non-empty array of Credential Queries as
	// defined in Section 6.1 that specify the requested Credentials."
	credQueries, ok := query["credentials"].([]any)
	if !ok || len(credQueries) == 0 {
		return []string{"OID4VP 1.0 §6: dcql_query.credentials is required and must be a non-empty array"}
	}

	var findings []string
	seen := make(map[string]bool, len(credQueries))
	for i, cq := range credQueries {
		cqMap, ok := cq.(map[string]any)
		if !ok {
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6: dcql_query.credentials[%d] must be an object", i))
			continue
		}

		// §6.1: "id: REQUIRED. [...] The value MUST be a non-empty string
		// consisting of alphanumeric, underscore (_), or hyphen (-)
		// characters. Within the Authorization Request, the same id MUST NOT
		// be present more than once."
		id, _ := cqMap["id"].(string)
		switch {
		case !isDCQLIdentifier(id):
			findings = append(findings, fmt.Sprintf(
				"OID4VP 1.0 §6.1: dcql_query.credentials[%d].id must be a non-empty string of alphanumeric, underscore or hyphen characters, got %q", i, id))
		case seen[id]:
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.1: the credential query id %q is present more than once", id))
		default:
			seen[id] = true
		}

		label := id
		if label == "" {
			label = fmt.Sprintf("credentials[%d]", i)
		}

		// §6.1: "format: REQUIRED. A string that specifies the format of the
		// requested Credential."
		if f, _ := cqMap["format"].(string); f == "" {
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.1: the credential query %q is missing the required format", label))
		}

		// §6.1: "multiple: OPTIONAL. A boolean".
		if m, present := cqMap["multiple"]; present {
			if _, ok := m.(bool); !ok {
				findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.1: the credential query %q has a multiple that is not a boolean", label))
			}
		}

		// §6.1 makes meta REQUIRED. An empty object places no constraints.
		meta, present := cqMap["meta"]
		if !present {
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.1: the credential query %q is missing the required meta (use an empty object to place no constraints)", label))
		} else if _, ok := meta.(map[string]any); !ok {
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.1: the credential query %q has a meta that is not an object", label))
		}
	}
	return findings
}

// isDCQLIdentifier reports whether an id has the syntax OID4VP 1.0 §6.1 gives
// it: "a non-empty string consisting of alphanumeric, underscore (_), or
// hyphen (-) characters".
func isDCQLIdentifier(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// Sort by issuance time so renewed credentials take precedence. Undated credentials
// come last and ties keep their order.
func sortMatchesNewestFirst(matches []CredentialMatch, credentials []StoredCredential) {
	matched := make(map[string]bool, len(matches))
	for _, m := range matches {
		matched[m.CredentialID] = true
	}
	issued := make(map[string]time.Time, len(matches))
	for _, c := range credentials {
		if matched[c.ID] {
			issued[c.ID] = CredentialIssuedAt(c)
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
func sortMatchesTrustedFirst(matches []CredentialMatch) {
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].QueryID != matches[j].QueryID {
			return false
		}
		return !matches[i].UntrustedAuthority && matches[j].UntrustedAuthority
	})
}

// Prefer complete claim matches over partial matches allowed in debug mode. Apply this
// priority last.
func sortMatchesCompleteFirst(matches []CredentialMatch) {
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
func keepOnePresentationPerQuery(matches []CredentialMatch, multiple map[string]bool) []CredentialMatch {
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

func sortMatchesByPreferredFormat(matches []CredentialMatch, preferred string) {
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

// matchesFormat checks if a credential matches the requested format. §6.1
// makes format REQUIRED and DCQLQueryFindings reports a missing one. Debug
// mode treats a missing format as a wildcard.
func matchesFormat(cred StoredCredential, queryFormat string) bool {
	if queryFormat == "" {
		return true
	}
	return cred.Format == queryFormat
}

// matchesMeta checks format-specific metadata (vct_values, doctype_value).
// DCQLQueryFindings reports a missing meta. Debug mode treats it as
// unconstrained. A vct_values entry matches that type and every type extending
// it (internal/credtype). ISO/IEC 18013-5 has no inheritance, so doctype_value
// matches exactly.
func matchesMeta(cred StoredCredential, cqMap map[string]any) bool {
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

	return true
}

func (w *Wallet) selectClaims(cred StoredCredential, cqMap map[string]any) claimSelection {
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
func selectFromClaimSets(cred StoredCredential, claimsQuery []any, claimSets []any) []string {
	claimByID := buildClaimByID(claimsQuery)

	for _, cs := range claimSets {
		csArr, ok := cs.([]any)
		if !ok {
			continue
		}

		var selected []string
		satisfiable := true

		for _, ref := range csArr {
			id, ok := ref.(string)
			if !ok {
				satisfiable = false
				break
			}

			claimQuery := claimByID[id]
			if claimQuery == nil {
				satisfiable = false
				break
			}

			selector := claimSelectorFor(cred, claimQuery)
			if selector == "" {
				satisfiable = false
				break
			}
			selected = append(selected, selector)
		}

		if satisfiable && len(selected) > 0 {
			return selected
		}
	}

	return nil
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
func claimSelectorFor(cred StoredCredential, cqMap map[string]any) string {
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
func selectAllRequestedClaims(cred StoredCredential, claimsQuery []any) claimSelection {
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
				emptyArrays = append(emptyArrays, claimPathString(path))
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

func claimSelectorFromPath(cred StoredCredential, path []any) string {
	if len(path) == 0 {
		return ""
	}

	if cred.Format == "mso_mdoc" {
		return claimKeyFromPath(cred, path)
	}

	key := claimKeyFromPath(cred, path)
	if key == "" {
		return ""
	}

	return claimPathString(path)
}

func missingClaimLabel(cred StoredCredential, path []any) string {
	if cred.Format == "mso_mdoc" && len(path) == 2 {
		ns, nsOK := path[0].(string)
		el, elOK := path[1].(string)
		if nsOK && elOK {
			return ns + ":" + el
		}
	}
	return claimPathString(path)
}

func claimPathString(path []any) string {
	if len(path) == 0 {
		return "<empty>"
	}

	var b strings.Builder
	for i, segment := range path {
		switch v := segment.(type) {
		case string:
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
func claimKeyFromPath(cred StoredCredential, path []any) string {
	if len(path) == 0 {
		return ""
	}

	if cred.Format == "mso_mdoc" {
		return mdocClaimKeyFromPath(cred, path)
	}

	key, ok := path[0].(string)
	if !ok {
		return ""
	}
	val, exists := cred.Claims[key]
	if !exists {
		return ""
	}

	if claimPathExists(val, path[1:]) {
		return key
	}

	return ""
}

// mdocClaimKeyFromPath applies a claims path pointer to an mdoc, per §7.2.1.
// The data element identifier is matched exactly: "If the data element does
// not exist in the Credential then abort processing and return an error."
func mdocClaimKeyFromPath(cred StoredCredential, path []any) string {
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

// claimValuesAtPath returns the claims a claims path pointer selects (§7).
// Processing a pointer yields a set of claims, so an array wildcard
// contributes one entry per element.
func claimValuesAtPath(cred StoredCredential, path []any) []any {
	if len(path) == 0 {
		return nil
	}

	if cred.Format == "mso_mdoc" {
		key := mdocClaimKeyFromPath(cred, path)
		if key == "" {
			return nil
		}
		return []any{mdocValueAsJSON(cred.Claims[key])}
	}

	return selectJSONClaims(cred.Claims, path)
}

// selectJSONClaims applies a claims path pointer to a JSON-based credential,
// per §7.1: "A string value indicates that the respective key is to be
// selected, a null value indicates that all elements of the currently selected
// array(s) are to be selected; and a non-negative integer indicates that the
// respective index in an array is to be selected."
func selectJSONClaims(root map[string]any, path []any) []any {
	selection := []any{any(root)}

	for _, segment := range path {
		var next []any
		for _, value := range selection {
			switch seg := segment.(type) {
			case string:
				obj, ok := value.(map[string]any)
				if !ok {
					continue
				}
				if v, exists := obj[seg]; exists {
					next = append(next, v)
				}
			case nil:
				arr, ok := value.([]any)
				if !ok {
					continue
				}
				next = append(next, arr...)
			default:
				idx, ok := claimPathIndex(seg)
				if !ok {
					return nil
				}
				arr, isArr := value.([]any)
				if !isArr || idx >= len(arr) {
					continue
				}
				next = append(next, arr[idx])
			}
		}
		// §7.1: "If the set of elements currently selected is empty, abort
		// processing and return an error."
		if len(next) == 0 {
			return nil
		}
		selection = next
	}

	return selection
}

// claimPathIndex reads an array index segment. §7: "A claims path pointer MUST
// be a non-empty array of strings, nulls and non-negative integers". JSON
// decoding returns those integers as float64.
func claimPathIndex(segment any) (int, bool) {
	switch v := segment.(type) {
	case float64:
		if v < 0 || v != float64(int(v)) {
			return 0, false
		}
		return int(v), true
	case int:
		if v < 0 {
			return 0, false
		}
		return v, true
	default:
		return 0, false
	}
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

func claimPathExists(value any, path []any) bool {
	if len(path) == 0 {
		return true
	}

	switch segment := path[0].(type) {
	case string:
		obj, ok := value.(map[string]any)
		if !ok {
			return false
		}
		next, exists := obj[segment]
		if !exists {
			return false
		}
		return claimPathExists(next, path[1:])
	case float64:
		arr, ok := value.([]any)
		if !ok {
			return false
		}
		idx := int(segment)
		if idx < 0 || idx >= len(arr) {
			return false
		}
		return claimPathExists(arr[idx], path[1:])
	case nil:
		arr, ok := value.([]any)
		if !ok {
			return false
		}
		if len(path) == 1 {
			return true
		}
		for _, item := range arr {
			if claimPathExists(item, path[1:]) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func filterClaims(cred StoredCredential, selectedKeys []string) map[string]any {
	filtered := make(map[string]any, len(selectedKeys))
	for _, k := range selectedKeys {
		if v, ok := claimValueBySelector(cred, k); ok {
			filtered[k] = v
		}
	}
	return filtered
}

func claimValueBySelector(cred StoredCredential, selector string) (any, bool) {
	if cred.Format == "mso_mdoc" {
		v, ok := cred.Claims[selector]
		return v, ok
	}

	path, ok := parseSDJWTSelector(selector)
	if !ok || len(path) == 0 {
		return nil, false
	}

	key, ok := path[0].(string)
	if !ok {
		return nil, false
	}
	value, ok := cred.Claims[key]
	if !ok {
		return nil, false
	}
	return claimValueAtPath(value, path[1:])
}

func parseSDJWTSelector(selector string) ([]any, bool) {
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

func claimValueAtPath(value any, path []any) (any, bool) {
	if len(path) == 0 {
		return value, true
	}

	switch segment := path[0].(type) {
	case string:
		obj, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		next, ok := obj[segment]
		if !ok {
			return nil, false
		}
		return claimValueAtPath(next, path[1:])
	case int:
		arr, ok := value.([]any)
		if !ok || segment < 0 || segment >= len(arr) {
			return nil, false
		}
		return claimValueAtPath(arr[segment], path[1:])
	case nil:
		arr, ok := value.([]any)
		if !ok {
			return nil, false
		}
		if len(path) < 2 {
			return arr, true
		}
		rest := path[1:]
		var out []any
		for _, item := range arr {
			if v, ok := claimValueAtPath(item, rest); ok {
				out = append(out, v)
			}
		}
		return out, len(out) > 0
	default:
		return nil, false
	}
}

// applyCredentialSets filters matches to satisfy credential_sets constraints,
// trying options containing the preferred format first. It returns nil when
// nothing may be returned: §6.4.2 requires a set to match "one of the options
// inside the Credential Set Query", and a wallet that "cannot deliver all
// non-optional Credentials [...] MUST NOT return any Credential(s)".
func applyCredentialSets(matches []CredentialMatch, credSets []any, preferredFormat string) []CredentialMatch {
	byQuery := make(map[string][]CredentialMatch)
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

	var result []CredentialMatch
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
// Each entry must have "type" and "values" (array) fields.
func checkTrustedAuthorities(cred StoredCredential, taList []any, clients ...*http.Client) bool {
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
				if checkETSITrustList(cred, u, clients...) {
					return true
				}
			}
		default:
			log.Printf("[DCQL]   trusted_authorities: unsupported type %q", taType)
		}
	}
	return false
}

func checkAuthorityKeyIdentifiers(cred StoredCredential, values []string) bool {
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

func extractCredentialCertificates(cred StoredCredential) ([]*x509.Certificate, error) {
	switch cred.Format {
	case "dc+sd-jwt":
		token, err := sdjwt.ParseLenient(cred.Raw)
		if err != nil {
			return nil, err
		}
		return extractX5CCertificates(token.Header)
	case "mso_mdoc":
		doc, err := mdoc.Parse(cred.Raw)
		if err != nil {
			return nil, err
		}
		return extractMDOCX5Chain(doc)
	default:
		return nil, nil
	}
}

func extractX5CCertificates(header map[string]any) ([]*x509.Certificate, error) {
	x5cRaw, ok := header["x5c"].([]any)
	if !ok || len(x5cRaw) == 0 {
		return nil, nil
	}

	certs := make([]*x509.Certificate, 0, len(x5cRaw))
	for _, entry := range x5cRaw {
		b64, ok := entry.(string)
		if !ok {
			return nil, nil
		}
		der, err := format.DecodeBase64Std(b64)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func extractMDOCX5Chain(doc *mdoc.Document) ([]*x509.Certificate, error) {
	if doc.IssuerAuth == nil || doc.IssuerAuth.UnprotectedHeader == nil {
		return nil, nil
	}

	x5chainRaw, ok := doc.IssuerAuth.UnprotectedHeader[int64(33)]
	if !ok {
		x5chainRaw, ok = doc.IssuerAuth.UnprotectedHeader[uint64(33)]
		if !ok {
			return nil, nil
		}
	}

	var certDERs [][]byte
	switch v := x5chainRaw.(type) {
	case []byte:
		certDERs = append(certDERs, v)
	case []any:
		for _, entry := range v {
			b, ok := entry.([]byte)
			if !ok {
				return nil, nil
			}
			certDERs = append(certDERs, b)
		}
	default:
		return nil, nil
	}

	certs := make([]*x509.Certificate, 0, len(certDERs))
	for _, der := range certDERs {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func checkETSITrustList(cred StoredCredential, trustListURL string, clients ...*http.Client) bool {
	tlRaw, err := format.FetchURL(trustListURL, clients...)
	// A verifier in Docker reaches the host as host.docker.internal. The wallet
	// on the host reaches the same server as localhost.
	if err != nil && strings.Contains(trustListURL, "host.docker.internal") {
		fallbackURL := strings.Replace(trustListURL, "host.docker.internal", "localhost", 1)
		log.Printf("[DCQL]   trusted_authorities: retrying with %s", fallbackURL)
		tlRaw, err = format.FetchURL(fallbackURL, clients...)
	}
	if err != nil {
		log.Printf("[DCQL]   trusted_authorities: failed to fetch trust list %s: %v", trustListURL, err)
		return false
	}

	tl, err := trustlist.Parse(tlRaw)
	if err != nil {
		log.Printf("[DCQL]   trusted_authorities: failed to parse trust list: %v", err)
		return false
	}

	tlCerts := trustlist.ExtractPublicKeys(tl)
	if len(tlCerts) == 0 {
		log.Printf("[DCQL]   trusted_authorities: trust list contains no certificates")
		return false
	}

	switch cred.Format {
	case "dc+sd-jwt":
		token, err := sdjwt.ParseLenient(cred.Raw)
		if err != nil {
			log.Printf("[DCQL]   trusted_authorities: failed to parse SD-JWT: %v", err)
			return false
		}
		key, err := validate.ExtractAndValidateX5C(token.Header, tlCerts)
		if err != nil {
			log.Printf("[DCQL]   trusted_authorities: x5c chain validation failed: %v", err)
			return false
		}
		return key != nil

	case "mso_mdoc":
		doc, err := mdoc.Parse(cred.Raw)
		if err != nil {
			log.Printf("[DCQL]   trusted_authorities: failed to parse mdoc: %v", err)
			return false
		}
		key, err := validate.ExtractAndValidateMDOCX5Chain(doc, tlCerts)
		if err != nil {
			log.Printf("[DCQL]   trusted_authorities: x5chain validation failed: %v", err)
			return false
		}
		return key != nil

	default:
		log.Printf("[DCQL]   trusted_authorities: unsupported credential format %q for chain validation", cred.Format)
		return false
	}
}
