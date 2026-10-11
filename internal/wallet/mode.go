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
	"fmt"
	"slices"
	"strings"
)

// ValidationMode decides whether normative findings stop a flow or become warnings.
type ValidationMode string

const (
	ValidationModeDebug  ValidationMode = "debug"
	ValidationModeStrict ValidationMode = "strict"
)

func ParseValidationMode(raw string) (ValidationMode, error) {
	switch ValidationMode(raw) {
	case "", ValidationModeDebug:
		return ValidationModeDebug, nil
	case ValidationModeStrict:
		return ValidationModeStrict, nil
	default:
		return "", fmt.Errorf("invalid validation mode %q (must be 'debug' or 'strict')", raw)
	}
}

// specCitedSummary names the specifications the findings cite. A finding
// starts with its citation, such as "OID4VP 1.0 §5.2:" or "ARF RPRC_19:".
func specCitedSummary(subject string, findings []string) string {
	var specs []string
	for _, finding := range findings {
		if spec := citedSpecification(finding); spec != "" && !slices.Contains(specs, spec) {
			specs = append(specs, spec)
		}
	}
	if len(specs) == 0 {
		return subject + " does not follow the specification"
	}
	return fmt.Sprintf("%s does not follow %s", subject, strings.Join(specs, " and "))
}

// citedSpecification is the citation before the first colon of a finding, up
// to its first section or rule reference. A citation names a version or
// standard number, or a reference, so plain prose before a colon is none.
func citedSpecification(finding string) string {
	citation, _, found := strings.Cut(finding, ":")
	if !found {
		return ""
	}
	var spec []string
	referenced, numbered := false, false
	for _, word := range strings.Fields(citation) {
		if isSectionReference(word) {
			referenced = true
			break
		}
		numbered = numbered || isVersionNumber(word)
		spec = append(spec, word)
	}
	if len(spec) == 0 || (!referenced && !numbered) {
		return ""
	}
	return strings.Join(spec, " ")
}

// isSectionReference matches §5.2, Appendix, Annex, Table and rule
// identifiers such as RPRC_19 or GEN-5.2.4-08.
func isSectionReference(word string) bool {
	if strings.HasPrefix(word, "§") || word == "Appendix" || word == "Annex" || word == "Table" {
		return true
	}
	letters := strings.IndexFunc(word, func(r rune) bool { return r < 'A' || r > 'Z' })
	return letters > 0 && letters+1 < len(word) && (word[letters] == '_' || word[letters] == '-') && word[letters+1] >= '0' && word[letters+1] <= '9'
}

// isVersionNumber matches 1.0, 18013-5 and similar.
func isVersionNumber(word string) bool {
	return strings.Trim(word, "0123456789.-") == "" && strings.ContainsAny(word, "0123456789")
}
