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

	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
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

// specCitedSummary names the specification of each finding once.
func specCitedSummary(subject string, list findings.List) string {
	var specs []string
	for _, finding := range list {
		if finding.Spec != "" && !slices.Contains(specs, finding.Spec) {
			specs = append(specs, finding.Spec)
		}
	}
	if len(specs) == 0 {
		return subject + " does not follow the specification"
	}
	return fmt.Sprintf("%s does not follow %s", subject, strings.Join(specs, " and "))
}
