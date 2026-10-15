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

// Package findings carries the failed checks of a credential, request or
// party. A refusal keeps them as a list, so every view can show them one by
// one.
package findings

import (
	"errors"
	"strings"
)

// Error refuses a flow because of its findings. Summary says what was
// checked, for example "authorization request validation failed".
type Error struct {
	Summary  string
	Findings []string
}

func (e *Error) Error() string {
	if len(e.Findings) == 0 {
		return e.Summary
	}
	return e.Summary + ": " + Join(e.Findings)
}

// Of returns the findings of err, or nil when err is no refusal on findings.
func Of(err error) []string {
	var e *Error
	if errors.As(err, &e) {
		return e.Findings
	}
	return nil
}

// Join writes findings as one text. Findings are sentences, so a period
// separates them.
func Join(findings []string) string {
	parts := make([]string, 0, len(findings))
	for _, finding := range findings {
		if finding = strings.TrimSuffix(strings.TrimSpace(finding), "."); finding != "" {
			parts = append(parts, finding)
		}
	}
	return strings.Join(parts, ". ")
}
