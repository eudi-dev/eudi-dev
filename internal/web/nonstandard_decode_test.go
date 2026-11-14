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

package web

import (
	"os"
	"strings"
	"testing"
)

func TestValidate_NonStandardSDJWT(t *testing.T) {
	raw, err := os.ReadFile("../../pkg/sdjwt/testdata/nested_sd_alg.txt")
	if err != nil {
		t.Fatal(err)
	}
	out, err := Validate(strings.TrimSpace(string(raw)), ValidateOpts{Offline: true})
	if err != nil {
		t.Fatalf("Validate refused to decode: %v", err)
	}
	claims, _ := out["resolvedClaims"].(map[string]any)
	if claims["family_name"] != "Mustermann" {
		t.Fatalf("family_name not resolved: %v", claims["family_name"])
	}
	devs, _ := out["deviations"].([]string)
	if len(devs) == 0 {
		t.Fatalf("expected deviations, got none")
	}
	checks, _ := out["validation"].(map[string]any)["checks"].([]CheckResult)
	var statusCheck *CheckResult
	for i := range checks {
		if checks[i].Name == "status" {
			statusCheck = &checks[i]
		}
	}
	if statusCheck == nil || statusCheck.Status != "warning" || !strings.Contains(statusCheck.Detail, "StatusList2021Entry") {
		t.Fatalf("status check not a warning about the W3C format: %+v", statusCheck)
	}
}
