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

package apierror

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
)

// findings stays a text array for older clients. finding_details adds the rule
// and group of each.
func TestRefusalBodyListsTextsAndDetails(t *testing.T) {
	finding := findings.ARF.Registration("RPA_03").New("the request is not signed with a relying party access certificate in x5c")
	rec := httptest.NewRecorder()
	WriteErr(rec, http.StatusBadRequest, InvalidRequest, &findings.Error{Summary: "authorization request validation failed", Findings: findings.List{finding}})

	var body struct {
		Findings       []string           `json:"findings"`
		FindingDetails []findings.Finding `json:"finding_details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Findings) != 1 || body.Findings[0] != "ARF RPA_03: the request is not signed with a relying party access certificate in x5c" {
		t.Errorf("findings = %v", body.Findings)
	}
	if len(body.FindingDetails) != 1 || body.FindingDetails[0] != finding {
		t.Errorf("finding_details = %+v", body.FindingDetails)
	}
}
