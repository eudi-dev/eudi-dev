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
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v2/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
)

func sdjwtVCTQuery(vct string) map[string]any {
	return map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{vct}},
				"claims": []any{map[string]any{"path": []any{"given_name"}}},
			},
		},
	}
}

// A German PID must match the base PID type it extends.
func TestEvaluateDCQL_ExtendingTypeAnswersForTheTypeItExtends(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.GenerateDefaultCredentials(nil, mock.GermanPIDVCT); err != nil {
		t.Fatalf("generating the German PID: %v", err)
	}
	logs := captureTestLogs(t)

	matches := w.EvaluateDCQL(sdjwtVCTQuery(mock.DefaultPIDVCT))
	if len(matches) != 1 {
		t.Fatalf("expected the German PID to answer, got %d matches", len(matches))
	}
	if matches[0].VCT != mock.GermanPIDVCT {
		t.Errorf("matched vct = %q, want %q", matches[0].VCT, mock.GermanPIDVCT)
	}
	if !strings.Contains(logs.String(), "an extending type answers for the type it extends") {
		t.Error("the log does not say why a credential of another type matched")
	}
}

// A base PID cannot satisfy a request for German attributes.
func TestEvaluateDCQL_ExtendedTypeDoesNotAnswerForTheExtendingOne(t *testing.T) {
	w := generateTestWalletWithPID(t)

	if matches := w.EvaluateDCQL(sdjwtVCTQuery(mock.GermanPIDVCT)); len(matches) != 0 {
		t.Fatalf("the country-independent PID answered a request for the German type: %d matches", len(matches))
	}
}

func TestEvaluateDCQL_BothPIDTypesHeld(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.GenerateProtectedDefaults(); err != nil {
		t.Fatalf("generating the baseline: %v", err)
	}

	matches := w.EvaluateDCQL(sdjwtVCTQuery(mock.DefaultPIDVCT))
	if len(matches) != 1 {
		t.Fatalf("expected exactly one credential to be presented, got %d", len(matches))
	}

	german := w.EvaluateDCQL(sdjwtVCTQuery(mock.GermanPIDVCT))
	if len(german) != 1 {
		t.Fatalf("expected the German PID to answer its own type, got %d matches", len(german))
	}
	if german[0].VCT != mock.GermanPIDVCT {
		t.Errorf("matched vct = %q, want %q", german[0].VCT, mock.GermanPIDVCT)
	}
}

// A credential of an unknown type still matches the types in its aka_vcts
// claim (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.2). This lets an issuer state
// inheritance without retrievable Type Metadata.
func TestEvaluateDCQL_AkaVCTsFromAnUnknownType(t *testing.T) {
	w := generateTestWallet(t)
	w.Credentials = append(w.Credentials, StoredCredential{
		ID:     "regional-pid",
		Format: "dc+sd-jwt",
		VCT:    "urn:example:pid:xx:1",
		Claims: map[string]any{
			"given_name":          "ERIKA",
			credtype.AkaVCTsClaim: []any{mock.DefaultPIDVCT},
		},
	})

	matches := w.EvaluateDCQL(sdjwtVCTQuery(mock.DefaultPIDVCT))
	if len(matches) != 1 {
		t.Fatalf("expected the aka_vcts credential to answer, got %d matches", len(matches))
	}
	if matches[0].CredentialID != "regional-pid" {
		t.Errorf("matched credential = %q, want regional-pid", matches[0].CredentialID)
	}
}

// The mdoc PIDs share a doctype because ISO/IEC 18013-5 has no inheritance
// between document types. A doctype request reaches both. The German elements
// live in their own namespace.
func TestEvaluateDCQL_MDocPIDsShareTheirDoctype(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.GenerateProtectedDefaults(); err != nil {
		t.Fatalf("generating the baseline: %v", err)
	}

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "mso_mdoc",
				"meta":   map[string]any{"doctype_value": mock.PIDNamespace},
				"claims": []any{
					map[string]any{"path": []any{credtype.GermanPIDNamespace, "birth_name"}},
				},
			},
		},
	}

	matches := w.EvaluateDCQL(query)
	if len(matches) != 1 {
		t.Fatalf("expected the German mdoc PID to answer, got %d matches", len(matches))
	}
	if len(matches[0].Claims) == 0 {
		t.Error("the national element was not selected for disclosure")
	}
}
