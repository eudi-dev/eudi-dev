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
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/dcql"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
)

func captureTestLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	origWriter := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)

	t.Cleanup(func() {
		log.SetOutput(origWriter)
		log.SetFlags(origFlags)
	})

	return &buf
}

func evaluateDCQL(t testing.TB, w *Wallet, query map[string]any) []consent.Match {
	t.Helper()
	matches, _ := w.matchDCQL(query)
	return matches
}

func evaluateDCQLWithOptions(t testing.TB, w *Wallet, query map[string]any) ([]consent.Match, *consent.CredentialOptions) {
	t.Helper()
	return w.matchDCQL(query)
}

func TestEvaluateDCQL_MatchesSDJWTByVCT(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
					map[string]any{"path": []any{"family_name"}},
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	m := matches[0]
	if m.QueryID != "pid" {
		t.Errorf("expected query ID 'pid', got %s", m.QueryID)
	}
	if m.Format != "dc+sd-jwt" {
		t.Errorf("expected format dc+sd-jwt, got %s", m.Format)
	}
	if m.VCT != mock.DefaultPIDVCT {
		t.Errorf("expected VCT urn:eudi:pid:1, got %s", m.VCT)
	}
	if len(m.SelectedKeys) != 2 {
		t.Errorf("expected 2 selected keys, got %d: %v", len(m.SelectedKeys), m.SelectedKeys)
	}
}

func TestEvaluateDCQL_MatchesMDocByDocType(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid_mdoc",
				"format": "mso_mdoc",
				"meta": map[string]any{
					"doctype_value": "eu.europa.ec.eudi.pid.1",
				},
				"claims": []any{
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "given_name"}},
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	m := matches[0]
	if m.QueryID != "pid_mdoc" {
		t.Errorf("expected query ID 'pid_mdoc', got %s", m.QueryID)
	}
	if m.Format != "mso_mdoc" {
		t.Errorf("expected format mso_mdoc, got %s", m.Format)
	}
	if m.DocType != "eu.europa.ec.eudi.pid.1" {
		t.Errorf("expected DocType eu.europa.ec.eudi.pid.1, got %s", m.DocType)
	}
}

func TestEvaluateDCQL_NoMatchWrongVCT(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "other",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{"urn:eudi:mdl:1"},
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for wrong VCT, got %d", len(matches))
	}
}

func TestEvaluateDCQL_NoMatchWrongFormat(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "wrong",
				"format": "jwt_vc",
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for wrong format, got %d", len(matches))
	}
}

func TestEvaluateDCQL_NoClaims_DebugSelectsNoSDJWTClaims(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeDebug

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "all",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if len(matches[0].SelectedKeys) != 0 {
		t.Fatalf("expected no selected claims in debug mode, got %v", matches[0].SelectedKeys)
	}
	if len(matches[0].Claims) != 0 {
		t.Fatalf("expected no disclosed claims in debug mode, got %v", matches[0].Claims)
	}
}

func TestEvaluateDCQL_NoClaims_DebugSelectsNoMDocElements(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeDebug

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid_mdoc",
				"format": "mso_mdoc",
				"meta": map[string]any{
					"doctype_value": "eu.europa.ec.eudi.pid.1",
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if len(matches[0].SelectedKeys) != 0 {
		t.Fatalf("expected no selected mdoc elements in debug mode, got %v", matches[0].SelectedKeys)
	}
	if len(matches[0].Claims) != 0 {
		t.Fatalf("expected no disclosed mdoc elements in debug mode, got %v", matches[0].Claims)
	}
}

func TestEvaluateDCQL_NoClaims_StrictSelectsNoSDJWTClaims(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeStrict

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if len(matches[0].SelectedKeys) != 0 {
		t.Fatalf("expected no selected claims in strict mode, got %v", matches[0].SelectedKeys)
	}
	if len(matches[0].Claims) != 0 {
		t.Fatalf("expected no disclosed claims in strict mode, got %v", matches[0].Claims)
	}
}

func TestEvaluateDCQL_NoClaims_StrictSelectsNoMDocElements(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeStrict

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid_mdoc",
				"format": "mso_mdoc",
				"meta": map[string]any{
					"doctype_value": "eu.europa.ec.eudi.pid.1",
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if len(matches[0].SelectedKeys) != 0 {
		t.Fatalf("expected no selected mdoc elements in strict mode, got %v", matches[0].SelectedKeys)
	}
	if len(matches[0].Claims) != 0 {
		t.Fatalf("expected no disclosed mdoc elements in strict mode, got %v", matches[0].Claims)
	}
}

func TestEvaluateDCQL_ClaimNotFound(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "missing",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"nonexistent_claim"}},
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches when required claim not found, got %d", len(matches))
	}
}

func TestEvaluateDCQL_MissingRequiredClaim_DebugModeWarnsAndMatches(t *testing.T) {
	w := generateTestWalletWithPID(t)
	logs := captureTestLogs(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "partial",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
					map[string]any{"path": []any{"nonexistent_claim"}},
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match in debug mode, got %d", len(matches))
	}
	if len(matches[0].SelectedKeys) != 1 || matches[0].SelectedKeys[0] != "given_name" {
		t.Fatalf("expected selected keys [given_name], got %v", matches[0].SelectedKeys)
	}
	if _, ok := matches[0].Claims["given_name"]; !ok {
		t.Fatal("expected given_name claim in matched credential")
	}
	if strings.Contains(logs.String(), "Warning:") == false {
		t.Fatalf("expected warning log, got %q", logs.String())
	}
	if strings.Contains(logs.String(), "nonexistent_claim") == false {
		t.Fatalf("expected missing claim path in logs, got %q", logs.String())
	}
}

func TestEvaluateDCQL_MultipleCredentialQueries(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid_sdjwt",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
			map[string]any{
				"id":     "pid_mdoc",
				"format": "mso_mdoc",
				"meta": map[string]any{
					"doctype_value": "eu.europa.ec.eudi.pid.1",
				},
				"claims": []any{
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "given_name"}},
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}

	foundSDJWT := false
	foundMDoc := false
	for _, m := range matches {
		if m.QueryID == "pid_sdjwt" {
			foundSDJWT = true
		}
		if m.QueryID == "pid_mdoc" {
			foundMDoc = true
		}
	}
	if !foundSDJWT {
		t.Error("expected match for pid_sdjwt")
	}
	if !foundMDoc {
		t.Error("expected match for pid_mdoc")
	}
}

func TestEvaluateDCQL_DefaultPIDMatchesVerifierQueries(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "cred1",
				"format": "mso_mdoc",
				"meta": map[string]any{
					"doctype_value": "eu.europa.ec.eudi.pid.1",
				},
				"claims": []any{
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "family_name"}},
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "birth_date"}},
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "resident_city"}},
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "expiry_date"}},
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "issuing_country"}},
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "place_of_birth"}},
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "resident_street"}},
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "resident_country"}},
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "issuing_authority"}},
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "resident_state"}},
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "given_name"}},
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "resident_postal_code"}},
				},
			},
			map[string]any{
				"id":     "cred2",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
					map[string]any{"path": []any{"date_of_expiry"}},
					map[string]any{"path": []any{"family_name"}},
					map[string]any{"path": []any{"address", "street_address"}},
					map[string]any{"path": []any{"place_of_birth", "locality"}},
					map[string]any{"path": []any{"birthdate"}},
					map[string]any{"path": []any{"address", "region"}},
					map[string]any{"path": []any{"address", "postal_code"}},
					map[string]any{"path": []any{"issuing_country"}},
					map[string]any{"path": []any{"address", "locality"}},
					map[string]any{"path": []any{"address", "country"}},
					map[string]any{"path": []any{"issuing_authority"}},
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}

	for _, match := range matches {
		switch match.QueryID {
		case "cred1":
			if _, ok := match.Claims["eu.europa.ec.eudi.pid.1:place_of_birth"]; !ok {
				t.Error("expected mdoc match to include place_of_birth")
			}
		case "cred2":
			if _, ok := match.Claims["place_of_birth.locality"]; !ok {
				t.Error("expected SD-JWT match to include place_of_birth.locality")
			}
			if _, ok := match.Claims["address.street_address"]; !ok {
				t.Error("expected SD-JWT match to include address.street_address")
			}
			// The PID Rulebook requires a German PID to carry these.
			if _, ok := match.Claims["date_of_expiry"]; !ok {
				t.Error("expected SD-JWT match to include date_of_expiry")
			}
			if _, ok := match.Claims["address.region"]; !ok {
				t.Error("expected SD-JWT match to include address.region")
			}
		default:
			t.Errorf("unexpected query ID %q", match.QueryID)
		}
	}
}

func TestEvaluateDCQL_ClaimSets_StringIDs(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid_sd_jwt",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"id": "family", "path": []any{"family_name"}},
					map[string]any{"id": "given", "path": []any{"given_name"}},
					map[string]any{"id": "birth", "path": []any{"birthdate"}},
				},
				"claim_sets": []any{
					[]any{"family", "given", "birth"},
					[]any{"family", "given"},
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	if len(matches[0].SelectedKeys) != 3 {
		t.Errorf("expected 3 selected keys (first claim_set), got %d: %v",
			len(matches[0].SelectedKeys), matches[0].SelectedKeys)
	}
}

func TestEvaluateDCQL_ClaimSets_FallbackToSecond(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"id": "family", "path": []any{"family_name"}},
					map[string]any{"id": "given", "path": []any{"given_name"}},
					map[string]any{"id": "nickname", "path": []any{"nickname"}}, // not in PID
				},
				"claim_sets": []any{
					[]any{"family", "nickname"}, // unsatisfiable
					[]any{"family", "given"},    // satisfiable
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	if len(matches[0].SelectedKeys) != 2 {
		t.Errorf("expected 2 selected keys (second claim_set), got %d: %v",
			len(matches[0].SelectedKeys), matches[0].SelectedKeys)
	}
}

func TestEvaluateDCQL_ClaimSets_NoneMatchable(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"id": "nickname", "path": []any{"nickname"}},
					map[string]any{"id": "website", "path": []any{"website"}},
				},
				"claim_sets": []any{
					[]any{"nickname"},
					[]any{"website"},
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches when no claim_set satisfiable, got %d", len(matches))
	}
}

func TestEvaluateDCQL_ClaimSets_IntegerIndicesRejected(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
					map[string]any{"path": []any{"family_name"}},
				},
				"claim_sets": []any{
					[]any{float64(0), float64(1)},
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches when claim_sets uses integer indices, got %d", len(matches))
	}
}

func TestEvaluateDCQL_CredentialSets_Required(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid_sdjwt",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
			map[string]any{
				"id":     "pid_mdoc",
				"format": "mso_mdoc",
				"meta": map[string]any{
					"doctype_value": "eu.europa.ec.eudi.pid.1",
				},
				"claims": []any{
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "given_name"}},
				},
			},
		},
		"credential_sets": []any{
			map[string]any{
				"required": true,
				"options": []any{
					[]any{"pid_sdjwt"},
					[]any{"pid_mdoc"},
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match (first option), got %d", len(matches))
	}
	if matches[0].QueryID != "pid_sdjwt" {
		t.Errorf("expected first option pid_sdjwt, got %s", matches[0].QueryID)
	}
}

func TestEvaluateDCQL_CredentialSets_RequiredUnsatisfiable(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "mdl",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{"urn:eudi:mdl:1"}, // not available
				},
			},
		},
		"credential_sets": []any{
			map[string]any{
				"required": true,
				"options": []any{
					[]any{"mdl"},
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if matches != nil {
		t.Errorf("expected nil for unsatisfiable required credential_set, got %d matches", len(matches))
	}
}

func TestEvaluateDCQL_PartialClaimMatch_StrictModeRejected(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeStrict

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
					map[string]any{"path": []any{"nonexistent_claim"}},
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for partial claim match in strict mode, got %d", len(matches))
	}
}

func TestEvaluateDCQL_OptionalClaimMissing_Accepted(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
					map[string]any{"path": []any{"nonexistent_claim"}, "required": false},
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match with optional claim missing, got %d", len(matches))
	}
	if len(matches[0].SelectedKeys) != 1 {
		t.Errorf("expected 1 selected key (only given_name), got %d: %v",
			len(matches[0].SelectedKeys), matches[0].SelectedKeys)
	}
}

func serveTrustList(t *testing.T, tlJWT string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		fmt.Fprint(w, tlJWT)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// etsiTLQuery asks for the PID from an issuer on one of the trusted lists.
func etsiTLQuery(listURLs ...any) map[string]any {
	return map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
				"trusted_authorities": []any{
					map[string]any{"type": "etsi_tl", "values": listURLs},
				},
			},
		},
	}
}

// walletSignedList is a trusted list that the wallet CA signs, so the wallet
// trusts its operator. It lists anchor as the issuance service.
func walletSignedList(t *testing.T, w *Wallet, anchor *x509.Certificate) string {
	t.Helper()
	list, err := provider.SignTrustList(w.CAKey, w.CertChain[len(w.CertChain)-1], lote.Options{
		IssuanceCertificates: []string{base64.StdEncoding.EncodeToString(anchor.Raw)},
	})
	if err != nil {
		t.Fatalf("generating trusted list: %v", err)
	}
	return list
}

func TestEvaluateDCQL_TrustedAuthorities_Match(t *testing.T) {
	w := generateTestWalletWithPID(t)
	ts := serveTrustList(t, walletSignedList(t, w, w.CertChain[len(w.CertChain)-1]))

	matches := evaluateDCQL(t, w, etsiTLQuery(ts.URL))
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].QueryID != "pid" {
		t.Errorf("expected query ID 'pid', got %s", matches[0].QueryID)
	}
}

func TestEvaluateDCQL_TrustedAuthorities_NoMatch(t *testing.T) {
	w := generateTestWalletWithPID(t)

	otherKey, _ := mock.GenerateKey()
	otherCACert, _ := mock.GenerateCACert(otherKey)
	ts := serveTrustList(t, walletSignedList(t, w, otherCACert))

	assertUntrustedAuthorityBehavior(t, w, etsiTLQuery(ts.URL))
}

// The wallet reads its own lists in process, so a query can name them even
// when no server publishes them.
func TestEvaluateDCQL_TrustedAuthorities_WalletOwnList(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeStrict

	if matches := evaluateDCQL(t, w, etsiTLQuery(w.TrustedLists().OwnListURL("pid"))); len(matches) != 1 || matches[0].UntrustedAuthority {
		t.Fatalf("want the PID anchored by the wallet's own PID list, got %+v", matches)
	}
}

// A trusted list the wallet cannot use matches nothing and draws a warning.
// Debug mode offers the credential as untrusted. Strict mode offers nothing.
func TestEvaluateDCQL_TrustedAuthorities_UnusableList(t *testing.T) {
	otherKey, _ := mock.GenerateKey()
	otherCACert, _ := mock.GenerateCACert(otherKey)
	foreign, err := generateEAATrustListJWT(otherKey, otherCACert)
	if err != nil {
		t.Fatal(err)
	}
	foreignList := serveTrustList(t, foreign).URL
	for name, listURL := range map[string]string{
		"signed by an unknown operator": foreignList,
		"unreachable":                   "http://127.0.0.1:1/trustlist",
	} {
		t.Run(name, func(t *testing.T) {
			w := generateTestWalletWithPID(t)
			query := etsiTLQuery(listURL)

			assertUntrustedAuthorityBehavior(t, w, query)
			if !slices.ContainsFunc(w.Log, func(e LogEntry) bool { return e.Severity == severityWarning && strings.Contains(e.Detail, listURL) }) {
				t.Errorf("no warning names %s", listURL)
			}
		})
	}
}

// A verifier in Docker names the host as host.docker.internal. The wallet's
// HTTP client reaches the same list through localhost.
func TestEvaluateDCQL_TrustedAuthorities_DockerHostList(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeStrict
	ts := serveTrustList(t, walletSignedList(t, w, w.CertChain[len(w.CertChain)-1]))
	port := ts.URL[strings.LastIndex(ts.URL, ":")+1:]

	if matches := evaluateDCQL(t, w, etsiTLQuery("http://host.docker.internal:"+port)); len(matches) != 1 {
		t.Fatalf("want the PID anchored by the list on the Docker host, got %d matches", len(matches))
	}
}

// Debug mode offers an untrusted match with a flag. Strict mode returns no match.
func assertUntrustedAuthorityBehavior(t *testing.T, w *Wallet, query map[string]any) {
	t.Helper()
	w.ValidationMode = ValidationModeDebug
	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 || !matches[0].UntrustedAuthority {
		t.Fatalf("debug mode: want 1 match flagged UntrustedAuthority, got %d matches (flag on first: %v)", len(matches), len(matches) > 0 && matches[0].UntrustedAuthority)
	}
	w.ValidationMode = ValidationModeStrict
	if strict := evaluateDCQL(t, w, query); len(strict) != 0 {
		t.Fatalf("strict mode: want 0 matches, got %d", len(strict))
	}
}

func TestEvaluateDCQL_TrustedAuthorities_AKIMatch(t *testing.T) {
	w := generateTestWalletWithPID(t)
	aki := w.CertChain[0].AuthorityKeyId
	if len(aki) == 0 {
		t.Fatal("expected test credential leaf certificate to include an authority key identifier")
	}

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
				"trusted_authorities": []any{
					map[string]any{"type": "aki", "values": []any{format.EncodeBase64URL(aki)}},
				},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
}

// OID4VP 1.0 §6.1.1: "A Credential is identified as a match to a Trusted
// Authorities Query if it matches with one of the provided values in one of
// the provided types." A trusted list the wallet cannot read matches nothing,
// and the other entries still decide.
func TestEvaluateDCQL_TrustedAuthorities_UnreadableListMatchesNothing(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeStrict
	unreadable := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(unreadable.Close)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
				"claims": []any{map[string]any{"path": []any{"given_name"}}},
				"trusted_authorities": []any{
					map[string]any{"type": "etsi_tl", "values": []any{unreadable.URL}},
					map[string]any{"type": "aki", "values": []any{format.EncodeBase64URL(w.CertChain[0].AuthorityKeyId)}},
				},
			},
		},
	}

	if matches := evaluateDCQL(t, w, query); len(matches) != 1 {
		t.Fatalf("expected the aki entry to match, got %d matches", len(matches))
	}
}

// The automatic selection prefers trusted matches. Debug mode still offers
// untrusted ones with a warning.
func TestEvaluateDCQL_TrustedAuthorities_TrustedIsTheDefault(t *testing.T) {
	w := generateTestWalletWithPID(t)
	aki := w.CertChain[0].AuthorityKeyId

	untrusted, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer: "https://issuer.example", VCT: mock.DefaultPIDVCT,
		Claims: templateClaims("pid-sdjwt"), Key: w.IssuerKey, CertChain: nil, HolderKey: &w.HolderKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}
	if _, err := w.ImportCredential(untrusted); err != nil {
		t.Fatalf("ImportCredential: %v", err)
	}

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
				"claims": []any{map[string]any{"path": []any{"given_name"}}},
				"trusted_authorities": []any{
					map[string]any{"type": "aki", "values": []any{format.EncodeBase64URL(aki)}},
				},
			},
		},
	}

	matches, options := evaluateDCQLWithOptions(t, w, query)
	if len(matches) != 1 || matches[0].UntrustedAuthority {
		t.Fatalf("auto-pick should be the trusted credential, got %d matches (untrusted first: %v)", len(matches), len(matches) > 0 && matches[0].UntrustedAuthority)
	}
	if options == nil || len(options.Queries) != 1 || len(options.Queries[0].Candidates) != 2 {
		t.Fatalf("want both credentials offered as candidates, got %+v", options)
	}
	if options.Queries[0].Candidates[0].UntrustedAuthority || !options.Queries[0].Candidates[1].UntrustedAuthority {
		t.Errorf("candidates should be ordered trusted then untrusted, got %+v", options.Queries[0].Candidates)
	}
}

func TestEvaluateDCQL_TrustedAuthorities_AKINoMatch(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
				"trusted_authorities": []any{
					map[string]any{"type": "aki", "values": []any{format.EncodeBase64URL([]byte("wrong-aki"))}},
				},
			},
		},
	}

	assertUntrustedAuthorityBehavior(t, w, query)
}

func TestEvaluateDCQL_TrustedAuthorities_UnsupportedType(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
				"trusted_authorities": []any{
					map[string]any{"type": "unsupported", "values": []any{"some-value"}},
				},
			},
		},
	}

	assertUntrustedAuthorityBehavior(t, w, query)
}

func TestEvaluateDCQL_TrustedAuthorities_NoCertChain(t *testing.T) {
	w := generateTestWallet(t)

	sdRaw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       mock.DefaultPIDVCT,
		Claims:    templateClaims("pid-sdjwt"),
		Key:       w.IssuerKey,
		CertChain: nil, // no x5c
		HolderKey: &w.HolderKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}
	if _, err := w.ImportCredential(sdRaw); err != nil {
		t.Fatalf("ImportCredential: %v", err)
	}

	// A credential without x5c has no chain to match against the trusted list.
	// It is rejected even when the list contains the CA of its signer.
	ts := serveTrustList(t, walletSignedList(t, w, w.CertChain[len(w.CertChain)-1]))

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
				"trusted_authorities": []any{
					map[string]any{"type": "etsi_tl", "values": []any{ts.URL}},
				},
			},
		},
	}

	assertUntrustedAuthorityBehavior(t, w, query)
}

// Each credential set must be satisfied on its own. Options within one set
// are alternatives.
func TestEvaluateDCQL_CredentialSets_MultipleRequiredSets(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid_sdjwt",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
				"claims": []any{map[string]any{"path": []any{"given_name"}}},
			},
			map[string]any{
				"id":     "pid_mdoc",
				"format": "mso_mdoc",
				"meta":   map[string]any{"doctype_value": "eu.europa.ec.eudi.pid.1"},
				"claims": []any{map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "given_name"}}},
			},
		},
		// Two required sets ask for both credentials.
		"credential_sets": []any{
			map[string]any{"required": true, "options": []any{[]any{"pid_sdjwt"}}},
			map[string]any{"required": true, "options": []any{[]any{"pid_mdoc"}}},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 2 {
		t.Fatalf("expected both credentials, got %d", len(matches))
	}
	seen := map[string]bool{}
	for _, m := range matches {
		seen[m.QueryID] = true
	}
	if !seen["pid_sdjwt"] || !seen["pid_mdoc"] {
		t.Errorf("expected pid_sdjwt and pid_mdoc, got %v", seen)
	}
}

func TestEvaluateDCQL_CredentialSets_OptionAskingForTwoCredentials(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid_sdjwt",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
				"claims": []any{map[string]any{"path": []any{"given_name"}}},
			},
			map[string]any{
				"id":     "pid_mdoc",
				"format": "mso_mdoc",
				"meta":   map[string]any{"doctype_value": "eu.europa.ec.eudi.pid.1"},
				"claims": []any{map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "given_name"}}},
			},
		},
		// An option listing two ids needs both credentials.
		"credential_sets": []any{
			map[string]any{"options": []any{[]any{"pid_sdjwt", "pid_mdoc"}}},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 2 {
		t.Fatalf("an option naming two credentials should return both, got %d", len(matches))
	}
}

func TestEvaluateDCQL_CredentialSets_OptionalSetIsSkipped(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid_sdjwt",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
				"claims": []any{map[string]any{"path": []any{"given_name"}}},
			},
			map[string]any{
				"id":     "mdl",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{"urn:eudi:mdl:1"}}, // not held
			},
		},
		"credential_sets": []any{
			map[string]any{"required": true, "options": []any{[]any{"pid_sdjwt"}}},
			// The wallet holds no mDL, but the set is optional, so the query
			// still succeeds with what it does hold.
			map[string]any{"required": false, "options": []any{[]any{"mdl"}}},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if matches == nil {
		t.Fatal("an unsatisfiable optional set must not fail the whole query")
	}
	if len(matches) != 1 || matches[0].QueryID != "pid_sdjwt" {
		t.Fatalf("expected only pid_sdjwt, got %d matches: %+v", len(matches), matches)
	}
}

// addSDJWTPID stores an SD-JWT PID under the ID, issued at iat and bound to
// the holder key.
func addSDJWTPID(t *testing.T, w *Wallet, id string, iat int64) {
	t.Helper()
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	x, y, err := format.ECPublicCoords(&w.HolderKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	holder := map[string]any{"kty": "EC", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y)}
	raw, err := jws.Sign(
		map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"},
		map[string]any{"vct": mock.DefaultPIDVCT, "iat": iat, "given_name": "Ada", "family_name": "Lovelace", "cnf": map[string]any{"jwk": holder}},
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	w.Credentials = append(w.Credentials, StoredCredential{
		ID:     id,
		Format: "dc+sd-jwt",
		VCT:    mock.DefaultPIDVCT,
		Raw:    raw,
		Claims: map[string]any{"vct": mock.DefaultPIDVCT, "iat": iat, "given_name": "Ada", "family_name": "Lovelace"},
	})
}

func pidQuery() map[string]any {
	return map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
					map[string]any{"path": []any{"family_name"}},
				},
			},
		},
	}
}

func TestEvaluateDCQL_OneCredentialPerQueryNewestWins(t *testing.T) {
	w := generateTestWallet(t)
	addSDJWTPID(t, w, "older", 1000)
	addSDJWTPID(t, w, "newer", 3000)
	addSDJWTPID(t, w, "middle", 2000)

	matches := evaluateDCQL(t, w, pidQuery())

	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1 (the query asks for one credential)", len(matches))
	}
	if matches[0].CredentialID != "newer" {
		t.Errorf("presented %s, want the newest credential (newer)", matches[0].CredentialID)
	}
}

// The wallet presents the most recently issued credential, even when it was
// not the last one stored.
func TestEvaluateDCQL_NewestWinsEvenWhenStoredFirst(t *testing.T) {
	w := generateTestWallet(t)
	addSDJWTPID(t, w, "newest", 9000)
	addSDJWTPID(t, w, "oldest", 1000)

	matches := evaluateDCQL(t, w, pidQuery())

	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(matches))
	}
	if matches[0].CredentialID != "newest" {
		t.Errorf("presented %s, want newest", matches[0].CredentialID)
	}
}

func TestEvaluateDCQL_LogsMatchesAndGroupedSkipReasons(t *testing.T) {
	w := generateTestWallet(t)
	for i := 0; i < 3; i++ {
		addSDJWTPID(t, w, fmt.Sprintf("pid-%d", i), int64(1000+i))
	}
	logs := captureTestLogs(t)
	evaluateDCQL(t, w, pidQuery())
	out := logs.String()
	if strings.Count(out, "matched, selected claims") != 3 || !strings.Contains(out, "query=pid: 2 other candidates not presented") {
		t.Fatalf("a matching query logged:\n%s", out)
	}

	logs.Reset()
	evaluateDCQL(t, w, map[string]any{"credentials": []any{map[string]any{
		"id": "mdl", "format": "mso_mdoc",
		"meta":   map[string]any{"doctype_value": "org.iso.18013.5.1.mDL"},
		"claims": []any{map[string]any{"path": []any{"org.iso.18013.5.1", "family_name"}}},
	}}})
	if !strings.Contains(logs.String(), "query=mdl: no match among 3 credentials: 3 format dc+sd-jwt (want mso_mdoc)") {
		t.Fatalf("a query nothing answers logged:\n%s", logs.String())
	}
}

// Each credential query keeps its own match, so a request for several
// credential types returns one of each.
func TestEvaluateDCQL_DistinctQueriesEachKeepAMatch(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid_sdjwt",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
				"claims": []any{map[string]any{"path": []any{"given_name"}}},
			},
			map[string]any{
				"id":     "pid_mdoc",
				"format": "mso_mdoc",
				"meta":   map[string]any{"doctype_value": mock.PIDNamespace},
				"claims": []any{map[string]any{"path": []any{mock.PIDNamespace, "given_name"}}},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)

	if len(matches) != 2 {
		t.Fatalf("matches = %d, want 2 (one per query id)", len(matches))
	}
	seen := map[string]bool{}
	for _, m := range matches {
		seen[m.QueryID] = true
	}
	if !seen["pid_sdjwt"] || !seen["pid_mdoc"] {
		t.Errorf("query ids = %v, want both pid_sdjwt and pid_mdoc", seen)
	}
}

// A query requires holder binding by default (OpenID4VP 1.0 §6.1). Strict
// mode answers it only with a bound credential. Debug mode offers an unbound
// one, flagged and after the bound ones.
func TestEvaluateDCQL_HolderBinding(t *testing.T) {
	w := generateTestWallet(t)
	noStatus := ""
	for _, unbound := range []bool{true, false} {
		if _, err := w.IssueCredential(IssueOptions{Format: "sdjwt", VCT: "urn:example:bearer", Unbound: unbound, StatusListURI: &noStatus}); err != nil {
			t.Fatal(err)
		}
	}
	query := sdjwtVCTQuery("urn:example:bearer")

	w.ValidationMode = ValidationModeStrict
	_, options := evaluateDCQLWithOptions(t, w, query)
	if candidates := options.Queries[0].Candidates; len(candidates) != 1 || candidates[0].Unbound {
		t.Errorf("strict candidates %+v, want only the bound credential", candidates)
	}

	w.ValidationMode = ValidationModeDebug
	_, options = evaluateDCQLWithOptions(t, w, query)
	if candidates := options.Queries[0].Candidates; len(candidates) != 2 || candidates[0].Unbound || !candidates[1].Unbound {
		t.Errorf("debug candidates %+v, want the bound credential first and the unbound one flagged", candidates)
	}

	query["credentials"].([]any)[0].(map[string]any)["require_cryptographic_holder_binding"] = false
	_, options = evaluateDCQLWithOptions(t, w, query)
	if candidates := options.Queries[0].Candidates; len(candidates) != 2 || candidates[0].Unbound || candidates[1].Unbound {
		t.Errorf("candidates %+v, want both credentials unflagged when the query accepts unbound ones", candidates)
	}
}

func TestDCQLHolderBindingFlagMustBeBoolean(t *testing.T) {
	query := sdjwtVCTQuery("urn:example:bearer")
	query["credentials"].([]any)[0].(map[string]any)["require_cryptographic_holder_binding"] = "false"
	if findings := dcql.QueryFindings(query); len(findings) != 1 || !strings.Contains(findings[0], "require_cryptographic_holder_binding that is not a boolean") {
		t.Fatalf("findings = %v", findings)
	}
}

// The wallet presents a jwt_vc_json credential without a Verifiable
// Presentation, so in strict mode it answers only a query without holder
// binding (OpenID4VP 1.0 Appendix B.1).
func TestEvaluateDCQL_HolderBindingOfAJWTCredential(t *testing.T) {
	w := generateTestWallet(t)
	jwt, err := signJWT(map[string]any{"alg": "ES256", "typ": "JWT"}, map[string]any{"vct": "urn:test:credential", "given_name": "Erika"}, w.IssuerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ImportCredential(jwt); err != nil {
		t.Fatal(err)
	}
	w.ValidationMode = ValidationModeStrict
	for _, tc := range []struct {
		binding bool
		want    int
	}{{true, 0}, {false, 1}} {
		query := map[string]any{"credentials": []any{map[string]any{"id": "vc", "format": "jwt_vc_json", "meta": map[string]any{}, "require_cryptographic_holder_binding": tc.binding}}}
		if matches := evaluateDCQL(t, w, query); len(matches) != tc.want {
			t.Errorf("binding required %v: matches %v, want %d", tc.binding, matches, tc.want)
		}
	}
}

// Strict mode refuses to present an mdoc without deviceKey, so it does not
// match even a query that accepts unbound credentials.
func TestEvaluateDCQL_UnboundMdocInStrictMode(t *testing.T) {
	w := generateTestWallet(t)
	noStatus := ""
	if _, err := w.IssueCredential(IssueOptions{Format: "mdoc", DocType: "org.example.bearer", Unbound: true, StatusListURI: &noStatus}); err != nil {
		t.Fatal(err)
	}
	cq := mdocQuery("bearer", "org.example.bearer")
	cq["require_cryptographic_holder_binding"] = false
	query := map[string]any{"credentials": []any{cq}}
	w.ValidationMode = ValidationModeDebug
	if matches := evaluateDCQL(t, w, query); len(matches) != 1 {
		t.Fatalf("debug matches %v, want the unbound mdoc", matches)
	}
	w.ValidationMode = ValidationModeStrict
	if matches := evaluateDCQL(t, w, query); len(matches) != 0 {
		t.Errorf("strict matches %v, want none", matches)
	}
}

// Debug mode presents an unbound SD-JWT VC to a query that requires holder
// binding and says so in the activity log (OpenID4VP 1.0 §6.1).
func TestPresentingAnUnboundCredentialLeavesAWarning(t *testing.T) {
	w := generateTestWallet(t)
	noStatus := ""
	issued, err := w.IssueCredential(IssueOptions{Format: "sdjwt", VCT: "urn:example:bearer", Unbound: true, StatusListURI: &noStatus})
	if err != nil {
		t.Fatal(err)
	}
	match := consent.Match{QueryID: "q", CredentialID: issued.Credential.ID, Format: "dc+sd-jwt", VCT: "urn:example:bearer", Unbound: true}
	if _, err := w.createVPTokenMap([]consent.Match{match}, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "n", ClientID: "x509_hash:abc", ResponseMode: "direct_post"}}); err != nil {
		t.Fatal(err)
	}
	if !hasWarningContaining(w, "no holder binding") {
		t.Error("no warning about the unbound credential")
	}
}
