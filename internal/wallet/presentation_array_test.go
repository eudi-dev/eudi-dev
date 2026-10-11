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
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/consent"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
)

func importNationalitiesPID(t *testing.T, w *Wallet) StoredCredential {
	t.Helper()
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       mock.DefaultPIDVCT,
		Claims:    templateClaims("pid-sdjwt"),
		Key:       w.IssuerKey,
		HolderKey: &w.HolderKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}
	cred, err := w.ImportCredential(raw)
	if err != nil {
		t.Fatalf("ImportCredential: %v", err)
	}
	return *cred
}

func presentedNationalities(t *testing.T, w *Wallet, m consent.Match) any {
	t.Helper()
	cred, _ := w.GetCredential(m.CredentialID)
	presentation, err := w.createSDJWTPresentation(cred, m.SelectedKeys, "nonce", "verifier", w.HolderKey)
	if err != nil {
		t.Fatalf("createSDJWTPresentation: %v", err)
	}
	token, err := sdjwt.Parse(presentation)
	if err != nil {
		t.Fatalf("parsing presentation: %v", err)
	}
	return token.ResolvedClaims["nationalities"]
}

func nationalitiesQuery(path ...any) map[string]any {
	return map[string]any{"credentials": []any{map[string]any{
		"id":     "pid",
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
		"claims": []any{map[string]any{"path": path}},
	}}}
}

// A path that ends at an array of selectively disclosable elements discloses the
// array without its elements. OpenID4VP 1.0 §7.1 selects elements with a null or
// an index. The wallet flags the claim so the consent dialog and the activity log
// can warn.
func TestPresentation_BareArrayPathDisclosesEmptyArray(t *testing.T) {
	w := generateTestWallet(t)
	importNationalitiesPID(t, w)

	matches := evaluateDCQL(t, w, nationalitiesQuery("nationalities"))
	if len(matches) != 1 {
		t.Fatalf("want one match, got %d", len(matches))
	}
	if !slices.Contains(matches[0].EmptyArrayClaims, "nationalities") {
		t.Fatalf("EmptyArrayClaims = %v, want it to name nationalities", matches[0].EmptyArrayClaims)
	}
	if arr, ok := presentedNationalities(t, w, matches[0]).([]any); !ok || len(arr) != 0 {
		t.Errorf("disclosed nationalities = %v, want an empty array", presentedNationalities(t, w, matches[0]))
	}
}

// An out-of-range array index is a missing claim. Debug mode can offer the credential
// with that warning if other claims match. Strict mode rejects it.
func TestPresentation_OutOfRangeIndexIsMissingNotDisclosed(t *testing.T) {
	w := generateTestWallet(t)
	importNationalitiesPID(t, w)

	query := map[string]any{"credentials": []any{map[string]any{
		"id":     "pid",
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
		"claims": []any{
			map[string]any{"path": []any{"given_name"}},
			map[string]any{"path": []any{"nationalities", float64(1)}},
		},
	}}}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 {
		t.Fatalf("want one match in debug mode, got %d", len(matches))
	}
	m := matches[0]
	if !slices.Contains(m.MissingClaims, "nationalities[1]") {
		t.Errorf("MissingClaims = %v, want it to name nationalities[1]", m.MissingClaims)
	}
	if _, ok := m.Claims["nationalities"]; ok {
		t.Errorf("nationalities should not be disclosed, got %v", m.Claims["nationalities"])
	}
	if _, ok := m.Claims["given_name"]; !ok {
		t.Errorf("given_name should be disclosed, claims = %v", m.Claims)
	}

	w.ValidationMode = ValidationModeStrict
	if got := evaluateDCQL(t, w, query); len(got) != 0 {
		t.Errorf("strict mode should not match an unsatisfiable request, got %d", len(got))
	}
}

// Group missing and empty-array claims into one presentation warning.
func TestPresentation_UndisclosedClaimsLoggedGrouped(t *testing.T) {
	w := generateTestWallet(t)
	importNationalitiesPID(t, w)

	query := map[string]any{"credentials": []any{map[string]any{
		"id":     "pid",
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
		"claims": []any{
			map[string]any{"path": []any{"nationalities"}},             // disclosed as []
			map[string]any{"path": []any{"nationalities", float64(1)}}, // out of range, missing
		},
	}}}
	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 {
		t.Fatalf("want one match, got %d", len(matches))
	}
	if _, err := vpToken(w, matches[0], &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "n", ClientID: "verifier"}}); err != nil {
		t.Fatalf("CreateVPToken: %v", err)
	}

	var warning *LogEntry
	entries := w.GetLog()
	for i, e := range entries {
		if e.Severity == severityWarning && strings.Contains(e.Detail, "does not disclose every requested claim") {
			warning = &entries[i]
			break
		}
	}
	if warning == nil {
		t.Fatal("no grouped presentation warning was logged")
	}
	if !strings.Contains(warning.Detail, "2 findings") {
		t.Errorf("warning detail = %q, want it to group 2 findings", warning.Detail)
	}
	findings := warning.Details["findings"]
	if !strings.Contains(fmt.Sprint(findings), "nationalities[1]") {
		t.Errorf("grouped findings %v do not mention the missing claim nationalities[1]", findings)
	}
}

func TestPresentation_NullArrayPathDisclosesElements(t *testing.T) {
	w := generateTestWallet(t)
	importNationalitiesPID(t, w)

	matches := evaluateDCQL(t, w, nationalitiesQuery("nationalities", nil))
	if len(matches) != 1 {
		t.Fatalf("want one match, got %d", len(matches))
	}
	if len(matches[0].EmptyArrayClaims) != 0 {
		t.Errorf("EmptyArrayClaims = %v, want none for a null selection", matches[0].EmptyArrayClaims)
	}
	arr, ok := presentedNationalities(t, w, matches[0]).([]any)
	if !ok || len(arr) != 1 || arr[0] != "NL" {
		t.Errorf("disclosed nationalities = %v, want [NL]", presentedNationalities(t, w, matches[0]))
	}
}
