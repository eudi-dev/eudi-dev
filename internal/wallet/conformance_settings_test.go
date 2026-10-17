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
	"net/http"
	"testing"
)

// PUT /api/config/conformance takes the setting names reported by
// GET /api/config, so every reported setting can be changed.
func TestConformancePatchUsesTheReportedNames(t *testing.T) {
	srv := newTestServer(t, false)
	resp := serverRequest(t, srv, http.MethodPut, "/api/config/conformance",
		`{"validation_mode":"strict","require_haip":true,"require_arf":true,"require_encrypted_request":true,"vci_version":"1.1","key_attestation_level":"none","force_client_attestation":true,"tls_verify_override":false}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("PUT answered %d: %s", resp.Code, resp.Body.String())
	}
	config := decodeJSON(t, serverRequest(t, srv, http.MethodGet, "/api/config", ""))
	for key, want := range map[string]any{
		"validation_mode": "strict", "require_haip": true, "require_arf": true, "require_encrypted_request": true,
		"vci_version": "1.1", "key_attestation_level": "none", "force_client_attestation": true,
		"tls_verify_override": false, "tls_verify": false,
	} {
		if config[key] != want {
			t.Errorf("%s = %v, want %v", key, config[key], want)
		}
	}
}

// An unknown setting name is refused, so a misspelled setting does not pass
// unnoticed. An unknown preferred format is refused too.
func TestConformanceSettingsRefuseUnknownValues(t *testing.T) {
	srv := newTestServer(t, false)
	if resp := serverRequest(t, srv, http.MethodPut, "/api/config/conformance", `{"haip":true}`); resp.Code != http.StatusBadRequest {
		t.Errorf("PUT with an unknown member answered %d, want 400", resp.Code)
	}
	if resp := serverRequest(t, srv, http.MethodPut, "/api/config/preferred-format", `{"format":"sd-jwt"}`); resp.Code != http.StatusBadRequest {
		t.Errorf("PUT preferred-format with an unknown format answered %d, want 400", resp.Code)
	}
	if got := srv.wallet.PreferredFormatSetting(); got != "" {
		t.Errorf("preferred format = %q after a refused change", got)
	}
}

// The ARF builds on HAIP, so turning the ARF checks on turns the HAIP checks
// on. A require_haip value in the same patch wins.
func TestTurningARFOnTurnsHAIPOn(t *testing.T) {
	off := false
	on := true
	w := generateTestWallet(t)
	if err := w.UpdateConformance(ConformancePatch{RequireARF: &on, RequireHAIP: &off}); err != nil {
		t.Fatal(err)
	}
	if got := w.Conformance(); got.RequireHAIP || !got.RequireARF {
		t.Errorf("with require_haip false in the patch: require_haip=%v require_arf=%v, want only ARF on", got.RequireHAIP, got.RequireARF)
	}

	w = generateTestWallet(t)
	if err := w.UpdateConformance(ConformancePatch{RequireARF: &on}); err != nil {
		t.Fatal(err)
	}
	if got := w.Conformance(); !got.RequireHAIP || !got.RequireARF {
		t.Errorf("after turning ARF on: require_haip=%v require_arf=%v, want both on", got.RequireHAIP, got.RequireARF)
	}
	if err := w.UpdateConformance(ConformancePatch{RequireHAIP: &off}); err != nil {
		t.Fatal(err)
	}
	if got := w.Conformance(); got.RequireHAIP || !got.RequireARF {
		t.Errorf("after turning HAIP off: require_haip=%v require_arf=%v, want only ARF on", got.RequireHAIP, got.RequireARF)
	}
}
