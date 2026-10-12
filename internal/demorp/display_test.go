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

package demorp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// OpenID4VCI §12.2.4 display metadata gives external wallets a logo and ticket colors
// to render.
func TestIssuerDisplayMetadata(t *testing.T) {
	d, _, _ := newDemoRP(t)
	handler := d.IssuerHandler()

	status, meta := doJSON(t, handler, "GET", "/.well-known/openid-credential-issuer", "", nil)
	if status != http.StatusOK {
		t.Fatalf("metadata status = %d", status)
	}

	issuerDisplay, _ := meta["display"].([]any)
	if len(issuerDisplay) == 0 {
		t.Fatal("issuer metadata declares no display")
	}
	entry, _ := issuerDisplay[0].(map[string]any)
	logo, _ := entry["logo"].(map[string]any)
	logoURI, _ := logo["uri"].(string)
	if !strings.HasSuffix(logoURI, "/issuer/logo.svg") {
		t.Errorf("issuer logo uri = %q", logoURI)
	}

	configs, _ := meta["credential_configurations_supported"].(map[string]any)
	ticket, _ := configs[ticketConfigurationID].(map[string]any)
	if ticket == nil {
		for id := range configs {
			t.Logf("configuration: %s", id)
		}
		t.Fatal("ticket configuration not found")
	}
	credMeta, _ := ticket["credential_metadata"].(map[string]any)
	display, _ := credMeta["display"].([]any)
	if len(display) == 0 {
		t.Fatal("ticket configuration declares no display")
	}
	ticketDisplay, _ := display[0].(map[string]any)
	if bg, _ := ticketDisplay["background_color"].(string); bg == "" {
		t.Error("ticket display has no background_color")
	}
	if tc, _ := ticketDisplay["text_color"].(string); tc == "" {
		t.Error("ticket display has no text_color")
	}
	ticketLogo, _ := ticketDisplay["logo"].(map[string]any)
	// The ticket is a template, so the issuer serves its logo with the
	// template images.
	if uri, _ := ticketLogo["uri"].(string); !strings.HasSuffix(uri, "/issuer/templates/demo-ticket/logo") {
		t.Errorf("ticket logo uri = %q", uri)
	}

	// The configuration's claims carry the template's display names.
	claims, _ := credMeta["claims"].([]any)
	var seatName string
	for _, raw := range claims {
		claim, _ := raw.(map[string]any)
		if path, _ := claim["path"].([]any); len(path) == 1 && path[0] == "seat" {
			claimDisplay, _ := claim["display"].([]any)
			if len(claimDisplay) > 0 {
				seatName, _ = claimDisplay[0].(map[string]any)["name"].(string)
			}
		}
	}
	if seatName != "Seat" {
		t.Errorf("seat display name = %q, want Seat", seatName)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/logo.svg", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("logo status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/svg+xml" {
		t.Errorf("logo content type = %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "<svg") {
		t.Error("logo body is not an SVG")
	}
}
