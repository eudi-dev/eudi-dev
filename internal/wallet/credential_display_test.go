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
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"image"
	"image/png"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

var tinyPNG, _ = base64.StdEncoding.DecodeString(
	"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")

// cardArtPNG is larger than the cache cap and shrinks to a small JPEG.
func cardArtPNG(t *testing.T) []byte {
	t.Helper()
	const width, height = 1700, 1080
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	state := uint32(1)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			offset := img.PixOffset(x, y)
			for c := 0; c < 3; c++ {
				state = state*1664525 + 1013904223
				dither := int(state>>16)%9 - 4
				band := 128 + 90*math.Sin((float64(x)+0.7*float64(y))/24+float64(c))
				img.Pix[offset+c] = uint8(min(255, max(0, int(band)+dither)))
			}
			img.Pix[offset+3] = 255
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encoding test art: %v", err)
	}
	if buf.Len() <= maxDisplayImageBytes {
		t.Fatalf("test art must exceed the cache cap, got %d bytes", buf.Len())
	}
	return buf.Bytes()
}

// pixelBombPNG is the 1x1 tinyPNG with an IHDR that declares 8192x8192 pixels,
// 67 megapixels past the 32-megapixel cap. A pixel bomb is a small file whose
// header declares huge dimensions.
func pixelBombPNG(t *testing.T) []byte {
	t.Helper()
	const side = 8192
	bomb := bytes.Clone(tinyPNG)
	// The IHDR chunk follows the 8-byte signature: length, type, 13 data bytes
	// starting with width and height, then a CRC over type and data.
	ihdr := bomb[12 : 12+4+13]
	binary.BigEndian.PutUint32(ihdr[4:], side)
	binary.BigEndian.PutUint32(ihdr[8:], side)
	binary.BigEndian.PutUint32(bomb[12+4+13:], crc32.ChecksumIEEE(ihdr))
	config, err := png.DecodeConfig(bytes.NewReader(bomb))
	if err != nil || config.Width != side || config.Height != side {
		t.Fatalf("crafted bomb header does not parse as %dx%d: %v", side, side, err)
	}
	return bomb
}

func displayIssuer(t *testing.T, w *Wallet, display []map[string]any) (*httptest.Server, string) {
	t.Helper()

	credRaw := generateTestCredential(t, w)
	var serverURL string

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":   serverURL,
				"credential_endpoint": serverURL + "/credential",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format":                "dc+sd-jwt",
						"vct":                   "urn:test:credential",
						"proof_types_supported": map[string]any{"jwt": map[string]any{"proof_signing_alg_values_supported": []any{"ES256"}}},
						"credential_metadata":   map[string]any{"display": display},
					},
				},
			})

		case strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			json.NewEncoder(rw).Encode(map[string]any{
				"issuer":         serverURL,
				"token_endpoint": serverURL + "/token",
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
				"c_nonce":      "test-c-nonce",
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			io.Copy(io.Discard, r.Body)
			json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}})

		case strings.HasSuffix(r.URL.Path, "/logo.png"):
			rw.Header().Set("Content-Type", "image/png")
			rw.Write(tinyPNG)

		case strings.HasSuffix(r.URL.Path, "/background.png"):
			rw.Header().Set("Content-Type", "image/png")
			rw.Write(tinyPNG)

		case strings.HasSuffix(r.URL.Path, "/huge.png"):
			rw.Header().Set("Content-Type", "image/png")
			rw.Write(bytes.Repeat([]byte{0x42}, maxDisplayImageBytes+1))

		case strings.HasSuffix(r.URL.Path, "/art.png"):
			rw.Header().Set("Content-Type", "image/png")
			rw.Write(cardArtPNG(t))

		case strings.HasSuffix(r.URL.Path, "/bomb.png"):
			rw.Header().Set("Content-Type", "image/png")
			rw.Write(pixelBombPNG(t))

		case strings.HasSuffix(r.URL.Path, "/page.html"):
			rw.Header().Set("Content-Type", "text/html")
			rw.Write([]byte("<html>not an image</html>"))

		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	serverURL = srv.URL
	// The display entries exist before the server URL, so image URIs use a
	// SERVER placeholder.
	for _, entry := range display {
		for _, key := range []string{"logo", "background_image"} {
			if obj, ok := entry[key].(map[string]any); ok {
				if uri, ok := obj["uri"].(string); ok {
					obj["uri"] = strings.Replace(uri, "SERVER", serverURL, 1)
				}
			}
		}
	}

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			preAuthorizedCodeGrant: map[string]any{"pre-authorized_code": "test-pre-auth-code"},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	return srv, "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))
}

func issueWithDisplay(t *testing.T, w *Wallet, display []map[string]any) *StoredCredential {
	t.Helper()
	srv, offerURI := displayIssuer(t, w, display)
	t.Cleanup(srv.Close)

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	for _, c := range w.GetCredentials() {
		if c.ID == result.CredentialID {
			return &c
		}
	}
	t.Fatalf("credential %s not in the store", result.CredentialID)
	return nil
}

// The wallet stores OpenID4VCI §12.2.4 display metadata and caches its
// images, so a card renders without contacting the issuer.
func TestProcessCredentialOffer_CredentialDisplay(t *testing.T) {
	t.Run("name, colors and images are stored with the credential", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name":             "Test Badge",
			"description":      "A styled test credential",
			"locale":           "en-US",
			"background_color": "#1a2b3c",
			"text_color":       "#ffffff",
			"logo":             map[string]any{"uri": "SERVER/logo.png", "alt_text": "Test issuer logo"},
			"background_image": map[string]any{"uri": "SERVER/background.png"},
		}})

		d := imported.Display
		if d == nil {
			t.Fatal("expected the credential to carry the display metadata")
		}
		if d.Name != "Test Badge" || d.Description != "A styled test credential" {
			t.Errorf("name/description = %q/%q", d.Name, d.Description)
		}
		if d.BackgroundColor != "#1a2b3c" || d.TextColor != "#ffffff" {
			t.Errorf("colors = %q/%q", d.BackgroundColor, d.TextColor)
		}
		if !strings.HasPrefix(d.LogoURI, "data:image/png;base64,") {
			t.Errorf("logo not cached as a data URI: %.60q", d.LogoURI)
		}
		if d.LogoAltText != "Test issuer logo" {
			t.Errorf("logo alt text = %q", d.LogoAltText)
		}
		if !strings.HasPrefix(d.BackgroundURI, "data:image/png;base64,") {
			t.Errorf("background image not cached as a data URI: %.60q", d.BackgroundURI)
		}
	})

	t.Run("an invalid color is dropped and warned about, the rest survives", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name":             "Test Badge",
			"background_color": "red;background:url(https://evil.example)",
			"text_color":       "#ffffff",
		}})

		d := imported.Display
		if d == nil || d.Name != "Test Badge" {
			t.Fatal("expected the display name to survive an invalid color")
		}
		if d.BackgroundColor != "" {
			t.Errorf("invalid background_color kept: %q", d.BackgroundColor)
		}
		if d.TextColor != "#ffffff" {
			t.Errorf("valid text_color dropped: %q", d.TextColor)
		}
		warning := findLogEntry(w.GetLog(), "credential_display_invalid")
		if warning == nil {
			t.Fatal("expected a credential_display_invalid entry")
		}
		if warning.Severity != severityWarning {
			t.Errorf("severity = %q, want %q", warning.Severity, severityWarning)
		}
		if !strings.Contains(warning.Detail, "background_color") {
			t.Errorf("detail does not name the field: %s", warning.Detail)
		}
	})

	t.Run("an image beyond the cap is rejected with a warning", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name": "Test Badge",
			"logo": map[string]any{"uri": "SERVER/huge.png"},
		}})

		if imported.Display == nil {
			t.Fatal("expected the display name to survive a rejected image")
		}
		if imported.Display.LogoURI != "" {
			t.Errorf("oversized logo should not be cached: %.60q", imported.Display.LogoURI)
		}
		if findLogEntry(w.GetLog(), "credential_display_image_rejected") == nil {
			t.Error("expected a credential_display_image_rejected entry")
		}
	})

	t.Run("a non-image answer is rejected with a warning", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name": "Test Badge",
			"logo": map[string]any{"uri": "SERVER/page.html"},
		}})

		if imported.Display == nil {
			t.Fatal("expected the display name to survive a rejected image")
		}
		if imported.Display.LogoURI != "" {
			t.Errorf("non-image logo should not be cached: %.60q", imported.Display.LogoURI)
		}
		if findLogEntry(w.GetLog(), "credential_display_image_rejected") == nil {
			t.Error("expected a credential_display_image_rejected entry")
		}
	})

	t.Run("card art beyond the cap is downscaled and cached", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name":             "Test Badge",
			"background_image": map[string]any{"uri": "SERVER/art.png"},
		}})

		d := imported.Display
		if d == nil || !strings.HasPrefix(d.BackgroundURI, "data:image/jpeg;base64,") {
			t.Fatalf("expected downscaled JPEG card art, got %.40q", d.BackgroundURI)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(d.BackgroundURI, "data:image/jpeg;base64,"))
		if err != nil {
			t.Fatalf("decoding cached art: %v", err)
		}
		if len(raw) > maxDisplayImageBytes {
			t.Errorf("cached art is %d bytes, over the %d cap", len(raw), maxDisplayImageBytes)
		}
		if entry := findLogEntry(w.GetLog(), "credential_display_image_rejected"); entry != nil {
			t.Errorf("downscalable art was rejected: %s", entry.Detail)
		}
	})

	t.Run("a pixel-bomb image is rejected before it is decoded whole", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name":             "Test Badge",
			"background_image": map[string]any{"uri": "SERVER/bomb.png"},
		}})

		if imported.Display == nil {
			t.Fatal("expected the display name to survive a rejected image")
		}
		if imported.Display.BackgroundURI != "" {
			t.Errorf("pixel bomb should not be cached: %.40q", imported.Display.BackgroundURI)
		}
		warning := findLogEntry(w.GetLog(), "credential_display_image_rejected")
		if warning == nil {
			t.Fatal("expected a credential_display_image_rejected entry")
		}
		if !strings.Contains(warning.Detail, "megapixel") {
			t.Errorf("detail does not name the dimension cap: %s", warning.Detail)
		}
	})

	t.Run("a data URI image is kept as it is", func(t *testing.T) {
		w := generateTestWallet(t)
		dataURI := "data:image/png;base64," + base64.StdEncoding.EncodeToString(tinyPNG)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name": "Test Badge",
			"logo": map[string]any{"uri": dataURI},
		}})

		if imported.Display == nil || imported.Display.LogoURI != dataURI {
			t.Errorf("data URI logo should be stored unchanged")
		}
	})

	t.Run("an SVG logo is kept", func(t *testing.T) {
		w := generateTestWallet(t)
		svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10"/></svg>`)
		dataURI := "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(svg)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name": "Test Badge",
			"logo": map[string]any{"uri": dataURI},
		}})

		// Issuers often use SVG logos, and an <img> tag renders them without
		// running scripts.
		if imported.Display == nil || imported.Display.LogoURI != dataURI {
			t.Errorf("SVG logo should be kept, got %.40q", imported.Display.LogoURI)
		}
	})

	t.Run("a low-contrast color pair is warned about and kept", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name":             "Test Badge",
			"background_color": "#888888",
			"text_color":       "#777777",
		}})

		d := imported.Display
		if d == nil || d.BackgroundColor != "#888888" || d.TextColor != "#777777" {
			t.Fatalf("expected the pair to be kept, got %+v", d)
		}
		warning := findLogEntry(w.GetLog(), "credential_display_low_contrast")
		if warning == nil {
			t.Fatal("expected a credential_display_low_contrast entry")
		}
		if !strings.Contains(warning.Detail, "3:1") {
			t.Errorf("detail does not name the threshold: %s", warning.Detail)
		}
	})

	t.Run("the summary carries the display for the UI", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, []map[string]any{{
			"name":             "Test Badge",
			"background_color": "#1a2b3c",
			"text_color":       "#ffffff",
		}})
		summary := CredentialSummary(*imported)
		d, ok := summary["display"].(map[string]any)
		if !ok || d["name"] != "Test Badge" {
			t.Errorf("summary display = %#v", summary["display"])
		}
	})

	t.Run("the summary references display images by URL, not inline data", func(t *testing.T) {
		c := StoredCredential{ID: "abc123", Display: &oid4vc.CredentialDisplay{
			Name:            "Art Badge",
			BackgroundColor: "#0f766e",
			LogoURI:         "data:image/png;base64," + base64.StdEncoding.EncodeToString(tinyPNG),
			BackgroundURI:   "data:image/jpeg;base64,/9j/4AAQ",
		}}
		d := CredentialSummary(c)["display"].(map[string]any)
		if d["logo_uri"] != "/api/credentials/abc123/display/logo" {
			t.Fatalf("logo_uri = %v, want a reference URL", d["logo_uri"])
		}
		if d["background_uri"] != "/api/credentials/abc123/display/background" {
			t.Fatalf("background_uri = %v, want a reference URL", d["background_uri"])
		}
		if d["background_color"] != "#0f766e" || d["name"] != "Art Badge" {
			t.Fatalf("non-image fields were dropped: %#v", d)
		}
	})

	t.Run("an external image URL is passed through unchanged", func(t *testing.T) {
		c := StoredCredential{ID: "x", Display: &oid4vc.CredentialDisplay{LogoURI: "https://issuer.example/logo.svg"}}
		d := CredentialSummary(c)["display"].(map[string]any)
		if d["logo_uri"] != "https://issuer.example/logo.svg" {
			t.Fatalf("external URL was rewritten: %v", d["logo_uri"])
		}
	})

	t.Run("a configuration without display stores none", func(t *testing.T) {
		w := generateTestWallet(t)
		imported := issueWithDisplay(t, w, nil)
		if imported.Display != nil {
			t.Errorf("expected no display, got %+v", imported.Display)
		}
	})
}

func TestGenerateDefaultCredentials_Display(t *testing.T) {
	w := generateTestWallet(t)
	for _, vct := range []string{mock.DefaultPIDVCT, germanPIDVCT} {
		if err := w.GenerateDefaultCredentials(nil, vct); err != nil {
			t.Fatalf("GenerateDefaultCredentials(%s): %v", vct, err)
		}
	}
	creds := w.GetCredentials()
	if len(creds) == 0 {
		t.Fatal("expected generated credentials")
	}
	for _, c := range creds {
		if c.Display == nil {
			t.Errorf("credential %s (%s) has no display", c.ID, c.Format)
			continue
		}
		if c.Display.Name == "" {
			t.Errorf("credential %s has no display name", c.ID)
		}
		if !strings.HasPrefix(c.Display.LogoURI, "data:image/svg+xml") {
			t.Errorf("credential %s does not carry the eudi-dev logo: %.40q", c.ID, c.Display.LogoURI)
		}
	}

	var german, independent *StoredCredential
	for i := range creds {
		switch creds[i].VCT {
		case germanPIDVCT:
			german = &creds[i]
		case mock.DefaultPIDVCT:
			independent = &creds[i]
		}
	}
	if german == nil || independent == nil {
		t.Fatalf("expected both PID types, got german=%v independent=%v", german != nil, independent != nil)
	}
	if german.Display.Name == independent.Display.Name {
		t.Errorf("the two PID types share the display name %q", german.Display.Name)
	}
	if !strings.HasPrefix(german.Display.BackgroundURI, "data:image/") {
		t.Errorf("the German PID carries no distinguishing background image: %.40q", german.Display.BackgroundURI)
	}
	if independent.Display.BackgroundURI != "" {
		t.Errorf("the country-independent PID should not carry a background image: %.40q", independent.Display.BackgroundURI)
	}
}

// Display image fetches follow the private address policy of ADR-0004,
// because issuer metadata is untrusted.
func TestCacheDisplayImage_BlocksInternalAddress(t *testing.T) {
	w := generateTestWallet(t)

	// The address policy lives in the default client.

	format.SetFetchPolicy(format.BlockPrivateAddresses)
	defer format.SetFetchPolicy(nil)

	// Loopback stands in for any internal target. The port is closed, so the
	// policy has to refuse at dial time for the test to see a policy error.
	got := w.cacheDisplayImage(nil, "http://127.0.0.1:9/internal.png", "logo")
	if got != "" {
		t.Errorf("a display image at an internal address was fetched: %.40q", got)
	}
	entry := findLogEntry(w.GetLog(), "credential_display_image_rejected")
	if entry == nil {
		t.Fatal("expected a credential_display_image_rejected entry")
	}
	if !strings.Contains(entry.Detail, "internal address") {
		t.Errorf("rejection does not name the policy block: %s", entry.Detail)
	}
}

func TestMergeCredentialDisplayOverlaysFields(t *testing.T) {
	base := &oid4vc.CredentialDisplay{Name: "Template", BackgroundColor: "#111", LogoURI: "logo", LogoAltText: "alt", BackgroundURI: "bg"}
	over := &oid4vc.CredentialDisplay{Name: "Custom", TextColor: "#fff"}
	got := mergeCredentialDisplay(base, over)
	if got.Name != "Custom" {
		t.Errorf("name not overridden: %q", got.Name)
	}
	if got.TextColor != "#fff" {
		t.Errorf("text color not laid over: %q", got.TextColor)
	}
	if got.BackgroundColor != "#111" {
		t.Errorf("base background color lost: %q", got.BackgroundColor)
	}
	if got.LogoURI != "logo" || got.BackgroundURI != "bg" {
		t.Error("base images were dropped by a name-only override")
	}
	if mergeCredentialDisplay(nil, over) != over {
		t.Error("a nil base should return the override unchanged")
	}
	if mergeCredentialDisplay(base, nil) != base {
		t.Error("a nil override should return the base unchanged")
	}
}

func TestIssueFromTemplateKeepsArtWhenNameOverridden(t *testing.T) {
	w := generateTestWallet(t)
	noStatus := ""
	res, err := w.IssueCredential(IssueOptions{
		Template:      "german-pid-sdjwt",
		StatusListURI: &noStatus,
		Display:       &IssueDisplay{Name: "My German PID"},
	})
	if err != nil {
		t.Fatalf("issuing from the German PID template: %v", err)
	}
	d := res.Credential.Display
	if d == nil {
		t.Fatal("the issued credential carries no display")
	}
	if d.Name != "My German PID" {
		t.Fatalf("display name = %q, want the override", d.Name)
	}
	if d.BackgroundURI == "" {
		t.Error("the template background image was dropped when the name was set")
	}
	if d.LogoURI == "" {
		t.Error("the template logo was dropped when the name was set")
	}
}

func TestIssueWithDisplayTemplateAppliesTemplateArt(t *testing.T) {
	w := generateTestWallet(t)
	noStatus := ""
	// The UI sends the claims of a template as explicit values and gives the
	// template name only for the display. Embedded images cannot travel in a form.
	res, err := w.IssueCredential(IssueOptions{
		Format:          "sdjwt",
		VCT:             "urn:example:pid",
		DisplayTemplate: "german-pid-sdjwt",
		StatusListURI:   &noStatus,
		Display:         &IssueDisplay{Name: "German PID", BackgroundColor: "#3d59a1"},
	})
	if err != nil {
		t.Fatalf("issuing with a display template: %v", err)
	}
	d := res.Credential.Display
	if d == nil {
		t.Fatal("the credential carries no display")
	}
	if d.BackgroundURI == "" || d.LogoURI == "" {
		t.Fatalf("the display template's art was not applied (bg=%q logo=%q)", d.BackgroundURI, d.LogoURI)
	}
	if d.Name != "German PID" {
		t.Fatalf("the name override was lost: %q", d.Name)
	}
}

func TestIssueUnboundCredentialHasNoHolderKey(t *testing.T) {
	w := generateTestWallet(t)
	noStatus := ""
	res, err := w.IssueCredential(IssueOptions{
		Format:        "sdjwt",
		VCT:           "urn:example:bearer",
		Unbound:       true,
		StatusListURI: &noStatus,
	})
	if err != nil {
		t.Fatalf("issuing an unbound credential: %v", err)
	}
	if credentialHolderBinding(res.Credential.Raw).Bound {
		t.Fatal("an unbound credential must carry no cnf")
	}
	if got := w.credentialHolderBindingState(*res.Credential); got != holderBindingNone {
		t.Fatalf("an unbound credential reads as %q, want no key binding", got)
	}

	bound, err := w.IssueCredential(IssueOptions{
		Format:        "sdjwt",
		VCT:           "urn:example:bound",
		StatusListURI: &noStatus,
	})
	if err != nil {
		t.Fatalf("issuing the default credential: %v", err)
	}
	if !credentialHolderBinding(bound.Credential.Raw).Bound {
		t.Fatal("the default credential must be bound to the wallet")
	}
}

func TestIssuedDisplayBoundsTextAndKeepsAltText(t *testing.T) {
	w := generateTestWallet(t)
	noStatus := ""
	longDesc := strings.Repeat("x", maxDisplayDescriptionRunes+200)
	res, err := w.IssueCredential(IssueOptions{
		Format:        "sdjwt",
		VCT:           "urn:example:x",
		StatusListURI: &noStatus,
		Display:       &IssueDisplay{Name: "Badge", Description: longDesc, LogoAltText: "the org logo"},
	})
	if err != nil {
		t.Fatalf("issuing with display: %v", err)
	}
	d := res.Credential.Display
	if d == nil {
		t.Fatal("the credential carries no display")
	}
	if got := len([]rune(d.Description)); got != maxDisplayDescriptionRunes {
		t.Fatalf("description was not capped: %d runes, want %d", got, maxDisplayDescriptionRunes)
	}
	if d.LogoAltText != "the org logo" {
		t.Fatalf("logo alt text was lost: %q", d.LogoAltText)
	}
}

func TestResolveCredentialDisplayBoundsIssuerText(t *testing.T) {
	w := generateTestWallet(t)
	metadata := map[string]any{
		"credential_configurations_supported": map[string]any{
			"cfg": map[string]any{
				"credential_metadata": map[string]any{
					"display": []any{
						map[string]any{
							"name":        strings.Repeat("N", 200),
							"description": strings.Repeat("d", maxDisplayDescriptionRunes+100),
							"locale":      strings.Repeat("l", 99),
						},
					},
				},
			},
		},
	}
	d := w.resolveCredentialDisplay(nil, metadata, "cfg")
	if d == nil {
		t.Fatal("no display resolved")
	}
	if len([]rune(d.Name)) != maxDisplayNameRunes {
		t.Fatalf("name not capped: %d", len([]rune(d.Name)))
	}
	if len([]rune(d.Description)) != maxDisplayDescriptionRunes {
		t.Fatalf("description not capped: %d", len([]rune(d.Description)))
	}
	if len([]rune(d.Locale)) != maxDisplayLocaleRunes {
		t.Fatalf("locale not capped: %d", len([]rune(d.Locale)))
	}
}

func TestPresentUnboundSDJWTOmitsKeyBinding(t *testing.T) {
	w := generateTestWallet(t)
	noStatus := ""
	res, err := w.IssueCredential(IssueOptions{
		Format: "sdjwt", VCT: "urn:example:bearer", Unbound: true, StatusListURI: &noStatus,
	})
	if err != nil {
		t.Fatalf("issuing an unbound credential: %v", err)
	}
	cred := *res.Credential
	key, err := w.batchSigningKey(cred)
	if err != nil {
		t.Fatalf("resolving the signing key: %v", err)
	}
	// A credential without cnf presents without a KB-JWT, so the token ends
	// with the final disclosure separator.
	token, err := w.createSDJWTPresentation(cred, nil, "nonce", "https://verifier.example", key)
	if err != nil {
		t.Fatalf("presenting the unbound credential: %v", err)
	}
	if !strings.HasSuffix(token, "~") {
		t.Fatalf("an unbound SD-JWT must present without a KB-JWT, got %q", token)
	}

	bound, err := w.IssueCredential(IssueOptions{
		Format: "sdjwt", VCT: "urn:example:bound", StatusListURI: &noStatus,
	})
	if err != nil {
		t.Fatalf("issuing a bound credential: %v", err)
	}
	bcred := *bound.Credential
	bkey, err := w.batchSigningKey(bcred)
	if err != nil {
		t.Fatalf("resolving the bound signing key: %v", err)
	}
	btoken, err := w.createSDJWTPresentation(bcred, nil, "nonce", "https://verifier.example", bkey)
	if err != nil {
		t.Fatalf("presenting the bound credential: %v", err)
	}
	if strings.HasSuffix(btoken, "~") {
		t.Fatal("a bound SD-JWT must carry a KB-JWT")
	}
}

func TestIssueUnboundBatchRejected(t *testing.T) {
	w := generateTestWallet(t)
	noStatus := ""
	if _, err := w.IssueCredential(IssueOptions{
		Format:        "sdjwt",
		VCT:           "urn:example:x",
		Unbound:       true,
		BatchSize:     3,
		StatusListURI: &noStatus,
	}); err == nil {
		t.Fatal("an unbound batch has no distinct keys and must be rejected")
	}
}

// ISO 18013-5 §9.1.2.4: an mdoc without MSO deviceKey cannot bind DeviceSigned
// to an issuer-vouched key. Strict mode refuses it, debug mode warns.
func TestPresentingAnMdocWithoutDeviceKey(t *testing.T) {
	for mode, wantErr := range map[ValidationMode]bool{ValidationModeStrict: true, ValidationModeDebug: false} {
		t.Run(string(mode), func(t *testing.T) {
			w := generateTestWallet(t)
			w.ValidationMode = mode
			noStatus := ""
			res, err := w.IssueCredential(IssueOptions{Format: "mdoc", DocType: "org.example.bearer", Unbound: true, StatusListURI: &noStatus})
			if err != nil {
				t.Fatalf("issuing an unbound mdoc: %v", err)
			}
			cred := *res.Credential
			key, err := w.batchSigningKey(cred)
			if err != nil {
				t.Fatal(err)
			}
			_, err = w.createMDocPresentation(cred, nil, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: "x509_hash:abc", Nonce: "n", ResponseURI: "https://verifier.example/response"}}, "", key)
			if (err != nil) != wantErr {
				t.Fatalf("error %v, want an error: %v", err, wantErr)
			}
		})
	}
}
