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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

func TestGetCredentialByID(t *testing.T) {
	srv := newTestServer(t, true)
	creds := srv.wallet.GetCredentials()
	if len(creds) == 0 {
		t.Fatal("expected test credentials")
	}

	resp := serverRequest(t, srv, http.MethodGet, "/api/credentials/"+creds[0].ID, "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	result := decodeJSON(t, resp)
	if result["id"] != creds[0].ID {
		t.Errorf("expected id %q, got %v", creds[0].ID, result["id"])
	}
	if result["format"] != creds[0].Format {
		t.Errorf("expected format %q, got %v", creds[0].Format, result["format"])
	}
	if result["raw"] != creds[0].Raw {
		t.Error("expected raw credential in response")
	}
}

func TestGetCredentialByIDNotFound(t *testing.T) {
	srv := newTestServer(t, true)
	resp := serverRequest(t, srv, http.MethodGet, "/api/credentials/nonexistent", "")
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.Code)
	}
}

func TestDeleteAllCredentials(t *testing.T) {
	srv := newTestServer(t, true)
	before := len(srv.wallet.GetCredentials())
	if before == 0 {
		t.Fatal("expected test credentials")
	}

	resp := serverRequest(t, srv, http.MethodDelete, "/api/credentials", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	result := decodeJSON(t, resp)
	if int(result["deleted"].(float64)) != before {
		t.Errorf("expected %d deleted, got %v", before, result["deleted"])
	}
	if remaining := len(srv.wallet.GetCredentials()); remaining != 0 {
		t.Errorf("expected empty wallet, got %d credentials", remaining)
	}
}

func TestIssueCredentialAPI(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantFormat string
	}{
		{"sdjwt with defaults", `{"format": "sdjwt"}`, "dc+sd-jwt"},
		{"sdjwt with pid claims", `{"format": "sdjwt", "pid": true, "omit": ["place_of_birth"]}`, "dc+sd-jwt"},
		{"jwt with custom claims", `{"format": "jwt", "claims": {"given_name": "Erika"}, "vct": "urn:example:vct"}`, "jwt_vc_json"},
		{"mdoc with defaults", `{"format": "mdoc", "exp": "24h", "nbf": "-1h"}`, "mso_mdoc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t, true)
			resp := serverRequest(t, srv, http.MethodPost, "/api/issue", tt.body)
			if resp.Code != http.StatusCreated {
				t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
			}
			result := decodeJSON(t, resp)
			if result["format"] != tt.wantFormat {
				t.Errorf("expected format %q, got %v", tt.wantFormat, result["format"])
			}
			raw, _ := result["raw"].(string)
			if raw == "" {
				t.Fatal("expected raw credential in response")
			}
			id, _ := result["id"].(string)
			if _, ok := srv.wallet.GetCredential(id); !ok {
				t.Errorf("expected credential %q stored in wallet", id)
			}
		})
	}
}

func TestIssueCredentialAPIDisplay(t *testing.T) {
	srv := newTestServer(t, true)
	tinyPNG := "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ/pLvAAAAAElFTkSuQmCC"
	body := `{"format":"sdjwt","vct":"urn:example:display","display":{"name":"Badge","description":"desc","background_color":"#0f766e","text_color":"#ffffff","logo":"` + tinyPNG + `"}}`
	resp := serverRequest(t, srv, http.MethodPost, "/api/issue", body)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
	}
	id, _ := decodeJSON(t, resp)["id"].(string)
	cred, ok := srv.wallet.GetCredential(id)
	if !ok || cred.Display == nil {
		t.Fatalf("issued credential carries no display: %+v", cred)
	}
	d := cred.Display
	if d.Name != "Badge" || d.Description != "desc" || d.BackgroundColor != "#0f766e" || d.TextColor != "#ffffff" {
		t.Errorf("display fields not stored: %+v", d)
	}
	if !strings.HasPrefix(d.LogoURI, "data:image/") {
		t.Errorf("logo not cached as a data URI: %.30q", d.LogoURI)
	}

	list := serverRequest(t, srv, http.MethodGet, "/api/credentials", "")
	listBody := list.Body.String()
	if strings.Contains(listBody, "data:image/") {
		t.Error("the credential listing still inlines a display image as a data URI")
	}
	// Omitting raw credentials and claim values keeps the overview response small even
	// when credentials contain images.
	if strings.Contains(listBody, `"raw":`) {
		t.Error("the credential listing still ships the raw credential string")
	}
	if strings.Contains(listBody, `"claims":`) {
		t.Error("the credential listing still ships the claim values")
	}
	if !strings.Contains(listBody, `"claim_count":`) {
		t.Error("the credential listing dropped the claim count")
	}
	one := serverRequest(t, srv, http.MethodGet, "/api/credentials/"+id, "")
	if !strings.Contains(one.Body.String(), `"raw":`) {
		t.Error("the single-credential GET dropped the raw credential")
	}

	img := serverRequest(t, srv, http.MethodGet, "/api/credentials/"+id+"/display/logo", "")
	if img.Code != http.StatusOK {
		t.Fatalf("display image GET: expected 200, got %d", img.Code)
	}
	if ct := img.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
	// The issuer chose the image, and an SVG opened on its own could run
	// scripts on the wallet's origin.
	if csp := img.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "sandbox") || img.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("display image served without the image sandbox: CSP %q", csp)
	}
	etag := img.Header().Get("ETag")
	// A reused credential ID can carry a new image, so the browser revalidates.
	if etag == "" || img.Header().Get("Cache-Control") != "no-cache" {
		t.Errorf("expected an ETag and Cache-Control no-cache, got etag=%q cache=%q", etag, img.Header().Get("Cache-Control"))
	}
	if img.Body.Len() == 0 {
		t.Error("the display image response is empty")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/credentials/"+id+"/display/logo", nil)
	req.Header.Set("If-None-Match", etag)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Errorf("conditional GET: expected 304, got %d", rec.Code)
	}
}

// Invalid display colors are ignored during issuance, as they are when processing
// offers.
func TestIssueCredentialAPIDropsInvalidColor(t *testing.T) {
	srv := newTestServer(t, true)
	body := `{"format":"sdjwt","vct":"urn:example:badcolor","display":{"name":"Bad","background_color":"#gggggg"}}`
	resp := serverRequest(t, srv, http.MethodPost, "/api/issue", body)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.Code)
	}
	id, _ := decodeJSON(t, resp)["id"].(string)
	cred, _ := srv.wallet.GetCredential(id)
	if cred.Display == nil || cred.Display.Name != "Bad" {
		t.Fatal("the display name should be kept")
	}
	if cred.Display.BackgroundColor != "" {
		t.Errorf("an invalid color should be dropped, got %q", cred.Display.BackgroundColor)
	}
}

// The PID template defines claims without restricting the credential format.
func TestIssueCredentialAPIPIDAsJWT(t *testing.T) {
	srv := newTestServer(t, true)
	resp := serverRequest(t, srv, http.MethodPost, "/api/issue", `{"format": "jwt", "pid": true}`)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
	}
	result := decodeJSON(t, resp)
	if result["format"] != "jwt_vc_json" {
		t.Errorf("expected format jwt_vc_json, got %v", result["format"])
	}
	claims, ok := result["claims"].(map[string]any)
	if !ok {
		t.Fatalf("expected claims object, got %v", result["claims"])
	}
	for _, name := range []string{"family_name", "given_name", "birthdate", "place_of_birth"} {
		if _, ok := claims[name]; !ok {
			t.Errorf("the issued JWT VC is missing the PID claim %q", name)
		}
	}
}

func TestIssueCredentialAPICustomClaims(t *testing.T) {
	srv := newTestServer(t, true)
	resp := serverRequest(t, srv, http.MethodPost, "/api/issue",
		`{"format": "sdjwt", "claims": {"given_name": "Erika", "family_name": "Mustermann"}}`)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
	}
	result := decodeJSON(t, resp)
	claims, ok := result["claims"].(map[string]any)
	if !ok {
		t.Fatalf("expected claims object, got %v", result["claims"])
	}
	if claims["given_name"] != "Erika" {
		t.Errorf("expected given_name claim, got %v", claims["given_name"])
	}
}

func TestIssueCredentialAPINamespacedMDOCClaims(t *testing.T) {
	srv := newTestServer(t, true)
	resp := serverRequest(t, srv, http.MethodPost, "/api/issue",
		`{"format": "mdoc", "claims": {"given_name": "Erika", "org.example.custom:loyalty_tier": "gold"}}`)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
	}
	result := decodeJSON(t, resp)
	claims, ok := result["claims"].(map[string]any)
	if !ok {
		t.Fatalf("expected claims object, got %v", result["claims"])
	}
	if claims["eu.europa.ec.eudi.pid.1:given_name"] != "Erika" {
		t.Errorf("expected given_name in default namespace, got claims %v", claims)
	}
	if claims["org.example.custom:loyalty_tier"] != "gold" {
		t.Errorf("expected loyalty_tier in custom namespace, got claims %v", claims)
	}
}

func TestIssueCredentialAPIInvalidRequests(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"missing format", `{}`},
		{"unknown format", `{"format": "x509"}`},
		{"invalid json", `{`},
		{"invalid exp", `{"format": "sdjwt", "exp": "tomorrow"}`},
		{"invalid nbf", `{"format": "sdjwt", "nbf": "tomorrow"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t, true)
			resp := serverRequest(t, srv, http.MethodPost, "/api/issue", tt.body)
			if resp.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", resp.Code, resp.Body.String())
			}
		})
	}
}

func TestCertificateExportAPI(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.IssuerURL = "https://localhost:18086"
	store := NewWalletStore(t.TempDir())
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatalf("initializing store: %v", err)
	}
	srv.SetStore(store)

	for _, path := range []string{"/api/certificates/ca", "/api/certificates/tls", "/api/certificates/relying-party-access-ca", "/api/certificates/registrar-ca"} {
		t.Run(path, func(t *testing.T) {
			resp := serverRequest(t, srv, http.MethodGet, path, "")
			if resp.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
			}
			if !strings.HasPrefix(resp.Body.String(), "-----BEGIN CERTIFICATE-----") {
				t.Errorf("expected PEM certificate, got %q", resp.Body.String()[:40])
			}

			resp = serverRequest(t, srv, http.MethodGet, path+"?format=jwks", "")
			if resp.Code != http.StatusOK {
				t.Fatalf("expected 200 for jwks, got %d: %s", resp.Code, resp.Body.String())
			}
			jwks := decodeJSON(t, resp)
			if _, ok := jwks["keys"]; !ok {
				t.Errorf("expected JWKS document, got %v", jwks)
			}

			resp = serverRequest(t, srv, http.MethodGet, path+"?format=der", "")
			if resp.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for unsupported format, got %d", resp.Code)
			}
		})
	}
}

func TestCertificateExportAPIWithoutStore(t *testing.T) {
	srv := newTestServer(t, true)
	resp := serverRequest(t, srv, http.MethodGet, "/api/certificates/ca", "")
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without store, got %d", resp.Code)
	}
}

// --adhoc-display-images keeps an issuer's https image URL, so the wallet's
// pages have to load images from the issuer.
func TestAdhocDisplayImagesLetPagesLoadIssuerImages(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.AdhocDisplayImages = true
	resp := serverRequest(t, srv, http.MethodGet, "/api/version", "")
	if csp := resp.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "img-src 'self' data: https:;") {
		t.Fatalf("CSP = %s", csp)
	}
}

// GET /api/config reads settings that PUT requests change at runtime. Run
// with -race.
func TestConfigReadsRuntimeSettingsUnderTheLock(t *testing.T) {
	srv := newTestServer(t, true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 20 {
			serverRequest(t, srv, http.MethodPut, "/api/config/preferred-format", `{"format":"mso_mdoc"}`)
			serverRequest(t, srv, http.MethodPut, "/api/config/auto-accept", `{"enabled":true}`)
		}
	}()
	for range 20 {
		serverRequest(t, srv, http.MethodGet, "/api/config", "")
	}
	<-done
}

// The flows read auto-accept while PUT /api/config/auto-accept changes it.
// Run with -race.
func TestFlowsReadAutoAcceptUnderTheLock(t *testing.T) {
	srv := newTestServer(t, true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 20 {
			serverRequest(t, srv, http.MethodPut, "/api/config/auto-accept", fmt.Sprintf(`{"enabled":%t}`, i%2 == 0))
		}
	}()
	for range 20 {
		srv.autoAccepts(&oid4vp.Request{})
	}
	<-done
}
