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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

func TestTemplatesListIncludesPredefined(t *testing.T) {
	srv := newTestServer(t, true)
	resp := serverRequest(t, srv, http.MethodGet, "/api/templates", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	templates := decodeJSONArray(t, resp)
	names := map[string]bool{}
	for _, item := range templates {
		tpl := item.(map[string]any)
		names[tpl["name"].(string)] = true
	}
	if !names["german-pid-sdjwt"] || !names["german-pid-mdoc"] {
		t.Errorf("predefined templates missing from list: %v", names)
	}
}

func TestTemplatesCRUD(t *testing.T) {
	srv := newTestServer(t, true)

	body := `{"format": "sdjwt", "vct": "urn:example:employee", "claims": {"employee_id": "E-1", "department": "IT"}, "always_disclosed": ["department"]}`
	resp := serverRequest(t, srv, http.MethodPut, "/api/templates/employee-card", body)
	if resp.Code != http.StatusOK {
		t.Fatalf("PUT expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	saved := decodeJSON(t, resp)
	if saved["name"] != "employee-card" || saved["vct"] != "urn:example:employee" {
		t.Errorf("unexpected saved template: %v", saved)
	}

	resp = serverRequest(t, srv, http.MethodGet, "/api/templates/employee-card", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("GET expected 200, got %d", resp.Code)
	}

	resp = serverRequest(t, srv, http.MethodDelete, "/api/templates/employee-card", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("DELETE expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	resp = serverRequest(t, srv, http.MethodGet, "/api/templates/employee-card", "")
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", resp.Code)
	}
	resp = serverRequest(t, srv, http.MethodDelete, "/api/templates/employee-card", "")
	if resp.Code != http.StatusNotFound {
		t.Fatalf("deleting it again: expected 404, got %d: %s", resp.Code, resp.Body.String())
	}

	resp = serverRequest(t, srv, http.MethodDelete, "/api/templates/german-pid-sdjwt", "")
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("deleting a predefined template: expected 400, got %d", resp.Code)
	}
}

func TestIssueWithTemplateAndOverrides(t *testing.T) {
	srv := newTestServer(t, true)

	body := `{"format": "sdjwt", "vct": "urn:example:employee", "claims": {"employee_id": "E-1", "department": "IT"}, "always_disclosed": ["department"]}`
	if resp := serverRequest(t, srv, http.MethodPut, "/api/templates/employee-card", body); resp.Code != http.StatusOK {
		t.Fatalf("PUT template: %d: %s", resp.Code, resp.Body.String())
	}

	resp := serverRequest(t, srv, http.MethodPost, "/api/issue", `{"template": "employee-card", "claims": {"employee_id": "E-42"}}`)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
	}
	result := decodeJSON(t, resp)
	if result["vct"] != "urn:example:employee" {
		t.Errorf("expected template vct, got %v", result["vct"])
	}

	cred, ok := srv.wallet.GetCredential(result["id"].(string))
	if !ok {
		t.Fatal("issued credential not stored")
	}
	token, err := sdjwt.Parse(cred.Raw)
	if err != nil {
		t.Fatalf("parsing issued SD-JWT: %v", err)
	}
	if token.ResolvedClaims["employee_id"] != "E-42" {
		t.Errorf("claim override not applied: %v", token.ResolvedClaims["employee_id"])
	}
	// department is always disclosed, so it appears directly in the payload.
	if token.Payload["department"] != "IT" {
		t.Errorf("expected department plainly in payload, got %v", token.Payload["department"])
	}
	if _, ok := token.Payload["employee_id"]; ok {
		t.Error("employee_id must stay selectively disclosable")
	}
}

func TestIssueTemplateFormatMismatch(t *testing.T) {
	srv := newTestServer(t, true)
	resp := serverRequest(t, srv, http.MethodPost, "/api/issue", `{"format": "mdoc", "template": "german-pid-sdjwt"}`)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "format") {
		t.Errorf("expected format mismatch error, got %s", resp.Body.String())
	}
}

func TestIssueAlwaysDisclosedRejectedForMdoc(t *testing.T) {
	srv := newTestServer(t, true)
	resp := serverRequest(t, srv, http.MethodPost, "/api/issue", `{"format": "mdoc", "always_disclosed": ["family_name"]}`)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestIssueSaveAsTemplate(t *testing.T) {
	srv := newTestServer(t, true)

	body := `{"format": "sdjwt", "vct": "urn:example:member", "claims": {"member_id": "M-7"}, "always_disclosed": ["member_id"], "save_as_template": "member-card"}`
	resp := serverRequest(t, srv, http.MethodPost, "/api/issue", body)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
	}
	result := decodeJSON(t, resp)
	if result["template_path"] == nil {
		t.Error("expected template_path in response")
	}

	resp = serverRequest(t, srv, http.MethodGet, "/api/templates/member-card", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("saved template not found: %d", resp.Code)
	}
	tpl := decodeJSON(t, resp)
	if tpl["vct"] != "urn:example:member" || tpl["format"] != "sdjwt" {
		t.Errorf("unexpected saved template: %v", tpl)
	}
	claims := tpl["claims"].(map[string]any)
	if claims["member_id"] != "M-7" {
		t.Errorf("saved template claims wrong: %v", claims)
	}
	always := tpl["always_disclosed"].([]any)
	if len(always) != 1 || always[0] != "member_id" {
		t.Errorf("saved template always_disclosed wrong: %v", always)
	}
}

func TestIssuePIDUsesTemplateOverride(t *testing.T) {
	srv := newTestServer(t, true)

	body := `{"format": "sdjwt", "vct": "urn:custom:pid", "claims": {"given_name": "OVERRIDDEN"}}`
	if resp := serverRequest(t, srv, http.MethodPut, "/api/templates/pid-sdjwt", body); resp.Code != http.StatusOK {
		t.Fatalf("PUT template: %d: %s", resp.Code, resp.Body.String())
	}

	resp := serverRequest(t, srv, http.MethodPost, "/api/issue", `{"format": "sdjwt", "pid": true}`)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
	}
	result := decodeJSON(t, resp)
	cred, _ := srv.wallet.GetCredential(result["id"].(string))
	token, err := sdjwt.Parse(cred.Raw)
	if err != nil {
		t.Fatalf("parsing issued SD-JWT: %v", err)
	}
	if token.ResolvedClaims["given_name"] != "OVERRIDDEN" {
		t.Errorf("PID issuance did not use the template override: %v", token.ResolvedClaims)
	}
	if len(token.Disclosures) != 1 {
		t.Errorf("expected 1 disclosure from overridden template, got %d", len(token.Disclosures))
	}
}

// The CLI loader accepts file paths. The HTTP endpoint must restrict input to names to
// prevent arbitrary file reads.
func TestGetTemplate_RefusesAPathInsteadOfAName(t *testing.T) {
	srv := newTestServer(t, false)
	dir := t.TempDir()
	srv.wallet.Templates = credtemplate.FileLocation(filepath.Join(dir, "templates"))

	secret := filepath.Join(dir, "secret.json")
	if err := os.WriteFile(secret, []byte(`{"name":"internal","format":"sdjwt","claims":{"api_key":"SECRET"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{
		secret,           // absolute path
		"../secret",      // relative escape
		"../secret.json", // relative escape with extension
		".ssh/id_rsa",    // hidden directory
	} {
		t.Run(name, func(t *testing.T) {
			rec := serverRequest(t, srv, "GET", "/api/templates/"+url.PathEscape(name), "")
			if rec.Code == http.StatusOK {
				t.Fatalf("a path was served as a template: %s", rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "SECRET") {
				t.Fatal("the file's contents were disclosed")
			}
		})
	}
}

func TestGetTemplate_StillServesABareName(t *testing.T) {
	srv := newTestServer(t, false)
	srv.wallet.Templates = credtemplate.FileLocation(t.TempDir())

	rec := serverRequest(t, srv, "GET", "/api/templates/german-pid-sdjwt", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// A request that can't add its template to the catalogue leaves no
// credential behind.
func TestAFailedCatalogueEntryLeavesNoCredential(t *testing.T) {
	srv := newTestServer(t, true)
	before := len(srv.wallet.GetCredentials())
	body := `{"format": "sdjwt", "vct": "urn:eudi:pid:1", "claims": {"given_name": "Erika"}, "save_as_template": "my-pid", "catalog": {"name": "My PID"}}`
	if resp := serverRequest(t, srv, http.MethodPost, "/api/issue", body); resp.Code < 400 || !strings.Contains(resp.Body.String(), "catalogue") {
		t.Fatalf("issue = %d %s, want a refusal for a type the catalogue has", resp.Code, resp.Body)
	}
	if got := len(srv.wallet.GetCredentials()); got != before {
		t.Errorf("the wallet holds %d credentials, want %d", got, before)
	}
}
