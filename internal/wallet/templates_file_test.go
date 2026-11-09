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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
)

// Each YAML document of a startup file holds one item or a list, and the
// items of all documents add up. An error counts the empty documents too.
func TestStartupItemsAddUpAcrossDocuments(t *testing.T) {
	type item struct {
		Name string `json:"name"`
	}
	items, err := decodeStartupItems[item]([]byte("name: a\n---\n- name: b\n- name: c\n---\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 || items[0].Name != "a" || items[2].Name != "c" {
		t.Fatalf("items %+v", items)
	}
	_, err = decodeStartupItems[item]([]byte("name: a\n---\n---\nnmae: b\n"))
	if err == nil || !strings.Contains(err.Error(), "YAML document 3") || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %v, want the document and the unknown field", err)
	}
}

// The API marks a configured template and refuses to change it, because its
// file belongs to the operator.
func TestTheAPIRefusesToChangeAConfiguredTemplate(t *testing.T) {
	srv := newTestServer(t, true)
	parsed, err := credtemplate.ParseConfigured([]credtemplate.ConfiguredFile{{
		Name: "cards.yaml",
		Data: []byte("name: staff-card\nformat: sdjwt\nvct: urn:example:staff:1\n"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	srv.wallet.Templates.Configured = &credtemplate.Configured{}
	srv.wallet.Templates.Configured.Set(parsed)

	resp := serverRequest(t, srv, http.MethodGet, "/api/templates/staff-card", "")
	if resp.Code != http.StatusOK || decodeJSON(t, resp)["configured"] != true {
		t.Fatalf("GET: %d %s, want a configured template", resp.Code, resp.Body.String())
	}
	resp = serverRequest(t, srv, http.MethodPut, "/api/templates/staff-card", `{"format": "sdjwt", "vct": "urn:example:changed:1"}`)
	if resp.Code != http.StatusConflict || !strings.Contains(resp.Body.String(), "cards.yaml") {
		t.Fatalf("PUT: %d %s, want 409 naming the file", resp.Code, resp.Body.String())
	}
	resp = serverRequest(t, srv, http.MethodDelete, "/api/templates/staff-card", "")
	if resp.Code != http.StatusConflict {
		t.Fatalf("DELETE: %d %s, want 409", resp.Code, resp.Body.String())
	}
}

// A directory of template files skips hidden files, such as an editor's swap
// file.
func TestTemplateFilesSkipHiddenFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "card.yaml"), []byte("name: staff-card\nformat: sdjwt\nvct: urn:example:staff:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".card.yaml"), []byte("half written"), 0o600); err != nil {
		t.Fatal(err)
	}
	templates, err := LoadTemplateFiles(dir)
	if err != nil || templates.Len() != 1 {
		t.Fatalf("loaded %d templates, err %v, want only card.yaml", templates.Len(), err)
	}
}
