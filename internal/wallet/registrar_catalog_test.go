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
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

func TestTheCatalogueAPI(t *testing.T) {
	srv, ts := registrarServer(t)
	resp := serverRequest(t, srv, "POST", "/api/catalog/attestations", mustJSON(t, diplomaCatalogEntry()))
	if resp.Code != http.StatusCreated {
		t.Fatalf("POST: %d %s", resp.Code, resp.Body.String())
	}
	var added registrar.CatalogAttestation
	if err := json.Unmarshal(resp.Body.Bytes(), &added); err != nil {
		t.Fatal(err)
	}

	// GET /schemas is a signed, paginated list (TS11 v1.0 §5.3.1).
	list := serverRequest(t, srv, "GET", "/api/catalog/schemas?supportedFormats=dc%2Bsd-jwt,mso_mdoc&attestationLoS=iso_18045_moderate", "")
	if list.Code != http.StatusOK || list.Header().Get("Content-Type") != "application/jwt" {
		t.Fatalf("GET /schemas: %d %s", list.Code, list.Header().Get("Content-Type"))
	}
	var page struct {
		Iss  string `json:"iss"`
		Iat  int64  `json:"iat"`
		Data struct {
			Total  int                           `json:"total"`
			Limit  int                           `json:"limit"`
			Offset int                           `json:"offset"`
			Data   []registrar.AttestationSchema `json:"data"`
		} `json:"data"`
	}
	decodeCompactJWTPayload(t, list.Body.String(), &page)
	if page.Iss == "" || page.Iat == 0 || page.Data.Total != 1 || page.Data.Limit != 20 || len(page.Data.Data) != 1 || page.Data.Data[0].ID != added.Schema.ID {
		t.Fatalf("page %+v", page)
	}
	if bad := serverRequest(t, srv, "GET", "/api/catalog/schemas?limit=0", ""); bad.Code != http.StatusBadRequest {
		t.Errorf("limit=0: %d", bad.Code)
	}
	if huge := serverRequest(t, srv, "GET", "/api/catalog/schemas?offset=1&limit=9223372036854775807", ""); huge.Code != http.StatusOK {
		t.Errorf("a huge limit: %d", huge.Code)
	}
	if past := serverRequest(t, srv, "GET", "/api/catalog/schemas?offset=1000", ""); past.Code != http.StatusOK {
		t.Errorf("an offset past the end: %d", past.Code)
	}

	// The schema URI serves the format-specific schema.
	schemaURL := added.Schema.SchemaURIs[0].URI
	if !strings.HasPrefix(schemaURL, ts.URL) {
		t.Fatalf("schema URI %s is not on the wallet %s", schemaURL, ts.URL)
	}
	typeMetadata := serverRequest(t, srv, "GET", strings.TrimPrefix(schemaURL, ts.URL), "")
	if typeMetadata.Code != http.StatusOK || !strings.Contains(typeMetadata.Body.String(), `"vct":"`+testDiplomaVCT+`"`) {
		t.Fatalf("type metadata: %d %s", typeMetadata.Code, typeMetadata.Body.String())
	}

	// PUT replaces the SchemaMeta, DELETE removes it (§5.3.2, §5.3.3).
	updated := added.Schema
	updated.Version = "2.0.0"
	if put := serverRequest(t, srv, "PUT", "/api/catalog/schemas/"+added.Schema.ID, mustJSON(t, updated)); put.Code != http.StatusOK || !strings.Contains(put.Body.String(), `"version":"2.0.0"`) {
		t.Fatalf("PUT: %d %s", put.Code, put.Body.String())
	}
	fromTemplate := srv.wallet.Registrar().CatalogAttestations()[0].Schema.ID
	if del := serverRequest(t, srv, "DELETE", "/api/catalog/schemas/"+fromTemplate, ""); del.Code != http.StatusNoContent {
		t.Errorf("DELETE of a template entry: %d", del.Code)
	}
	if del := serverRequest(t, srv, "DELETE", "/api/catalog/schemas/"+added.Schema.ID, ""); del.Code != http.StatusNoContent {
		t.Fatalf("DELETE: %d %s", del.Code, del.Body.String())
	}
	if del := serverRequest(t, srv, "DELETE", "/api/catalog/schemas/"+added.Schema.ID, ""); del.Code != http.StatusNotFound {
		t.Errorf("DELETE again: %d", del.Code)
	}
}

func TestTheCatalogueIsStored(t *testing.T) {
	for name, open := range map[string]func(t *testing.T) *WalletStore{
		"file":   func(t *testing.T) *WalletStore { return NewWalletStore(t.TempDir()) },
		"entity": func(t *testing.T) *WalletStore { store, _ := entityStore(t); return store },
	} {
		t.Run(name, func(t *testing.T) {
			store := open(t)
			w, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Registrar().AddCatalogAttestation(diplomaCatalogEntry()); err != nil {
				t.Fatal(err)
			}
			if err := store.Save(w); err != nil {
				t.Fatal(err)
			}
			reloaded, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			if len(reloaded.Catalog) != 1 || reloaded.Catalog[0].Name != "University diploma" {
				t.Fatalf("stored catalogue %+v", reloaded.Catalog)
			}
			reloaded.ResetToBaseline()
			if len(reloaded.Catalog) != 0 {
				t.Error("a demo reset kept the added attestations")
			}
		})
	}
}

// A user template is added to the catalogue only when it is saved with
// catalogue fields. Bad fields store neither the template nor the entry.
func TestASavedTemplateJoinsTheCatalogueOnRequest(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.Templates = credtemplate.FileLocation(t.TempDir())
	names := func() []string {
		var out []string
		for _, e := range srv.wallet.Registrar().CatalogAttestations() {
			out = append(out, e.Name)
		}
		return out
	}
	template := `"format":"sdjwt","vct":"urn:example:library:1","claims":{"member_id":"42","address":{"locality":"Utrecht"}}`

	if w := serverRequest(t, srv, "PUT", "/api/templates/plain-card", `{`+template+`}`); w.Code != http.StatusOK {
		t.Fatalf("plain save: %d %s", w.Code, w.Body.String())
	}
	if slices.Contains(names(), "plain-card") {
		t.Error("a template saved without catalogue fields is in the catalogue")
	}

	for _, bad := range []string{
		`{"name":"Library card","schema":{"rulebookURI":"javascript:alert(1)"}}`,
		`{"name":"EUDI PID"}`,
		`{"name":"Library card","schema":{"attestationLoS":"iso_18045_extreme"}}`,
	} {
		if w := serverRequest(t, srv, "PUT", "/api/templates/library-card", `{`+template+`,"catalog":`+bad+`}`); w.Code < 400 {
			t.Errorf("catalog %s: %d, want an error", bad, w.Code)
		}
	}
	if _, err := credtemplate.Load("library-card", srv.wallet.Templates); err == nil {
		t.Error("a template with bad catalogue fields was saved")
	}
	if w := serverRequest(t, srv, "PUT", "/api/templates/untyped", `{"format":"sdjwt","claims":{},"catalog":{"name":"Untyped"}}`); w.Code < 400 {
		t.Errorf("a template without a vct joined the catalogue: %d", w.Code)
	}

	body := `{` + template + `,"catalog":{"name":"Library card","schema":{"rulebookURI":"https://library.example/rulebook","attestationLoS":"iso_18045_moderate"}}}`
	if w := serverRequest(t, srv, "PUT", "/api/templates/library-card", body); w.Code != http.StatusOK {
		t.Fatalf("save with catalogue fields: %d %s", w.Code, w.Body.String())
	}
	entries := srv.wallet.Registrar().CatalogAttestations()
	i := slices.IndexFunc(entries, func(e registrar.CatalogAttestation) bool { return e.Name == "Library card" })
	if i < 0 {
		t.Fatalf("the template is not in the catalogue: %v", names())
	}
	card := entries[i]
	want := [][]any{{"address"}, {"address", "locality"}, {"member_id"}}
	if card.Template || card.Credentials[0].Type != "urn:example:library:1" || !reflect.DeepEqual(card.Credentials[0].Claims, want) {
		t.Errorf("entry %+v", card)
	}
	if card.Schema.RulebookURI != "https://library.example/rulebook" || card.Schema.AttestationLoS != "iso_18045_moderate" {
		t.Errorf("schema %+v", card.Schema)
	}

	issue := `{"format":"sdjwt","vct":"urn:example:badge:1","claims":{"level":"gold"},"save_as_template":"badge","catalog":{"name":"Badge"}}`
	if w := serverRequest(t, srv, "POST", "/api/issue", issue); w.Code != http.StatusCreated {
		t.Fatalf("issue with catalogue fields: %d %s", w.Code, w.Body.String())
	}
	if !slices.Contains(names(), "Badge") {
		t.Errorf("the issued template is not in the catalogue: %v", names())
	}
	before := len(srv.wallet.GetCredentials())
	issue = `{"format":"sdjwt","vct":"urn:example:badge:2","claims":{},"save_as_template":"badge-2","catalog":{"name":"Badge"}}`
	if w := serverRequest(t, srv, "POST", "/api/issue", issue); w.Code < 400 {
		t.Errorf("a duplicate catalogue name was accepted: %d", w.Code)
	}
	if len(srv.wallet.GetCredentials()) != before {
		t.Error("the credential was issued although its catalogue entry was refused")
	}
}

// A template format may be written as an alias.
func TestAPredefinedOverrideWithAFormatAliasStaysInTheCatalogue(t *testing.T) {
	w := generateTestWallet(t)
	if _, err := credtemplate.Save(w.Templates, credtemplate.Template{
		Name: "pid-sdjwt", Format: "dc+sd-jwt", VCT: "urn:eudi:pid:1", Claims: map[string]any{"given_name": "Erika"},
		Display: &credtemplate.TemplateDisplay{Name: "EUDI PID"},
	}); err != nil {
		t.Fatal(err)
	}
	entry, ok := w.catalogueEntryFor("dc+sd-jwt", []string{"urn:eudi:pid:1"})
	if !ok || entry.Name != "EUDI PID" {
		t.Errorf("entry %+v, want the EUDI PID", entry)
	}
}

// The UI renders the levels of security and holder bindings from the
// registrar, and the registrar accepts each of them.
func TestTheCatalogueServesItsSchemaOptions(t *testing.T) {
	srv := newTestServer(t, false)
	resp := serverRequest(t, srv, "GET", "/api/catalog/schema-options", "")
	var options map[string][]registrar.SchemaOption
	if err := json.Unmarshal(resp.Body.Bytes(), &options); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(options["attestationLoS"], registrar.AttestationLevels) || !reflect.DeepEqual(options["bindingType"], registrar.BindingTypes) {
		t.Fatalf("options %v", options)
	}
	for i, level := range registrar.AttestationLevels {
		entry := diplomaCatalogEntry()
		entry.Name = fmt.Sprintf("Diploma %d", i)
		entry.Credentials = []registrar.CatalogCredential{{Format: "dc+sd-jwt", Type: fmt.Sprintf("urn:example:diploma:level:%d", i), Claims: [][]any{{"degree"}}}}
		entry.Schema.AttestationLoS = level.Value
		entry.Schema.BindingType = registrar.BindingTypes[i].Value
		if resp := serverRequest(t, srv, "POST", "/api/catalog/attestations", mustJSON(t, entry)); resp.Code != http.StatusCreated {
			t.Errorf("an entry with %s and %s answers %d: %s", level.Value, registrar.BindingTypes[i].Value, resp.Code, resp.Body.String())
		}
	}
}
