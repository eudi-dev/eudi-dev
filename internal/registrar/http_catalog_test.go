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

package registrar

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
)

// schemaPage is the data of a TS11 v1.0 §5.3.1 GET /schemas response.
type schemaPage struct {
	Total  int                 `json:"total"`
	Limit  int                 `json:"limit"`
	Offset int                 `json:"offset"`
	Data   []AttestationSchema `json:"data"`
}

func addTestDiploma(t *testing.T, api *testAPI) CatalogAttestation {
	t.Helper()
	rec := api.do(http.MethodPost, "/api/catalog/attestations", diplomaCatalogEntry(), "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	return decodeBody[CatalogAttestation](t, rec)
}

// TS11 v1.0 §5.3.1 lists the filters of GET /schemas.
func TestTheSchemaSearchFilters(t *testing.T) {
	api := newTestAPI(t)
	diploma := addTestDiploma(t, api).Schema
	all := len(api.CatalogAttestations())
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"", all},
		{"id=" + diploma.ID, 1},
		{"supportedFormats=" + url.QueryEscape("dc+sd-jwt, mso_mdoc") + "&attestationLoS=iso_18045_moderate", 1},
		{"bindingType=claim", 0},
		{"trustedAuthoritiesFrameworkType=etsi_tl&trustedAuthoritiesValue=" + url.QueryEscape("https://example.com/lote"), 1},
		{"trustedAuthoritiesFrameworkType=aki", 0},
		{"schemaUri=" + url.QueryEscape(diploma.SchemaURIs[1].URI), 1},
		{"rulebookUri=" + url.QueryEscape("https://example.com/diploma-rulebook"), 1},
		{"rulebookUri=" + url.QueryEscape("https://example.com/other"), 0},
	} {
		t.Run(tc.query, func(t *testing.T) {
			rec := api.do(http.MethodGet, catalogSchemaPath+"?"+tc.query, nil, acceptJSON)
			page := decodeBody[wrpResponse[schemaPage]](t, rec).Data
			if rec.Code != http.StatusOK || page.Total != tc.want || len(page.Data) != tc.want || page.Data == nil {
				t.Errorf("%d: total %d, %d schemas, want %d", rec.Code, page.Total, len(page.Data), tc.want)
			}
			if tc.want == 1 && page.Data[0].ID != diploma.ID {
				t.Errorf("found %s, want the diploma", page.Data[0].ID)
			}
		})
	}
}

func TestTheSchemaListPages(t *testing.T) {
	api := newTestAPI(t)
	all := api.CatalogAttestations()
	if len(all) < 3 {
		t.Fatalf("%d template entries, want at least 3", len(all))
	}
	page := decodeBody[wrpResponse[schemaPage]](t, api.do(http.MethodGet, catalogSchemaPath+"?limit=2&offset=1", nil, acceptJSON)).Data
	if page.Total != len(all) || page.Limit != 2 || page.Offset != 1 || len(page.Data) != 2 || page.Data[0].ID != all[1].Schema.ID || page.Data[1].ID != all[2].Schema.ID {
		t.Errorf("page %+v, want entries 2 and 3 of %d", page, len(all))
	}
	page = decodeBody[wrpResponse[schemaPage]](t, api.do(http.MethodGet, catalogSchemaPath+"?offset=1000", nil, acceptJSON)).Data
	if page.Offset != len(all) || page.Data == nil || len(page.Data) != 0 {
		t.Errorf("page past the end %+v, want an empty list", page)
	}
	wantError(t, api.do(http.MethodGet, catalogSchemaPath+"?offset=-1", nil, acceptJSON), http.StatusBadRequest, apierror.InvalidRequest, "offset must be a non-negative integer")
}

// TS11 v1.0 §4.3.4: each schema URI serves the schema of its format.
func TestTheCatalogueServesEachSchema(t *testing.T) {
	api := newTestAPI(t)
	diploma := addTestDiploma(t, api)
	id := diploma.Schema.ID

	rec := api.do(http.MethodGet, catalogSchemaPath+"/"+id, nil, acceptJSON)
	if got := decodeBody[wrpResponse[AttestationSchema]](t, rec).Data; rec.Code != http.StatusOK || got.ID != id || got.RulebookURI != "https://example.com/diploma-rulebook" {
		t.Errorf("schema: %d %s", rec.Code, rec.Body)
	}
	wantError(t, api.do(http.MethodGet, catalogSchemaPath+"/unknown", nil, acceptJSON), http.StatusNotFound, apierror.NotFound, "not found")

	for _, uri := range diploma.Schema.SchemaURIs {
		u, err := url.Parse(uri.URI)
		if err != nil {
			t.Fatal(err)
		}
		rec := api.do(http.MethodGet, u.EscapedPath(), nil, "")
		if rec.Code != http.StatusOK || rec.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("%s: %d %s", uri.URI, rec.Code, rec.Body)
		}
		schema := decodeBody[map[string]any](t, rec)
		if schema["name"] != "University diploma" {
			t.Errorf("%s: %v", uri.FormatIdentifier, schema)
		}
		switch uri.FormatIdentifier {
		case "dc+sd-jwt":
			if schema["vct"] != testDiplomaVCT || fmt.Sprint(schema["claims"]) != "[map[path:[degree]] map[path:[graduation_date]]]" {
				t.Errorf("type metadata %v", schema)
			}
		case "mso_mdoc":
			if schema["docType"] != "org.example.diploma.1" || fmt.Sprint(schema["namespaces"]) != "map[org.example.diploma.1:[map[identifier:degree]]]" {
				t.Errorf("mdoc schema %v", schema)
			}
		}
	}
	wantError(t, api.do(http.MethodGet, catalogSchemaPath+"/"+id+"/jwt_vc_json", nil, ""), http.StatusNotFound, apierror.NotFound, "not found")
	wantError(t, api.do(http.MethodGet, catalogSchemaPath+"/unknown/mso_mdoc", nil, ""), http.StatusNotFound, apierror.NotFound, "not found")
}

// TS11 v1.0 §5.3.2 and §5.3.3: an added entry can be changed and deleted, the
// entry of a template only through its template.
func TestTheCatalogueAPIUpdatesAndDeletes(t *testing.T) {
	api := newTestAPI(t)
	diploma := addTestDiploma(t, api)
	id := diploma.Schema.ID
	template := api.CatalogAttestations()[0].Schema

	changed := diploma.Schema
	changed.Version = "2.0"
	changed.BindingType = "claim"
	rec := api.do(http.MethodPut, catalogSchemaPath+"/"+id, changed, "")
	if got := decodeBody[AttestationSchema](t, rec); rec.Code != http.StatusOK || got.Version != "2.0" || got.BindingType != "claim" || got.ID != id {
		t.Errorf("update: %d %s", rec.Code, rec.Body)
	}

	otherID := changed
	otherID.ID = "another"
	sameFormats := changed
	sameFormats.SupportedFormats = []string{"dc+sd-jwt"}
	for _, tc := range []struct {
		name   string
		id     string
		body   any
		status int
		code   string
		want   string
	}{
		{"malformed JSON", id, "{", http.StatusBadRequest, apierror.InvalidRequest, "invalid attestation schema"},
		{"another id", id, otherID, http.StatusBadRequest, apierror.InvalidRequest, `the id in the body is "another"`},
		{"other formats", id, sameFormats, http.StatusBadRequest, apierror.InvalidRequest, "can't be changed"},
		{"invalid level", id, AttestationSchema{AttestationLoS: "high"}, http.StatusBadRequest, apierror.InvalidRequest, "attestationLoS"},
		{"unknown entry", "unknown", AttestationSchema{}, http.StatusNotFound, apierror.NotFound, "not in the catalogue"},
		{"template entry", template.ID, AttestationSchema{}, http.StatusForbidden, apierror.Forbidden, "Change the template instead"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantError(t, api.do(http.MethodPut, catalogSchemaPath+"/"+tc.id, tc.body, ""), tc.status, tc.code, tc.want)
		})
	}

	if rec := api.do(http.MethodDelete, catalogSchemaPath+"/"+id, nil, ""); rec.Code != http.StatusNoContent {
		t.Errorf("delete: %d %s", rec.Code, rec.Body)
	}
	wantError(t, api.do(http.MethodDelete, catalogSchemaPath+"/"+id, nil, ""), http.StatusNotFound, apierror.NotFound, "not in the catalogue")
	if rec := api.do(http.MethodDelete, catalogSchemaPath+"/"+template.ID, nil, ""); rec.Code != http.StatusNoContent {
		t.Errorf("delete a template entry: %d %s", rec.Code, rec.Body)
	}
	wantError(t, api.do(http.MethodDelete, catalogSchemaPath+"/"+template.ID, nil, ""), http.StatusNotFound, apierror.NotFound, "not in the catalogue")
	if api.changes != 4 {
		t.Errorf("%d changes saved, want 4", api.changes)
	}
}

// On the public demo, visitors keep their hands off the template entries and
// the entries of the operator's catalogue file.
func TestThePublicDemoKeepsTheOperatorEntries(t *testing.T) {
	api := newTestAPI(t)
	api.h.KeepOperatorEntries = func() bool { return true }
	operator := diplomaCatalogEntry()
	if _, err := api.SetOperatorCatalog([]CatalogAttestation{operator}); err != nil {
		t.Fatal(err)
	}
	operatorID := catalogEntryID(operator.Name)
	templateID := api.CatalogAttestations()[0].Schema.ID
	visitor := diplomaCatalogEntry()
	visitor.Name = "Visitor diploma"
	visitor.Credentials = []CatalogCredential{{Format: "dc+sd-jwt", Type: "urn:example:visitor:1"}}
	rec := api.do(http.MethodPost, "/api/catalog/attestations", visitor, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	visitorID := decodeBody[CatalogAttestation](t, rec).Schema.ID

	wantError(t, api.do(http.MethodPut, catalogSchemaPath+"/"+operatorID, AttestationSchema{}, ""), http.StatusForbidden, apierror.Forbidden, "visitors can't change it")
	wantError(t, api.do(http.MethodDelete, catalogSchemaPath+"/"+operatorID, nil, ""), http.StatusForbidden, apierror.Forbidden, "visitors can't delete it")
	wantError(t, api.do(http.MethodDelete, catalogSchemaPath+"/"+templateID, nil, ""), http.StatusForbidden, apierror.Forbidden, "visitors can't delete them")
	if _, ok := api.CatalogAttestation(operatorID); !ok {
		t.Error("the operator entry is gone")
	}
	if rec := api.do(http.MethodDelete, catalogSchemaPath+"/"+visitorID, nil, ""); rec.Code != http.StatusNoContent {
		t.Errorf("deleting a visitor's entry: %d %s", rec.Code, rec.Body)
	}
}

func TestTheCatalogueAPIAddsEntries(t *testing.T) {
	api := newTestAPI(t)
	added := addTestDiploma(t, api)
	listed := decodeBody[[]CatalogAttestation](t, api.do(http.MethodGet, "/api/catalog/attestations", nil, ""))
	if !slices.ContainsFunc(listed, func(e CatalogAttestation) bool { return e.Schema.ID == added.Schema.ID && !e.Template }) {
		t.Errorf("the list leaves out the added entry %s", added.Schema.ID)
	}

	wantError(t, api.do(http.MethodPost, "/api/catalog/attestations", "{", ""), http.StatusBadRequest, apierror.InvalidRequest, "invalid attestation")
	wantError(t, api.do(http.MethodPost, "/api/catalog/attestations", diplomaCatalogEntry(), ""), http.StatusBadRequest, apierror.InvalidRequest, "already lists")
	for i := len(api.Catalog); i < maxCatalogEntries; i++ {
		api.Catalog = append(api.Catalog, CatalogAttestation{Name: fmt.Sprintf("Entry %d", i), Schema: AttestationSchema{ID: fmt.Sprint(i)}})
	}
	another := diplomaCatalogEntry()
	another.Name = "Another diploma"
	another.Credentials = []CatalogCredential{{Format: "dc+sd-jwt", Type: "urn:example:another:1"}}
	wantError(t, api.do(http.MethodPost, "/api/catalog/attestations", another, ""), http.StatusConflict, apierror.Conflict, "maximum number of attestations")
}

func TestTheCatalogueAPIListsItsOptions(t *testing.T) {
	api := newTestAPI(t)
	categories := decodeBody[[]Category](t, api.do(http.MethodGet, "/api/catalog/categories", nil, ""))
	var ids []string
	for _, c := range categories {
		ids = append(ids, c.ID)
	}
	if !slices.Equal(ids, []string{"pid", "qeaa", "pub-eaa", "eaa"}) {
		t.Errorf("categories %v", ids)
	}
	options := decodeBody[map[string][]SchemaOption](t, api.do(http.MethodGet, "/api/catalog/schema-options", nil, ""))
	if !slices.Equal(OptionValues(options["attestationLoS"]), OptionValues(AttestationLevels)) || !slices.Equal(OptionValues(options["bindingType"]), []string{"key", "claim", "biometric", "none"}) {
		t.Errorf("options %+v", options)
	}
}

// The registrar's default contact URLs lead to placeholder pages.
func TestThePlaceholderPagesAreServed(t *testing.T) {
	api := newTestAPI(t)
	for _, path := range []string{"/privacy-policy", "/support", "/supervisory-authority", "/rulebook"} {
		rec := api.do(http.MethodGet, path, nil, "")
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(rec.Body.String(), "Placeholder page") {
			t.Errorf("%s: %d %s", path, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
}
