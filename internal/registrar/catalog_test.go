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
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jsonutil"
	"github.com/dominikschlosser/eudi-dev/v3/internal/lote"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

func diplomaCatalogEntry() CatalogAttestation {
	isLOTE := true
	return CatalogAttestation{
		Name: "University diploma",
		Credentials: []CatalogCredential{
			{Format: "dc+sd-jwt", Type: testDiplomaVCT, Claims: [][]any{{"degree"}, {"graduation_date"}}},
			{Format: "mso_mdoc", Type: "org.example.diploma.1", Claims: [][]any{{"org.example.diploma.1", "degree"}}},
		},
		Schema: AttestationSchema{
			RulebookURI:        "https://example.com/diploma-rulebook",
			AttestationLoS:     "iso_18045_moderate",
			TrustedAuthorities: []TrustAuthority{{FrameworkType: "etsi_tl", Value: "https://example.com/lote", IsLOTE: &isLOTE}},
		},
	}
}

func TestTheCatalogueListsThePIDTemplates(t *testing.T) {
	w := generateTestWallet(t)
	entries := w.CatalogAttestations()
	i := slices.IndexFunc(entries, func(e CatalogAttestation) bool { return e.Name == "EUDI PID" })
	if i < 0 {
		t.Fatalf("no EUDI PID entry in %d entries", len(entries))
	}
	pid := entries[i]
	if !pid.Template || len(pid.Credentials) != 2 || pid.Credentials[0].Type != mock.DefaultPIDVCT || pid.Credentials[1].Type != mock.PIDNamespace {
		t.Fatalf("EUDI PID %+v", pid)
	}
	s := pid.Schema
	if !strings.Contains(s.RulebookURI, "pid-rulebook.md") || s.AttestationLoS != "iso_18045_high" || s.BindingType != "key" {
		t.Errorf("schema %+v", s)
	}
	if len(s.TrustedAuthorities) != 1 || s.TrustedAuthorities[0].FrameworkType != "etsi_tl" ||
		s.TrustedAuthorities[0].Value != "https://wallet.example/api/trustlists/pid" || s.TrustedAuthorities[0].IsLOTE == nil || !*s.TrustedAuthorities[0].IsLOTE {
		t.Errorf("trusted authorities %+v, want the wallet's PID provider list", s.TrustedAuthorities)
	}
	if !slices.Equal(s.SupportedFormats, []string{"dc+sd-jwt", "mso_mdoc"}) || len(s.SchemaURIs) != 2 ||
		s.SchemaURIs[0].URI != "https://wallet.example/api/catalog/schemas/"+s.ID+"/dc+sd-jwt" {
		t.Errorf("formats %v, schema URIs %+v", s.SupportedFormats, s.SchemaURIs)
	}
	// The ids stay the same on every instance.
	other := generateTestWallet(t)
	other.env.base = "https://other.example"
	if again := other.CatalogAttestations(); again[i].Schema.ID != s.ID {
		t.Errorf("template entry id changed: %s, then %s", s.ID, again[i].Schema.ID)
	}
}

// The schema of the TS11 API has exactly the members of the normative JSON
// schema (EC TS11 v1.0 Annex A.2, additionalProperties false).
func TestCatalogueSchemasFollowTheTS11DataModel(t *testing.T) {
	w := generateTestWallet(t)
	for _, entry := range w.CatalogAttestations() {
		encoded, err := json.Marshal(entry.Schema)
		if err != nil {
			t.Fatal(err)
		}
		var members map[string]any
		if err := json.Unmarshal(encoded, &members); err != nil {
			t.Fatal(err)
		}
		allowed := []string{"id", "version", "rulebookURI", "trustedAuthorities", "attestationLoS", "bindingType", "supportedFormats", "schemaURIs"}
		for name := range members {
			if !slices.Contains(allowed, name) {
				t.Errorf("%s: member %q is not in the TS11 schema", entry.Name, name)
			}
		}
		for _, required := range []string{"version", "rulebookURI", "attestationLoS", "bindingType", "supportedFormats", "schemaURIs"} {
			if members[required] == nil {
				t.Errorf("%s: required member %q is missing", entry.Name, required)
			}
		}
	}
}

func TestAddingToTheCatalogue(t *testing.T) {
	w := generateTestWallet(t)
	added, err := w.AddCatalogAttestation(diplomaCatalogEntry())
	if err != nil {
		t.Fatal(err)
	}
	if added.Schema.ID == "" || added.Schema.Version != "1.0.0" || added.Schema.BindingType != "key" || added.Template {
		t.Fatalf("added %+v, want an assigned id and the defaults", added.Schema)
	}
	sdjwt, ok := added.FormatSchema("dc+sd-jwt")
	if !ok || sdjwt["vct"] != testDiplomaVCT {
		t.Errorf("SD-JWT VC type metadata %v", sdjwt)
	}
	mdoc, ok := added.FormatSchema("mso_mdoc")
	if !ok || mdoc["docType"] != "org.example.diploma.1" {
		t.Errorf("mdoc schema %v", mdoc)
	}

	updated := added.Schema
	updated.Version = "1.1.0"
	if got, err := w.UpdateCatalogSchema(added.Schema.ID, updated); err != nil || got.Schema.Version != "1.1.0" {
		t.Fatalf("update: %v %+v", err, got.Schema)
	}
	updated.SchemaURIs = []SchemaURI{{FormatIdentifier: "dc+sd-jwt", URI: "https://elsewhere.example/schema"}}
	if _, err := w.UpdateCatalogSchema(added.Schema.ID, updated); err == nil {
		t.Error("an update changed the schema URIs")
	}

	// The entry of a predefined template is removed from the catalogue, and its
	// type can be added again.
	fromTemplate := w.CatalogAttestations()[0]
	if err := w.DeleteCatalogAttestation(fromTemplate.Schema.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.CatalogAttestation(fromTemplate.Schema.ID); ok {
		t.Error("the deleted template entry is still listed")
	}
	readded := fromTemplate
	readded.Template = false
	if _, err := w.AddCatalogAttestation(readded); err != nil {
		t.Errorf("adding the type of a deleted template entry: %v", err)
	}
	if err := w.DeleteCatalogAttestation(added.Schema.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.CatalogAttestation(added.Schema.ID); ok {
		t.Error("the deleted entry is still listed")
	}
}

func TestCatalogueEntriesAreChecked(t *testing.T) {
	w := generateTestWallet(t)
	for _, tc := range []struct {
		name   string
		change func(*CatalogAttestation)
		want   string
	}{
		{"no name", func(e *CatalogAttestation) { e.Name = " " }, "needs a name"},
		{"no formats", func(e *CatalogAttestation) { e.Credentials = nil }, "at least one format"},
		{"a format twice", func(e *CatalogAttestation) { e.Credentials[1].Format = "dc+sd-jwt" }, "listed twice"},
		{"another format", func(e *CatalogAttestation) { e.Credentials[0].Format = "ldp_vc" }, "not dc+sd-jwt or mso_mdoc"},
		{"no type", func(e *CatalogAttestation) { e.Credentials[0].Type = "" }, "needs its type"},
		{"an mdoc claim without namespace", func(e *CatalogAttestation) { e.Credentials[1].Claims = [][]any{{"degree"}} }, "namespace and an element"},
		{"an unknown level of security", func(e *CatalogAttestation) { e.Schema.AttestationLoS = "high" }, "attestationLoS"},
		{"an unknown binding type", func(e *CatalogAttestation) { e.Schema.BindingType = "device" }, "bindingType"},
		{"a version that is not semantic", func(e *CatalogAttestation) { e.Schema.Version = "v1" }, "semantic versioning"},
		{"isLOTE on another framework", func(e *CatalogAttestation) { e.Schema.TrustedAuthorities[0].FrameworkType = "aki" }, "isLOTE"},
		{"a relative rulebook", func(e *CatalogAttestation) { e.Schema.RulebookURI = "rulebook.md" }, "not an http or https URL"},
		{"a script rulebook", func(e *CatalogAttestation) { e.Schema.RulebookURI = "javascript:alert(1)" }, "not an http or https URL"},
		{"a script trusted list", func(e *CatalogAttestation) { e.Schema.TrustedAuthorities[0].Value = "javascript:alert(1)" }, "not an http or https URL"},
		{"the name of a template entry", func(e *CatalogAttestation) { e.Name = "eudi pid" }, "already lists"},
		{"an unknown category", func(e *CatalogAttestation) { e.Category = "eea" }, "not one of"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := diplomaCatalogEntry()
			tc.change(&entry)
			if _, err := w.AddCatalogAttestation(entry); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// An entry without trusted authorities links the wallet's list of its
// category, and the category sets the default level of security.
func TestTheCategoryNamesTheTrustedList(t *testing.T) {
	w := generateTestWallet(t)
	for category, level := range map[string]string{"": "iso_18045_basic", "qeaa": "iso_18045_high", "pub-eaa": "iso_18045_high"} {
		entry := diplomaCatalogEntry()
		entry.Name += " " + category
		entry.Credentials = entry.Credentials[:1]
		entry.Credentials[0].Type += category
		entry.Category = category
		entry.Schema = AttestationSchema{}
		added, err := w.AddCatalogAttestation(entry)
		if err != nil {
			t.Fatal(err)
		}
		want := jsonutil.FirstNonEmpty(category, "eaa")
		s := added.Schema
		if added.Category != want || s.AttestationLoS != level || len(s.TrustedAuthorities) != 1 || s.TrustedAuthorities[0].Value != "https://wallet.example/api/trustlists/"+want {
			t.Errorf("category %q: %s with %s and %+v", category, added.Category, s.AttestationLoS, s.TrustedAuthorities)
		}
	}
}

// The wallet finds the trusted list of a received credential by its type, so
// a type has one entry.
func TestACatalogueTypeHasOneEntry(t *testing.T) {
	w := generateTestWallet(t)
	_, err := w.AddCatalogAttestation(CatalogAttestation{Name: "Other PID", Credentials: []CatalogCredential{{Format: "dc+sd-jwt", Type: "urn:eudi:pid:1"}}})
	if err == nil || !strings.Contains(err.Error(), "EUDI PID") {
		t.Errorf("a second entry for the PID type: %v", err)
	}
}

// A removed template entry stays removed when its template is renamed,
// because the removal records the entry's types.
func TestARemovedTemplateEntryStaysRemovedAfterARename(t *testing.T) {
	w := generateTestWallet(t)
	var ticket credtemplate.Template
	for _, tpl := range credtemplate.PredefinedTemplates() {
		if tpl.Name == "demo-ticket" {
			ticket = tpl
		}
	}
	entryFor := func() (CatalogAttestation, bool) {
		for _, e := range w.CatalogAttestations() {
			if slices.ContainsFunc(e.Credentials, func(c CatalogCredential) bool { return c.Type == ticket.VCT }) {
				return e, true
			}
		}
		return CatalogAttestation{}, false
	}
	entry, ok := entryFor()
	if !ok {
		t.Fatal("the demo ticket has no catalogue entry")
	}
	if err := w.DeleteCatalogAttestation(entry.Schema.ID); err != nil {
		t.Fatal(err)
	}
	renamed := *ticket.Display
	renamed.Name = "Renamed ticket"
	ticket.Display = &renamed
	if _, err := credtemplate.Save(w.env.templates, ticket); err != nil {
		t.Fatal(err)
	}
	if e, ok := entryFor(); ok {
		t.Errorf("the renamed template brought back %q", e.Name)
	}
}

// The categories with a list type of ETSI TS 119 602 use the constants that
// lote.Sign switches on.
func TestCategoryListTypesAreTheETSITypes(t *testing.T) {
	if got := CategoryOf(credtemplate.CategoryPID).LoTEType; got != lote.PIDProvidersListType {
		t.Errorf("PID list type %q, want %q", got, lote.PIDProvidersListType)
	}
	if got := CategoryOf(credtemplate.CategoryPubEAA).LoTEType; got != lote.PubEAAProvidersListType {
		t.Errorf("PuB-EAA list type %q, want %q", got, lote.PubEAAProvidersListType)
	}
}

// The category table names every category of the templates in their order,
// and each list type and entitlement leads back to its category.
func TestCategoryTableWorksBothWays(t *testing.T) {
	var ids []string
	for _, c := range Categories() {
		ids = append(ids, c.ID)
		if got, ok := CategoryOfListType(c.LoTEType); !ok || got != c.ID {
			t.Errorf("list type %s gives %q, want %s", c.LoTEType, got, c.ID)
		}
		if got, ok := CategoryOfEntitlement(c.Entitlement); !ok || got != c.ID {
			t.Errorf("entitlement %s gives %q, want %s", c.Entitlement, got, c.ID)
		}
		if !slices.Contains(registeredEntitlements, c.Entitlement) || !slices.Contains(OptionValues(AttestationLevels), c.AttestationLoS) {
			t.Errorf("category %s has an unregistered entitlement or level of security", c.ID)
		}
	}
	if !slices.Equal(ids, credtemplate.Categories) {
		t.Errorf("categories %v, want %v", ids, credtemplate.Categories)
	}
}
