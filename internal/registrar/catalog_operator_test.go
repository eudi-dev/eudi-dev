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
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

func operatorEntry(name, vct string) CatalogAttestation {
	return CatalogAttestation{Name: name, Credentials: []CatalogCredential{{Format: "dc+sd-jwt", Type: vct, Claims: [][]any{{"member_id"}}}}}
}

// An operator entry takes its id from its name, so it keeps its id across
// restarts, and a file loaded again changes nothing.
func TestTheOperatorCatalogueKeepsItsIDs(t *testing.T) {
	w := generateTestWallet(t)
	if changed, err := w.SetOperatorCatalog(nil); err != nil || changed {
		t.Fatalf("an empty file on an empty catalogue: changed %v, %v", changed, err)
	}
	visitor, err := w.AddCatalogAttestation(operatorEntry("Visitor card", "urn:example:visitor:1"))
	if err != nil {
		t.Fatal(err)
	}
	file := []CatalogAttestation{operatorEntry("Member card", "urn:example:member:1"), operatorEntry("Library card", "urn:example:library:1")}
	if changed, err := w.SetOperatorCatalog(file); err != nil || !changed {
		t.Fatalf("first load: changed %v, %v", changed, err)
	}
	for _, e := range file {
		id := catalogEntryID(e.Name)
		entry, ok := w.CatalogAttestation(id)
		if !ok || !entry.Operator || entry.Template || !w.IsOperatorCatalogID(id) {
			t.Errorf("%s: %+v, want an operator entry under %s", e.Name, entry, id)
		}
	}
	if w.IsOperatorCatalogID(visitor.Schema.ID) {
		t.Error("an added entry counts as the operator's")
	}
	if changed, err := w.SetOperatorCatalog(file); err != nil || changed {
		t.Errorf("the same file again: changed %v, %v", changed, err)
	}

	if changed, err := w.SetOperatorCatalog(file[1:]); err != nil || !changed {
		t.Fatalf("a shorter file: changed %v, %v", changed, err)
	}
	var names []string
	for _, e := range w.Catalog {
		names = append(names, e.Name)
	}
	if want := []string{"Visitor card", "Library card"}; !slices.Equal(names, want) {
		t.Errorf("stored catalogue %v, want %v", names, want)
	}
}

func TestTheOperatorCatalogueNamesTheRefusedEntry(t *testing.T) {
	w := generateTestWallet(t)
	before := slices.Clone(w.Catalog)
	for _, tc := range []struct {
		name    string
		entries []CatalogAttestation
		index   int
		want    string
	}{
		{"invalid entry", []CatalogAttestation{operatorEntry("Member card", "urn:example:member:1"), {Name: "No formats"}}, 1, "entry 2: an attestation needs at least one format"},
		{"template name", []CatalogAttestation{operatorEntry("EUDI PID", "urn:example:pid:1")}, 0, `entry 1: the catalogue already lists "EUDI PID"`},
		{"type twice in the file", []CatalogAttestation{operatorEntry("Member card", "urn:example:member:1"), operatorEntry("Other card", "urn:example:member:1")}, 1, "entry 2: the catalogue already lists urn:example:member:1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := w.SetOperatorCatalog(tc.entries)
			var entryErr *CatalogEntryError
			if !errors.As(err, &entryErr) || entryErr.Index != tc.index || !strings.HasPrefix(err.Error(), tc.want) || !errors.Is(err, entryErr.Err) {
				t.Errorf("error %v, want %q", err, tc.want)
			}
			if !reflect.DeepEqual(w.Catalog, before) {
				t.Errorf("a refused file changed the catalogue to %+v", w.Catalog)
			}
		})
	}
}

// CheckCatalogEntry checks the data model alone, and CheckCatalogAttestation
// also compares the entry with the catalogue. Neither adds it.
func TestCheckingACatalogueEntry(t *testing.T) {
	w := generateTestWallet(t)
	pidName := operatorEntry("EUDI PID", "urn:example:pid:1")
	if err := CheckCatalogEntry(pidName); err != nil {
		t.Errorf("CheckCatalogEntry: %v, want the data model accepted", err)
	}
	if err := CheckCatalogEntry(CatalogAttestation{Name: "No formats"}); err == nil || !strings.Contains(err.Error(), "at least one format") {
		t.Errorf("CheckCatalogEntry without formats: %v", err)
	}
	if err := w.CheckCatalogAttestation(pidName); err == nil || !strings.Contains(err.Error(), `already lists "EUDI PID"`) {
		t.Errorf("CheckCatalogAttestation: %v, want the name taken", err)
	}
	if err := w.CheckCatalogAttestation(operatorEntry("Member card", "urn:example:member:1")); err != nil {
		t.Errorf("CheckCatalogAttestation: %v", err)
	}
	if len(w.Catalog) != 0 {
		t.Errorf("a check stored %+v", w.Catalog)
	}
}

// An SD-JWT object claim is listed with its members. An mdoc claim is an
// element of the template's namespace, or namespace:element.
func TestATemplateBecomesACatalogueEntry(t *testing.T) {
	sdjwt := credtemplate.Template{
		Name: "member", Format: "dc+sd-jwt", VCT: "urn:example:member:1",
		Claims:  map[string]any{"name": "Erika", "address": map[string]any{"street": "Main", "city": "Berlin"}},
		Display: &credtemplate.TemplateDisplay{Name: "Member card"},
	}
	entry, err := TemplateCatalogAttestation(sdjwt, CatalogAttestation{})
	if err != nil {
		t.Fatal(err)
	}
	want := []CatalogCredential{{Format: "dc+sd-jwt", Type: "urn:example:member:1", Claims: [][]any{{"address"}, {"address", "city"}, {"address", "street"}, {"name"}}}}
	if entry.Name != "Member card" || entry.Category != "eaa" || !reflect.DeepEqual(entry.Credentials, want) {
		t.Errorf("entry %+v, want %+v", entry, want)
	}

	mdoc := credtemplate.Template{
		Name: "membership", Format: "mso_mdoc", DocType: "org.example.member.1", Namespace: "org.example.member", Category: "qeaa",
		Claims: map[string]any{"name": "Erika", "org.example.extra:level": "gold"},
	}
	entry, err = TemplateCatalogAttestation(mdoc, CatalogAttestation{Name: "Gold card", Category: "pub-eaa"})
	if err != nil {
		t.Fatal(err)
	}
	want = []CatalogCredential{{Format: "mso_mdoc", Type: "org.example.member.1", Claims: [][]any{{"org.example.member", "name"}, {"org.example.extra", "level"}}}}
	if entry.Name != "Gold card" || entry.Category != "pub-eaa" || !reflect.DeepEqual(entry.Credentials, want) {
		t.Errorf("entry %+v, want %+v", entry, want)
	}

	for _, tc := range []struct {
		name string
		t    credtemplate.Template
		want string
	}{
		{"plain JWT", credtemplate.Template{Name: "jwt", Format: "jwt", VCT: "urn:example:jwt"}, "only an SD-JWT VC template"},
		{"no vct", credtemplate.Template{Name: "untyped", Format: "sdjwt"}, "only an SD-JWT VC template"},
		{"unknown format", credtemplate.Template{Name: "ldp", Format: "ldp_vc"}, "ldp_vc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := TemplateCatalogAttestation(tc.t, CatalogAttestation{}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want %q", err, tc.want)
			}
		})
	}
}

func TestATemplateCatalogueEntryIsChecked(t *testing.T) {
	w := generateTestWallet(t)
	member := credtemplate.Template{Name: "member", Format: "sdjwt", VCT: "urn:example:member:1", Claims: map[string]any{"name": "Erika"}}
	entry, err := w.TemplateCatalogEntry(member, CatalogAttestation{Schema: AttestationSchema{AttestationLoS: "iso_18045_high"}})
	if err != nil || entry.Name != "member" || entry.Schema.AttestationLoS != "iso_18045_high" {
		t.Errorf("entry %+v, %v", entry, err)
	}
	if _, err := w.TemplateCatalogEntry(member, CatalogAttestation{Name: "EUDI PID"}); err == nil || !strings.Contains(err.Error(), "already lists") {
		t.Errorf("a template entry with the PID's name: %v", err)
	}
	if _, err := w.TemplateCatalogEntry(credtemplate.Template{Name: "jwt", Format: "jwt"}, CatalogAttestation{}); err == nil {
		t.Error("a plain JWT template got an entry")
	}
}

func saveTestTemplate(t *testing.T, w *testWallet, tpl credtemplate.Template, catalog string) {
	t.Helper()
	if catalog != "" {
		tpl.Catalog = json.RawMessage(catalog)
	}
	if _, err := credtemplate.Save(w.env.templates, tpl); err != nil {
		t.Fatal(err)
	}
}

// A template with a catalog object makes up a catalogue entry with the
// object's fields.
func TestATemplateCatalogObjectMakesUpAnEntry(t *testing.T) {
	w := generateTestWallet(t)
	saveTestTemplate(t, w, credtemplate.Template{Name: "member-a-sdjwt", Format: "sdjwt", VCT: "urn:example:member:1", Rulebook: "https://example.com/member-rulebook", Claims: map[string]any{"name": "Erika"}},
		`{"name":"Member card","category":"qeaa","schema":{"bindingType":"claim"}}`)
	saveTestTemplate(t, w, credtemplate.Template{Name: "member-b-mdoc", Format: "mdoc", DocType: "org.example.member.1", Claims: map[string]any{"name": "Erika"}},
		`{"name":"Member card"}`)
	// A user template without a catalog object is added only on request.
	saveTestTemplate(t, w, credtemplate.Template{Name: "plain", Format: "sdjwt", VCT: "urn:example:plain:1", Claims: map[string]any{"name": "Erika"}}, "")

	i := slices.IndexFunc(w.CatalogAttestations(), func(e CatalogAttestation) bool { return e.Name == "Member card" })
	if i < 0 {
		t.Fatal("no entry for the member templates")
	}
	entry := w.CatalogAttestations()[i]
	if !entry.Template || entry.Category != "qeaa" || entry.Schema.ID != catalogEntryID("Member card") || entry.Schema.BindingType != "claim" ||
		entry.Schema.RulebookURI != "https://example.com/member-rulebook" || !slices.Equal(entry.Schema.SupportedFormats, []string{"dc+sd-jwt", "mso_mdoc"}) {
		t.Errorf("entry %+v", entry)
	}
	if !w.IsTemplateCatalogID(entry.Schema.ID) {
		t.Error("the entry does not count as a template entry")
	}
	if slices.ContainsFunc(w.CatalogAttestations(), func(e CatalogAttestation) bool { return e.Name == "plain" }) {
		t.Error("a template without a catalog object is listed")
	}
	if err := w.CheckTemplateCatalog(nil); err != nil {
		t.Errorf("CheckTemplateCatalog: %v", err)
	}
}

// CheckTemplateCatalog names the template whose catalog object the catalogue
// can't take. The catalogue leaves an invalid object out.
func TestCheckTemplateCatalogNamesTheTemplate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		vct     string
		catalog string
		want    string
	}{
		{"malformed object", "urn:example:member:1", `{"name":5}`, `template "member": catalog:`},
		{"invalid field", "urn:example:member:1", `{"schema":{"attestationLoS":"high"}}`, `template "member": attestationLoS "high"`},
		{"the PID's type", mock.DefaultPIDVCT, `{"name":"Member card"}`, `template "member": the catalogue already lists ` + mock.DefaultPIDVCT + ` (dc+sd-jwt) under "EUDI PID"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			saveTestTemplate(t, w, credtemplate.Template{Name: "member", Format: "sdjwt", VCT: tc.vct, Claims: map[string]any{"name": "Erika"}}, tc.catalog)
			if err := w.CheckTemplateCatalog(nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want %q", err, tc.want)
			}
		})
	}
	w := generateTestWallet(t)
	saveTestTemplate(t, w, credtemplate.Template{Name: "member", Format: "sdjwt", VCT: "urn:example:member:1", Claims: map[string]any{"name": "Erika"}}, `{"schema":{"bindingType":"device"}}`)
	if slices.ContainsFunc(w.CatalogAttestations(), func(e CatalogAttestation) bool {
		return slices.ContainsFunc(e.Credentials, func(c CatalogCredential) bool { return c.Type == "urn:example:member:1" })
	}) {
		t.Error("the catalogue lists an invalid catalog object")
	}
}

// With a template to save, CheckTemplateCatalog checks the templates as they
// would be and reports only that template's problems.
func TestCheckTemplateCatalogBeforeSaving(t *testing.T) {
	w := generateTestWallet(t)
	saveTestTemplate(t, w, credtemplate.Template{Name: "broken", Format: "sdjwt", VCT: "urn:example:broken:1", Claims: map[string]any{}}, `{"schema":{"bindingType":"device"}}`)
	saveTestTemplate(t, w, credtemplate.Template{Name: "member", Format: "sdjwt", VCT: "urn:example:member:1", Claims: map[string]any{}}, `{"name":"Member card"}`)

	same := credtemplate.Template{Name: "other", Format: "sdjwt", VCT: "urn:example:other:1", Claims: map[string]any{}, Catalog: json.RawMessage(`{"name":"Member card"}`)}
	if err := w.CheckTemplateCatalog(&same); err == nil || !strings.Contains(err.Error(), `template "other": another template already makes up "Member card" in dc+sd-jwt`) || strings.Contains(err.Error(), "broken") {
		t.Errorf("error %v, want the clash of the template to save", err)
	}
	clash := credtemplate.Template{Name: "other", Format: "sdjwt", VCT: "urn:example:member:1", Claims: map[string]any{}, Catalog: json.RawMessage(`{"name":"Club card"}`)}
	if err := w.CheckTemplateCatalog(&clash); err == nil || !strings.Contains(err.Error(), `template "other": the catalogue already lists urn:example:member:1`) {
		t.Errorf("error %v, want the type taken", err)
	}
	fixed := credtemplate.Template{Name: "member", Format: "sdjwt", VCT: "urn:example:member:2", Claims: map[string]any{}, Catalog: json.RawMessage(`{"name":"Member card"}`)}
	if err := w.CheckTemplateCatalog(&fixed); err != nil {
		t.Errorf("replacing a valid template: %v", err)
	}
	if err := w.CheckTemplateCatalog(nil); err == nil || !strings.Contains(err.Error(), `template "broken"`) {
		t.Errorf("error %v, want the broken template", err)
	}
}

// A template file can reach the template directory without
// CheckTemplateCatalog. Its catalog object then leaves the predefined entries
// as they are, and each type keeps one entry.
func TestATemplateCatalogObjectKeepsThePredefinedEntries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		catalog string
	}{
		{"the PID's type under another name", `{"name":"Other"}`},
		{"the name of the PID entry", `{"name":"EUDI PID"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			saveTestTemplate(t, w, credtemplate.Template{Name: "a-member", Format: "sdjwt", VCT: mock.DefaultPIDVCT, Claims: map[string]any{"name": "Erika"}}, tc.catalog)
			var listing []string
			for _, e := range w.CatalogAttestations() {
				for _, c := range e.Credentials {
					if c.Format == "dc+sd-jwt" && c.Type == mock.DefaultPIDVCT {
						listing = append(listing, e.Name)
					}
				}
			}
			if !slices.Equal(listing, []string{"EUDI PID"}) {
				t.Errorf("entries for %s: %v, want only the predefined EUDI PID", mock.DefaultPIDVCT, listing)
			}
		})
	}
}
