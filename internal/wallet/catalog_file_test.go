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
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
)

const diplomaCatalogYAML = `name: University diploma
category: qeaa
credentials:
  - format: dc+sd-jwt
    type: urn:example:diploma:1
    claims: [[degree], [graduation_date]]
schema:
  version: 1.0
  attestationLoS: iso_18045_moderate
`

const libraryCatalogJSON = `[
  {"name": "Library card", "credentials": [{"format": "mso_mdoc", "type": "org.example.library.1", "claims": [["org.example.library.1", "member_id"]]}]},
  {"name": "Gym pass", "credentials": [{"format": "dc+sd-jwt", "type": "urn:example:gym:1"}]}
]`

func writeCatalogFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadCatalog(t *testing.T, path string) *CatalogFile {
	t.Helper()
	file, err := LoadCatalogFile(path)
	if err != nil {
		t.Fatalf("LoadCatalogFile: %v", err)
	}
	return file
}

func catalogEntryNamed(w *Wallet, name string) (registrar.CatalogAttestation, bool) {
	entries := w.Registrar().CatalogAttestations()
	i := slices.IndexFunc(entries, func(e registrar.CatalogAttestation) bool { return e.Name == name })
	if i < 0 {
		return registrar.CatalogAttestation{}, false
	}
	return entries[i], true
}

// A catalogue file holds one entry or a list, and a directory holds such
// files in name order.
func TestLoadCatalogFileReadsFilesDirectoriesAndLists(t *testing.T) {
	dir := t.TempDir()
	writeCatalogFile(t, dir, "a-diploma.yaml", diplomaCatalogYAML)
	writeCatalogFile(t, dir, "b-library.json", libraryCatalogJSON)
	writeCatalogFile(t, dir, "notes.txt", "not a catalogue")

	file := loadCatalog(t, dir)
	var names []string
	for _, e := range file.Entries {
		names = append(names, e.Name)
	}
	if !slices.Equal(names, []string{"University diploma", "Library card", "Gym pass"}) {
		t.Fatalf("entries %v", names)
	}
	if v := file.Entries[0].Schema.Version; v != "1.0" {
		t.Errorf("version %q, want the YAML 1.0 as text", v)
	}
	if single := loadCatalog(t, filepath.Join(dir, "a-diploma.yaml")); len(single.Entries) != 1 {
		t.Errorf("single file: %d entries", len(single.Entries))
	}
}

// A bad entry stops the start with the file and the entry in the message.
func TestLoadCatalogFileNamesTheFileAndEntryOfAnError(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"format.yaml":  "name: Bad format\ncredentials: [{format: jwt_vc_json, type: urn:x}]\n",
		"unknown.yaml": "name: Typo\ncredentails: []\n",
		"ca.yaml":      "name: Missing CA\ncredentials: [{format: dc+sd-jwt, type: urn:x}]\nissuerCA: missing.pem\n",
	} {
		path := writeCatalogFile(t, dir, name, content)
		_, err := LoadCatalogFile(path)
		if err == nil || !strings.Contains(err.Error(), path) {
			t.Errorf("%s: %v, want an error naming the file", name, err)
		}
	}
	path := writeCatalogFile(t, t.TempDir(), "format.yaml", "name: Bad format\ncredentials: [{format: jwt_vc_json, type: urn:x}]\n")
	if _, err := LoadCatalogFile(path); err == nil || !strings.Contains(err.Error(), `"Bad format"`) {
		t.Errorf("error %v, want the entry name", err)
	}

	dup := t.TempDir()
	writeCatalogFile(t, dup, "a.yaml", "name: Twice\ncredentials: [{format: dc+sd-jwt, type: urn:a}]\n")
	writeCatalogFile(t, dup, "b.yaml", "name: twice\ncredentials: [{format: dc+sd-jwt, type: urn:b}]\n")
	if _, err := LoadCatalogFile(dup); err == nil || !strings.Contains(err.Error(), "a.yaml") || !strings.Contains(err.Error(), "b.yaml") {
		t.Errorf("duplicate name: %v, want both files", err)
	}

	w := generateTestWallet(t)
	w.Templates = credtemplate.FileLocation(t.TempDir())
	if _, err := w.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{Name: "Added diploma", Credentials: []registrar.CatalogCredential{{Format: "dc+sd-jwt", Type: "urn:example:diploma:1"}}}); err != nil {
		t.Fatal(err)
	}
	clash := writeCatalogFile(t, t.TempDir(), "diploma.yaml", diplomaCatalogYAML)
	if _, err := w.ApplyCatalogFile(loadCatalog(t, clash)); err == nil || !strings.Contains(err.Error(), clash) || !strings.Contains(err.Error(), "University diploma") {
		t.Errorf("clash with an added entry: %v, want the file and the entry", err)
	}
}

// Every start applies the file again. Entries keep their ids, a changed
// entry is updated, and an entry dropped from the file is removed. Entries added
// through the API stay.
func TestApplyCatalogFileIsIdempotentAndFollowsTheFile(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(t.TempDir())
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	w.Templates = credtemplate.FileLocation(t.TempDir())
	writeCatalogFile(t, dir, "a-diploma.yaml", diplomaCatalogYAML)
	library := writeCatalogFile(t, dir, "b-library.json", libraryCatalogJSON)

	if changed, err := w.ApplyCatalogFile(loadCatalog(t, dir)); err != nil || !changed {
		t.Fatalf("first apply: changed %v, %v", changed, err)
	}
	if _, err := w.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{Name: "Visitor badge", Credentials: []registrar.CatalogCredential{{Format: "dc+sd-jwt", Type: "urn:example:badge:1"}}}); err != nil {
		t.Fatal(err)
	}
	diploma, ok := catalogEntryNamed(w, "University diploma")
	if !ok || !diploma.Operator || diploma.Category != "qeaa" || diploma.Schema.AttestationLoS != "iso_18045_moderate" {
		t.Fatalf("diploma entry %+v", diploma)
	}
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}

	restarted, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	restarted.Templates = w.Templates
	if changed, err := restarted.ApplyCatalogFile(loadCatalog(t, dir)); err != nil || changed {
		t.Fatalf("restart with the same file: changed %v, %v", changed, err)
	}
	again, _ := catalogEntryNamed(restarted, "University diploma")
	if again.Schema.ID != diploma.Schema.ID || len(restarted.Registrar().CatalogAttestations()) != len(w.Registrar().CatalogAttestations()) {
		t.Fatalf("restart changed the catalogue: id %s, want %s", again.Schema.ID, diploma.Schema.ID)
	}

	writeCatalogFile(t, dir, "a-diploma.yaml", strings.Replace(diplomaCatalogYAML, "iso_18045_moderate", "iso_18045_high", 1))
	if err := os.Remove(library); err != nil {
		t.Fatal(err)
	}
	if changed, err := restarted.ApplyCatalogFile(loadCatalog(t, dir)); err != nil || !changed {
		t.Fatalf("changed file: changed %v, %v", changed, err)
	}
	updated, _ := catalogEntryNamed(restarted, "University diploma")
	if updated.Schema.ID != diploma.Schema.ID || updated.Schema.AttestationLoS != "iso_18045_high" {
		t.Errorf("updated entry %+v", updated)
	}
	for name, want := range map[string]bool{"Library card": false, "Gym pass": false, "Visitor badge": true} {
		if _, ok := catalogEntryNamed(restarted, name); ok != want {
			t.Errorf("%s listed: %v, want %v", name, ok, want)
		}
	}

	if changed, err := restarted.ApplyCatalogFile(nil); err != nil || !changed {
		t.Fatalf("start without --catalog: changed %v, %v", changed, err)
	}
	if _, ok := catalogEntryNamed(restarted, "University diploma"); ok {
		t.Error("the entry of the earlier file stayed")
	}
}

// issuerCA puts the CA on the trusted list of the entry's category, as
// catalog add --issuer-ca does.
func TestCatalogFileIssuerCALandsOnTheCategoryList(t *testing.T) {
	w := generateTestWallet(t)
	w.Templates = credtemplate.FileLocation(t.TempDir())
	foreign := generateTestWallet(t)
	dir := t.TempDir()
	writeCatalogFile(t, dir, "issuer.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreign.Signer().TrustAnchor().Raw})))
	path := writeCatalogFile(t, dir, "diploma.yaml", diplomaCatalogYAML+"issuerCA: issuer.pem\n")

	file := loadCatalog(t, path)
	for range 2 {
		if _, err := w.ApplyCatalogFile(file); err != nil {
			t.Fatal(err)
		}
	}
	entities := w.TrustedLists().Entities()
	if len(entities) != 1 || entities[0].List != "qeaa" || entities[0].Name != "University diploma issuer" {
		t.Fatalf("trusted entities %+v, want the CA once on the qeaa list", entities)
	}

	linked := writeCatalogFile(t, dir, "linked.yaml", "name: Linked\ncredentials: [{format: dc+sd-jwt, type: urn:x}]\nissuerCA: issuer.pem\nschema:\n  trustedAuthorities: [{frameworkType: etsi_tl, value: https://lists.example/eaa}]\n")
	if _, err := LoadCatalogFile(linked); err == nil || !strings.Contains(err.Error(), "trustedAuthorities") {
		t.Errorf("issuerCA with trustedAuthorities: %v", err)
	}
}

// On a public demo visitors can't change or delete the operator's entries.
// Outside the demo the API changes them until the next start.
func TestOperatorCatalogEntriesAreFixedOnTheDemo(t *testing.T) {
	for _, demo := range []bool{true, false} {
		srv := newTestServer(t, true)
		srv.wallet.Templates = credtemplate.FileLocation(t.TempDir())
		if _, err := srv.wallet.ApplyCatalogFile(loadCatalog(t, writeCatalogFile(t, t.TempDir(), "diploma.yaml", diplomaCatalogYAML))); err != nil {
			t.Fatal(err)
		}
		if demo {
			if err := srv.SetDemo(DemoOptions{}); err != nil {
				t.Fatal(err)
			}
		}
		entry, _ := catalogEntryNamed(srv.wallet, "University diploma")
		want := http.StatusForbidden
		if !demo {
			want = http.StatusOK
		}
		schema := entry.Schema
		schema.Version = "2.0.0"
		if w := serverRequest(t, srv, "PUT", "/api/catalog/schemas/"+entry.Schema.ID, mustJSON(t, schema)); w.Code != want {
			t.Errorf("demo %v: PUT = %d %s, want %d", demo, w.Code, w.Body.String(), want)
		}
		if !demo {
			want = http.StatusNoContent
		}
		if w := serverRequest(t, srv, "DELETE", "/api/catalog/schemas/"+entry.Schema.ID, ""); w.Code != want {
			t.Errorf("demo %v: DELETE = %d %s, want %d", demo, w.Code, w.Body.String(), want)
		}
	}
}

// A demo reset clears the catalogue and the added providers. The baseline
// pre-registers the file's entries and their CA again.
func TestDemoResetPreRegistersTheCatalogueAgain(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.Templates = credtemplate.FileLocation(t.TempDir())
	foreign := generateTestWallet(t)
	dir := t.TempDir()
	writeCatalogFile(t, dir, "issuer.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreign.Signer().TrustAnchor().Raw})))
	file := loadCatalog(t, writeCatalogFile(t, dir, "diploma.yaml", diplomaCatalogYAML+"issuerCA: issuer.pem\n"))
	baseline := func() error {
		if _, err := srv.wallet.ApplyCatalogFile(file); err != nil {
			return err
		}
		return srv.wallet.GenerateProtectedDefaults()
	}
	if err := srv.SetDemo(DemoOptions{ResetInterval: time.Hour, Baseline: baseline}); err != nil {
		t.Fatal(err)
	}
	if err := baseline(); err != nil {
		t.Fatal(err)
	}
	before, _ := catalogEntryNamed(srv.wallet, "University diploma")
	if err := srv.wallet.TrustedLists().RemoveEntity(srv.wallet.TrustedLists().Entities()[0].ID); err != nil {
		t.Fatal(err)
	}

	if err := srv.demoReset(); err != nil {
		t.Fatalf("demoReset: %v", err)
	}
	after, ok := catalogEntryNamed(srv.wallet, "University diploma")
	if !ok || after.Schema.ID != before.Schema.ID {
		t.Fatalf("after reset: %+v, want the entry with id %s", after, before.Schema.ID)
	}
	if entities := srv.wallet.TrustedLists().Entities(); !slices.ContainsFunc(entities, func(e trustedlists.Entity) bool { return e.List == "qeaa" }) {
		t.Errorf("after reset the issuer CA is missing: %+v", entities)
	}
}

const libraryTemplateJSON = `{"format": "sdjwt", "vct": "urn:example:library:1", "claims": {"member_id": "42"}, "display": {"name": "Library"},
  "catalog": {"name": "Library card", "category": "pub-eaa", "schema": {"rulebookURI": "https://library.example/rulebook"}}}`

// A template file with a catalog object makes up its own entry. The entry
// follows the template file, and saving the template keeps the object.
func TestATemplateFileCarriesItsCatalogueEntry(t *testing.T) {
	srv := newTestServer(t, true)
	dir := t.TempDir()
	srv.wallet.Templates = credtemplate.FileLocation(dir)
	writeCatalogFile(t, dir, "library.json", libraryTemplateJSON)
	if err := srv.wallet.Registrar().CheckTemplateCatalog(nil); err != nil {
		t.Fatalf("CheckTemplateCatalog: %v", err)
	}

	entry, ok := catalogEntryNamed(srv.wallet, "Library card")
	if !ok || !entry.Template || entry.Category != "pub-eaa" || entry.Schema.RulebookURI != "https://library.example/rulebook" ||
		len(entry.Credentials) != 1 || entry.Credentials[0].Type != "urn:example:library:1" {
		t.Fatalf("entry %+v", entry)
	}
	got := serverRequest(t, srv, "GET", "/api/templates/library", "")
	var tpl credtemplate.Template
	if err := json.Unmarshal(got.Body.Bytes(), &tpl); err != nil || tpl.Category != "pub-eaa" || !strings.Contains(string(tpl.Catalog), "Library card") {
		t.Fatalf("GET template: %v %s", err, got.Body.String())
	}

	// The template editor sends the template without catalog when its
	// catalogue box is clear.
	if w := serverRequest(t, srv, "PUT", "/api/templates/library", `{"format":"sdjwt","vct":"urn:example:library:1","claims":{"member_id":"43"}}`); w.Code != http.StatusOK {
		t.Fatalf("PUT without catalog: %d %s", w.Code, w.Body.String())
	}
	if kept, ok := catalogEntryNamed(srv.wallet, "Library card"); !ok || kept.Schema.ID != entry.Schema.ID {
		t.Fatalf("saving the template dropped its entry")
	}
	if w := serverRequest(t, srv, "PUT", "/api/templates/library", `{"format":"sdjwt","vct":"urn:example:library:1","claims":{},"catalog":{"name":"Library pass","schema":{"attestationLoS":"iso_18045_high"}}}`); w.Code != http.StatusOK {
		t.Fatalf("PUT with catalog: %d %s", w.Code, w.Body.String())
	}
	renamed, ok := catalogEntryNamed(srv.wallet, "Library pass")
	if !ok || !renamed.Template || renamed.Schema.AttestationLoS != "iso_18045_high" {
		t.Fatalf("updated entry %+v", renamed)
	}
	if _, ok := catalogEntryNamed(srv.wallet, "Library card"); ok {
		t.Error("the old entry of the template stayed")
	}
	if slices.ContainsFunc(srv.wallet.Registrar().CatalogAttestations(), func(e registrar.CatalogAttestation) bool { return !e.Template && !e.Operator }) {
		t.Error("the template's catalog object became an added entry")
	}

	if w := serverRequest(t, srv, "DELETE", "/api/templates/library", ""); w.Code != http.StatusOK {
		t.Fatalf("DELETE template: %d", w.Code)
	}
	if _, ok := catalogEntryNamed(srv.wallet, "Library pass"); ok {
		t.Error("the entry outlived its template")
	}
}

// An invalid catalog object stops the start with the template's name. So does
// a catalog object that reuses the name of another entry.
func TestCheckTemplateCatalogNamesTheTemplate(t *testing.T) {
	for name, catalog := range map[string]string{
		"bad-los":   `{"name": "Bad level", "schema": {"attestationLoS": "iso_18045_extreme"}}`,
		"taken":     `{"name": "University diploma"}`,
		"not-typed": `{"name": "Untyped"}`,
	} {
		w := generateTestWallet(t)
		dir := t.TempDir()
		w.Templates = credtemplate.FileLocation(dir)
		if _, err := w.Registrar().AddCatalogAttestation(diplomaCatalogEntry()); err != nil {
			t.Fatal(err)
		}
		vct := `"vct": "urn:example:` + name + `:1", `
		if name == "not-typed" {
			vct = ""
		}
		writeCatalogFile(t, dir, name+".json", `{"format": "sdjwt", `+vct+`"claims": {}, "catalog": `+catalog+`}`)
		if err := w.Registrar().CheckTemplateCatalog(nil); err == nil || !strings.Contains(err.Error(), `"`+name+`"`) {
			t.Errorf("%s: %v, want an error naming the template", name, err)
		}
	}
}
