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

package credtemplate

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

// The German PID types come from the predefined templates.
const (
	germanPIDVCT       = "urn:eudi:pid:de:1"
	germanPIDNamespace = "eu.europa.ec.eudi.pid.de.1"
)

func TestPredefinedTemplates(t *testing.T) {
	predefined := PredefinedTemplates()
	if len(predefined) != 9 {
		t.Fatalf("expected 9 pre-defined templates, got %d", len(predefined))
	}

	sdjwt, err := Load("pid-sdjwt", FileLocation(t.TempDir()))
	if err != nil {
		t.Fatalf("loading pre-defined template: %v", err)
	}
	if !sdjwt.Predefined {
		t.Error("expected Predefined=true")
	}
	if sdjwt.Format != "sdjwt" || sdjwt.VCT != mock.DefaultPIDVCT {
		t.Errorf("unexpected format/vct: %q %q", sdjwt.Format, sdjwt.VCT)
	}
	if !sdjwt.Baseline {
		t.Error("pid-sdjwt is not a baseline PID")
	}

	// Each load gives its own claims.
	sdjwt.Claims["family_name"] = "CHANGED"
	sdjwt.Claims["address"].(map[string]any)["country"] = "XX"
	again, _ := Predefined("pid-sdjwt")
	if again.Claims["family_name"] != "'t Hart" || again.Claims["address"].(map[string]any)["country"] != "NL" {
		t.Errorf("a second load shares the changed claims: %v", again.Claims)
	}
}

// Every built-in template file is a valid template with a known category.
func TestPredefinedTemplateFilesAreValid(t *testing.T) {
	for _, tpl := range PredefinedTemplates() {
		if err := CheckCategory(tpl.Category); err != nil || tpl.Category == "" {
			t.Errorf("%s: category %q: %v", tpl.Name, tpl.Category, err)
		}
		for name, value := range tpl.Claims {
			if s, ok := value.(string); ok && strings.HasPrefix(s, "embedded:") {
				t.Errorf("%s: claim %s references a missing file %s", tpl.Name, name, s)
			}
		}
	}
}

// A claim "embedded:<file>" carries the file as a data URI, in a user
// template too.
func TestEmbeddedClaimsBecomeDataURIs(t *testing.T) {
	dir := t.TempDir()
	content := `{"format": "mdoc", "doctype": "org.example.1", "claims": {"portrait": "embedded:portraits/dutch.jpg", "nested": {"photo": "embedded:portraits/italian.jpg"}}}`
	if err := os.WriteFile(filepath.Join(dir, "photo.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	tpl, err := Load("photo", FileLocation(dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{tpl.Claims["portrait"], tpl.Claims["nested"].(map[string]any)["photo"]} {
		if s, _ := value.(string); !strings.HasPrefix(s, "data:image/jpeg;base64,/9j/") {
			t.Errorf("claim = %.40v, want a JPEG data URI", value)
		}
	}
}

func TestPredefinedGermanPIDTemplates(t *testing.T) {
	sdjwt, err := Load("german-pid-sdjwt", FileLocation(t.TempDir()))
	if err != nil {
		t.Fatalf("loading pre-defined template: %v", err)
	}
	if sdjwt.VCT != germanPIDVCT {
		t.Errorf("german-pid-sdjwt vct = %q, want %q", sdjwt.VCT, germanPIDVCT)
	}

	mdoc, err := Load("german-pid-mdoc", FileLocation(t.TempDir()))
	if err != nil {
		t.Fatalf("loading pre-defined template: %v", err)
	}
	// ISO/IEC 18013-5 has no inheritance between document types, so the
	// German PID shares the doctype and differs by its second namespace.
	if mdoc.DocType != mock.PIDNamespace {
		t.Errorf("german-pid-mdoc doctype = %q, want %q", mdoc.DocType, mock.PIDNamespace)
	}
	if _, ok := mdoc.Claims[germanPIDNamespace+":birth_name"]; !ok {
		t.Errorf("german-pid-mdoc is missing %s:birth_name", germanPIDNamespace)
	}
}

// IT-Wallet 1.4.7 §11.2: the PID has no address and keeps the issuer claims out of
// the selective disclosures. §11.1.2.1 makes its sub opaque and unique per
// credential.
func TestPredefinedItalianPIDTemplates(t *testing.T) {
	first, err := Load("italian-pid-sdjwt", FileLocation(t.TempDir()))
	if err != nil {
		t.Fatalf("loading pre-defined template: %v", err)
	}
	if first.VCT != "urn:eudi:pid:it:1" {
		t.Errorf("vct = %q, want %q", first.VCT, "urn:eudi:pid:it:1")
	}
	if _, ok := first.Claims["address"]; ok {
		t.Error("the Italian PID carries an address")
	}
	for _, claim := range []string{"sub", "date_of_expiry", "verification", "issuing_authority", "issuing_country"} {
		if !slices.Contains(first.AlwaysDisclosed, claim) {
			t.Errorf("%s is selectively disclosable", claim)
		}
	}
	one, two := first.WithUniqueClaims(first.Claims), first.WithUniqueClaims(first.Claims)
	if one["sub"] == "" || one["sub"] == two["sub"] {
		t.Errorf("sub %v then %v, want a new identifier for each issuance", one["sub"], two["sub"])
	}

	mdoc, err := Load("italian-pid-mdoc", FileLocation(t.TempDir()))
	if err != nil {
		t.Fatalf("loading pre-defined template: %v", err)
	}
	if mdoc.DocType != mock.PIDNamespace {
		t.Errorf("italian-pid-mdoc doctype = %q, want %q", mdoc.DocType, mock.PIDNamespace)
	}
	for _, element := range []string{"sub", "verification"} {
		if _, ok := mdoc.Claims["eu.europa.ec.eudi.pid.it.1"+":"+element]; !ok {
			t.Errorf("italian-pid-mdoc is missing %s:%s", "eu.europa.ec.eudi.pid.it.1", element)
		}
	}
}

func TestPredefinedDutchPIDTemplates(t *testing.T) {
	sdjwt, err := Load("dutch-pid-sdjwt", FileLocation(t.TempDir()))
	if err != nil {
		t.Fatalf("loading pre-defined template: %v", err)
	}
	if sdjwt.VCT != "urn:eudi:pid:nl:1" || sdjwt.Claims["bsn"] != "999991772" {
		t.Errorf("dutch-pid-sdjwt has vct %q and bsn %v, want %q and the sample BSN", sdjwt.VCT, sdjwt.Claims["bsn"], "urn:eudi:pid:nl:1")
	}

	// ARF PID_05 and PID_06: the PID doctype with the Dutch elements in a
	// domestic namespace.
	mdoc, err := Load("dutch-pid-mdoc", FileLocation(t.TempDir()))
	if err != nil {
		t.Fatalf("loading pre-defined template: %v", err)
	}
	if mdoc.DocType != mock.PIDNamespace {
		t.Errorf("dutch-pid-mdoc doctype = %q, want %q", mdoc.DocType, mock.PIDNamespace)
	}
	if _, ok := mdoc.Claims["eu.europa.ec.eudi.pid.nl.1"+":bsn"]; !ok {
		t.Errorf("dutch-pid-mdoc is missing %s:bsn", "eu.europa.ec.eudi.pid.nl.1")
	}
}

func TestPIDTemplatesCarryDisplayDescription(t *testing.T) {
	cases := map[string][]string{
		"pid-sdjwt":         {"EUDI PID Rulebook v1.7", "https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md"},
		"pid-mdoc":          {"EUDI PID Rulebook v1.7", "https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md"},
		"german-pid-sdjwt":  {"German PID Rulebook 1.0.0", "https://bmi.usercontent.opencode.de/eudi-wallet/eidas-2.0-architekturkonzept/content/features/PID/german-pid-rulebook/"},
		"german-pid-mdoc":   {"German PID Rulebook 1.0.0", "https://bmi.usercontent.opencode.de/eudi-wallet/eidas-2.0-architekturkonzept/content/features/PID/german-pid-rulebook/"},
		"italian-pid-sdjwt": {"IT-Wallet Technical Specifications 1.4.7", "https://italia.github.io/eid-wallet-it-docs/releases/1.4.7/en/credential-data-model-pid.html"},
		"italian-pid-mdoc":  {"IT-Wallet Technical Specifications 1.4.7", "https://italia.github.io/eid-wallet-it-docs/releases/1.4.7/en/credential-data-model-pid.html"},
		"dutch-pid-sdjwt":   {"NL Wallet", "https://github.com/MinBZK/nl-wallet/blob/ea1402d2ad96202617bee6771ac1395c73e96322/scripts/devenv/eudi_pid_nl_1.json"},
		"dutch-pid-mdoc":    {"NL Wallet", "https://github.com/MinBZK/nl-wallet/blob/ea1402d2ad96202617bee6771ac1395c73e96322/scripts/devenv/eudi_pid_nl_1.json"},
	}
	for name, wants := range cases {
		tpl, err := Load(name, FileLocation(t.TempDir()))
		if err != nil {
			t.Fatalf("loading %s: %v", name, err)
		}
		if tpl.Display == nil || tpl.Display.Description == "" {
			t.Fatalf("%s carries no display description", name)
		}
		for _, want := range wants {
			if !strings.Contains(tpl.Display.Description, want) {
				t.Errorf("%s description %q does not mention %q", name, tpl.Display.Description, want)
			}
		}
	}
}

// An empty date claim of a PID template is the date of issuance, and the
// expiry five years later. A set date stays.
func TestPIDTemplatesFillTheirEmptyDates(t *testing.T) {
	dir := t.TempDir()
	content := `{"format": "sdjwt", "vct": "urn:eudi:pid:fr:1", "category": "pid", "claims": {"date_of_issuance": "", "date_of_expiry": "2000-01-01"}}`
	if err := os.WriteFile(filepath.Join(dir, "french.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	user, err := Load("french", FileLocation(dir))
	if err != nil {
		t.Fatal(err)
	}
	today := time.Now().UTC()
	if got, want := user.Claims["date_of_issuance"], today.Format(time.DateOnly); got != want {
		t.Errorf("date_of_issuance = %v, want %v", got, want)
	}
	if got := user.Claims["date_of_expiry"]; got != "2000-01-01" {
		t.Errorf("date_of_expiry = %v, want the date of the template", got)
	}

	tpl, err := Load("pid-mdoc", FileLocation(t.TempDir()))
	if err != nil {
		t.Fatalf("loading pre-defined template: %v", err)
	}
	if got, want := tpl.Claims["expiry_date"], today.AddDate(5, 0, 0).Format(time.DateOnly); got != want {
		t.Errorf("expiry_date = %v, want %v", got, want)
	}
	// The German PID carries no issuance date, and refreshing must not invent one.
	german, err := Load("german-pid-sdjwt", FileLocation(t.TempDir()))
	if err != nil {
		t.Fatalf("loading pre-defined template: %v", err)
	}
	if _, ok := german.Claims["date_of_issuance"]; ok {
		t.Error("the German PID gained an issuance date its rulebook does not define")
	}
}

func TestPIDTemplateNames(t *testing.T) {
	tests := []struct {
		vct         string
		sdjwt, mdoc string
		known       bool
	}{
		{"", "pid-sdjwt", "pid-mdoc", true},
		{mock.DefaultPIDVCT, "pid-sdjwt", "pid-mdoc", true},
		{germanPIDVCT, "german-pid-sdjwt", "german-pid-mdoc", true},
		{"urn:eudi:pid:it:1", "italian-pid-sdjwt", "italian-pid-mdoc", true},
		{"urn:eudi:pid:nl:1", "dutch-pid-sdjwt", "dutch-pid-mdoc", true},
		{"urn:eudi:pid:fr:1", "french-pid-sdjwt", "french-pid-mdoc", true},
		// Unknown PID types use the base PID claims with the requested VCT.
		{"urn:example:custom:1", "pid-sdjwt", "pid-mdoc", false},
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"french-pid-sdjwt": `{"format": "sdjwt", "vct": "urn:eudi:pid:fr:1", "display": {"name": "French PID"}, "claims": {}}`,
		"french-pid-mdoc":  `{"format": "mdoc", "doctype": "eu.europa.ec.eudi.pid.1", "display": {"name": "French PID"}, "claims": {}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, tt := range tests {
		sdjwt, mdoc, known := PIDTemplateNames(tt.vct, FileLocation(dir))
		if sdjwt != tt.sdjwt || mdoc != tt.mdoc || known != tt.known {
			t.Errorf("PIDTemplateNames(%q) = %q, %q, %t, want %q, %q, %t",
				tt.vct, sdjwt, mdoc, known, tt.sdjwt, tt.mdoc, tt.known)
		}
	}
}

func TestUniqueClaimsGetANewValueForEveryCredential(t *testing.T) {
	tpl := &Template{UniqueClaims: []string{"sub", "absent"}}
	claims := map[string]any{"sub": "sample", "given_name": "Bianca"}
	first, second := tpl.WithUniqueClaims(claims), tpl.WithUniqueClaims(claims)
	if first["sub"] == "sample" || first["sub"] == second["sub"] {
		t.Errorf("sub = %v and %v, want two new values", first["sub"], second["sub"])
	}
	if first["given_name"] != "Bianca" || claims["sub"] != "sample" {
		t.Errorf("other claims or the template claims changed: %v, %v", first, claims)
	}
	if _, ok := first["absent"]; ok {
		t.Error("a unique claim outside the credential was added")
	}
}

func TestLoadFromFileAndByName(t *testing.T) {
	dir := t.TempDir()
	content := `{"format": "sdjwt", "vct": "urn:example:test", "claims": {"a": 1}, "always_disclosed": ["a"]}`
	path := filepath.Join(dir, "my-cred.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	byName, err := Load("my-cred", FileLocation(dir))
	if err != nil {
		t.Fatalf("loading by name: %v", err)
	}
	if byName.Name != "my-cred" {
		t.Errorf("expected name from file name, got %q", byName.Name)
	}
	if byName.VCT != "urn:example:test" || len(byName.AlwaysDisclosed) != 1 {
		t.Errorf("unexpected template: %+v", byName)
	}

	byPath, err := Load(path, Location{})
	if err != nil {
		t.Fatalf("loading by path: %v", err)
	}
	if byPath.Name != "my-cred" {
		t.Errorf("expected name from file name, got %q", byPath.Name)
	}

	if _, err := Load("does-not-exist", FileLocation(dir)); err == nil {
		t.Error("expected error for unknown template")
	}
}

func TestLoadTemplateExtension(t *testing.T) {
	dir := t.TempDir()
	content := `{"format": "mdoc", "claims": {"family_name": "TEST"}}`
	if err := os.WriteFile(filepath.Join(dir, "my-mdoc.template"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	tpl, err := Load("my-mdoc", FileLocation(dir))
	if err != nil {
		t.Fatalf("loading .template file: %v", err)
	}
	if tpl.Name != "my-mdoc" || tpl.Format != "mdoc" {
		t.Errorf("unexpected template: %+v", tpl)
	}
}

func TestLoadRejectsInvalidFormat(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte(`{"format": "nope", "claims": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("bad", FileLocation(dir)); err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestListUserOverridesPredefined(t *testing.T) {
	dir := t.TempDir()
	content := `{"format": "sdjwt", "vct": "urn:custom", "claims": {"a": 1}}`
	if err := os.WriteFile(filepath.Join(dir, "german-pid-sdjwt.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	templates, err := List(FileLocation(dir))
	if err != nil {
		t.Fatal(err)
	}
	var found *Template
	for i := range templates {
		if templates[i].Name == "german-pid-sdjwt" {
			found = &templates[i]
		}
	}
	if found == nil {
		t.Fatal("german-pid-sdjwt missing from list")
	}
	if found.Predefined || found.VCT != "urn:custom" {
		t.Errorf("user template did not override the pre-defined one: %+v", found)
	}
}

func TestListMissingDir(t *testing.T) {
	templates, err := List(FileLocation(filepath.Join(t.TempDir(), "nope")))
	if err != nil {
		t.Fatalf("missing dir must not error: %v", err)
	}
	if len(templates) != len(PredefinedTemplates()) {
		t.Errorf("expected only built-ins, got %d", len(templates))
	}
}

func TestSaveAndDelete(t *testing.T) {
	dir := t.TempDir()
	tpl := Template{
		Name:            "test-cred",
		Format:          "sdjwt",
		VCT:             "urn:example:test",
		Claims:          map[string]any{"given_name": "ERIKA"},
		AlwaysDisclosed: []string{"given_name"},
		Predefined:      true,
	}
	path, err := Save(FileLocation(dir), tpl)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load("test-cred", FileLocation(dir))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Predefined {
		t.Error("saved template must not be marked pre-defined")
	}
	if loaded.VCT != tpl.VCT || len(loaded.AlwaysDisclosed) != 1 {
		t.Errorf("round trip mismatch: %+v", loaded)
	}

	if err := Delete(FileLocation(dir), "test-cred"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("template file still exists after delete")
	}
	if err := Delete(FileLocation(dir), "german-pid-sdjwt"); err == nil {
		t.Error("deleting a pre-defined template must fail")
	}
	if err := Delete(FileLocation(dir), "test-cred"); err == nil {
		t.Error("deleting a missing template must fail")
	}
}

func TestSaveRejectsBadNames(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"", "../escape", "a/b", ".hidden"} {
		if _, err := Save(FileLocation(dir), Template{Name: name}); err == nil {
			t.Errorf("expected error for name %q", name)
		}
	}
}

func TestMergeClaims(t *testing.T) {
	base := map[string]any{"a": 1, "nested": map[string]any{"x": 1}}
	merged := MergeClaims(base, map[string]any{"a": 2, "b": 3})
	if merged["a"] != 2 || merged["b"] != 3 {
		t.Errorf("override not applied: %+v", merged)
	}
	merged["nested"].(map[string]any)["x"] = 99
	if base["nested"].(map[string]any)["x"] != 1 {
		t.Error("MergeClaims must not share nested maps with base")
	}
}

// An unreadable template is reported, and the readable ones still come back.
func TestListReturnsTheReadableTemplatesWithTheError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Save(FileLocation(dir), Template{Name: "club", Format: "sdjwt", VCT: "urn:example:club:1"}); err != nil {
		t.Fatal(err)
	}
	templates, err := List(FileLocation(dir))
	if err == nil {
		t.Error("the broken template was not reported")
	}
	names := map[string]bool{}
	for _, tpl := range templates {
		names[tpl.Name] = true
	}
	if !names["club"] || !names["demo-ticket"] {
		t.Errorf("templates %v, want the stored and the predefined ones", names)
	}
}

// Resolve applies a request to a template the same way for every issuer.
func TestResolve(t *testing.T) {
	tpl := &Template{
		Name: "t", Format: "sdjwt", VCT: "urn:t", Exp: "48h",
		Claims:          map[string]any{"a": 1, "b": 2, "id": "x"},
		AlwaysDisclosed: []string{"a"},
		UniqueClaims:    []string{"id"},
	}

	r, err := Resolve(tpl, Request{Claims: map[string]any{"b": 3}, Omit: []string{"a"}, AlwaysDisclosed: []string{"b", "a"}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Format != "sdjwt" || r.VCT != "urn:t" || r.Exp != 48*time.Hour {
		t.Errorf("resolved %+v, want the template's format, vct and exp", r)
	}
	if _, ok := r.Claims["a"]; ok || r.Claims["b"] != 3 {
		t.Errorf("claims = %v, want b overridden and a omitted", r.Claims)
	}
	if len(r.AlwaysDisclosed) != 2 {
		t.Errorf("always disclosed = %v, want the merged list", r.AlwaysDisclosed)
	}
	if first, second := r.CredentialClaims()["id"], r.CredentialClaims()["id"]; first == "x" || first == second {
		t.Errorf("unique claim id = %v then %v, want a fresh value per credential", first, second)
	}

	if _, err := Resolve(tpl, Request{Format: "mdoc"}); err == nil {
		t.Error("a sdjwt template resolved for mdoc")
	}
	if _, err := Resolve(&Template{Name: "bad", Exp: "soon"}, Request{Format: "sdjwt"}); err == nil {
		t.Error("an invalid template exp was accepted")
	}
	if _, err := Resolve(&Template{Name: "m", AlwaysDisclosed: []string{"a"}}, Request{Format: "mdoc"}); err == nil {
		t.Error("always-disclosed claims were accepted for mdoc")
	}

	defaults, err := Resolve(nil, Request{Format: "mso_mdoc"})
	if err != nil {
		t.Fatal(err)
	}
	if defaults.Format != "mdoc" || defaults.DocType != DefaultDocType || defaults.Namespace != DefaultDocType || defaults.Exp != DefaultExp {
		t.Errorf("defaults = %+v", defaults)
	}
}
