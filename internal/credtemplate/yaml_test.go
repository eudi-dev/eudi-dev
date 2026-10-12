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
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A YAML template file is the same template as its JSON form.
func TestYAMLTemplateMatchesJSON(t *testing.T) {
	tests := []struct {
		name, json, yaml string
	}{
		{
			name: "sdjwt with display, catalog and unique claims",
			json: `{
  "description": "Employee badge",
  "format": "sdjwt",
  "vct": "urn:example:employee",
  "exp": "720h",
  "category": "qeaa",
  "rulebook": "https://example.com/rulebook",
  "claims": {
    "employee_id": "E-1",
    "sub": "",
    "postal_code": "01234",
    "birthdate": "1990-01-01",
    "level": 3,
    "ratio": 1.5,
    "active": true,
    "answer": "yes",
    "nickname": null,
    "address": {"country": "DE", "locality": "KÖLN"},
    "roles": ["admin", "dev"],
    "age_equal_or_over": {"18": true, "65": false}
  },
  "always_disclosed": ["employee_id", "address.country"],
  "unique_claims": ["sub"],
  "display": {
    "name": "Acme Employee",
    "background_color": "#0f766e",
    "text_color": "#ffffff",
    "logo": "embedded:images/logo.svg",
    "logo_alt_text": "Acme logo",
    "background_image": "data:image/png;base64,iVBORw0KGgo="
  },
  "catalog": {
    "name": "Employee card",
    "category": "eaa",
    "schema": {"version": "1.2.0", "rulebookURI": "https://example.com/rulebook", "trustedAuthorities": [{"frameworkType": "etsi_tl", "value": "https://example.com/tl", "isLOTE": true}]}
  }
}`,
			yaml: `description: Employee badge
format: sdjwt
vct: urn:example:employee
exp: 720h
category: qeaa
rulebook: https://example.com/rulebook
claims:
  employee_id: E-1
  sub: ""
  postal_code: "01234"
  birthdate: 1990-01-01
  level: 3
  ratio: 1.5
  active: true
  answer: yes
  nickname: null
  address:
    country: DE
    locality: KÖLN
  roles: [admin, dev]
  age_equal_or_over:
    18: true
    65: false
always_disclosed: [employee_id, address.country]
unique_claims: [sub]
display:
  name: Acme Employee
  background_color: "#0f766e"
  text_color: "#ffffff"
  logo: embedded:images/logo.svg
  logo_alt_text: Acme logo
  background_image: data:image/png;base64,iVBORw0KGgo=
catalog:
  name: Employee card
  category: eaa
  schema:
    version: 1.2.0
    rulebookURI: https://example.com/rulebook
    trustedAuthorities:
      - frameworkType: etsi_tl
        value: https://example.com/tl
        isLOTE: true
`,
		},
		{
			name: "mdoc with namespaced claims",
			json: `{
  "format": "mso_mdoc",
  "doctype": "eu.europa.ec.eudi.pid.1",
  "namespace": "eu.europa.ec.eudi.pid.1",
  "category": "pid",
  "claims": {
    "family_name": "MUSTERMANN",
    "birth_date": "1964-08-12",
    "issuance_date": "",
    "eu.europa.ec.eudi.pid.de.1:birth_name": "GABLER",
    "age_in_years": 62,
    "portrait": "embedded:portraits/default.jpg"
  }
}`,
			yaml: `format: mso_mdoc
doctype: eu.europa.ec.eudi.pid.1
namespace: eu.europa.ec.eudi.pid.1
category: pid
claims:
  family_name: MUSTERMANN
  birth_date: 1964-08-12
  issuance_date: ""
  eu.europa.ec.eudi.pid.de.1:birth_name: GABLER
  age_in_years: 62
  portrait: embedded:portraits/default.jpg
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonDir, yamlDir := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(jsonDir, "card.json"), tt.json)
			writeFile(t, filepath.Join(yamlDir, "card.yaml"), tt.yaml)
			fromJSON, err := Load("card", FileLocation(jsonDir))
			if err != nil {
				t.Fatal(err)
			}
			fromYAML, err := Load("card", FileLocation(yamlDir))
			if err != nil {
				t.Fatal(err)
			}
			fromJSON.Catalog, fromYAML.Catalog = sortedKeys(t, fromJSON.Catalog), sortedKeys(t, fromYAML.Catalog)
			want, _ := json.Marshal(fromJSON)
			got, _ := json.Marshal(fromYAML)
			if string(got) != string(want) {
				t.Errorf("YAML template\n%s\nwant\n%s", got, want)
			}
			if !reflect.DeepEqual(fromYAML.Claims, fromJSON.Claims) {
				t.Errorf("YAML claims %#v, want %#v", fromYAML.Claims, fromJSON.Claims)
			}
		})
	}
}

func sortedKeys(t *testing.T, raw json.RawMessage) json.RawMessage {
	t.Helper()
	if raw == nil {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	sorted, _ := json.Marshal(value)
	return sorted
}

func TestLoadYAMLExtensions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "one.yaml"), "format: sdjwt\nvct: urn:example:one\nclaims: {a: 1}\n")
	writeFile(t, filepath.Join(dir, "two.yml"), "format: mdoc\ndoctype: org.example.two\nclaims: {b: 2}\n")

	for name, want := range map[string]string{"one": "urn:example:one", "two": "org.example.two"} {
		tpl, err := Load(name, FileLocation(dir))
		if err != nil {
			t.Fatalf("loading %s by name: %v", name, err)
		}
		if tpl.Name != name || tpl.VCT+tpl.DocType != want {
			t.Errorf("template %s: %+v", name, tpl)
		}
	}
	byPath, err := Load(filepath.Join(dir, "two.yml"), Location{})
	if err != nil || byPath.Name != "two" {
		t.Fatalf("loading by path: %+v, %v", byPath, err)
	}
	templates, err := List(FileLocation(dir))
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, tpl := range templates {
		listed[tpl.Name] = true
	}
	if !listed["one"] || !listed["two"] {
		t.Errorf("list %v lacks the YAML templates", listed)
	}
}

// Unquoted YAML values follow YAML typing, except where JSON has no
// equivalent: dates and integers with a leading zero stay as written.
func TestYAMLClaimTyping(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "typed.yaml"), `claims:
  quoted_zip: "01234"
  plain_zip: 01234
  hex: 0x1F
  number: 42
  negative: -7
  float: 2.5
  date: 2026-10-12
  timestamp: 2026-10-12T10:00:00Z
  bool: true
  yes_word: yes
  off_word: off
  quoted_bool: "true"
`)
	tpl, err := Load("typed", FileLocation(dir))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"quoted_zip":  "01234",
		"plain_zip":   "01234",
		"hex":         "0x1F",
		"number":      float64(42),
		"negative":    float64(-7),
		"float":       2.5,
		"date":        "2026-10-12",
		"timestamp":   "2026-10-12T10:00:00Z",
		"bool":        true,
		"yes_word":    "yes",
		"off_word":    "off",
		"quoted_bool": "true",
	}
	if !reflect.DeepEqual(tpl.Claims, want) {
		t.Errorf("claims %#v, want %#v", tpl.Claims, want)
	}
}

func TestYAMLTemplateErrorsNameTheFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "broken.yaml"), "claims: [unclosed\n")
	writeFile(t, filepath.Join(dir, "badformat.yml"), "format: nope\nclaims: {}\n")
	for _, name := range []string{"broken", "badformat"} {
		_, err := Load(name, FileLocation(dir))
		if err == nil || !strings.Contains(err.Error(), name+".y") {
			t.Errorf("Load(%s) error %v, want one naming the file", name, err)
		}
	}
}

// Two files of one name are refused, since either could be the template.
func TestTemplateFilesOfOneNameClash(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "card.json"), `{"format": "sdjwt", "claims": {}}`)
	writeFile(t, filepath.Join(dir, "card.yaml"), "format: sdjwt\nclaims: {}\n")
	writeFile(t, filepath.Join(dir, "other.yaml"), "format: sdjwt\nclaims: {}\n")
	loc := FileLocation(dir)

	assertClash := func(what string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "card.json") || !strings.Contains(err.Error(), "card.yaml") {
			t.Errorf("%s: error %v, want one naming card.json and card.yaml", what, err)
		}
	}
	_, err := Load("card", loc)
	assertClash("Load", err)
	assertClash("Delete", Delete(loc, "card"))

	templates, err := List(loc)
	assertClash("List", err)
	names := map[string]bool{}
	for _, tpl := range templates {
		names[tpl.Name] = true
	}
	if !names["other"] || names["card"] {
		t.Errorf("list %v, want other without card", names)
	}
}

func TestDeleteRemovesTheYAMLFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "card.yml")
	writeFile(t, path, "format: sdjwt\nclaims: {a: 1}\n")
	if err := Delete(FileLocation(dir), "card"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("card.yml still exists: %v", err)
	}
}

// The wallet saves JSON. The saved file replaces a YAML file of that name.
func TestSaveReplacesTheYAMLFile(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "card.yaml")
	writeFile(t, yamlPath, "format: sdjwt\nclaims: {a: 1}\n")
	path, err := Save(FileLocation(dir), Template{Name: "card", Format: "sdjwt", Claims: map[string]any{"a": 2}})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Ext(path) != ".json" {
		t.Errorf("saved to %s, want a JSON file", path)
	}
	if _, err := os.Stat(yamlPath); !os.IsNotExist(err) {
		t.Errorf("card.yaml still exists: %v", err)
	}
	tpl, err := Load("card", FileLocation(dir))
	if err != nil || tpl.Claims["a"] != float64(2) {
		t.Errorf("loaded %+v, %v, want the saved claims", tpl, err)
	}
}

func TestDecodeDetectsTheFormatOfUnnamedInput(t *testing.T) {
	for _, input := range []string{
		`{"name": "card", "format": "sdjwt", "claims": {"zip": "01234"}}`,
		"name: card\nformat: sdjwt\nclaims:\n  zip: 01234\n",
	} {
		tpl, err := Decode([]byte(input), "")
		if err != nil {
			t.Fatalf("Decode(%q): %v", input, err)
		}
		if tpl.Name != "card" || tpl.Format != "sdjwt" || tpl.Claims["zip"] != "01234" {
			t.Errorf("Decode(%q) = %+v", input, tpl)
		}
	}
}
