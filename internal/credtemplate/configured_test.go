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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const twoTemplates = `name: first-card
format: sdjwt
vct: urn:example:first:1
---
name: second-card
format: sdjwt
vct: urn:example:second:1
`

func TestParseAllReadsEveryDocumentAndList(t *testing.T) {
	for _, tc := range []struct {
		file, data string
	}{
		{"cards.yaml", twoTemplates},
		{"cards.yaml", "- {name: first-card, format: sdjwt, vct: 'urn:example:first:1'}\n- {name: second-card, format: sdjwt, vct: 'urn:example:second:1'}\n"},
		{"cards.json", `[{"name": "first-card", "format": "sdjwt", "vct": "urn:example:first:1"}, {"name": "second-card", "format": "sdjwt", "vct": "urn:example:second:1"}]`},
		{"CARDS.YAML", twoTemplates},
		{"stdin", twoTemplates},
		{"stdin", `[{"name": "first-card", "format": "sdjwt", "vct": "urn:example:first:1"}, {"name": "second-card", "format": "sdjwt", "vct": "urn:example:second:1"}]`},
	} {
		templates, err := parseAll([]byte(tc.data), tc.file)
		if err != nil {
			t.Fatalf("%s: %v", tc.data, err)
		}
		if len(templates) != 2 || templates[0].Name != "first-card" || templates[1].Name != "second-card" {
			t.Fatalf("%s: templates %+v", tc.data, templates)
		}
	}
}

func TestParseAllRefusesWhatItCannotTellApart(t *testing.T) {
	for _, tc := range []struct {
		name, data, want string
	}{
		{"unknown field", twoTemplates + "colour: red\n", "template 2"},
		{"unnamed template", twoTemplates + "---\nformat: sdjwt\nvct: urn:example:third:1\n", "template 3 needs a name"},
		{"same name twice", twoTemplates + "---\nname: first-card\nformat: sdjwt\nvct: urn:example:third:1\n", `"first-card" appears twice`},
		{"no template", "# nothing yet\n", "holds no template"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseAll([]byte(tc.data), "cards.yaml"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// A configured template replaces a stored one of the same name, and its file
// is the only place to change it.
func TestConfiguredTemplatesReplaceStoredOnesAndRefuseChanges(t *testing.T) {
	loc := FileLocation(t.TempDir())
	if _, err := Save(loc, Template{Name: "first-card", Format: "sdjwt", VCT: "urn:example:stored:1"}); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseConfigured([]ConfiguredFile{{Name: "cards.yaml", Data: []byte(twoTemplates)}})
	if err != nil {
		t.Fatal(err)
	}
	loc.Configured = &Configured{}
	loc.Configured.Set(parsed)

	loaded, err := Load("first-card", loc)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.VCT != "urn:example:first:1" || !loaded.Configured {
		t.Fatalf("loaded %+v, want the configured template", loaded)
	}
	listed, err := List(loc)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, tpl := range listed {
		if tpl.Name == "first-card" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("first-card is listed %d times", count)
	}

	if _, err := Save(loc, Template{Name: "second-card", Format: "sdjwt", VCT: "urn:example:changed:1"}); !errors.Is(err, ErrConfigured) {
		t.Fatalf("saving a configured template: %v", err)
	}
	if err := Delete(loc, "second-card"); !errors.Is(err, ErrConfigured) {
		t.Fatalf("deleting a configured template: %v", err)
	}
}

func TestATemplateNameAppearsOnceAcrossTheFiles(t *testing.T) {
	_, err := ParseConfigured([]ConfiguredFile{
		{Name: "a.yaml", Data: []byte("name: first-card\nformat: sdjwt\nvct: urn:example:a:1\n")},
		{Name: "b.yaml", Data: []byte("name: first-card\nformat: sdjwt\nvct: urn:example:b:1\n")},
	})
	if err == nil || !strings.Contains(err.Error(), "appears in a.yaml and b.yaml") {
		t.Fatalf("error = %v, want one naming both files", err)
	}
}

func TestATemplateFileEndsAfterItsTemplate(t *testing.T) {
	data := `{"name": "first-card", "format": "sdjwt", "vct": "urn:example:first:1"}
{"name": "second-card", "format": "sdjwt", "vct": "urn:example:second:1"}`
	if _, err := parseAll([]byte(data), "cards.json"); err == nil || !strings.Contains(err.Error(), "data follows the template") {
		t.Fatalf("error = %v, want one about the second object", err)
	}
}

// A template file given by path and a stored template load as older releases
// wrote them: unknown fields are skipped, and a stored YAML file with several
// documents gives its first one.
func TestTemplatesOutsideTheConfigurationLoadLeniently(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old-card.json")
	if err := os.WriteFile(path, []byte(`{"name": "old-card", "format": "sdjwt", "vct": "urn:example:old:1", "retired_field": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if tpl, err := Load(path, Location{}); err != nil || tpl.Name != "old-card" {
		t.Fatalf("Load(%s) = %+v, %v", path, tpl, err)
	}

	if err := os.WriteFile(filepath.Join(dir, "stored-card.yaml"), []byte(twoTemplates+"retired_field: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tpl, err := Load("stored-card", FileLocation(dir))
	if err != nil || tpl.VCT != "urn:example:first:1" {
		t.Fatalf("Load(stored-card) = %+v, %v, want the first document", tpl, err)
	}
}

// A configured PID template gets today's dates on every read, and its empty
// date claims stay empty for the next read.
func TestAConfiguredPIDTemplateGetsCurrentDates(t *testing.T) {
	parsed, err := ParseConfigured([]ConfiguredFile{{Name: "pid.yaml", Data: []byte(`name: staff-pid
format: sdjwt
vct: urn:eudi:pid:1
category: pid
claims:
  given_name: Erika
  date_of_issuance: ""
`)}})
	if err != nil {
		t.Fatal(err)
	}
	configured := &Configured{}
	configured.Set(parsed)

	today := time.Now().UTC().Format(time.DateOnly)
	for range 2 {
		loaded, ok := configured.lookup("staff-pid")
		if !ok || loaded.Claims["date_of_issuance"] != today {
			t.Fatalf("lookup gave %v, want date_of_issuance %s", loaded, today)
		}
		if listed := configured.Templates(); listed[0].Claims["date_of_issuance"] != today {
			t.Fatalf("Templates gave date_of_issuance %v, want %s", listed[0].Claims["date_of_issuance"], today)
		}
	}
	if parsed.templates[0].Claims["date_of_issuance"] != "" {
		t.Fatalf("the parsed template holds date_of_issuance %v, want it empty", parsed.templates[0].Claims["date_of_issuance"])
	}
}
