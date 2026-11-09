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

package configschema

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
)

var update = flag.Bool("update", false, "rewrite docs/schemas")

const schemaDir = "../../docs/schemas"

func TestPublishedSchemasMatchTheTypes(t *testing.T) {
	for _, kind := range Kinds() {
		t.Run(kind.Name, func(t *testing.T) {
			want, err := kind.Generate().JSON()
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(schemaDir, kind.Name+".schema.json")
			if *update {
				if err := os.WriteFile(path, want, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s is out of date. Run go test ./internal/configschema -update", path)
			}
		})
	}
}

// Operators copy the example configuration files, so each one must pass the
// published schema of its input.
func TestExampleConfigurationFilesMatchTheSchemas(t *testing.T) {
	examples := map[string][]string{
		"templates":             {"../../examples/kubernetes/config/templates"},
		"transaction-templates": {"../../examples/kubernetes/config/transaction-templates"},
		"catalog":               {"../../examples/kubernetes/config/catalog", "../../examples/public-demo/catalog"},
		"relying-parties":       {"../../examples/kubernetes/config/relying-parties", "../../examples/public-demo/relying-parties"},
		"credentials":           {"../../examples/kubernetes/config/credentials"},
	}
	for _, kind := range Kinds() {
		schema := compile(t, kind)
		checked := 0
		for _, dir := range examples[kind.Name] {
			files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				for i, document := range yamlDocuments(t, file) {
					if err := schema.Validate(document); err != nil {
						t.Errorf("%s document %d: %v", file, i+1, err)
					}
					checked++
				}
			}
		}
		if checked == 0 {
			t.Errorf("no example checks the %s schema", kind.Name)
		}
	}
}

func TestSchemasRefuseAnUnknownField(t *testing.T) {
	documents := map[string]string{
		"templates":             `{"name": "x", "vct": "urn:x", "colour": "red"}`,
		"transaction-templates": `{"name": "x", "transaction_data": {"type": "urn:x"}, "colour": "red"}`,
		"catalog":               `[{"name": "x", "colour": "red"}]`,
		"relying-parties":       `{"colour": "red"}`,
		"credentials":           `{"credentials": [{"id": "x", "template": "x", "colour": "red"}]}`,
	}
	for _, kind := range Kinds() {
		document, err := jsonschema.UnmarshalJSON(strings.NewReader(documents[kind.Name]))
		if err != nil {
			t.Fatal(err)
		}
		if compile(t, kind).Validate(document) == nil {
			t.Errorf("the %s schema accepts the unknown field colour", kind.Name)
		}
	}
}

func compile(t *testing.T, kind Kind) *jsonschema.Schema {
	t.Helper()
	data, err := kind.Generate().JSON()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	url := kind.Name + ".schema.json"
	if err := compiler.AddResource(url, doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(url)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

// yamlDocuments converts each document like the wallet before decoding.
func yamlDocuments(t *testing.T, file string) []any {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	converted, err := credtemplate.YAMLDocumentsToJSON(data)
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	documents := make([]any, 0, len(converted))
	for _, document := range converted {
		value, err := jsonschema.UnmarshalJSON(bytes.NewReader(document.JSON))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		documents = append(documents, value)
	}
	return documents
}
