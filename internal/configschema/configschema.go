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

// Package configschema derives JSON Schemas for the configuration files of
// wallet serve from the Go types of their loaders. The schemas are as strict
// as the decoders, so an editor flags refused fields.
package configschema

import (
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// Kind is one configuration input of wallet serve.
type Kind struct {
	// Name is the input's name in --config, such as "templates".
	Name        string
	Title       string
	Description string
	item        reflect.Type
	// list means a document holds one item or a list of items.
	list bool
}

// Kinds lists the inputs in the order of the documentation.
func Kinds() []Kind {
	return []Kind{
		{
			Name:        "templates",
			Title:       "eudi-dev credential templates",
			Description: "A document of a --templates file: one credential template or a list of templates.",
			item:        reflect.TypeFor[credtemplate.Template](),
			list:        true,
		},
		{
			Name:        "transaction-templates",
			Title:       "eudi-dev transaction templates",
			Description: "A document of a --transaction-templates file: one transaction template or a list of templates.",
			item:        reflect.TypeFor[wallet.TransactionTemplateFileEntry](),
			list:        true,
		},
		{
			Name:        "catalog",
			Title:       "eudi-dev catalogue entries",
			Description: "A document of a --catalog file: one attestation type or a list of them.",
			item:        reflect.TypeFor[wallet.CatalogFileEntry](),
			list:        true,
		},
		{
			Name:        "relying-parties",
			Title:       "eudi-dev relying parties",
			Description: "A document of a --relying-parties file: one relying party registration or a list of them.",
			item:        reflect.TypeFor[registrar.WalletRelyingParty](),
			list:        true,
		},
		{
			Name:        "credentials",
			Title:       "eudi-dev startup credentials",
			Description: "A document of a --credentials file. The credentials lists of all documents add up.",
			item:        reflect.TypeFor[wallet.CredentialsFile](),
		},
	}
}

// Schema is a JSON Schema (draft 2020-12) document.
type Schema map[string]any

// Generate returns the schema of one YAML document or JSON file of the kind.
func (k Kind) Generate() Schema {
	g := &generator{defs: map[string]any{}}
	root := g.schemaFor(k.item)
	if k.list {
		root = map[string]any{"oneOf": []any{root, map[string]any{"type": "array", "items": root}}}
	}
	schema := Schema{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"$id":         "https://raw.githubusercontent.com/eudi-dev/eudi-dev/main/docs/schemas/" + k.Name + ".schema.json",
		"title":       k.Title,
		"description": k.Description,
	}
	for key, value := range root {
		schema[key] = value
	}
	if len(g.defs) > 0 {
		schema["$defs"] = g.defs
	}
	return schema
}

// JSON returns the schema as indented JSON with a final newline.
func (s Schema) JSON() ([]byte, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

type generator struct {
	defs map[string]any
}

var (
	jsonUnmarshaler = reflect.TypeFor[json.Unmarshaler]()
	textUnmarshaler = reflect.TypeFor[encoding.TextUnmarshaler]()
	schemaer        = reflect.TypeFor[interface{ JSONSchema() map[string]any }]()
	timeType        = reflect.TypeFor[time.Time]()
	rawMessageType  = reflect.TypeFor[json.RawMessage]()
)

func (g *generator) schemaFor(t reflect.Type) map[string]any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case t.Implements(schemaer):
		return reflect.Zero(t).Interface().(interface{ JSONSchema() map[string]any }).JSONSchema()
	case t == timeType:
		return map[string]any{"type": "string", "format": "date-time"}
	case t == rawMessageType:
		return map[string]any{}
	case reflect.PointerTo(t).Implements(jsonUnmarshaler):
		// A custom decoder takes more than one shape. The decoder checks it.
		return map[string]any{}
	case reflect.PointerTo(t).Implements(textUnmarshaler):
		return map[string]any{"type": "string"}
	}
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Interface:
		return map[string]any{}
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return map[string]any{"type": "string", "contentEncoding": "base64"}
		}
		return map[string]any{"type": "array", "items": g.schemaFor(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": g.schemaFor(t.Elem())}
	case reflect.Struct:
		return g.structRef(t)
	}
	panic(fmt.Sprintf("configschema: no schema for %s", t))
}

// structRef puts a named struct into $defs, which also ends a recursion.
func (g *generator) structRef(t reflect.Type) map[string]any {
	if t.Name() == "" {
		return g.structSchema(t)
	}
	name := defName(t)
	if _, ok := g.defs[name]; !ok {
		g.defs[name] = true
		g.defs[name] = g.structSchema(t)
	}
	return map[string]any{"$ref": "#/$defs/" + name}
}

func defName(t reflect.Type) string {
	pkg := t.PkgPath()
	return pkg[strings.LastIndex(pkg, "/")+1:] + "." + t.Name()
}

func (g *generator) structSchema(t reflect.Type) map[string]any {
	properties := map[string]any{}
	var required []any
	g.addFields(t, properties, &required)
	schema := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

// addFields follows encoding/json: an embedded struct without a JSON name
// adds its fields to the outer object. A field tagged schema:"required" is
// required.
func (g *generator) addFields(t reflect.Type, properties map[string]any, required *[]any) {
	for i := range t.NumField() {
		field := t.Field(i)
		tag := field.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" && tag == "-" {
			continue
		}
		if field.Anonymous && name == "" {
			embedded := field.Type
			for embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if embedded.Kind() == reflect.Struct {
				g.addFields(embedded, properties, required)
				continue
			}
		}
		if !field.IsExported() {
			continue
		}
		if name == "" {
			name = field.Name
		}
		properties[name] = g.schemaFor(field.Type)
		if field.Tag.Get("schema") == "required" {
			*required = append(*required, name)
		}
	}
}
