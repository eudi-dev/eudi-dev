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

package oid4vp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
)

// PayloadField is a top-level member of the payload of a TS12 type.
type PayloadField struct {
	Name     string `json:"name"`
	Required bool   `json:"required,omitempty"`
	// Type is the JSON Schema type, such as string, number or object. A
	// member that refers to another schema has none.
	Type string `json:"type,omitempty"`
}

type payloadSchema struct {
	Properties json.RawMessage `json:"properties"`
	Required   []string        `json:"required"`
}

// TS12PayloadFields lists the payload members of a TS12 type in the order of
// its schema (TS12 v1.0.1 §4.3).
func TS12PayloadFields(typ string) ([]PayloadField, error) {
	if !slices.Contains(TS12TransactionDataTypes, typ) {
		return nil, fmt.Errorf("%s is not a TS12 transaction data type", typ)
	}
	data, err := ts12SchemaFiles.ReadFile("ts12schema/" + ts12SchemaFile(typ))
	if err != nil {
		return nil, err
	}
	var schema payloadSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, fmt.Errorf("TS12 schema of %s: %w", typ, err)
	}
	// A map loses the member order, so the properties are read as tokens.
	dec := json.NewDecoder(bytes.NewReader(schema.Properties))
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("TS12 schema of %s: %w", typ, err)
	}
	var fields []PayloadField
	for dec.More() {
		name, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("TS12 schema of %s: %w", typ, err)
		}
		var property struct {
			Type string `json:"type"`
		}
		if err := dec.Decode(&property); err != nil {
			return nil, fmt.Errorf("TS12 schema of %s: %w", typ, err)
		}
		key := name.(string)
		fields = append(fields, PayloadField{Name: key, Required: slices.Contains(schema.Required, key), Type: property.Type})
	}
	return fields, nil
}
