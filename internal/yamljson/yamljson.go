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

// Package yamljson converts YAML documents to JSON. A YAML file then goes
// through the same JSON decoder as its JSON form and gets the same types.
package yamljson

import (
	"encoding/json"
	"regexp"

	"go.yaml.in/yaml/v3"
)

// Convert parses a YAML document and returns it as JSON. Each fix edits the
// parsed document before the conversion.
func Convert(data []byte, fixes ...func(*yaml.Node)) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	for _, fix := range fixes {
		fix(&root)
	}
	var document any
	if err := root.Decode(&document); err != nil {
		return nil, err
	}
	return json.Marshal(document)
}

var decimalInt = regexp.MustCompile(`^[-+]?(0|[1-9][0-9]*)$`)

// KeepStrings keeps scalars as text where JSON has no YAML equivalent. A
// mapping key stays a string, as in JSON. A date such as 1990-01-01 stays the
// date as written. YAML reads it as a timestamp. An integer written other than
// in plain decimal, such as the postal code 01234 or 0x1F, stays text. YAML
// reads 01234 as the octal number 668.
func KeepStrings(node *yaml.Node) {
	if node.Kind == yaml.ScalarNode && node.Style == 0 {
		switch {
		case node.Tag == "!!timestamp":
			node.Tag = "!!str"
		case node.Tag == "!!int" && !decimalInt.MatchString(node.Value):
			node.Tag = "!!str"
		}
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			if node.Content[i].Kind == yaml.ScalarNode {
				node.Content[i].Tag = "!!str"
			}
		}
	}
	for _, child := range node.Content {
		KeepStrings(child)
	}
}

// KeepVersionStrings keeps the value of every version key as text, so a
// version such as 1.0 stays "1.0". YAML reads it as a number.
func KeepVersionStrings(node *yaml.Node) {
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == "version" && node.Content[i+1].Kind == yaml.ScalarNode {
				node.Content[i+1].Tag = "!!str"
			}
		}
	}
	for _, child := range node.Content {
		KeepVersionStrings(child)
	}
}
