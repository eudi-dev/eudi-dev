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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"go.yaml.in/yaml/v3"
)

// YAMLDocument is one document of a YAML stream converted to JSON. Number
// counts every document of the stream from 1, including empty ones. Errors use
// this number, so it matches the count of a person reading the file.
type YAMLDocument struct {
	Number int
	JSON   []byte
}

// YAMLDocumentsToJSON converts every document of a YAML stream to JSON and
// skips empty documents. Scalars stay text where YAML and JSON read them as
// different types: 1990-01-01 is a timestamp in YAML, 01234 is the octal
// number 668, a mapping key can be a number, and a version such as 1.0 is a
// float.
func YAMLDocumentsToJSON(data []byte) ([]YAMLDocument, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var documents []YAMLDocument
	for i := 1; ; i++ {
		var root yaml.Node
		err := decoder.Decode(&root)
		if errors.Is(err, io.EOF) {
			return documents, nil
		}
		if err != nil {
			if i > 1 {
				return nil, fmt.Errorf("YAML document %d: %w", i, err)
			}
			return nil, err
		}
		keepStrings(&root)
		var document any
		if err := root.Decode(&document); err != nil {
			return nil, err
		}
		if document == nil {
			continue
		}
		encoded, err := json.Marshal(document)
		if err != nil {
			return nil, err
		}
		documents = append(documents, YAMLDocument{Number: i, JSON: encoded})
	}
}

var decimalInt = regexp.MustCompile(`^[-+]?(0|[1-9][0-9]*)$`)

func keepStrings(node *yaml.Node) {
	if node.Kind == yaml.ScalarNode && node.Style == 0 {
		switch {
		case node.Tag == "!!timestamp":
			node.Tag = "!!str"
		case node.Tag == "!!int" && !decimalInt.MatchString(node.Value):
			node.Tag = "!!str"
		}
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Kind == yaml.ScalarNode {
				node.Content[i].Tag = "!!str"
			}
			if node.Content[i].Value == "version" && node.Content[i+1].Kind == yaml.ScalarNode {
				node.Content[i+1].Tag = "!!str"
			}
		}
	}
	for _, child := range node.Content {
		keepStrings(child)
	}
}
