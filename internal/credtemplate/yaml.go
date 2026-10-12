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
	"regexp"

	"go.yaml.in/yaml/v3"
)

// YAMLToJSON converts a YAML template, catalogue or credentials file to JSON,
// so it goes through the same decoder as its JSON form. Scalars stay text
// where YAML would read them as another type than JSON does: 1990-01-01 is
// a timestamp in YAML, 01234 is the octal number 668, a mapping key can be a
// number, and a version such as 1.0 is a float.
func YAMLToJSON(data []byte) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	keepStrings(&root)
	var document any
	if err := root.Decode(&document); err != nil {
		return nil, err
	}
	return json.Marshal(document)
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
