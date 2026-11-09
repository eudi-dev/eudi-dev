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
	"fmt"
	"path/filepath"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/txtemplate"
)

// TransactionTemplateFileEntry is a transaction template in a file.
type TransactionTemplateFileEntry struct {
	Name            string                    `json:"name"`
	Description     string                    `json:"description,omitempty"`
	TransactionData TransactionDataFileObject `json:"transaction_data" schema:"required"`
}

// TransactionDataFileObject is one transaction data entry of a presentation
// request (OpenID4VP 1.0 §5.1). The members of its type can be anything.
type TransactionDataFileObject map[string]any

// JSONSchema describes the members defined by OpenID4VP 1.0 §5.1 for every
// type. A template may leave out credential_ids, because the verifier adds the
// ids of its own credential queries.
func (TransactionDataFileObject) JSONSchema() map[string]any {
	strings := map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "minItems": 1}
	return map[string]any{
		"type":     "object",
		"required": []any{"type"},
		"properties": map[string]any{
			"type":                        map[string]any{"type": "string", "minLength": 1},
			"credential_ids":              strings,
			"transaction_data_hashes_alg": strings,
		},
	}
}

// LoadTransactionTemplateFiles reads the files of --transaction-templates: a
// YAML or JSON file, every .yaml, .yml and .json file of a directory in name
// order, or stdin for "-". A file holds one template or several, and each
// template name is unique across all files.
func LoadTransactionTemplateFiles(path string) (txtemplate.ConfiguredTemplates, error) {
	sources, err := readStartupSources(path)
	if err != nil {
		return txtemplate.ConfiguredTemplates{}, err
	}
	files := make([]txtemplate.ConfiguredFile, 0, len(sources))
	for _, source := range sources {
		entries, err := decodeStartupItems[TransactionTemplateFileEntry](source.data)
		if err != nil {
			return txtemplate.ConfiguredTemplates{}, fmt.Errorf("%s: %w", source.name, err)
		}
		file := txtemplate.ConfiguredFile{Name: source.name}
		for _, entry := range entries {
			name := entry.Name
			// A nameless template alone in a file gets the file name, as for
			// credential templates.
			if len(entries) == 1 && strings.TrimSpace(name) == "" && source.dir != "" {
				base := filepath.Base(source.name)
				name = strings.TrimSuffix(base, filepath.Ext(base))
			}
			file.Templates = append(file.Templates, txtemplate.Template{
				Name:            name,
				Description:     entry.Description,
				TransactionData: entry.TransactionData,
			})
		}
		files = append(files, file)
	}
	return txtemplate.ParseConfigured(files)
}
