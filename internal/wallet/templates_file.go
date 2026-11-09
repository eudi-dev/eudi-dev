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

import "github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"

// LoadTemplateFiles reads the template files of --templates: a YAML or JSON
// file, every .yaml, .yml and .json file of a directory in name order, or
// stdin for "-". A file holds one template or several, and each template name
// is unique across all files.
func LoadTemplateFiles(path string) (credtemplate.ConfiguredTemplates, error) {
	sources, err := readStartupSources(path)
	if err != nil {
		return credtemplate.ConfiguredTemplates{}, err
	}
	files := make([]credtemplate.ConfiguredFile, 0, len(sources))
	for _, source := range sources {
		files = append(files, credtemplate.ConfiguredFile{Name: source.name, Data: source.data})
	}
	return credtemplate.ParseConfigured(files)
}
