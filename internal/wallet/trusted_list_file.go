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
	"regexp"
	"slices"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
)

var trustedListFileExtensions = []string{".jwt", ".json"}

var trustedListFileID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// LoadTrustedListFiles reads complete trusted lists: a .jwt file holds a signed
// list and a .json file its content. The file name is the list's ID, so a
// directory publishes one list per file.
func LoadTrustedListFiles(path string) ([]trustedlists.FileList, error) {
	sources, err := readSources(path, trustedListFileExtensions)
	if err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("%s has no .jwt or .json file", path)
	}
	seen := map[string]bool{}
	lists := make([]trustedlists.FileList, 0, len(sources))
	for _, source := range sources {
		base := filepath.Base(source.name)
		extension := strings.ToLower(filepath.Ext(base))
		if !slices.Contains(trustedListFileExtensions, extension) {
			return nil, fmt.Errorf("%s: a trusted list file ends in .jwt or .json", source.name)
		}
		id := strings.TrimSuffix(base, filepath.Ext(base))
		if !trustedListFileID.MatchString(id) || id == trustedlists.ListOfListsID {
			return nil, fmt.Errorf("%s: the file name is the list's ID, so it may only hold lowercase letters, digits and dashes, and it can't be %q", source.name, trustedlists.ListOfListsID)
		}
		if seen[id] {
			return nil, fmt.Errorf("%s: another file has the same name, and the file name is the list's ID", source.name)
		}
		seen[id] = true
		raw := strings.TrimSpace(string(source.data))
		if strings.HasPrefix(raw, "{") {
			_, err = trustedlists.ParseFileListContent(raw)
		} else {
			_, err = lote.Parse(raw)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", source.name, err)
		}
		lists = append(lists, trustedlists.FileList{ID: id, Raw: raw})
	}
	return lists, nil
}
