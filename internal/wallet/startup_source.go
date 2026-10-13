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
	"io"
	"os"
	"path/filepath"
	"strings"
)

// startupSource is one file read by a wallet serve flag such as --catalog.
type startupSource struct {
	name string
	// dir resolves paths relative to the file. It is empty for stdin.
	dir  string
	data []byte
}

// readStartupSources reads a YAML or JSON file, every .yaml, .yml and .json
// file of a directory in name order, or stdin for "-".
func readStartupSources(path string) ([]startupSource, error) {
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		return []startupSource{{name: "stdin", data: data}}, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	files := []string{path}
	if info.IsDir() {
		dirEntries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		files = nil
		for _, entry := range dirEntries {
			switch strings.ToLower(filepath.Ext(entry.Name())) {
			case ".yaml", ".yml", ".json":
				files = append(files, filepath.Join(path, entry.Name()))
			}
		}
	}
	sources := make([]startupSource, 0, len(files))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		sources = append(sources, startupSource{name: file, dir: filepath.Dir(file), data: data})
	}
	return sources, nil
}
