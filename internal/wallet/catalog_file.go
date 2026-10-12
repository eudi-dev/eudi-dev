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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
)

// CatalogFile holds the attestation types pre-registered by the operator in
// the catalogue (wallet serve --catalog).
type CatalogFile struct {
	Entries []CatalogFileEntry
}

// CatalogFileEntry is a catalogue entry in the shape of the catalogue API,
// with the CA of the operator's issuer.
type CatalogFileEntry struct {
	registrar.CatalogAttestation
	// IssuerCA is a PEM file, relative to the catalogue file. The wallet puts
	// its CA on the trusted list of the entry's category.
	IssuerCA string `json:"issuerCA,omitempty"`

	source   string
	issuerCA []byte
}

// LoadCatalogFile reads a YAML or JSON catalogue file, every .yaml, .yml and
// .json file of a directory in name order, or stdin for "-". A file holds one
// entry or a list of entries.
func LoadCatalogFile(path string) (*CatalogFile, error) {
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		entries, err := parseCatalogSource("stdin", "", data)
		if err != nil {
			return nil, err
		}
		return checkCatalogNames(entries)
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
	var entries []CatalogFileEntry
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		parsed, err := parseCatalogSource(file, filepath.Dir(file), data)
		if err != nil {
			return nil, err
		}
		entries = append(entries, parsed...)
	}
	return checkCatalogNames(entries)
}

// parseCatalogSource reads the entries of one file and their issuer CAs. dir
// resolves a relative IssuerCA path.
func parseCatalogSource(name, dir string, data []byte) ([]CatalogFileEntry, error) {
	encoded, err := credtemplate.YAMLToJSON(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if bytes.HasPrefix(encoded, []byte{'{'}) {
		encoded = slices.Concat([]byte{'['}, encoded, []byte{']'})
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var entries []CatalogFileEntry
	if err := decoder.Decode(&entries); err != nil {
		return nil, fmt.Errorf("%s: expected a catalogue entry or a list of entries: %w", name, err)
	}
	for i := range entries {
		e := &entries[i]
		e.source = name
		if err := registrar.CheckCatalogEntry(e.CatalogAttestation); err != nil {
			return nil, fmt.Errorf("%s: %s: %w", name, e.label(i), err)
		}
		if e.IssuerCA == "" {
			continue
		}
		if len(e.Schema.TrustedAuthorities) > 0 {
			return nil, fmt.Errorf("%s: %s: issuerCA puts the CA on the wallet's list of the category, and trustedAuthorities links another list. Use one of them", name, e.label(i))
		}
		file := e.IssuerCA
		if !filepath.IsAbs(file) {
			file = filepath.Join(dir, file)
		}
		if e.issuerCA, err = os.ReadFile(file); err != nil {
			return nil, fmt.Errorf("%s: %s: reading issuerCA: %w", name, e.label(i), err)
		}
		if _, err := e.issuerEntity(); err != nil {
			return nil, fmt.Errorf("%s: %s: issuerCA: %w", name, e.label(i), err)
		}
	}
	return entries, nil
}

func (e CatalogFileEntry) label(i int) string {
	if name := strings.TrimSpace(e.Name); name != "" {
		return fmt.Sprintf("entry %q", name)
	}
	return fmt.Sprintf("entry %d", i+1)
}

// issuerEntity returns the provider for IssuerCA on the list of the entry's
// category.
func (e CatalogFileEntry) issuerEntity() (trustedlists.Entity, error) {
	category := jsonutil.FirstNonEmpty(e.Category, credtemplate.CategoryEAA)
	return trustedlists.NewEntity(category, strings.TrimSpace(e.Name)+" issuer", string(e.issuerCA))
}

// checkCatalogNames refuses a name that two entries share, because the name
// makes up the id of an entry.
func checkCatalogNames(entries []CatalogFileEntry) (*CatalogFile, error) {
	seen := map[string]string{}
	for _, e := range entries {
		key := strings.ToLower(strings.TrimSpace(e.Name))
		if other, dup := seen[key]; dup {
			return nil, fmt.Errorf("the catalogue entry %q appears in %s and %s", e.Name, other, e.source)
		}
		seen[key] = e.source
	}
	return &CatalogFile{Entries: entries}, nil
}

// ApplyCatalogFile makes the entries of file the operator's entries of the
// catalogue and puts their issuer CAs on the trusted lists. A nil file
// removes the operator's entries of an earlier start. The CAs of removed
// entries stay on their lists. It reports whether the stored state changed.
func (w *Wallet) ApplyCatalogFile(file *CatalogFile) (bool, error) {
	var entries []registrar.CatalogAttestation
	var issuers []trustedlists.Entity
	if file != nil {
		for _, e := range file.Entries {
			entries = append(entries, e.CatalogAttestation)
			if e.issuerCA == nil {
				continue
			}
			entity, err := e.issuerEntity()
			if err != nil {
				return false, fmt.Errorf("%s: entry %q: issuerCA: %w", e.source, e.Name, err)
			}
			issuers = append(issuers, entity)
		}
	}
	changed, err := w.Registrar().SetOperatorCatalog(entries)
	if entryErr := (*registrar.CatalogEntryError)(nil); errors.As(err, &entryErr) {
		e := file.Entries[entryErr.Index]
		return false, fmt.Errorf("%s: %s: %w", e.source, e.label(entryErr.Index), entryErr.Err)
	}
	if err != nil {
		return false, err
	}
	stored := w.TrustedLists().Entities()
	for _, entity := range issuers {
		if slices.ContainsFunc(stored, func(s trustedlists.Entity) bool { return s.ID == entity.ID }) {
			continue
		}
		if err := w.TrustedLists().StoreEntity(entity); err != nil {
			return false, fmt.Errorf("putting the issuer CA of %q on the %s list: %w", strings.TrimSuffix(entity.Name, " issuer"), entity.List, err)
		}
		changed = true
	}
	return changed, nil
}
