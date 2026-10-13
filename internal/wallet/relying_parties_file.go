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
	"fmt"
	"slices"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

// RelyingPartiesFile holds the relying parties registered by the operator on
// every start (wallet serve --relying-parties).
type RelyingPartiesFile struct {
	Parties []registrar.WalletRelyingParty
	sources []string
}

// LoadRelyingPartiesFile reads a YAML or JSON file, every .yaml, .yml and
// .json file of a directory in name order, or stdin for "-". A file holds one
// registration or a list of registrations, in the shape that
// POST /api/registrar/wrp takes.
func LoadRelyingPartiesFile(path string) (*RelyingPartiesFile, error) {
	sources, err := readStartupSources(path)
	if err != nil {
		return nil, err
	}
	file := &RelyingPartiesFile{}
	seen := map[string]string{}
	for _, source := range sources {
		parties, err := parseRelyingPartiesSource(source.name, source.data)
		if err != nil {
			return nil, err
		}
		for _, rp := range parties {
			id := rp.Identifier[0].Identifier
			if other, dup := seen[id]; dup {
				return nil, fmt.Errorf("the relying party %s appears in %s and %s", id, other, source.name)
			}
			seen[id] = source.name
			file.Parties = append(file.Parties, rp)
			file.sources = append(file.sources, source.name)
		}
	}
	return file, nil
}

// parseRelyingPartiesSource reads the registrations of one file. Each start
// registers them again, so every identifier the registrar would otherwise
// generate must be in the file. A new intended use identifier would revoke
// the certificates issued before the restart.
func parseRelyingPartiesSource(name string, data []byte) ([]registrar.WalletRelyingParty, error) {
	encoded, err := credtemplate.YAMLToJSON(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if bytes.HasPrefix(encoded, []byte{'{'}) {
		encoded = slices.Concat([]byte{'['}, encoded, []byte{']'})
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var parties []registrar.WalletRelyingParty
	if err := decoder.Decode(&parties); err != nil {
		return nil, fmt.Errorf("%s: expected a relying party or a list of relying parties: %w", name, err)
	}
	for i := range parties {
		rp := &parties[i]
		label := relyingPartyLabel(*rp, i)
		if len(rp.Identifier) == 0 || strings.TrimSpace(rp.Identifier[0].Identifier) == "" {
			return nil, fmt.Errorf("%s: %s needs an identifier", name, label)
		}
		// The registrar stores the identifier trimmed, and the next start
		// looks the registration up by it.
		rp.Identifier[0].Identifier = strings.TrimSpace(rp.Identifier[0].Identifier)
		for _, service := range rp.Services {
			for _, use := range service.IntendedUses {
				if strings.TrimSpace(use.IntendedUseIdentifier) == "" {
					return nil, fmt.Errorf("%s: %s: every intended use needs an intendedUseIdentifier", name, label)
				}
			}
		}
	}
	return parties, nil
}

func relyingPartyLabel(rp registrar.WalletRelyingParty, i int) string {
	if len(rp.Identifier) > 0 && strings.TrimSpace(rp.Identifier[0].Identifier) != "" {
		return "relying party " + strings.TrimSpace(rp.Identifier[0].Identifier)
	}
	if name := strings.TrimSpace(rp.TradeName); name != "" {
		return fmt.Sprintf("relying party %q", name)
	}
	return fmt.Sprintf("relying party %d", i+1)
}

// Identifiers returns the first identifier of every registration.
func (f *RelyingPartiesFile) Identifiers() []string {
	if f == nil {
		return nil
	}
	ids := make([]string, 0, len(f.Parties))
	for _, rp := range f.Parties {
		ids = append(ids, rp.Identifier[0].Identifier)
	}
	return ids
}

// ApplyRelyingPartiesFile registers the relying parties of file. A
// registration that differs from the file is replaced, so the file wins over
// changes made through the API. It reports whether the stored state changed.
func (w *Wallet) ApplyRelyingPartiesFile(file *RelyingPartiesFile) (bool, error) {
	if file == nil {
		return false, nil
	}
	changed := false
	for i, rp := range file.Parties {
		_, updated, err := w.Registrar().EnsureRelyingParty(rp)
		if err != nil {
			return changed, fmt.Errorf("%s: %s: %w", file.sources[i], relyingPartyLabel(rp, i), err)
		}
		changed = changed || updated
	}
	return changed, nil
}
