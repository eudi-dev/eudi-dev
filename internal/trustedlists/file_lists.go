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

package trustedlists

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
)

// FileList is a complete trusted list from a --trusted-list file, which the
// wallet publishes under its own URL. Raw is a signed list as a compact JWT, or
// the list's LoTE content as JSON, which the wallet signs itself.
type FileList struct {
	ID  string
	Raw string
}

// ParseFileListContent reads the LoTE content of a list given as JSON. The
// content may stand alone or sit under the LoTE key of the signed payload.
func ParseFileListContent(raw string) (map[string]any, error) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, err
	}
	if inner, ok := doc["LoTE"].(map[string]any); ok {
		doc = inner
	}
	if _, ok := doc["ListAndSchemeInformation"].(map[string]any); !ok {
		return nil, fmt.Errorf("the list has no ListAndSchemeInformation")
	}
	return doc, nil
}

// SignedFileList returns the list as the wallet publishes it. A list in JSON
// is signed with the key of the wallet's list of trusted lists.
func (t *Set) SignedFileList(id string) (string, bool, error) {
	for _, file := range t.settings.FileLists {
		if file.ID != id {
			continue
		}
		raw := strings.TrimSpace(file.Raw)
		if !strings.HasPrefix(raw, "{") {
			return raw, true, nil
		}
		content, err := ParseFileListContent(raw)
		if err != nil {
			return "", true, err
		}
		key, chain, err := t.env.Signer().TrustList(config.WalletName, listOfListsTerritory)
		if err != nil {
			return "", true, err
		}
		signed, err := lote.SignList(key, chain[0], time.Now(), content)
		return signed, true, err
	}
	return "", false, nil
}

func (t *Set) isFileList(rawURL string) bool {
	id, own := t.ownListID(rawURL)
	return own && slices.ContainsFunc(t.settings.FileLists, func(f FileList) bool { return f.ID == id })
}

// FileListProblem names the first file list that the wallet can't use: its name
// is taken by one of the wallet's own lists, or it doesn't verify.
func (t *Set) FileListProblem() error {
	for _, file := range t.settings.FileLists {
		if _, taken := t.FindGroup(file.ID, "", ""); taken {
			return fmt.Errorf("the wallet already has a list %q, so rename the file", file.ID)
		}
		if _, err := t.ReadList(t.OwnListURL(file.ID)); err != nil {
			return fmt.Errorf("the list %q: %w", file.ID, err)
		}
	}
	return nil
}

func (t *Set) fileListEntries(issuer string) []indexEntry {
	entries := make([]indexEntry, 0, len(t.settings.FileLists))
	for _, file := range t.settings.FileLists {
		path := provider.TrustedListPath(file.ID)
		entry := indexEntry{ID: file.ID, Description: "Published from a file by the operator of this wallet", Category: "Operator lists", Path: path, File: true}
		if signed, _, err := t.SignedFileList(file.ID); err == nil {
			if list, err := lote.Parse(signed); err == nil {
				entry.LoTEType, entry.EntityName = list.SchemeInfo.LoTEType, list.SchemeInfo.SchemeOperatorName
			}
		}
		if issuer != "" {
			entry.AdvertisedURL = issuer + path
			entry.URL = entry.AdvertisedURL
		}
		entries = append(entries, entry)
	}
	return entries
}
