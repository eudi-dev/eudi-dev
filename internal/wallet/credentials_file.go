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
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/yamljson"
)

// CredentialsFile lists credentials the wallet adds on every start. An entry
// either issues a credential from a template or imports a finished one.
type CredentialsFile struct {
	Credentials []CredentialsFileEntry `json:"credentials"`
}

// CredentialsFileEntry holds either a template with optional overrides or a
// finished credential.
type CredentialsFileEntry struct {
	ID              string         `json:"id"`
	Template        string         `json:"template"`
	Format          string         `json:"format"`
	Claims          map[string]any `json:"claims"`
	AlwaysDisclosed []string       `json:"always_disclosed"`
	Omit            []string       `json:"omit"`
	Exp             string         `json:"exp"`
	Display         *IssueDisplay  `json:"display"`
	// Protected keeps visitors from deleting or revoking the credential. When
	// it is unset, AddFileCredentials applies its default.
	Protected *bool `json:"protected"`
	// Credential is a finished SD-JWT VC, JWT VC or mdoc.
	Credential string `json:"credential"`
}

func (e CredentialsFileEntry) hasOverrides() bool {
	return e.Format != "" || e.Claims != nil || e.AlwaysDisclosed != nil || e.Omit != nil || e.Exp != "" || e.Display != nil
}

// Credential IDs appear in API paths and UI selectors.
var credentialsFileID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// LoadCredentialsFile reads a YAML or JSON credentials file, every .yaml, .yml
// and .json file of a directory in name order, or stdin for "-".
func LoadCredentialsFile(path string) (*CredentialsFile, error) {
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		return parseCredentialsSource("stdin", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return parseCredentialsSource(path, data)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	merged := &CredentialsFile{}
	seen := map[string]string{}
	for _, entry := range entries {
		switch strings.ToLower(filepath.Ext(entry.Name())) {
		case ".yaml", ".yml", ".json":
		default:
			continue
		}
		file := filepath.Join(path, entry.Name())
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		parsed, err := parseCredentialsSource(file, data)
		if err != nil {
			return nil, err
		}
		for _, c := range parsed.Credentials {
			if other, dup := seen[c.ID]; dup {
				return nil, fmt.Errorf("credential id %q appears in %s and %s", c.ID, other, file)
			}
			seen[c.ID] = file
		}
		merged.Credentials = append(merged.Credentials, parsed.Credentials...)
	}
	return merged, nil
}

func parseCredentialsSource(name string, data []byte) (*CredentialsFile, error) {
	file, err := ParseCredentialsFile(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return file, nil
}

// ParseCredentialsFile reads YAML or JSON. YAML is converted to JSON before
// decoding, so entries use the template JSON field names and claims get the
// same value types as an issue API request.
func ParseCredentialsFile(data []byte) (*CredentialsFile, error) {
	encoded, err := yamljson.Convert(data, yamljson.KeepStrings)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var file CredentialsFile
	if err := decoder.Decode(&file); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i, entry := range file.Credentials {
		switch {
		case !credentialsFileID.MatchString(entry.ID):
			return nil, fmt.Errorf("credential %d: id %q must start with a letter or digit and contain only letters, digits, '.', '_' and '-'", i+1, entry.ID)
		case seen[entry.ID]:
			return nil, fmt.Errorf("credential id %q appears twice", entry.ID)
		case (entry.Template == "") == (entry.Credential == ""):
			return nil, fmt.Errorf("credential %q needs either a template or a credential", entry.ID)
		case entry.Credential != "" && entry.hasOverrides():
			return nil, fmt.Errorf("credential %q: only a template entry takes overrides", entry.ID)
		}
		if entry.Exp != "" {
			if _, err := time.ParseDuration(entry.Exp); err != nil {
				return nil, fmt.Errorf("credential %q: invalid exp: %w", entry.ID, err)
			}
		}
		seen[entry.ID] = true
	}
	return &file, nil
}

// AddFileCredentials adds every entry under its ID and replaces an earlier
// copy with that ID, so a restart adds no duplicates. An entry without its own
// protected setting gets protectByDefault.
func (w *Wallet) AddFileCredentials(file *CredentialsFile, protectByDefault bool) error {
	for _, entry := range file.Credentials {
		if err := w.addFileCredential(entry); err != nil {
			return fmt.Errorf("credential %q: %w", entry.ID, err)
		}
		protected := protectByDefault
		if entry.Protected != nil {
			protected = *entry.Protected
		}
		w.setProtected(entry.ID, protected)
	}
	return nil
}

// addFileCredential issues or imports the entry first, so a failure keeps the
// copy from an earlier start.
func (w *Wallet) addFileCredential(entry CredentialsFileEntry) error {
	var added string
	if entry.Credential != "" {
		imported, err := w.ImportCredential(entry.Credential)
		if err != nil {
			return err
		}
		added = imported.ID
	} else {
		var expiresIn time.Duration
		if entry.Exp != "" {
			expiresIn, _ = time.ParseDuration(entry.Exp)
		}
		result, err := w.IssueCredential(IssueOptions{
			Template:        entry.Template,
			Format:          entry.Format,
			Claims:          entry.Claims,
			AlwaysDisclosed: entry.AlwaysDisclosed,
			Omit:            entry.Omit,
			ExpiresIn:       expiresIn,
			Display:         entry.Display,
		})
		if err != nil {
			return err
		}
		added = result.Credential.ID
	}
	w.replaceCredential(entry.ID, added)
	return nil
}

// replaceCredential removes the credential with the ID, even a protected one,
// and gives that ID to the added credential. The removed credential's status
// entry goes too.
func (w *Wallet) replaceCredential(id, added string) {
	if id == added {
		return
	}
	w.mu.Lock()
	w.Credentials = slices.DeleteFunc(w.Credentials, func(c StoredCredential) bool { return c.ID == id })
	delete(w.StatusEntries, id)
	w.mu.Unlock()
	w.renameCredential(added, id)
}

func (w *Wallet) setProtected(id string, protected bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.Credentials {
		if w.Credentials[i].ID == id {
			w.Credentials[i].Protected = protected
		}
	}
}
