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

// Package txtemplate stores named transaction data entries for presentation
// requests (OpenID4VP 1.0 §5.1). The built-in templates are the files under
// transactions/ of the defaults tree. They show the SCA transaction types of
// EUDI TS12 v1.0.1 §4.3. A user template replaces the built-in template with
// the same name, and a template from the operator's transaction template files
// replaces both.
package txtemplate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"
	"syscall"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/defaults"
	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
)

// Template is a named transaction data entry.
type Template struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// TransactionData is the decoded entry. A verifier adds credential_ids
	// when the template has none, because they refer to the verifier's own
	// credential queries.
	TransactionData map[string]any `json:"transaction_data"`
	// Predefined marks the built-in templates. Template files can't set it.
	Predefined bool `json:"predefined,omitempty"`
	// Visitor marks a template saved by a visitor of a public demo.
	Visitor bool `json:"visitor,omitempty"`
	// Configured marks a template from the operator's transaction template
	// files. Template files can't set it.
	Configured bool `json:"configured,omitempty"`
}

// Type is the type member of the entry.
func (t Template) Type() string {
	typ, _ := t.TransactionData["type"].(string)
	return typ
}

// Check refuses a template without a name or a type, because no request could
// carry it.
func (t Template) Check() error {
	if !credtemplate.IsBareName(t.Name) {
		return fmt.Errorf("invalid transaction template name %q", t.Name)
	}
	if t.TransactionData == nil {
		return errors.New("transaction_data must be an object")
	}
	if strings.TrimSpace(t.Type()) == "" {
		return errors.New("transaction_data needs a type")
	}
	return nil
}

// Location is a prefix inside a store that holds user templates. The zero
// Location holds none and refuses to save.
type Location struct {
	Store  storage.Store
	Prefix string
	// Configured holds the templates of the operator's transaction template
	// files. They can't be changed through the location.
	Configured *Configured
}

func (l Location) key(name string) string {
	return path.Join(l.Prefix, name+".json")
}

// ErrNotFound reports a name with no stored or predefined template.
var ErrNotFound = errors.New("not found")

const predefinedDir = "transactions"

// Predefined reads the built-in templates from the defaults tree.
func Predefined() []Template {
	entries, err := defaults.ReadDir(predefinedDir)
	if err != nil {
		panic(fmt.Sprintf("reading the predefined transaction templates: %v", err))
	}
	var templates []Template
	for _, entry := range entries {
		data, err := defaults.ReadFile(path.Join(predefinedDir, entry.Name()))
		if err != nil {
			panic(fmt.Sprintf("reading the predefined transaction template %s: %v", entry.Name(), err))
		}
		t, err := parse(data, strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			panic(fmt.Sprintf("predefined transaction template: %v", err))
		}
		t.Predefined = true
		templates = append(templates, t)
	}
	return templates
}

func predefined(name string) (Template, bool) {
	for _, t := range Predefined() {
		if t.Name == name {
			return t, true
		}
	}
	return Template{}, false
}

// List returns the predefined and the stored templates, sorted by name. A
// stored template replaces a predefined one of the same name. Unreadable
// templates are reported as an error, and the readable ones are still
// returned.
func List(loc Location) ([]Template, error) {
	byName := map[string]Template{}
	for _, t := range Predefined() {
		byName[t.Name] = t
	}
	var errs []error
	var names []string
	var err error
	if loc.Store != nil {
		names, err = loc.Store.List(loc.Prefix)
	}
	if err != nil {
		errs = append(errs, fmt.Errorf("reading the transaction templates: %w", err))
	}
	for _, file := range names {
		name, ok := strings.CutSuffix(file, ".json")
		if !ok {
			continue
		}
		t, err := loadStored(loc, name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		byName[name] = t
	}
	for _, t := range loc.Configured.Templates() {
		byName[t.Name] = t
	}
	templates := make([]Template, 0, len(byName))
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		templates = append(templates, byName[name])
	}
	return templates, errors.Join(errs...)
}

// Load returns the configured template of that name, or else the stored one,
// or else the predefined one.
func Load(loc Location, name string) (Template, error) {
	if !credtemplate.IsBareName(name) {
		return Template{}, fmt.Errorf("invalid transaction template name %q", name)
	}
	if t, ok := loc.Configured.lookup(name); ok {
		return t, nil
	}
	if loc.Store != nil {
		t, err := loadStored(loc, name)
		if err == nil || !errors.Is(err, fs.ErrNotExist) {
			return t, err
		}
	}
	if t, ok := predefined(name); ok {
		return t, nil
	}
	return Template{}, fmt.Errorf("transaction template %q %w", name, ErrNotFound)
}

// Save stores a template under its name.
func Save(loc Location, t Template) error {
	t.Name = strings.TrimSpace(t.Name)
	if err := t.Check(); err != nil {
		return err
	}
	if err := loc.Configured.refuseChange(t.Name); err != nil {
		return err
	}
	if loc.Store == nil {
		return errors.New("this wallet has no storage for transaction templates")
	}
	t.Predefined = false
	t.Configured = false
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding transaction template: %w", err)
	}
	if _, err := loc.Store.Write(loc.key(t.Name), append(data, '\n'), 0o644); err != nil {
		if errors.Is(err, syscall.EROFS) || errors.Is(err, fs.ErrPermission) {
			return &credtemplate.StorageError{Err: fmt.Errorf("the wallet cannot write %s: %w. Put mounted transaction template files in --transaction-templates (EUDI_DEV_TRANSACTION_TEMPLATES)", loc.Store.Locate(loc.key(t.Name)), err)}
		}
		return &credtemplate.StorageError{Err: fmt.Errorf("writing transaction template: %w", err)}
	}
	return nil
}

// Delete removes a stored template. Deleting a stored template that replaces
// a predefined one restores the predefined one.
func Delete(loc Location, name string) error {
	if !credtemplate.IsBareName(name) {
		return fmt.Errorf("invalid transaction template name %q", name)
	}
	if err := loc.Configured.refuseChange(name); err != nil {
		return err
	}
	exists := false
	if loc.Store != nil {
		var err error
		if exists, err = loc.Store.Exists(loc.key(name)); err != nil {
			return &credtemplate.StorageError{Err: err}
		}
	}
	if exists {
		if err := loc.Store.Delete(loc.key(name)); err != nil {
			return &credtemplate.StorageError{Err: err}
		}
		return nil
	}
	if _, ok := predefined(name); ok {
		return fmt.Errorf("transaction template %q is predefined and cannot be deleted", name)
	}
	return fmt.Errorf("transaction template %q %w", name, ErrNotFound)
}

func loadStored(loc Location, name string) (Template, error) {
	data, err := loc.Store.Read(loc.key(name))
	if err != nil {
		return Template{}, fmt.Errorf("reading transaction template %s: %w", name, err)
	}
	return parse(data, name)
}

// parse reads a template file. The file name is the template's name.
func parse(data []byte, name string) (Template, error) {
	var t Template
	if err := json.Unmarshal(data, &t); err != nil {
		return Template{}, fmt.Errorf("parsing transaction template %s: %w", name, err)
	}
	t.Name = name
	t.Predefined = false
	t.Configured = false
	if err := t.Check(); err != nil {
		return Template{}, fmt.Errorf("transaction template %s: %w", name, err)
	}
	return t, nil
}

// DecodeAll reads the templates of a YAML or JSON input, in the format of
// `templates transactions show` or a template file. Each YAML document holds
// one template or a list. An unknown field is an error.
func DecodeAll(data []byte) ([]Template, error) {
	documents, err := credtemplate.YAMLDocumentsToJSON(data)
	if err != nil {
		return nil, err
	}
	var templates []Template
	for _, doc := range documents {
		document := doc.JSON
		if bytes.HasPrefix(document, []byte{'{'}) {
			document = slices.Concat([]byte{'['}, document, []byte{']'})
		}
		decoder := json.NewDecoder(bytes.NewReader(document))
		decoder.DisallowUnknownFields()
		var part []Template
		if err := decoder.Decode(&part); err != nil {
			if len(documents) > 1 {
				return nil, fmt.Errorf("YAML document %d: %w", doc.Number, err)
			}
			return nil, err
		}
		templates = append(templates, part...)
	}
	return templates, nil
}
