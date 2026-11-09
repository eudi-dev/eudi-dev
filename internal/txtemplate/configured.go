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

package txtemplate

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// ConfiguredFile holds the templates of one file of the operator's
// configuration, and its file name for error messages.
type ConfiguredFile struct {
	Name      string
	Templates []Template
}

// ConfiguredTemplates are the checked templates of the operator's transaction
// template files.
type ConfiguredTemplates struct {
	templates []Template
	// source maps each template to its file.
	source map[string]string
}

// ParseConfigured checks the templates of the files. A template name may
// appear only once across all files.
func ParseConfigured(files []ConfiguredFile) (ConfiguredTemplates, error) {
	parsed := ConfiguredTemplates{source: map[string]string{}}
	for _, file := range files {
		if len(file.Templates) == 0 {
			return ConfiguredTemplates{}, fmt.Errorf("%s holds no transaction template", file.Name)
		}
		for i, t := range file.Templates {
			t.Name = strings.TrimSpace(t.Name)
			if err := t.Check(); err != nil {
				return ConfiguredTemplates{}, fmt.Errorf("%s, transaction template %d: %w", file.Name, i+1, err)
			}
			if other, dup := parsed.source[t.Name]; dup {
				return ConfiguredTemplates{}, fmt.Errorf("the transaction template %q appears in %s and %s", t.Name, other, file.Name)
			}
			parsed.source[t.Name] = file.Name
			t.Predefined = false
			t.Visitor = false
			t.Configured = true
			parsed.templates = append(parsed.templates, t)
		}
	}
	return parsed, nil
}

// Len returns the number of templates.
func (t ConfiguredTemplates) Len() int {
	return len(t.templates)
}

// Configured holds the templates of the wallet's transaction template files.
// A reload replaces them while the server runs.
type Configured struct {
	mu  sync.RWMutex
	set ConfiguredTemplates
}

// Set replaces the configured templates.
func (c *Configured) Set(templates ConfiguredTemplates) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.set = templates
}

// Templates returns the configured templates. A nil Configured has none.
func (c *Configured) Templates() []Template {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]Template(nil), c.set.templates...)
}

func (c *Configured) lookup(name string) (Template, bool) {
	for _, t := range c.Templates() {
		if t.Name == name {
			return t, true
		}
	}
	return Template{}, false
}

// refuseChange refuses to save or delete a configured template. Its file
// belongs to the operator, and the next start would bring it back.
func (c *Configured) refuseChange(name string) error {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	file, ok := c.set.source[name]
	c.mu.RUnlock()
	if ok {
		return fmt.Errorf("%w: transaction template %q comes from %s. Change that file instead", ErrConfigured, name, file)
	}
	return nil
}

// ErrConfigured reports a change to a template from the operator's
// transaction template files.
var ErrConfigured = errors.New("read-only transaction template")
