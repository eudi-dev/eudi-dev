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

package credtemplate

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
)

// ConfiguredFile is a template file as read from the operator's configuration,
// and its name for error messages.
type ConfiguredFile struct {
	Name string
	Data []byte
}

// ConfiguredTemplates are the parsed templates of the operator's template
// files. Their PID dates stay empty until a read fills them, so a
// long-running server issues current dates, as it does for stored templates.
type ConfiguredTemplates struct {
	templates []Template
	// source maps each template to its file.
	source map[string]string
}

// ParseConfigured parses the template files. A template name may appear only
// once across all files.
func ParseConfigured(files []ConfiguredFile) (ConfiguredTemplates, error) {
	parsed := ConfiguredTemplates{source: map[string]string{}}
	for _, file := range files {
		templates, err := parseAll(file.Data, file.Name)
		if err != nil {
			return ConfiguredTemplates{}, err
		}
		for _, t := range templates {
			if other, dup := parsed.source[t.Name]; dup {
				return ConfiguredTemplates{}, fmt.Errorf("the template %q appears in %s and %s", t.Name, other, file.Name)
			}
			parsed.source[t.Name] = file.Name
			t.Configured = true
			// A demo reset deletes visitor templates, and a configured one
			// can't be deleted.
			t.Visitor = false
			parsed.templates = append(parsed.templates, t)
		}
	}
	return parsed, nil
}

// Len returns the number of templates.
func (t ConfiguredTemplates) Len() int {
	return len(t.templates)
}

// Configured holds the templates of the wallet's template files. A reload
// replaces them while the server runs.
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
	set := c.set
	c.mu.RUnlock()
	templates := make([]Template, 0, len(set.templates))
	for _, t := range set.templates {
		templates = append(templates, withPIDDates(t))
	}
	return templates
}

// Len returns the number of configured templates.
func (c *Configured) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.set.Len()
}

func (c *Configured) lookup(name string) (*Template, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	set := c.set
	c.mu.RUnlock()
	for _, t := range set.templates {
		if t.Name == name {
			t = withPIDDates(t)
			return &t, true
		}
	}
	return nil, false
}

// files returns the template files that hold the configured templates,
// sorted by file name.
func (c *Configured) files() []string {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	files := slices.Collect(maps.Values(c.set.source))
	slices.Sort(files)
	return slices.Compact(files)
}

// CheckChangeable reports ErrConfigured for a template that comes from the
// operator's template files.
func (l Location) CheckChangeable(name string) error {
	return l.Configured.refuseChange(name)
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
		return fmt.Errorf("%w: template %q comes from %s. Change that file instead", ErrConfigured, name, file)
	}
	return nil
}

// ErrConfigured reports a change to a template from the operator's template
// files.
var ErrConfigured = errors.New("read-only template")
