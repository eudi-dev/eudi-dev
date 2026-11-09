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

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/txtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// serveConfigInput is one kind of configuration file of wallet serve. Its
// name is also the name of its file or subdirectory in --config.
type serveConfigInput struct {
	name string
	flag string
	path *string
}

func serveConfigInputs(opts *walletServeOptions) []serveConfigInput {
	return []serveConfigInput{
		{name: "templates", flag: "--templates", path: &opts.TemplatesFile},
		{name: "transaction-templates", flag: "--transaction-templates", path: &opts.TransactionTemplatesFile},
		{name: "catalog", flag: "--catalog", path: &opts.CatalogFile},
		{name: "relying-parties", flag: "--relying-parties", path: &opts.RelyingPartiesFile},
		{name: "credentials", flag: "--credentials", path: &opts.CredentialsFile},
	}
}

// applyConfigDir sets each input without a flag of its own from the --config
// directory. An input is a subdirectory or a file named after it, with or
// without a .yaml, .yml or .json extension.
func applyConfigDir(opts *walletServeOptions) error {
	dir := opts.ConfigDir
	if dir == "" {
		return nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("--config: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("--config: %s is not a directory", dir)
	}
	found := 0
	known := map[string]bool{}
	inputs := serveConfigInputs(opts)
	names := make([]string, len(inputs))
	for i, input := range inputs {
		names[i] = input.name
	}
	for _, input := range inputs {
		var matches []string
		for _, candidate := range append([]string{input.name}, configFileNames(input.name)...) {
			known[candidate] = true
			path := filepath.Join(dir, candidate)
			if _, err := os.Stat(path); err != nil {
				continue
			}
			matches = append(matches, path)
		}
		switch {
		case len(matches) == 0:
			continue
		case len(matches) > 1:
			return fmt.Errorf("--config: %s has more than one %s input: %s. Keep one", dir, input.name, strings.Join(matches, " and "))
		case *input.path != "":
			return fmt.Errorf("%s %s and %s both set the %s. Use one of them", input.flag, *input.path, matches[0], input.name)
		}
		*input.path = matches[0]
		found++
	}
	if found == 0 {
		return fmt.Errorf("--config: %s holds none of %s, as a subdirectory or a file", dir, strings.Join(names, ", "))
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("--config: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if known[name] || strings.HasPrefix(name, ".") || !slices.Contains([]string{".yaml", ".yml", ".json"}, strings.ToLower(filepath.Ext(name))) {
			continue
		}
		fmt.Fprintf(os.Stderr, "warning: --config: %s isn't one of the inputs %s, so the wallet ignores it\n", filepath.Join(dir, name), strings.Join(names, ", "))
	}
	return nil
}

func configFileNames(name string) []string {
	return []string{name + ".yaml", name + ".yml", name + ".json"}
}

// serveConfig holds the content of the wallet serve configuration files.
type serveConfig struct {
	templates            credtemplate.ConfiguredTemplates
	transactionTemplates txtemplate.ConfiguredTemplates
	catalog              *wallet.CatalogFile
	relyingParties       *wallet.RelyingPartiesFile
	credentials          *wallet.CredentialsFile
}

func loadServeConfig(opts *walletServeOptions) (*serveConfig, error) {
	cfg := &serveConfig{}
	var err error
	if opts.TemplatesFile != "" {
		if cfg.templates, err = wallet.LoadTemplateFiles(opts.TemplatesFile); err != nil {
			return nil, fmt.Errorf("reading the template files: %w", err)
		}
	}
	if opts.TransactionTemplatesFile != "" {
		if cfg.transactionTemplates, err = wallet.LoadTransactionTemplateFiles(opts.TransactionTemplatesFile); err != nil {
			return nil, fmt.Errorf("reading the transaction template files: %w", err)
		}
	}
	if opts.CatalogFile != "" {
		if cfg.catalog, err = wallet.LoadCatalogFile(opts.CatalogFile); err != nil {
			return nil, fmt.Errorf("reading the catalogue file: %w", err)
		}
	}
	if opts.RelyingPartiesFile != "" {
		if cfg.relyingParties, err = wallet.LoadRelyingPartiesFile(opts.RelyingPartiesFile); err != nil {
			return nil, fmt.Errorf("reading the relying parties file: %w", err)
		}
	}
	if opts.CredentialsFile != "" {
		if cfg.credentials, err = wallet.LoadCredentialsFile(opts.CredentialsFile); err != nil {
			return nil, fmt.Errorf("reading the credentials file: %w", err)
		}
	}
	return cfg, nil
}

// summary lists how many items each configuration input holds, and its path.
func (c *serveConfig) summary(opts *walletServeOptions) []string {
	var lines []string
	add := func(path string, n int, one, many string) {
		if path == "" {
			return
		}
		noun := many
		if n == 1 {
			noun = one
		}
		lines = append(lines, fmt.Sprintf("%d %s from %s", n, noun, path))
	}
	add(opts.TemplatesFile, c.templates.Len(), "template", "templates")
	add(opts.TransactionTemplatesFile, c.transactionTemplates.Len(), "transaction template", "transaction templates")
	if c.catalog != nil {
		add(opts.CatalogFile, len(c.catalog.Entries), "catalogue entry", "catalogue entries")
	}
	if c.relyingParties != nil {
		add(opts.RelyingPartiesFile, len(c.relyingParties.Parties), "relying party", "relying parties")
	}
	if c.credentials != nil {
		add(opts.CredentialsFile, len(c.credentials.Credentials), "credential", "credentials")
	}
	return lines
}

// applyServeConfig makes the wallet match next. A nil previous applies all of
// next, as at startup. Otherwise only the inputs that changed are applied
// again, so an unchanged credentials file doesn't issue its credentials anew.
// The catalogue and the templates apply together, because a template can carry
// a catalogue entry and the two must not clash. The templates are set before
// the catalogue, so one change can move an entry between them in both
// directions. Credentials and registrations take their category from the
// catalogue, and credentials refer to templates, so they apply after the
// catalogue and the templates. applied holds next for each input that applied
// and previous for the others.
func applyServeConfig(w *wallet.Wallet, next, previous *serveConfig, protectByDefault bool) (applied serveConfig, changed bool, err error) {
	if previous != nil {
		applied = *previous
	}
	catalogChanged := previous == nil || !reflect.DeepEqual(next.catalog, previous.catalog)
	templatesChanged := previous == nil || !reflect.DeepEqual(next.templates, previous.templates)
	if catalogChanged || templatesChanged {
		w.Templates.Configured.Set(next.templates)
		rollback := func() {
			w.Templates.Configured.Set(applied.templates)
			if catalogChanged {
				_, _ = w.ApplyCatalogFile(applied.catalog)
			}
		}
		if catalogChanged {
			updated, err := w.ApplyCatalogFile(next.catalog)
			changed = changed || updated
			if err != nil {
				rollback()
				return applied, changed, fmt.Errorf("pre-registering the catalogue entries: %w", err)
			}
		}
		if err := w.Registrar().CheckTemplateCatalog(nil); err != nil {
			rollback()
			return applied, changed, fmt.Errorf("the catalogue entries of the templates: %w", err)
		}
		applied.catalog, applied.templates = next.catalog, next.templates
	}
	if previous == nil || !reflect.DeepEqual(next.transactionTemplates, previous.transactionTemplates) {
		w.TransactionTemplates.Configured.Set(next.transactionTemplates)
		applied.transactionTemplates = next.transactionTemplates
	}
	if previous == nil || !reflect.DeepEqual(next.relyingParties, previous.relyingParties) {
		updated, err := w.ApplyRelyingPartiesFile(next.relyingParties)
		changed = changed || updated
		if err != nil {
			return applied, changed, fmt.Errorf("registering the relying parties: %w", err)
		}
		applied.relyingParties = next.relyingParties
	}
	if next.credentials != nil && (previous == nil || !reflect.DeepEqual(next.credentials, previous.credentials)) {
		changed = true
		if err := w.AddFileCredentials(next.credentials, protectByDefault); err != nil {
			return applied, changed, fmt.Errorf("adding the startup credentials: %w", err)
		}
	}
	applied.credentials = next.credentials
	return applied, changed, nil
}

// watchServeConfig reads the configuration files every interval and calls
// reload when they differ from the applied configuration. A configuration that
// doesn't load waits for the next change. One that doesn't apply is tried
// again on every tick, because the cause can go away, such as a database
// outage.
func watchServeConfig(stop <-chan struct{}, applied func() *serveConfig, interval time.Duration, opts *walletServeOptions, reload func(*serveConfig) error, logf func(string, ...any)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	warned := ""
	warn := func(format string, err error) {
		if message := fmt.Sprintf(format, err); message != warned {
			logf("%s", message)
			warned = message
		}
	}
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		next, err := loadServeConfig(opts)
		if err != nil {
			warn("  WARNING: the configuration files don't load, so the wallet keeps the previous configuration: %v", err)
			continue
		}
		if reflect.DeepEqual(next, applied()) {
			warned = ""
			continue
		}
		if err := reload(next); err != nil {
			warn("  WARNING: applying the changed configuration files failed and is tried again: %v", err)
			continue
		}
		warned = ""
		logf("  Configuration reloaded: %s", strings.Join(next.summary(opts), ", "))
	}
}
