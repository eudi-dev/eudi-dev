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
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
	"github.com/eudi-dev/eudi-dev/v3/internal/txtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

const configTestTemplates = `name: first-card
format: sdjwt
vct: urn:example:first:1
claims: {member_id: M-1}
---
name: second-card
format: sdjwt
vct: urn:example:second:1
claims: {member_id: M-2}
`

func writeConfigFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// A rename replaces the file in one step, so a running watcher never
	// reads it half written.
	if err := os.WriteFile(path+".tmp", []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
}

func TestConfigDirSetsEachInputFromASubdirectoryOrAFile(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, filepath.Join(dir, "templates", "cards.yaml"), configTestTemplates)
	writeConfigFile(t, filepath.Join(dir, "catalog.yml"), "[]\n")
	writeConfigFile(t, filepath.Join(dir, "credentials.json"), `{"credentials": []}`)
	writeConfigFile(t, filepath.Join(dir, "relying-parties"), "[]\n")
	writeConfigFile(t, filepath.Join(dir, "transaction-templates.yaml"), "[]\n")

	opts := &walletServeOptions{ConfigDir: dir}
	if err := applyConfigDir(opts); err != nil {
		t.Fatal(err)
	}
	if opts.TemplatesFile != filepath.Join(dir, "templates") ||
		opts.CatalogFile != filepath.Join(dir, "catalog.yml") ||
		opts.CredentialsFile != filepath.Join(dir, "credentials.json") ||
		opts.RelyingPartiesFile != filepath.Join(dir, "relying-parties") ||
		opts.TransactionTemplatesFile != filepath.Join(dir, "transaction-templates.yaml") {
		t.Fatalf("inputs = %+v", opts)
	}
}

func TestConfigDirRefusesAmbiguousInputs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []string
		opts  walletServeOptions
		want  string
	}{
		{"two catalogues", []string{"catalog.yaml", "catalog/a.yaml"}, walletServeOptions{}, "more than one catalog input"},
		{"flag and directory", []string{"catalog.yaml"}, walletServeOptions{CatalogFile: "other.yaml"}, "--catalog other.yaml and"},
		{"no input", []string{"notes.txt"}, walletServeOptions{}, "holds none of"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, file := range tc.files {
				writeConfigFile(t, filepath.Join(dir, file), "[]\n")
			}
			opts := tc.opts
			opts.ConfigDir = dir
			if err := applyConfigDir(&opts); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
		})
	}
	file := filepath.Join(t.TempDir(), "templates.yaml")
	writeConfigFile(t, file, configTestTemplates)
	if err := applyConfigDir(&walletServeOptions{ConfigDir: file}); err == nil || !strings.Contains(err.Error(), "is not a directory") {
		t.Fatalf("error = %v, want one for a file passed as --config", err)
	}
}

// A reload applies only the inputs that changed, so the credentials of an
// unchanged file are not issued again.
func TestApplyServeConfigAppliesOnlyChangedInputs(t *testing.T) {
	w := newServingTestWallet(t)
	w.Templates.Configured = &credtemplate.Configured{}
	w.TransactionTemplates.Configured = &txtemplate.Configured{}
	credentials := &wallet.CredentialsFile{Credentials: []wallet.CredentialsFileEntry{{ID: "alice-pid", Template: "pid-sdjwt"}}}
	first := &serveConfig{credentials: credentials}
	if _, changed, err := applyServeConfig(w, first, nil, true); err != nil || !changed {
		t.Fatalf("first apply: changed %v, err %v", changed, err)
	}
	count := len(w.Credentials)

	same := &serveConfig{credentials: &wallet.CredentialsFile{Credentials: []wallet.CredentialsFileEntry{{ID: "alice-pid", Template: "pid-sdjwt"}}}}
	if _, changed, err := applyServeConfig(w, same, first, true); err != nil || changed {
		t.Fatalf("unchanged apply: changed %v, err %v", changed, err)
	}
	if len(w.Credentials) != count {
		t.Fatalf("unchanged files changed the credentials from %d to %d", count, len(w.Credentials))
	}

	next := &serveConfig{credentials: &wallet.CredentialsFile{Credentials: []wallet.CredentialsFileEntry{
		{ID: "alice-pid", Template: "pid-sdjwt"}, {ID: "bob-pid", Template: "pid-sdjwt"},
	}}}
	if _, changed, err := applyServeConfig(w, next, same, true); err != nil || !changed {
		t.Fatalf("changed apply: changed %v, err %v", changed, err)
	}
	if _, ok := w.GetCredential("bob-pid"); !ok {
		t.Fatal("the added credential is missing")
	}
}

// One change can move a catalogue entry between the catalogue file and a
// template in both directions. A catalogue entry that clashes with a template
// is refused, also when only the catalogue changed, and the wallet keeps the
// previous catalogue.
func TestApplyServeConfigMovesCatalogueEntriesAndRefusesClashes(t *testing.T) {
	w := newServingTestWallet(t)
	w.Templates.Configured = &credtemplate.Configured{}
	w.TransactionTemplates.Configured = &txtemplate.Configured{}
	dir := t.TempDir()
	opts := &walletServeOptions{CatalogFile: filepath.Join(dir, "catalog.yaml"), TemplatesFile: filepath.Join(dir, "templates.yaml")}
	const catalogEntry = `name: Employee card
category: eaa
credentials:
  - format: dc+sd-jwt
    type: urn:example:employee:1
`
	const plainTemplate = "name: employee-card\nformat: sdjwt\nvct: urn:example:employee:1\n"
	const templateWithEntry = plainTemplate + "catalog:\n  name: Employee card\n  category: eaa\n"
	load := func(catalog, templates string) *serveConfig {
		t.Helper()
		writeConfigFile(t, opts.CatalogFile, catalog)
		writeConfigFile(t, opts.TemplatesFile, templates)
		return loadTestServeConfig(t, opts)
	}

	inCatalog := load(catalogEntry, plainTemplate)
	applied, _, err := applyServeConfig(w, inCatalog, nil, false)
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	inTemplate := load("[]\n", templateWithEntry)
	if applied, _, err = applyServeConfig(w, inTemplate, &applied, false); err != nil {
		t.Fatalf("moving the entry into the template: %v", err)
	}
	if !reflect.DeepEqual(applied, *inTemplate) {
		t.Fatal("applied doesn't hold the moved entry")
	}
	if applied, _, err = applyServeConfig(w, inCatalog, &applied, false); err != nil {
		t.Fatalf("moving the entry into the catalogue: %v", err)
	}
	if applied, _, err = applyServeConfig(w, inTemplate, &applied, false); err != nil {
		t.Fatal(err)
	}

	clash := load(catalogEntry, templateWithEntry)
	refused, _, err := applyServeConfig(w, clash, &applied, false)
	if err == nil {
		t.Fatal("a catalogue entry that clashes with a template applied")
	}
	if !reflect.DeepEqual(refused, applied) {
		t.Fatal("the refused catalogue replaced the applied one")
	}
	if _, _, err := applyServeConfig(w, inCatalog, &refused, false); err != nil {
		t.Fatalf("the wallet didn't keep the previous catalogue: %v", err)
	}
	fresh := newServingTestWallet(t)
	fresh.Templates.Configured = &credtemplate.Configured{}
	if _, _, err := applyServeConfig(fresh, clash, nil, false); err == nil {
		t.Fatal("a start with the clashing files succeeded")
	}
}

// An input that fails keeps its previous version in applied, so the next
// reload applies it again. The inputs before it are applied.
func TestApplyServeConfigReportsWhatApplied(t *testing.T) {
	w := newServingTestWallet(t)
	w.Templates.Configured = &credtemplate.Configured{}
	w.TransactionTemplates.Configured = &txtemplate.Configured{}
	previous := &serveConfig{credentials: &wallet.CredentialsFile{Credentials: []wallet.CredentialsFileEntry{{ID: "alice-pid", Template: "pid-sdjwt"}}}}
	if _, _, err := applyServeConfig(w, previous, nil, false); err != nil {
		t.Fatal(err)
	}
	relyingParties := &wallet.RelyingPartiesFile{}
	next := &serveConfig{
		relyingParties: relyingParties,
		credentials:    &wallet.CredentialsFile{Credentials: []wallet.CredentialsFileEntry{{ID: "bob", Template: "no-such-template"}}},
	}
	applied, _, err := applyServeConfig(w, next, previous, false)
	if err == nil {
		t.Fatal("a credential with a missing template applied")
	}
	if applied.relyingParties != relyingParties {
		t.Fatal("the relying parties applied but are not in applied")
	}
	if applied.credentials != previous.credentials {
		t.Fatal("the failed credentials replaced the previous ones in applied")
	}
}

// --check loads the files into a wallet in memory, prints the summary and
// leaves the wallet directory untouched.
func TestWalletServeCheckPrintsTheConfigurationWithoutAWallet(t *testing.T) {
	resetFlags(rootCmd)
	clearFlagEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	walletDir = ""
	config := t.TempDir()
	writeConfigFile(t, filepath.Join(config, "templates", "cards.yaml"), configTestTemplates)
	writeConfigFile(t, filepath.Join(config, "credentials.yaml"), "credentials:\n  - id: first\n    template: first-card\n")
	writeConfigFile(t, filepath.Join(config, "transaction-templates.yaml"), "name: refund\ntransaction_data: {type: urn:example:refund}\n")

	var err error
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"wallet", "serve", "--config", config, "--check"})
		err = rootCmd.Execute()
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"2 templates from " + filepath.Join(config, "templates"), "1 credential from " + filepath.Join(config, "credentials.yaml"), "1 transaction template from " + filepath.Join(config, "transaction-templates.yaml")} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".eudi-dev", "wallet")); !os.IsNotExist(err) {
		t.Fatalf("--check created the wallet directory: %v", err)
	}
}

func TestWalletServeCheckRefusesAnUnknownField(t *testing.T) {
	resetFlags(rootCmd)
	clearFlagEnv(t)
	t.Setenv("HOME", t.TempDir())
	walletDir = ""
	file := filepath.Join(t.TempDir(), "templates.yaml")
	writeConfigFile(t, file, configTestTemplates+"---\nname: third-card\ncolour: red\n")

	rootCmd.SetArgs([]string{"wallet", "serve", "--templates", file, "--check"})
	err := captureStdoutErr(t, rootCmd.Execute)
	if err == nil || !strings.Contains(err.Error(), "template 3") || !strings.Contains(err.Error(), "colour") {
		t.Fatalf("error = %v, want one naming the third template and the field", err)
	}
}

func captureStdoutErr(t *testing.T, fn func() error) error {
	t.Helper()
	var err error
	captureStdout(t, func() { err = fn() })
	return err
}

// A CLI command that finds no server works on a wallet in memory and warns
// once. Its changes are lost when it exits.
func TestALocalMemoryWalletWarnsOnce(t *testing.T) {
	resetFlags(rootCmd)
	t.Setenv("HOME", t.TempDir())
	walletDir = ""
	storageSpec = ""
	remoteFlag = ""
	t.Setenv(storage.EnvVar, "memory")
	memoryWalletWarning = sync.Once{}

	stderr := captureStderr(t, func() {
		for range 2 {
			if _, _, err := loadWallet(); err != nil {
				t.Fatal(err)
			}
		}
	})
	if strings.Count(stderr, "new wallet in memory") != 1 {
		t.Fatalf("stderr = %q, want one warning", stderr)
	}

	remoteFlag = "local"
	t.Cleanup(func() { remoteFlag = "" })
	memoryWalletWarning = sync.Once{}
	if stderr := captureStderr(t, func() {
		if _, _, err := loadWallet(); err != nil {
			t.Fatal(err)
		}
	}); stderr != "" {
		t.Fatalf("--remote local warned: %q", stderr)
	}

	remoteFlag = ""
	storageSpec = "memory"
	t.Cleanup(func() { storageSpec = "" })
	memoryWalletWarning = sync.Once{}
	if stderr := captureStderr(t, func() {
		if _, _, err := loadWallet(); err != nil {
			t.Fatal(err)
		}
	}); stderr != "" {
		t.Fatalf("--storage memory warned: %q", stderr)
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stderr
	os.Stderr = writer
	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(reader)
		done <- string(data)
	}()
	fn()
	os.Stderr = previous
	_ = writer.Close()
	out := <-done
	_ = reader.Close()
	return out
}
