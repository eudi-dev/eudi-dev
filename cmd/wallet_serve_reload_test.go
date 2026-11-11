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
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/txtemplate"
)

// startWatcher runs watchServeConfig from the current state of the files
// until the test ends and returns its log. A reload without an error becomes
// the applied configuration.
func startWatcher(t *testing.T, opts *walletServeOptions, reload func(*serveConfig) error) func() []string {
	t.Helper()
	var current atomic.Pointer[serveConfig]
	current.Store(loadTestServeConfig(t, opts))
	return runWatcher(t, opts, 10*time.Millisecond, current.Load, func(next *serveConfig) error {
		if err := reload(next); err != nil {
			return err
		}
		current.Store(next)
		return nil
	})
}

func loadTestServeConfig(t *testing.T, opts *walletServeOptions) *serveConfig {
	t.Helper()
	cfg, err := loadServeConfig(opts)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// runWatcher runs watchServeConfig until the test ends and returns its log.
func runWatcher(t *testing.T, opts *walletServeOptions, interval time.Duration, applied func() *serveConfig, reload func(*serveConfig) error) func() []string {
	t.Helper()
	var mu sync.Mutex
	var logs []string
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchServeConfig(stop, applied, interval, opts, reload, func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			logs = append(logs, fmt.Sprintf(format, args...))
		})
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
	})
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(logs)
	}
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A file that no longer loads leaves the wallet as it was and is reported
// once, and the next good version is applied.
func TestWatchServeConfigReloadsChangedFilesAndSkipsBrokenOnes(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "templates.yaml")
	writeConfigFile(t, file, configTestTemplates)
	opts := &walletServeOptions{TemplatesFile: file}
	reloads := make(chan int, 4)
	logs := startWatcher(t, opts, func(cfg *serveConfig) error {
		reloads <- cfg.templates.Len()
		return nil
	})

	writeConfigFile(t, file, "name: broken\ncolour: red\n")
	waitFor(t, "the warning for the broken file", func() bool { return len(logs()) > 0 })
	time.Sleep(50 * time.Millisecond)
	writeConfigFile(t, file, configTestTemplates+"---\nname: third-card\nformat: sdjwt\nvct: urn:example:third:1\n")
	select {
	case count := <-reloads:
		if count != 3 {
			t.Fatalf("reloaded %d templates, want 3", count)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the changed file was not reloaded")
	}
	got := logs()
	if len(got) != 2 || !strings.Contains(got[0], "don't load, so the wallet keeps the previous configuration") || !strings.Contains(got[1], "Configuration reloaded: 3 templates") {
		t.Fatalf("logs = %q, want one warning for the broken file and then the reload", got)
	}
}

// A configuration that loads but doesn't apply is tried again on the next
// tick without another change, and the failure is reported once.
func TestWatchServeConfigRetriesAFailedApply(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "templates.yaml")
	writeConfigFile(t, file, configTestTemplates)
	opts := &walletServeOptions{TemplatesFile: file}
	var mu sync.Mutex
	attempts := 0
	logs := startWatcher(t, opts, func(*serveConfig) error {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts < 3 {
			return errors.New("database unavailable")
		}
		return nil
	})

	writeConfigFile(t, file, configTestTemplates+"---\nname: third-card\nformat: sdjwt\nvct: urn:example:third:1\n")
	waitFor(t, "the reload", func() bool {
		got := logs()
		return len(got) > 0 && strings.Contains(got[len(got)-1], "Configuration reloaded")
	})
	got := logs()
	if len(got) != 2 || !strings.Contains(got[0], "database unavailable") {
		t.Fatalf("logs = %q, want one apply warning and then the reload", got)
	}
}

// The watcher reads an input directory anew on every tick, so it sees an added
// file.
func TestWatchServeConfigReadsAnAddedFile(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, filepath.Join(dir, "templates", "cards.yaml"), configTestTemplates)
	opts := &walletServeOptions{TemplatesFile: filepath.Join(dir, "templates")}
	logs := startWatcher(t, opts, func(*serveConfig) error { return nil })

	writeConfigFile(t, filepath.Join(dir, "templates", "more.yaml"), "name: third-card\nformat: sdjwt\nvct: urn:example:third:1\n")
	waitFor(t, "the reload", func() bool {
		got := logs()
		return len(got) == 1 && strings.Contains(got[0], "Configuration reloaded: 3 templates")
	})
}

// A reload that applies only some inputs keeps those in the applied
// configuration. Reverting the files then brings the wallet back to them.
func TestWatchServeConfigRevertsAPartlyAppliedReload(t *testing.T) {
	w := newServingTestWallet(t)
	w.Templates.Configured = &credtemplate.Configured{}
	w.TransactionTemplates.Configured = &txtemplate.Configured{}
	dir := t.TempDir()
	parties := filepath.Join(dir, "relying-parties.yaml")
	credentials := filepath.Join(dir, "credentials.yaml")
	const firstParties = "identifier: [{identifier: NLTEST.00000071}]\ntradeName: First shop\nlegalPerson: {legalName: [First shop B.V.]}\n"
	const goodCredentials = "credentials:\n  - id: alice-pid\n    template: pid-sdjwt\n"
	writeConfigFile(t, parties, firstParties)
	writeConfigFile(t, credentials, goodCredentials)
	opts := &walletServeOptions{RelyingPartiesFile: parties, CredentialsFile: credentials}
	first := loadTestServeConfig(t, opts)
	applied, _, err := applyServeConfig(w, first, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var current atomic.Pointer[serveConfig]
	current.Store(&applied)
	logs := runWatcher(t, opts, 10*time.Millisecond, current.Load, func(next *serveConfig) error {
		applied, _, err := applyServeConfig(w, next, current.Load(), false)
		current.Store(&applied)
		return err
	})

	writeConfigFile(t, parties, "identifier: [{identifier: NLTEST.00000072}]\ntradeName: Second shop\nlegalPerson: {legalName: [Second shop B.V.]}\n")
	writeConfigFile(t, credentials, "credentials:\n  - id: bob\n    template: no-such-template\n")
	waitFor(t, "the failed apply", func() bool { return len(logs()) > 0 })
	if !reflect.DeepEqual(current.Load().relyingParties, loadTestServeConfig(t, opts).relyingParties) {
		t.Fatal("the second relying parties file did not apply")
	}

	writeConfigFile(t, parties, firstParties)
	writeConfigFile(t, credentials, goodCredentials)
	waitFor(t, "the reverted files", func() bool {
		got := logs()
		return strings.Contains(got[len(got)-1], "Configuration reloaded")
	})
	if !reflect.DeepEqual(current.Load().relyingParties, first.relyingParties) {
		t.Fatal("the wallet kept the relying parties of the failed reload")
	}
}

// A credential and the new template it names, saved one after the other within
// one interval, apply together. The watcher may read the files between the two
// saves, and that read must not apply.
func TestWatchServeConfigAppliesFilesSavedTogether(t *testing.T) {
	w := newServingTestWallet(t)
	w.Templates.Configured = &credtemplate.Configured{}
	w.TransactionTemplates.Configured = &txtemplate.Configured{}
	dir := t.TempDir()
	templates := filepath.Join(dir, "templates.yaml")
	credentials := filepath.Join(dir, "credentials.yaml")
	writeConfigFile(t, templates, configTestTemplates)
	writeConfigFile(t, credentials, "credentials:\n  - id: alice-pid\n    template: pid-sdjwt\n")
	opts := &walletServeOptions{TemplatesFile: templates, CredentialsFile: credentials}
	applied, _, err := applyServeConfig(w, loadTestServeConfig(t, opts), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var current atomic.Pointer[serveConfig]
	current.Store(&applied)
	const interval = 100 * time.Millisecond
	logs := runWatcher(t, opts, interval, current.Load, func(next *serveConfig) error {
		applied, _, err := applyServeConfig(w, next, current.Load(), false)
		current.Store(&applied)
		return err
	})

	for range 2 {
		before := len(logs())
		writeConfigFile(t, credentials, "credentials:\n  - id: third\n    template: third-card\n")
		time.Sleep(3 * interval / 4)
		writeConfigFile(t, templates, configTestTemplates+"---\nname: third-card\nformat: sdjwt\nvct: urn:example:third:1\n")
		waitFor(t, "the reload", func() bool {
			got := logs()
			return len(got) > before && strings.Contains(got[len(got)-1], "Configuration reloaded: 3 templates")
		})
		if got := logs()[before:]; len(got) != 1 {
			t.Fatalf("logs = %q, want only the reload", got)
		}
		writeConfigFile(t, credentials, "credentials:\n  - id: alice-pid\n    template: pid-sdjwt\n")
		writeConfigFile(t, templates, configTestTemplates)
		waitFor(t, "the revert", func() bool { return reflect.DeepEqual(current.Load(), loadTestServeConfig(t, opts)) })
		// This revert applied just after a tick. Waiting half an interval makes
		// the test save the credentials file before a tick and the template
		// file after it.
		time.Sleep(interval / 2)
	}
}
