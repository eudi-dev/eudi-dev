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

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBaseDirResolution(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("EUDI_DEV_HOME", "")

	if got, want := BaseDir(), filepath.Join(home, ".eudi-dev"); got != want {
		t.Errorf("default: expected %s, got %s", want, got)
	}
	t.Setenv("EUDI_DEV_HOME", "/tmp/new-home")
	if got := BaseDir(); got != "/tmp/new-home" {
		t.Errorf("new env: expected /tmp/new-home, got %s", got)
	}
}

// A user of eudi-dev 2 learns how to keep their state, because BaseDir
// reads neither OID4VC_DEV_HOME nor ~/.oid4vc-dev.
func TestLegacyHomeWarnings(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("EUDI_DEV_HOME", "")
	t.Setenv("OID4VC_DEV_HOME", "")

	if got := LegacyHomeWarnings(); len(got) != 0 {
		t.Fatalf("fresh home: expected no warnings, got %q", got)
	}

	if err := os.Mkdir(filepath.Join(home, ".oid4vc-dev"), 0o700); err != nil {
		t.Fatal(err)
	}
	got := LegacyHomeWarnings()
	if len(got) != 1 || !strings.Contains(got[0], "mv ~/.oid4vc-dev ~/.eudi-dev") {
		t.Fatalf("legacy directory: expected the mv hint, got %q", got)
	}

	t.Setenv("OID4VC_DEV_HOME", "/tmp/old-home")
	got = LegacyHomeWarnings()
	if len(got) != 2 || !strings.Contains(got[0], "EUDI_DEV_HOME=/tmp/old-home") {
		t.Fatalf("legacy variable: expected the EUDI_DEV_HOME hint, got %q", got)
	}

	if err := os.Mkdir(filepath.Join(home, ".eudi-dev"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OID4VC_DEV_HOME", "")
	if got := LegacyHomeWarnings(); len(got) != 0 {
		t.Fatalf("migrated home: expected no warnings, got %q", got)
	}

	t.Setenv("OID4VC_DEV_HOME", "/tmp/old-home")
	t.Setenv("EUDI_DEV_HOME", "/tmp/new-home")
	if got := LegacyHomeWarnings(); len(got) != 0 {
		t.Fatalf("EUDI_DEV_HOME set: expected no warnings, got %q", got)
	}
}
