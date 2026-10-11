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

// Package testenv isolates tests from the developer's eudi-dev home.
package testenv

import (
	"fmt"
	"os"
	"testing"
)

// Main runs the tests of a package with a temporary home directory. The
// default wallet, its templates and the active remote wallet live under the
// home directory, so tests that reach them must not see the real one.
// Explicit home overrides are cleared because they would restore it.
func Main(m *testing.M) {
	dir, err := os.MkdirTemp("", "eudi-dev-tests-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating temporary home directory: %v\n", err)
		os.Exit(1)
	}
	for name, value := range map[string]string{"HOME": dir, "USERPROFILE": dir, "EUDI_DEV_HOME": "", "OID4VC_DEV_HOME": ""} {
		set := func() error { return os.Setenv(name, value) }
		if value == "" {
			set = func() error { return os.Unsetenv(name) }
		}
		if err := set(); err != nil {
			fmt.Fprintf(os.Stderr, "setting %s: %v\n", name, err)
			os.Exit(1)
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
