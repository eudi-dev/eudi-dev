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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestTrustedListFlagTellsURLsFromFiles(t *testing.T) {
	next := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	path := filepath.Join(t.TempDir(), "operator.json")
	content := `{"ListAndSchemeInformation": {"NextUpdate": "` + next + `"}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	f := addConformanceFlags(&cobra.Command{})
	f.trustedLists = []string{"https://lists.example/one", path}
	got, err := f.resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !slices.Equal(got.trust.ConfiguredLists, []string{"https://lists.example/one"}) {
		t.Errorf("URLs = %v", got.trust.ConfiguredLists)
	}
	if len(got.trust.FileLists) != 1 || got.trust.FileLists[0].ID != "operator" {
		t.Errorf("files = %+v", got.trust.FileLists)
	}
	f.trustedLists = []string{path, path}
	if _, err := f.resolve(); err == nil || !strings.Contains(err.Error(), "two files") {
		t.Errorf("the same ID twice = %v", err)
	}
	f.trustedLists = []string{"/no/such/file"}
	if _, err := f.resolve(); err == nil || !strings.Contains(err.Error(), "not an http or https URL") {
		t.Errorf("a missing file = %v", err)
	}
}
