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
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The web UI's command passes the signing key itself. The loaders read it from
// a private temporary file that is gone after the run.
func TestAnInlineSigningKeyIsReadLikeAFile(t *testing.T) {
	const pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEA\n-----END PRIVATE KEY-----"
	issueKeyPath, issueCertPath = pem, "chain.pem"
	t.Cleanup(func() { issueKeyPath, issueCertPath = "", "" })

	var file string
	err := withInlineSigningMaterial(func(*cobra.Command, []string) error {
		file = issueKeyPath
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		if !strings.Contains(string(data), "MIGHAgEA") {
			t.Errorf("file holds %q, want the key", data)
		}
		info, err := os.Stat(file)
		if err != nil {
			return err
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("file mode %v, want 0600", info.Mode().Perm())
		}
		if issueCertPath != "chain.pem" {
			t.Errorf("--cert %q, want the file path unchanged", issueCertPath)
		}
		return nil
	})(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("the temporary key file is still there: %v", err)
	}
	if issueKeyPath != pem {
		t.Errorf("--key is %q after the run, want the value as given", issueKeyPath)
	}
}

func TestACatalogueEntryNeedsATemplate(t *testing.T) {
	issueCatalog, issueSaveTemplate = `{"name":"Gym membership"}`, ""
	t.Cleanup(func() { issueCatalog, issueSaveTemplate = "", "" })
	if _, err := catalogEntryArg(); err == nil || !strings.Contains(err.Error(), "--save-template") {
		t.Fatalf("err %v, want --catalog refused without --save-template", err)
	}
	issueSaveTemplate = "gym"
	entry, err := catalogEntryArg()
	if err != nil || entry.Name != "Gym membership" {
		t.Fatalf("entry %+v, err %v, want the parsed entry", entry, err)
	}
}
