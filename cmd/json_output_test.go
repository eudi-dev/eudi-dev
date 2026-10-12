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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// resetFlags puts every flag back to its default, because cobra keeps flag
// values between Execute calls in one process.
func resetFlags(c *cobra.Command) {
	reset := func(f *pflag.Flag) {
		if slice, ok := f.Value.(pflag.SliceValue); ok {
			_ = slice.Replace(nil)
		} else {
			_ = f.Value.Set(f.DefValue)
		}
		f.Changed = false
	}
	c.Flags().VisitAll(reset)
	c.PersistentFlags().VisitAll(reset)
	for _, sub := range c.Commands() {
		resetFlags(sub)
	}
}

// runJSON runs the command with --json and requires its stdout to be exactly
// one JSON document (ADR 0020).
func runJSON(t *testing.T, args ...string) map[string]any {
	t.Helper()
	var doc any
	runJSONInto(t, &doc, args...)
	obj, ok := doc.(map[string]any)
	if !ok {
		t.Fatalf("%v printed %T, want a JSON object", args, doc)
	}
	return obj
}

func runJSONInto(t *testing.T, doc any, args ...string) {
	t.Helper()
	walletDirBefore := walletDir
	t.Cleanup(func() {
		jsonOutput = false
		resetFlags(rootCmd)
		walletDir = walletDirBefore
	})
	// A test that runs a command without this helper leaves its flag values.
	resetFlags(rootCmd)
	var runErr error
	out := captureStdout(t, func() {
		// Other tests point cobra's output at a buffer.
		rootCmd.SetOut(nil)
		rootCmd.SetArgs(append(args, "--json"))
		runErr = rootCmd.Execute()
	})
	jsonOutput = false
	resetFlags(rootCmd)
	walletDir = walletDirBefore
	if runErr != nil {
		t.Fatalf("%v: %v", args, runErr)
	}
	if err := json.Unmarshal([]byte(out), doc); err != nil {
		t.Fatalf("%v did not print one JSON document: %v\n%s", args, err, out)
	}
}

func TestJSONOutputIsOneDocument(t *testing.T) {
	resetRemoteTestState(t)
	dir := walletDir

	if doc := runJSON(t, "version"); doc["version"] == "" {
		t.Errorf("version: %v", doc)
	}
	issued := runJSON(t, "issue", "sdjwt", "--pid")
	credential, _ := issued["credential"].(string)
	if credential == "" {
		t.Fatalf("issue sdjwt: %v", issued)
	}
	runJSON(t, "issue", "mdoc", "--pid")

	if creds := runJSON(t, "wallet", "list")["credentials"]; creds == nil || len(creds.([]any)) != 0 {
		t.Errorf("an empty wallet lists %v, want []", creds)
	}

	credFile := filepath.Join(t.TempDir(), "cred.txt")
	if err := os.WriteFile(credFile, []byte(credential), 0o600); err != nil {
		t.Fatal(err)
	}
	imported := runJSON(t, "wallet", "import", credFile)
	id, _ := imported["id"].(string)
	if id == "" {
		t.Fatalf("wallet import: %v", imported)
	}
	if doc := runJSON(t, "wallet", "show", id); doc["raw"] != credential {
		t.Errorf("wallet show printed %v, want the stored credential", doc)
	}
	if doc := runJSON(t, "wallet", "remove", id); doc["id"] != id {
		t.Errorf("wallet remove: %v", doc)
	}

	if doc := runJSON(t, "trust", "show"); !strings.Contains(doc["trust_list"].(string), ".") {
		t.Errorf("trust show: %v", doc)
	}
	if doc := runJSON(t, "trust", "show", "--url"); !strings.HasPrefix(doc["url"].(string), "http") {
		t.Errorf("trust show --url: %v", doc)
	}
	if doc := runJSON(t, "trust", "list"); doc["trust_lists"] == nil || doc["lists_url"] == nil {
		t.Errorf("trust list: %v", doc)
	}
	if doc := runJSON(t, "trust", "ca-cert"); !strings.Contains(doc["pem"].(string), "BEGIN CERTIFICATE") {
		t.Errorf("trust ca-cert: %v", doc)
	}
	if doc := runJSON(t, "trust", "ca-cert", "--jwks"); doc["keys"] == nil {
		t.Errorf("trust ca-cert --jwks: %v", doc)
	}
	var logs []any
	runJSONInto(t, &logs, "wallet", "logs")
	runJSON(t, "wallet", "logs", "clean")
	if doc := runJSON(t, "wallet", "use"); doc["target"] != "local" {
		t.Errorf("wallet use: %v", doc)
	}

	csrFile := filepath.Join(t.TempDir(), "verifier.csr")
	if err := os.WriteFile(csrFile, []byte(testCSR(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	registered := runJSON(t, "registrar", "issuers", "add", "--name", "Shop", "--attestation", "dc+sd-jwt:urn:example:diploma:1")
	identifier := registered["identifier"].([]any)[0].(map[string]any)["identifier"].(string)
	if doc := runJSON(t, "registrar", "access-cert", "--csr", csrFile, "--identifier", identifier); !strings.HasPrefix(doc["certificate"].(string), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("registrar access-cert: %v", doc)
	}
	var records []any
	runJSONInto(t, &records, "registrar", "issuers")
	if len(records) != 1 {
		t.Errorf("registrar issuers printed %d records, want the registration", len(records))
	}

	var templates []any
	runJSONInto(t, &templates, "templates", "list")
	if len(templates) == 0 {
		t.Error("templates list printed no templates")
	}
	if doc := runJSON(t, "templates", "save", "json-test", "--claims", `{"a":"b"}`); doc["name"] != "json-test" {
		t.Errorf("templates save: %v", doc)
	}
	if doc := runJSON(t, "templates", "delete", "json-test"); doc["deleted"] != "json-test" {
		t.Errorf("templates delete: %v", doc)
	}

	if walletDir != dir {
		t.Fatalf("the wallet directory changed to %q", walletDir)
	}
}

func TestJSONIsRefusedWithoutASingleResult(t *testing.T) {
	resetRemoteTestState(t)
	for _, args := range [][]string{
		{"completion", "bash"},
		{"decoder"},
		{"wallet", "serve"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Cleanup(func() {
				jsonOutput = false
				resetFlags(rootCmd)
			})
			rootCmd.SetArgs(append(args, "--json"))
			err := rootCmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "--json does not work with this command") {
				t.Fatalf("err = %v, want --json refused", err)
			}
		})
	}
}

func TestRemoteFlowErrorFailsRefusedFlows(t *testing.T) {
	for _, tc := range []struct {
		result  map[string]any
		wantErr bool
	}{
		{map[string]any{"status": "submitted", "response": map[string]any{"status_code": float64(200)}}, false},
		{map[string]any{"status": "completed"}, false},
		{map[string]any{"status": "deferred"}, false},
		{map[string]any{"status": "submitted", "response": map[string]any{"status_code": float64(400)}}, true},
		{map[string]any{"status": "denied"}, true},
		{map[string]any{"status": "no_match", "error": "access_denied"}, true},
		{map[string]any{"status": "failed", "error": "invalid_grant"}, true},
		{map[string]any{"status": "refused", "error": "access_denied", "error_description": "ARF RPRC_21"}, true},
	} {
		if err := remoteFlowError(tc.result); (err != nil) != tc.wantErr {
			t.Errorf("%v: err = %v, want an error %v", tc.result, err, tc.wantErr)
		}
	}
}

func TestTrustAndCatalogCommandsPrintJSON(t *testing.T) {
	resetRemoteTestState(t)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, testCAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	entity := runJSON(t, "trust", "add-ca", "--list", "eaa", "--name", "Diploma Provider", "--ca", ca)
	id, _ := entity["id"].(string)
	if id == "" || entity["list"] != "eaa" {
		t.Fatalf("trust add-ca: %v", entity)
	}
	if doc := runJSON(t, "trust", "rm-ca", id); doc["removed"] != id {
		t.Errorf("trust rm-ca: %v", doc)
	}

	// The wallet keeps a list it cannot read yet and names the reason.
	unreadable := httptest.NewServer(http.NotFoundHandler())
	defer unreadable.Close()
	listURL := unreadable.URL + "/lists/eaa"
	if link := runJSON(t, "trust", "add-list", listURL); link["url"] != listURL || link["error"] == nil {
		t.Errorf("trust add-list: %v", link)
	}
	if doc := runJSON(t, "trust", "rm-list", listURL); doc["removed"] != listURL {
		t.Errorf("trust rm-list: %v", doc)
	}

	var entries []map[string]any
	runJSONInto(t, &entries, "catalog", "list")
	var names []string
	for _, entry := range entries {
		name, _ := entry["name"].(string)
		names = append(names, name)
	}
	if !slices.Contains(names, "EUDI PID") {
		t.Errorf("catalog list printed %v, want the PID template entry", names)
	}
}
