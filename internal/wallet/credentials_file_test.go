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

package wallet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
)

func writeCredentialsFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing credentials file: %v", err)
	}
	return path
}

func TestCredentialsFileKeepsClaimValuesAsWritten(t *testing.T) {
	path := writeCredentialsFile(t, `
credentials:
  - id: erika
    template: german-pid-sdjwt
    claims:
      birthdate: 1970-01-31
      age_equal_or_over: {18: true, 65: false}
      sex: 2
    display:
      background_color: "#0f766e"
`)

	file, err := LoadCredentialsFile(path)
	if err != nil {
		t.Fatalf("LoadCredentialsFile: %v", err)
	}
	entry := file.Credentials[0]
	if got := entry.Claims["birthdate"]; got != "1970-01-31" {
		t.Errorf("birthdate %#v, want the string 1970-01-31", got)
	}
	ages, _ := entry.Claims["age_equal_or_over"].(map[string]any)
	if ages["18"] != true || ages["65"] != false {
		t.Errorf("age_equal_or_over %#v, want string keys 18 and 65", entry.Claims["age_equal_or_over"])
	}
	if got := entry.Claims["sex"]; got != float64(2) {
		t.Errorf("sex %#v, want the number 2", got)
	}
	if entry.Display == nil || entry.Display.BackgroundColor != "#0f766e" {
		t.Errorf("display %#v, want background_color #0f766e", entry.Display)
	}
}

func TestCredentialsFileRejectsInvalidEntries(t *testing.T) {
	for _, tc := range []struct {
		name, content, want string
	}{
		{"unknown field", "credentials:\n  - id: a\n    template: pid-sdjwt\n    clams: {}\n", "unknown field"},
		{"duplicate id", "credentials:\n  - id: a\n    template: pid-sdjwt\n  - id: a\n    template: pid-mdoc\n", "appears twice"},
		{"id with a slash", "credentials:\n  - id: a/b\n    template: pid-sdjwt\n", "must start with"},
		{"neither template nor credential", "credentials:\n  - id: a\n", "needs either a template or a credential"},
		{"template and credential", "credentials:\n  - id: a\n    template: pid-sdjwt\n    credential: eyJ\n", "needs either a template or a credential"},
		{"credential with overrides", "credentials:\n  - id: a\n    credential: eyJ\n    claims: {given_name: X}\n", "only a template entry takes overrides"},
		{"bad exp", "credentials:\n  - id: a\n    template: pid-sdjwt\n    exp: soon\n", "invalid exp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadCredentialsFile(writeCredentialsFile(t, tc.content))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestAddFileCredentialsIssuesFromTemplatesUnderTheirIDs(t *testing.T) {
	w := generateTestWallet(t)
	if _, err := credtemplate.Save(w.Templates, credtemplate.Template{
		Name:   "employee-card",
		Format: "sdjwt",
		VCT:    "urn:example:employee",
		Claims: map[string]any{"employee_id": "E-1", "department": "IT"},
	}); err != nil {
		t.Fatalf("saving template: %v", err)
	}
	file, err := LoadCredentialsFile(writeCredentialsFile(t, `
credentials:
  - id: employee-alice
    template: employee-card
    claims:
      employee_id: E-2
    always_disclosed: [department]
  - id: pid-mdoc
    template: pid-mdoc
`))
	if err != nil {
		t.Fatalf("LoadCredentialsFile: %v", err)
	}

	if err := w.AddFileCredentials(file, false); err != nil {
		t.Fatalf("AddFileCredentials: %v", err)
	}

	alice, ok := w.GetCredential("employee-alice")
	if !ok {
		t.Fatal("no credential with ID employee-alice")
	}
	if alice.VCT != "urn:example:employee" || alice.Claims["employee_id"] != "E-2" || alice.Claims["department"] != "IT" {
		t.Errorf("employee-alice has vct %q and claims %v, want the template merged with the override", alice.VCT, alice.Claims)
	}
	if mdocPID, ok := w.GetCredential("pid-mdoc"); !ok || mdocPID.Format != "mso_mdoc" {
		t.Errorf("pid-mdoc %+v, want an mdoc PID", mdocPID)
	}
}

func TestAddFileCredentialsReplacesTheCopyOfAnEarlierStart(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example"
	file, err := LoadCredentialsFile(writeCredentialsFile(t, "credentials:\n  - id: jan\n    template: pid-sdjwt\n"))
	if err != nil {
		t.Fatalf("LoadCredentialsFile: %v", err)
	}

	for start := 1; start <= 2; start++ {
		if err := w.AddFileCredentials(file, false); err != nil {
			t.Fatalf("start %d: AddFileCredentials: %v", start, err)
		}
	}

	count := 0
	for _, c := range w.GetCredentials() {
		if c.ID == "jan" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%d credentials with ID jan after two starts, want 1", count)
	}
	if _, ok := w.StatusEntryFor("jan"); !ok {
		t.Error("the status entry is not registered under the ID jan")
	}
}

func TestAddFileCredentialsImportsFinishedCredentialsUnderTheirIDs(t *testing.T) {
	issuer := generateTestWallet(t)
	issued, err := issuer.IssueCredential(IssueOptions{Template: "pid-sdjwt"})
	if err != nil {
		t.Fatalf("issuing the finished credential: %v", err)
	}
	w := generateTestWallet(t)
	file, err := ParseCredentialsFile([]byte("credentials:\n  - id: foreign-pid\n    credential: " + issued.Raw + "\n  - id: own-pid\n    template: pid-mdoc\n"))
	if err != nil {
		t.Fatalf("ParseCredentialsFile: %v", err)
	}

	for start := 1; start <= 2; start++ {
		if err := w.AddFileCredentials(file, false); err != nil {
			t.Fatalf("start %d: AddFileCredentials: %v", start, err)
		}
	}

	foreign, ok := w.GetCredential("foreign-pid")
	if !ok || foreign.Raw != issued.Raw {
		t.Fatalf("foreign-pid %+v, want the finished credential", foreign)
	}
	if _, ok := w.GetCredential("own-pid"); !ok {
		t.Fatal("no credential with ID own-pid")
	}
	if got := len(w.GetCredentials()); got != 2 {
		t.Fatalf("%d credentials after two starts, want 2", got)
	}
}

func TestLoadCredentialsFileReadsEveryFileOfADirectory(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"a-pids.yaml":  "credentials:\n  - id: jan\n    template: pid-sdjwt\n",
		"b-extra.json": `{"credentials": [{"id": "erika", "template": "german-pid-sdjwt"}]}`,
		"c-notes.txt":  "not a credentials file",
		"d-mdocs.yml":  "credentials:\n  - id: jan-mdoc\n    template: pid-mdoc\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	file, err := LoadCredentialsFile(dir)
	if err != nil {
		t.Fatalf("LoadCredentialsFile: %v", err)
	}

	var ids []string
	for _, c := range file.Credentials {
		ids = append(ids, c.ID)
	}
	if got := strings.Join(ids, ","); got != "jan,erika,jan-mdoc" {
		t.Fatalf("IDs %s, want jan,erika,jan-mdoc in file name order", got)
	}
}

func TestLoadCredentialsFileRejectsAnIDInTwoFilesOfADirectory(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.yaml", "b.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("credentials:\n  - id: jan\n    template: pid-sdjwt\n"), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	_, err := LoadCredentialsFile(dir)
	if err == nil || !strings.Contains(err.Error(), "appears in") {
		t.Fatalf("error %v, want one naming both files", err)
	}
}

func TestLoadCredentialsFileReadsStdin(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	stdin := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() { os.Stdin = stdin })
	if _, err := writer.WriteString("credentials:\n  - id: jan\n    template: pid-sdjwt\n"); err != nil {
		t.Fatalf("writing stdin: %v", err)
	}
	writer.Close()

	file, err := LoadCredentialsFile("-")
	if err != nil {
		t.Fatalf("LoadCredentialsFile: %v", err)
	}
	if len(file.Credentials) != 1 || file.Credentials[0].ID != "jan" {
		t.Fatalf("credentials %+v, want the entry jan", file.Credentials)
	}
}

func TestFileCredentialsReplaceTheirProtectedCopies(t *testing.T) {
	w := generateTestWallet(t)
	file, err := ParseCredentialsFile([]byte("credentials:\n  - id: kept\n    template: pid-sdjwt\n  - id: open\n    template: pid-sdjwt\n    protected: false\n"))
	if err != nil {
		t.Fatalf("ParseCredentialsFile: %v", err)
	}
	for start := 1; start <= 2; start++ {
		if err := w.AddFileCredentials(file, true); err != nil {
			t.Fatalf("start %d: AddFileCredentials: %v", start, err)
		}
	}
	if got := len(w.GetCredentials()); got != 2 {
		t.Fatalf("%d credentials after two starts, want 2", got)
	}
	if c, _ := w.GetCredential("kept"); !c.Protected {
		t.Error("kept is not protected, want the default")
	}
	if c, _ := w.GetCredential("open"); c.Protected {
		t.Error("open is protected, want its own setting")
	}
}

// A start that can't issue an entry keeps the copy from an earlier start.
func TestAFailedEntryKeepsTheCopyOfAnEarlierStart(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example"
	good, err := LoadCredentialsFile(writeCredentialsFile(t, "credentials:\n  - id: jan\n    template: pid-sdjwt\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddFileCredentials(good, false); err != nil {
		t.Fatal(err)
	}
	broken, err := LoadCredentialsFile(writeCredentialsFile(t, "credentials:\n  - id: jan\n    template: no-such-template\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddFileCredentials(broken, false); err == nil {
		t.Fatal("an unknown template was accepted")
	}
	if _, ok := w.GetCredential("jan"); !ok {
		t.Error("the earlier copy is gone")
	}
}
