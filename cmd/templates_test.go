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
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// resetTemplateTestState resets the package-level flag variables and the
// cobra Changed markers that other tests in this package may have left
// behind, then points the wallet directory at a fresh temp dir.
func resetTemplateTestState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	walletDir = dir
	t.Cleanup(func() { walletDir = "" })
	issueClaims = ""
	issueTemplate = ""
	issueAlwaysDisclosed = nil
	issueSaveTemplate = ""
	issuePID = false
	issueOmit = nil
	issueKeyPath = ""
	issueToWallet = false
	templatesDir = ""
	issueVCT = mock.DefaultPIDVCT
	issueDocType = "eu.europa.ec.eudi.pid.1"
	issueNamespace = "eu.europa.ec.eudi.pid.1"
	issueExpires = "720h"
	for _, c := range []*cobra.Command{issueSDJWTCmd, issueJWTCmd, issueMDOCCmd, templatesSaveCmd, templatesImportCmd} {
		c.Flags().VisitAll(func(f *pflag.Flag) { f.Changed = false })
	}
	return dir
}

func TestTemplatesSaveListDelete_EndToEnd(t *testing.T) {
	dir := resetTemplateTestState(t)

	rootCmd.SetArgs([]string{"templates", "save", "employee-card",
		"--format", "sdjwt", "--vct", "urn:example:employee",
		"--claims", `{"employee_id": "E-1", "department": "IT"}`,
		"--always-disclosed", "department",
		"--wallet-dir", dir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("templates save: %v", err)
	}

	tpl, err := credtemplate.Load("employee-card", wallet.NewWalletStore(dir).Templates())
	if err != nil {
		t.Fatalf("loading saved template: %v", err)
	}
	if tpl.VCT != "urn:example:employee" || len(tpl.AlwaysDisclosed) != 1 {
		t.Errorf("unexpected template: %+v", tpl)
	}

	rootCmd.SetArgs([]string{"templates", "delete", "employee-card", "--wallet-dir", dir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("templates delete: %v", err)
	}
	if _, err := credtemplate.Load("employee-card", wallet.NewWalletStore(dir).Templates()); err == nil {
		t.Error("template still loadable after delete")
	}
}

func TestTemplatesSaveFromPredefined(t *testing.T) {
	dir := resetTemplateTestState(t)

	rootCmd.SetArgs([]string{"templates", "save", "my-pid",
		"--from", "german-pid-sdjwt", "--vct", "urn:custom:pid",
		"--wallet-dir", dir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("templates save --from: %v", err)
	}

	tpl, err := credtemplate.Load("my-pid", wallet.NewWalletStore(dir).Templates())
	if err != nil {
		t.Fatalf("loading saved template: %v", err)
	}
	if tpl.VCT != "urn:custom:pid" {
		t.Errorf("expected overridden vct, got %q", tpl.VCT)
	}
	if len(tpl.Claims) == 0 || tpl.Claims["family_name"] != "MUSTERMANN" {
		t.Errorf("expected claims copied from predefined template, got %d claims", len(tpl.Claims))
	}
	if tpl.Predefined {
		t.Error("copied template must not be marked predefined")
	}
}

func TestTemplatesImport(t *testing.T) {
	dir := resetTemplateTestState(t)

	src := filepath.Join(t.TempDir(), "shared-cred.json")
	content := `{"format": "sdjwt", "vct": "urn:shared", "claims": {"a": 1}, "always_disclosed": ["a"]}`
	if err := os.WriteFile(src, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"templates", "import", src, "--wallet-dir", dir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("templates import: %v", err)
	}

	tpl, err := credtemplate.Load("shared-cred", wallet.NewWalletStore(dir).Templates())
	if err != nil {
		t.Fatalf("loading imported template: %v", err)
	}
	if tpl.VCT != "urn:shared" || len(tpl.AlwaysDisclosed) != 1 {
		t.Errorf("unexpected imported template: %+v", tpl)
	}
}

func TestIssueSDJWT_WithTemplateAndSaveTemplate(t *testing.T) {
	dir := resetTemplateTestState(t)

	if _, err := credtemplate.Save(wallet.NewWalletStore(dir).Templates(), credtemplate.Template{
		Name:            "member-card",
		Format:          "sdjwt",
		VCT:             "urn:example:member",
		Claims:          map[string]any{"member_id": "M-1", "level": "gold"},
		AlwaysDisclosed: []string{"level"},
	}); err != nil {
		t.Fatalf("seeding template: %v", err)
	}

	rootCmd.SetArgs([]string{"issue", "sdjwt",
		"--template", "member-card",
		"--claims", `{"member_id": "M-42"}`,
		"--save-template", "member-card-covered",
		"--wallet-dir", dir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt --template: %v", err)
	}

	saved, err := credtemplate.Load("member-card-covered", wallet.NewWalletStore(dir).Templates())
	if err != nil {
		t.Fatalf("loading saved template: %v", err)
	}
	if saved.Claims["member_id"] != "M-42" {
		t.Errorf("expected merged claim in saved template, got %v", saved.Claims["member_id"])
	}
	if len(saved.AlwaysDisclosed) != 1 || saved.AlwaysDisclosed[0] != "level" {
		t.Errorf("expected always_disclosed carried over, got %v", saved.AlwaysDisclosed)
	}
	if saved.VCT != "urn:example:member" {
		t.Errorf("expected template vct applied, got %q", saved.VCT)
	}
}

func TestIssueMDOC_TemplateWithAlwaysDisclosedFails(t *testing.T) {
	dir := resetTemplateTestState(t)

	if _, err := credtemplate.Save(wallet.NewWalletStore(dir).Templates(), credtemplate.Template{
		Name:            "bad-mdoc",
		Format:          "mdoc",
		Claims:          map[string]any{"family_name": "X"},
		AlwaysDisclosed: []string{"family_name"},
	}); err != nil {
		t.Fatalf("seeding template: %v", err)
	}

	rootCmd.SetArgs([]string{"issue", "mdoc", "--template", "bad-mdoc", "--wallet-dir", dir})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected error for always-disclosed with mdoc")
	}
}

func TestTemplatesDirFlagOverridesWalletDir(t *testing.T) {
	resetTemplateTestState(t)
	customDir := t.TempDir()

	rootCmd.SetArgs([]string{"templates", "save", "custom-cred",
		"--format", "sdjwt", "--vct", "urn:example:custom",
		"--claims", `{"a": "1"}`,
		"--templates-dir", customDir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("templates save --templates-dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(customDir, "custom-cred.json")); err != nil {
		t.Fatalf("template not written to custom dir: %v", err)
	}

	rootCmd.SetArgs([]string{"issue", "sdjwt", "--template", "custom-cred", "--templates-dir", customDir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt --templates-dir: %v", err)
	}

	templatesDir = ""
	rootCmd.SetArgs([]string{"issue", "sdjwt", "--template", "custom-cred"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected custom template to be invisible without --templates-dir")
	}
}

const yamlTemplate = `format: sdjwt
vct: urn:example:member
claims:
  member_id: M-1
  postal_code: "01234"
always_disclosed: [member_id]
`

func writeYAMLTemplate(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(yamlTemplate), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestIssueFromYAMLTemplateFile(t *testing.T) {
	dir := resetTemplateTestState(t)
	src := filepath.Join(t.TempDir(), "member.yaml")
	writeYAMLTemplate(t, src)

	rootCmd.SetArgs([]string{"issue", "sdjwt", "--template", src, "--save-template", "member-copy", "--wallet-dir", dir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt --template file.yaml: %v", err)
	}
	saved, err := credtemplate.Load("member-copy", wallet.NewWalletStore(dir).Templates())
	if err != nil {
		t.Fatal(err)
	}
	if saved.VCT != "urn:example:member" || saved.Claims["postal_code"] != "01234" {
		t.Errorf("unexpected template: %+v", saved)
	}
}

func TestTemplatesSaveFromAndImportYAMLFile(t *testing.T) {
	dir := resetTemplateTestState(t)
	src := filepath.Join(t.TempDir(), "member.yml")
	writeYAMLTemplate(t, src)

	t.Cleanup(func() { templateFrom = "" })
	rootCmd.SetArgs([]string{"templates", "save", "copied", "--from", src, "--wallet-dir", dir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("templates save --from file.yml: %v", err)
	}
	rootCmd.SetArgs([]string{"templates", "import", src, "--wallet-dir", dir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("templates import file.yml: %v", err)
	}
	for _, name := range []string{"copied", "member"} {
		tpl, err := credtemplate.Load(name, wallet.NewWalletStore(dir).Templates())
		if err != nil {
			t.Fatal(err)
		}
		if tpl.VCT != "urn:example:member" || tpl.Claims["postal_code"] != "01234" || len(tpl.AlwaysDisclosed) != 1 {
			t.Errorf("template %s: %+v", name, tpl)
		}
	}
}

func TestTemplatesDeleteRemovesYAMLFile(t *testing.T) {
	resetTemplateTestState(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "member.yaml")
	writeYAMLTemplate(t, path)

	rootCmd.SetArgs([]string{"templates", "delete", "member", "--templates-dir", dir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("templates delete: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("member.yaml still exists: %v", err)
	}
}
