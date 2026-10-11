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
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// registration-cert needs no intended use ID when the relying party has only
// one intended use.
func TestWalletRegistrarRegistersAndCertifies(t *testing.T) {
	resetRemoteTestState(t)
	t.Cleanup(func() { resetFlags(rootCmd); rootCmd.SetOut(nil) })
	dcql := filepath.Join(t.TempDir(), "query.json")
	if err := os.WriteFile(dcql, []byte(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["given_name"]}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := walletDir
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"wallet", "registrar", "verifiers", "add", "--name", "Example Shop", "--purpose", "Age check", "--dcql", dcql})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("wallet registrar verifiers add: %v", err)
		}
	})
	identifier := regexp.MustCompile(`as ([A-Z]{2}TEST\.[0-9A-F]+)`).FindStringSubmatch(out)
	if identifier == nil || !strings.Contains(out, "Intended use: ") {
		t.Fatalf("output %q, want the assigned identifier and intended use", out)
	}
	resetFlags(rootCmd)
	walletDir = dir

	registrationCert := func(args ...string) string {
		t.Helper()
		resetFlags(rootCmd)
		walletDir = dir
		buf := new(bytes.Buffer)
		rootCmd.SetOut(buf)
		rootCmd.SetArgs(append([]string{"wallet", "registrar", "registration-cert", "--identifier", identifier[1]}, args...))
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("wallet registrar registration-cert %v: %v", args, err)
		}
		return strings.TrimSpace(buf.String())
	}
	var verifierInfo []map[string]any
	if out := registrationCert(); json.Unmarshal([]byte(out), &verifierInfo) != nil || verifierInfo[0]["format"] != "registration_cert" {
		t.Fatalf("output %q, want the verifier_info value alone", out)
	}
	first := registrationCert()
	if out := registrationCert("--jwt"); strings.Count(out, ".") != 2 || strings.ContainsAny(out, "\n[") || !strings.Contains(first, out) {
		t.Fatalf("output %q, want the bare current certificate", out)
	}
	if out := registrationCert("--new"); out == first {
		t.Fatalf("--new printed the current certificate %q, want a new one", out)
	}
}

func TestRegistrarRegistersAnIssuer(t *testing.T) {
	resetRemoteTestState(t)
	t.Cleanup(func() { resetFlags(rootCmd); rootCmd.SetOut(nil) })
	dir := walletDir
	run := func(args ...string) string {
		t.Helper()
		resetFlags(rootCmd)
		walletDir = dir
		buf := new(bytes.Buffer)
		rootCmd.SetOut(buf)
		var err error
		out := captureStdout(t, func() {
			rootCmd.SetArgs(append([]string{"wallet", "registrar"}, args...))
			err = rootCmd.Execute()
		})
		if err != nil {
			t.Fatalf("wallet registrar %v: %v", args, err)
		}
		return strings.TrimSpace(out + buf.String())
	}
	out := run("issuers", "add", "--name", "Example University", "--service-id", "diplomas", "--attestation", "dc+sd-jwt:urn:example:diploma:1")
	identifier := regexp.MustCompile(`as ([A-Z]{2}TEST\.[0-9A-F]+)`).FindStringSubmatch(out)
	if identifier == nil || !strings.Contains(out, "Attestation: dc+sd-jwt urn:example:diploma:1") {
		t.Fatalf("output %q, want the identifier and the attestation", out)
	}

	// The issuer's only certificate target is its service, so no flag is needed.
	var issuerInfo []map[string]any
	if out := run("registration-cert", "--identifier", identifier[1]); json.Unmarshal([]byte(out), &issuerInfo) != nil ||
		len(issuerInfo) != 2 || issuerInfo[0]["format"] != "registrar_dataset" || issuerInfo[1]["format"] != "registration_cert" {
		t.Fatalf("output %q, want the issuer_info value", out)
	}
	if out := run("registration-cert", "--identifier", identifier[1], "--service-id", "diplomas", "--provider", "--jwt"); strings.Count(out, ".") != 2 {
		t.Fatalf("output %q, want the bare certificate", out)
	}
	if out := run("revoke", "--identifier", identifier[1], "--service-id", "diplomas"); !strings.Contains(out, "Revoked 1 registration certificate") {
		t.Fatalf("output %q, want the newest certificate revoked", out)
	}
	if out := run("issuers"); !strings.Contains(out, identifier[1]) || !strings.Contains(out, "dc+sd-jwt:urn:example:diploma:1") {
		t.Fatalf("issuers %q, want the registered issuer", out)
	}
	if out := run("verifiers"); strings.Contains(out, identifier[1]) {
		t.Fatalf("verifiers %q lists the issuer", out)
	}
	resetFlags(rootCmd)
	walletDir = dir
	rootCmd.SetArgs([]string{"wallet", "registrar", "verifiers", "rm", identifier[1]})
	if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "is not a registered verifier") {
		t.Fatalf("verifiers rm of an issuer: %v", err)
	}
	if out := run("issuers", "rm", identifier[1]); !strings.Contains(out, "Removed "+identifier[1]) {
		t.Fatalf("rm %q", out)
	}
}

func TestTheIssuerCommandChecksItsFlags(t *testing.T) {
	resetRemoteTestState(t)
	t.Cleanup(func() { resetFlags(rootCmd) })
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--name", "X"}, `required flag(s) "attestation" not set`},
		{[]string{"--name", "X", "--attestation", "diploma"}, "is not format:type"},
		{[]string{"--name", "X", "--attestation", "ldp_vc:urn:example:x"}, "not dc+sd-jwt or mso_mdoc"},
		{[]string{"--name", "X", "--attestation", "dc+sd-jwt:urn:example:x", "--category", "provider"}, "--category takes pid, qeaa, pub-eaa, eaa"},
	} {
		resetFlags(rootCmd)
		rootCmd.SetArgs(append([]string{"wallet", "registrar", "issuers", "add"}, tc.args...))
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: got %v, want %q", tc.args, err, tc.want)
		}
	}
}

// One registration holds both roles (CIR (EU) 2025/848 Annex I). --to adds the
// other role and issues its certificate, and registration-cert prints it again.
func TestRegistrarAddsTheOtherRoleToARegistration(t *testing.T) {
	resetRemoteTestState(t)
	t.Cleanup(func() { resetFlags(rootCmd); rootCmd.SetOut(nil) })
	dir := walletDir
	dcql := filepath.Join(t.TempDir(), "query.json")
	if err := os.WriteFile(dcql, []byte(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["given_name"]}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		t.Helper()
		resetFlags(rootCmd)
		walletDir = dir
		buf := new(bytes.Buffer)
		rootCmd.SetOut(buf)
		var err error
		out := captureStdout(t, func() {
			rootCmd.SetArgs(append([]string{"wallet", "registrar"}, args...))
			err = rootCmd.Execute()
		})
		if err != nil {
			t.Fatalf("wallet registrar %v: %v", args, err)
		}
		return strings.TrimSpace(out + buf.String())
	}
	out := run("verifiers", "add", "--name", "Ticket Shop", "--purpose", "Ticket check", "--dcql", dcql)
	identifier := regexp.MustCompile(`as ([A-Z]{2}TEST\.[0-9A-F]+)`).FindStringSubmatch(out)[1]

	var issuerInfo []map[string]any
	issued := run("issuers", "add", "--to", identifier, "--attestation", "dc+sd-jwt:urn:example:ticket:1")
	if json.Unmarshal([]byte(issued), &issuerInfo) != nil || len(issuerInfo) != 2 || issuerInfo[1]["format"] != "registration_cert" {
		t.Fatalf("issuers add --to printed %q, want the issuer_info value", issued)
	}
	if current := run("registration-cert", "--identifier", identifier, "--provider"); current != issued {
		t.Errorf("registration-cert printed %q, want the issued %q", current, issued)
	}

	// An issuer lists further types next to its others, with a new certificate.
	extended := run("issuers", "add", "--to", identifier, "--attestation", "dc+sd-jwt:urn:example:ticket:2")
	if extended == issued || !strings.Contains(extended, "urn:example:ticket:1") || !strings.Contains(extended, "urn:example:ticket:2") {
		t.Fatalf("issuers add --to on an issuer printed %q, want a new issuer_info with both types", extended)
	}

	var verifierInfo []map[string]any
	added := run("verifiers", "add", "--to", identifier, "--purpose", "Identity check", "--dcql", dcql)
	if json.Unmarshal([]byte(added), &verifierInfo) != nil || verifierInfo[0]["format"] != "registration_cert" {
		t.Fatalf("verifiers add --to printed %q, want the verifier_info value", added)
	}
	if out := run("issuers"); !strings.Contains(out, identifier) {
		t.Errorf("issuers %q, want the party", out)
	}
	if out := run("verifiers"); !strings.Contains(out, identifier) {
		t.Errorf("verifiers %q, want the party", out)
	}
}

// Each list subcommand describes the listing, not its parent's subcommands.
func TestListSubcommandsDescribeTheListing(t *testing.T) {
	for _, path := range [][]string{
		{"wallet", "catalog", "list"},
		{"wallet", "trust", "list"},
		{"wallet", "registrar", "verifiers", "list"},
		{"wallet", "registrar", "issuers", "list"},
	} {
		list, _, err := rootCmd.Find(path)
		if err != nil {
			t.Fatalf("%v: %v", path, err)
		}
		if !strings.HasPrefix(list.Short, "List the ") || list.Short == list.Parent().Short {
			t.Errorf("%v: Short %q, want a description of the listing", path, list.Short)
		}
	}
}
