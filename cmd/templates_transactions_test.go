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
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/txtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// Importing the show output of a template creates a copy under another name.
// Deleting the copy keeps the predefined template.
func TestTransactionTemplatesShowImportDelete(t *testing.T) {
	dir := resetTemplateTestState(t)
	transactionTemplateImportName = ""
	transactionTemplatesImportCmd.Flags().VisitAll(func(f *pflag.Flag) { f.Changed = false })

	shown := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"templates", "transactions", "show", "payment", "--wallet-dir", dir})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("show: %v", err)
		}
	})
	file := filepath.Join(t.TempDir(), "payment.json")
	if err := os.WriteFile(file, []byte(shown), 0o600); err != nil {
		t.Fatal(err)
	}
	rootCmd.SetArgs([]string{"templates", "transactions", "import", file, "--name", "shop-payment", "--wallet-dir", dir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("import: %v", err)
	}
	transactionTemplateImportName = ""
	loc := wallet.NewWalletStore(dir).TransactionTemplates()
	copied, err := txtemplate.Load(loc, "shop-payment")
	if err != nil || copied.Predefined || copied.Type() != "urn:eudi:sca:payment:1" {
		t.Fatalf("imported %+v, %v, want a user copy of the payment", copied, err)
	}

	listed := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"templates", "transactions", "list", "--wallet-dir", dir})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("list: %v", err)
		}
	})
	if fields := strings.Fields(lineWith(listed, "shop-payment")); len(fields) < 3 || fields[1] != "urn:eudi:sca:payment:1" || fields[2] != "user" {
		t.Fatalf("list lacks the user copy:\n%s", listed)
	}

	rootCmd.SetArgs([]string{"templates", "transactions", "delete", "shop-payment", "--wallet-dir", dir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := txtemplate.Load(loc, "shop-payment"); err == nil {
		t.Fatal("the deleted template still loads")
	}
}

func TestTransactionTemplatesImportRefusesAnUnknownField(t *testing.T) {
	dir := resetTemplateTestState(t)
	transactionTemplateImportName = ""
	rootCmd.SetArgs([]string{"templates", "transactions", "import", `{"name": "x", "transaction_data": {"type": "urn:x"}, "colour": "red"}`, "--wallet-dir", dir})
	if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "colour") {
		t.Fatalf("error = %v, want the unknown field", err)
	}
}

func lineWith(text, prefix string) string {
	for line := range strings.Lines(text) {
		if strings.HasPrefix(line, prefix+" ") {
			return line
		}
	}
	return ""
}

func TestTransactionTemplatesTypesListTheAcceptedTypes(t *testing.T) {
	resetRemoteTestState(t)
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	w := wallet.New(holderKey, issuerKey, false)
	w.SetConformance(wallet.ConformanceSettings{TransactionData: true, TransactionDataTypes: []string{"urn:example:refund"}})
	srv := wallet.NewServer(w, 0, nil)
	srv.ShutdownFunc = func() {}
	url, err := srv.ListenAndServeBackground()
	if err != nil {
		t.Fatal(err)
	}

	listed := captureStdout(t, func() {
		resetFlags(rootCmd)
		rootCmd.SetArgs([]string{"templates", "transactions", "types", "--remote", url})
		if err := rootCmd.Execute(); err != nil {
			t.Fatal(err)
		}
	})
	for _, want := range []string{
		"urn:eudi:sca:login_risk_transaction:1  transaction_id*, date_time, service, action*",
		"urn:example:refund",
		"Hash algorithms: sha-256, sha-384, sha-512",
	} {
		if !strings.Contains(listed, want) {
			t.Errorf("types %q, want %q", listed, want)
		}
	}
}
