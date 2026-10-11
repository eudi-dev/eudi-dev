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
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestMovedCommandsNameTheirReplacementAndRunNothing(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"serve", "--port", "1"}, "eudi serve is now eudi decoder"},
		{[]string{"wallet", "registrar", "verifiers", "add", "--name", "Shop"}, "eudi wallet registrar is now eudi registrar"},
		{[]string{"wallet", "catalog", "add", "--name", "Diploma"}, "eudi wallet catalog is now eudi catalog"},
		{[]string{"wallet", "trust", "add-ca", "--list", "pid", "--ca", "ca.pem"}, "eudi wallet trust is now eudi trust"},
		{[]string{"wallet", "trust-list", "--url"}, "eudi wallet trust-list is now eudi trust show"},
		{[]string{"wallet", "trusted-list", "--id", "lists"}, "eudi wallet trusted-list is now eudi trust show"},
		{[]string{"wallet", "ca-cert", "--out", "ca.pem"}, "eudi wallet ca-cert is now eudi trust ca-cert"},
		{[]string{"wallet", "present", "openid4vp://?x"}, "eudi wallet present is now eudi wallet accept"},
		{[]string{"wallet", "listen"}, "eudi wallet listen is now eudi wallet serve --register"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			resetRemoteTestState(t)
			useLocalTestWallet(t)
			t.Cleanup(func() { resetFlags(rootCmd) })
			rootCmd.SetArgs(tc.args)
			err := rootCmd.Execute()
			if err == nil || err.Error() != tc.want {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if entries, _ := os.ReadDir(walletDir); len(entries) != 0 {
				t.Errorf("the moved command touched the wallet directory: %v", entries)
			}
		})
	}
}

func TestMovedCommandsAreReachableWithTheWalletFlags(t *testing.T) {
	for _, path := range [][]string{
		{"decoder"},
		{"registrar", "verifiers", "add"},
		{"registrar", "issuers"},
		{"registrar", "access-cert"},
		{"catalog", "add"},
		{"trust", "list"},
		{"trust", "show"},
		{"trust", "add-ca"},
		{"trust", "add-list"},
		{"trust", "ca-cert"},
		{"wallet", "tls-cert"},
	} {
		cmd, rest, err := rootCmd.Find(path)
		if err != nil || len(rest) != 0 || cmd.Hidden || cmd.Name() != path[len(path)-1] {
			t.Errorf("%v: found %q rest %v err %v", path, cmd.CommandPath(), rest, err)
			continue
		}
		if path[0] == "decoder" {
			continue
		}
		for _, name := range []string{"wallet-dir", "remote", "storage", "mode", "tls-verify"} {
			if cmd.Flags().Lookup(name) == nil && cmd.InheritedFlags().Lookup(name) == nil {
				t.Errorf("%v has no --%s", path, name)
			}
		}
	}
}

func TestMovedCommandsComplete(t *testing.T) {
	resetRemoteTestState(t)
	t.Cleanup(func() {
		resetFlags(rootCmd)
		rootCmd.SetOut(nil)
	})
	complete := func(args ...string) string {
		var out bytes.Buffer
		rootCmd.SetOut(&out)
		rootCmd.SetArgs(append([]string{cobra.ShellCompRequestCmd}, args...))
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("completing %v: %v", args, err)
		}
		return out.String()
	}
	if out := complete("registrar", "--mode", ""); !strings.Contains(out, "strict") {
		t.Errorf("registrar --mode completes %q", out)
	}
	if out := complete(""); !strings.Contains(out, "trust\t") || !strings.Contains(out, "decoder\t") || strings.Contains(out, "serve\t") {
		t.Errorf("top-level completion: %q", out)
	}
	if out := complete("wallet", ""); strings.Contains(out, "registrar\t") || !strings.Contains(out, "accept\t") {
		t.Errorf("wallet completion: %q", out)
	}
	// Completion reads an existing wallet only.
	store, err := openStore()
	if err != nil {
		t.Fatal(err)
	}
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}
	if out := complete("trust", "show", ""); !strings.Contains(out, "lists\t") || !strings.Contains(out, "access-ca\t") {
		t.Errorf("trust show completes %q", out)
	}
}
