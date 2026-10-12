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

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// clearFlagEnv hides the EUDI_DEV_ variables of the shell running the tests.
func clearFlagEnv(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, flagEnvPrefix) {
			t.Setenv(name, "")
			os.Unsetenv(name)
		}
	}
}

func parsedServeCmd(t *testing.T, args ...string) (*cobra.Command, *walletServeOptions) {
	t.Helper()
	cmd, opts := walletServeCmdWithOptions()
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatal(err)
	}
	return cmd, opts
}

// Every wallet serve flag can be set as EUDI_DEV_<FLAG>, so the image is
// configurable by its environment alone.
func TestFlagEnvSetsServeFlags(t *testing.T) {
	clearFlagEnv(t)
	t.Setenv("EUDI_DEV_PORT", "9000")
	t.Setenv("EUDI_DEV_AUTO_ACCEPT", "true")
	t.Setenv("EUDI_DEV_BASE_URL", "http://wallet:9000")
	t.Setenv("EUDI_DEV_DEMO_VERIFIER_ISSUER_CA", "a.pem, b.pem")
	t.Setenv("EUDI_DEV_CREDENTIAL", "one.json,two.json")
	t.Setenv("EUDI_DEV_LOG_FORMAT", "json")
	cmd, opts := parsedServeCmd(t)

	if err := applyFlagEnv(cmd.Flags()); err != nil {
		t.Fatal(err)
	}
	if opts.Port != 9000 || !opts.AutoAccept || opts.BaseURL != "http://wallet:9000" || opts.LogFormat != "json" {
		t.Fatalf("options = port %d, auto-accept %v, base URL %q, log format %q", opts.Port, opts.AutoAccept, opts.BaseURL, opts.LogFormat)
	}
	if !slices.Equal(opts.DemoVerifierIssuerCAs, []string{"a.pem", "b.pem"}) {
		t.Fatalf("--demo-verifier-issuer-ca = %#v", opts.DemoVerifierIssuerCAs)
	}
	if !slices.Equal(opts.CredFiles, []string{"one.json", "two.json"}) {
		t.Fatalf("--credential = %#v", opts.CredFiles)
	}
	// A value from the environment counts as set, so it wins over the stored
	// base URL and a detached server receives it as a flag.
	if !cmd.Flags().Changed("base-url") {
		t.Fatal("--base-url from the environment does not count as set")
	}
	args, err := serializeWalletServeArgs(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "--port") || !slices.Contains(args, "9000") {
		t.Fatalf("detached arguments %#v lack --port 9000", args)
	}
}

func TestFlagEnvLosesToTheCommandLine(t *testing.T) {
	clearFlagEnv(t)
	t.Setenv("EUDI_DEV_PORT", "9000")
	t.Setenv("EUDI_DEV_AUTO_ACCEPT", "true")
	t.Setenv("EUDI_DEV_TRUSTED_LIST", "https://env.example/list")
	cmd, opts := parsedServeCmd(t, "--port", "9100", "--auto-accept=false", "--trusted-list", "https://flag.example/list")

	if err := applyFlagEnv(cmd.Flags()); err != nil {
		t.Fatal(err)
	}
	if opts.Port != 9100 || opts.AutoAccept {
		t.Fatalf("port %d, auto-accept %v, want the command line values", opts.Port, opts.AutoAccept)
	}
	if !slices.Equal(opts.Conformance.trustedLists, []string{"https://flag.example/list"}) {
		t.Fatalf("--trusted-list = %#v", opts.Conformance.trustedLists)
	}
}

func TestFlagEnvRefusesAnUnknownVariable(t *testing.T) {
	clearFlagEnv(t)
	t.Setenv("EUDI_DEV_PROT", "9000")
	cmd, _ := parsedServeCmd(t)

	err := applyFlagEnv(cmd.Flags())
	if err == nil || !strings.Contains(err.Error(), "EUDI_DEV_PROT") {
		t.Fatalf("error = %v, want one naming EUDI_DEV_PROT", err)
	}
}

func TestFlagEnvRefusesAnInvalidValue(t *testing.T) {
	clearFlagEnv(t)
	t.Setenv("EUDI_DEV_PORT", "abc")
	cmd, _ := parsedServeCmd(t)

	err := applyFlagEnv(cmd.Flags())
	if err == nil || !strings.Contains(err.Error(), "EUDI_DEV_PORT") {
		t.Fatalf("error = %v, want one naming EUDI_DEV_PORT", err)
	}
}

// The state directory, storage, seed and private network variables keep their
// own handling, which every command shares.
func TestFlagEnvKnowsTheDirectVariables(t *testing.T) {
	clearFlagEnv(t)
	t.Setenv(config.HomeEnvVar, t.TempDir())
	t.Setenv(storage.EnvVar, storage.KindMemory)
	t.Setenv(wallet.SeedEnvVar, "")
	t.Setenv(allowPrivateNetworksEnv, "true")
	cmd, _ := parsedServeCmd(t)

	if err := applyFlagEnv(cmd.Flags()); err != nil {
		t.Fatal(err)
	}
	if cmd.Flags().Changed(allowPrivateNetworksFlag) {
		t.Fatalf("$%s set --%s, which --demo refuses", allowPrivateNetworksEnv, allowPrivateNetworksFlag)
	}
}

func TestWalletServeRefusesAnUnknownVariable(t *testing.T) {
	clearFlagEnv(t)
	t.Setenv("EUDI_DEV_AUTOACCEPT", "true")
	t.Cleanup(func() { walletDir = "" })

	rootCmd.SetArgs([]string{"wallet", "serve", "--wallet-dir", filepath.Join(t.TempDir(), "wallet")})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "EUDI_DEV_AUTOACCEPT") {
		t.Fatalf("error = %v, want one naming EUDI_DEV_AUTOACCEPT", err)
	}
}

// The detached server runs in the foreground, so it must not detach again.
func TestDetachedChildEnvDropsDetached(t *testing.T) {
	t.Setenv("EUDI_DEV_DETACHED", "true")
	t.Setenv("EUDI_DEV_PORT", "9000")

	env := detachedChildEnv("")
	if slices.Contains(env, "EUDI_DEV_DETACHED=true") || !slices.Contains(env, "EUDI_DEV_PORT=9000") {
		t.Fatalf("child environment keeps EUDI_DEV_DETACHED or lost EUDI_DEV_PORT")
	}
}
