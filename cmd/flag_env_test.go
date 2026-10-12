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

	"github.com/eudi-dev/eudi-dev/v2/internal/config"
	"github.com/eudi-dev/eudi-dev/v2/internal/storage"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
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
	t.Setenv("EUDI_DEV_DEMO_VERIFIER_TRUST_ANCHOR", "a.pem, b.pem")
	t.Setenv("EUDI_DEV_CREDENTIAL", "one.json,two.json")
	t.Setenv("EUDI_DEV_LOG_FORMAT", "json")
	t.Setenv("EUDI_DEV_ALLOW_PRIVATE_NETWORKS", "true")
	cmd, opts := parsedServeCmd(t)

	if err := applyFlagEnv(cmd.Flags()); err != nil {
		t.Fatal(err)
	}
	if opts.Port != 9000 || !opts.AutoAccept || opts.BaseURL != "http://wallet:9000" || opts.LogFormat != "json" || !opts.AllowPrivateNetworks {
		t.Fatalf("options = port %d, auto-accept %v, base URL %q, log format %q, allow private networks %v",
			opts.Port, opts.AutoAccept, opts.BaseURL, opts.LogFormat, opts.AllowPrivateNetworks)
	}
	if !slices.Equal(opts.DemoVerifierTrust, []string{"a.pem", "b.pem"}) {
		t.Fatalf("--demo-verifier-trust-anchor = %#v", opts.DemoVerifierTrust)
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
	joined := strings.Join(args, " ")
	for _, want := range []string{"--port 9000", "--demo-verifier-trust-anchor a.pem --demo-verifier-trust-anchor b.pem", "--allow-private-networks=true"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("detached arguments %q lack %q", joined, want)
		}
	}
}

func TestFlagEnvLosesToTheCommandLine(t *testing.T) {
	clearFlagEnv(t)
	t.Setenv("EUDI_DEV_PORT", "9000")
	t.Setenv("EUDI_DEV_AUTO_ACCEPT", "true")
	t.Setenv("EUDI_DEV_CREDENTIAL", "env.json")
	cmd, opts := parsedServeCmd(t, "--port", "9100", "--auto-accept=false", "--credential", "flag.json")

	if err := applyFlagEnv(cmd.Flags()); err != nil {
		t.Fatal(err)
	}
	if opts.Port != 9100 || opts.AutoAccept {
		t.Fatalf("port %d, auto-accept %v, want the command line values", opts.Port, opts.AutoAccept)
	}
	if !slices.Equal(opts.CredFiles, []string{"flag.json"}) {
		t.Fatalf("--credential = %#v", opts.CredFiles)
	}
}

// A value from the environment counts as given, so it wins over a default
// that --demo implies.
func TestFlagEnvWinsOverDemoDefaults(t *testing.T) {
	clearFlagEnv(t)
	t.Setenv("EUDI_DEV_DEMO", "true")
	t.Setenv("EUDI_DEV_HAIP", "false")
	cmd, opts := parsedServeCmd(t)

	if err := applyFlagEnv(cmd.Flags()); err != nil {
		t.Fatal(err)
	}
	applyDemoProfileDefaults(cmd, opts, &wallet.Wallet{})
	if !opts.Demo || opts.HAIP {
		t.Fatalf("demo %v, haip %v, want demo without HAIP", opts.Demo, opts.HAIP)
	}
}

func TestFlagEnvIgnoresAnEmptyValue(t *testing.T) {
	clearFlagEnv(t)
	t.Setenv("EUDI_DEV_PORT", "")
	cmd, opts := parsedServeCmd(t)

	if err := applyFlagEnv(cmd.Flags()); err != nil {
		t.Fatal(err)
	}
	if opts.Port != config.DefaultWalletPort || cmd.Flags().Changed("port") {
		t.Fatalf("port %d, want the default", opts.Port)
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

// The state directory, storage and seed variables keep their own handling,
// which every command shares.
func TestFlagEnvKnowsTheDirectVariables(t *testing.T) {
	clearFlagEnv(t)
	t.Setenv(config.HomeEnvVar, t.TempDir())
	t.Setenv(storage.EnvVar, storage.KindMemory)
	t.Setenv(wallet.SeedEnvVar, "secret")
	cmd, _ := parsedServeCmd(t)
	// --storage and --seed are persistent flags of the wallet command.
	cmd.Flags().String("storage", "", "")
	cmd.Flags().String("seed", "", "")

	if err := applyFlagEnv(cmd.Flags()); err != nil {
		t.Fatal(err)
	}
	if cmd.Flags().Changed("storage") || cmd.Flags().Changed("seed") {
		t.Fatal("a directly read variable set its flag")
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
