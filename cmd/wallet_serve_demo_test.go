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
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// Explicit flags can override each demo default.
func TestDemoModeImpliesEUDIProfile(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantMode       wallet.ValidationMode
		wantHAIP       bool
		wantVCIVersion wallet.VCIVersion
	}{
		{
			name:           "plain serve keeps the permissive defaults",
			args:           []string{"--port", "0"},
			wantMode:       wallet.ValidationModeDebug,
			wantHAIP:       false,
			wantVCIVersion: wallet.VCIVersion10,
		},
		{
			name:           "demo implies HAIP in debug and the 1.1 feature level",
			args:           []string{"--port", "0", "--demo"},
			wantMode:       wallet.ValidationModeDebug,
			wantHAIP:       true,
			wantVCIVersion: wallet.VCIVersion11,
		},
		{
			name:           "explicit mode wins over the demo default",
			args:           []string{"--port", "0", "--demo", "--mode", "strict"},
			wantMode:       wallet.ValidationModeStrict,
			wantHAIP:       true,
			wantVCIVersion: wallet.VCIVersion11,
		},
		{
			name:           "explicit haip=false wins over the demo default",
			args:           []string{"--port", "0", "--demo", "--haip=false"},
			wantMode:       wallet.ValidationModeDebug,
			wantHAIP:       false,
			wantVCIVersion: wallet.VCIVersion11,
		},
		{
			name:           "explicit vci-version wins over the demo default",
			args:           []string{"--port", "0", "--demo", "--vci-version", "1.0"},
			wantMode:       wallet.ValidationModeDebug,
			wantHAIP:       true,
			wantVCIVersion: wallet.VCIVersion10,
		},
		{
			name:           "haip without demo is still available on its own",
			args:           []string{"--port", "0", "--haip"},
			wantMode:       wallet.ValidationModeDebug,
			wantHAIP:       true,
			wantVCIVersion: wallet.VCIVersion10,
		},
		{
			name:           "the 1.1 feature level is available without demo",
			args:           []string{"--port", "0", "--vci-version", "1.1"},
			wantMode:       wallet.ValidationModeDebug,
			wantHAIP:       false,
			wantVCIVersion: wallet.VCIVersion11,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := resolveServeProfile(t, tc.args)
			if w.ValidationMode != tc.wantMode {
				t.Errorf("validation mode = %q, want %q", w.ValidationMode, tc.wantMode)
			}
			if w.RequireHAIP != tc.wantHAIP {
				t.Errorf("RequireHAIP = %v, want %v", w.RequireHAIP, tc.wantHAIP)
			}
			if got := w.VCIFeatureVersion(); got != tc.wantVCIVersion {
				t.Errorf("VCIVersion = %q, want %q", got, tc.wantVCIVersion)
			}
		})
	}
}

// Reject invalid versions during flag parsing, before the first issuance.
func TestServeRejectsAnUnknownVCIVersion(t *testing.T) {
	cmd, opts := walletServeCmdWithOptions()
	if err := cmd.ParseFlags([]string{"--port", "0", "--vci-version", "1.2"}); err != nil {
		t.Fatalf("parsing flags: %v", err)
	}
	if _, err := serveConformance(cmd, opts); err == nil {
		t.Fatal("the serve flags accepted an unknown version")
	}
}

func resolveServeProfile(t *testing.T, args []string) *wallet.Wallet {
	w, _ := resolveServeProfileWithOptions(t, args)
	return w
}

func resolveServeProfileWithOptions(t *testing.T, args []string) (*wallet.Wallet, *walletServeOptions) {
	t.Helper()

	cmd, opts := walletServeCmdWithOptions()
	// --mode is a persistent flag on the parent command.
	cmd.Flags().StringVar(&walletValidationMode, "mode", string(wallet.ValidationModeDebug), "")
	t.Cleanup(func() { walletValidationMode = string(wallet.ValidationModeDebug) })

	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("parsing %v: %v", args, err)
	}

	conformance, err := serveConformance(cmd, opts)
	if err != nil {
		t.Fatalf("resolving the serve flags: %v", err)
	}
	w := newTestServeWallet(t)
	conformance.apply(w)
	return w, opts
}

func TestDemoModePIDBaselineIsOverridable(t *testing.T) {
	_, withDefault := resolveServeProfileWithOptions(t, []string{"--port", "0", "--demo"})
	if !withDefault.PID {
		t.Error("demo did not imply the PID baseline")
	}
	_, disabled := resolveServeProfileWithOptions(t, []string{"--port", "0", "--demo", "--pid=false"})
	if disabled.PID {
		t.Error("explicit --pid=false did not win over the demo default")
	}
	_, plain := resolveServeProfileWithOptions(t, []string{"--port", "0"})
	if plain.PID {
		t.Error("plain serve seeded a PID baseline nobody asked for")
	}
}

func newTestServeWallet(t *testing.T) *wallet.Wallet {
	t.Helper()

	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating holder key: %v", err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	return wallet.New(holderKey, issuerKey, false)
}
