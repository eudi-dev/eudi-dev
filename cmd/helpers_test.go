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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/v3/internal/config"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/trustlist"
	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

func TestTypeLabel(t *testing.T) {
	tests := []struct {
		name    string
		vct     string
		docType string
		format  string
		want    string
	}{
		{"vct preferred", "urn:eu.europa.ec:pid", "org.iso.mdl", "dc+sd-jwt", "urn:eu.europa.ec:pid"},
		{"docType fallback", "", "org.iso.mdl", "mso_mdoc", "org.iso.mdl"},
		{"format fallback", "", "", "dc+sd-jwt", "dc+sd-jwt"},
		{"all empty", "", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := typeLabel(tt.vct, tt.docType, tt.format)
			if got != tt.want {
				t.Errorf("typeLabel(%q, %q, %q) = %q, want %q", tt.vct, tt.docType, tt.format, got, tt.want)
			}
		})
	}
}

func TestCredLabel(t *testing.T) {
	tests := []struct {
		name string
		cred wallet.StoredCredential
		want string
	}{
		{"with VCT", wallet.StoredCredential{VCT: "urn:pid", DocType: "org.iso.mdl", Format: "dc+sd-jwt"}, "urn:pid"},
		{"with DocType only", wallet.StoredCredential{DocType: "org.iso.mdl", Format: "mso_mdoc"}, "org.iso.mdl"},
		{"format only", wallet.StoredCredential{Format: "dc+sd-jwt"}, "dc+sd-jwt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := credLabel(tt.cred)
			if got != tt.want {
				t.Errorf("credLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		max   int
		want  string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 5, "hello..."},
		{"", 5, ""},
		{"ab", 1, "a..."},
	}

	for _, tt := range tests {
		got := format.Truncate(tt.input, tt.max)
		if got != tt.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
		}
	}
}

func TestParseClaimsOverrides(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		result, err := parseClaimsOverrides("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("valid JSON", func(t *testing.T) {
		result, err := parseClaimsOverrides(`{"given_name":"Max","age":30}`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result["given_name"] != "Max" {
			t.Errorf("expected given_name=Max, got %v", result["given_name"])
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := parseClaimsOverrides("{invalid")
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

func TestApplySessionTranscriptMode(t *testing.T) {
	tests := []struct {
		mode    string
		want    wallet.SessionTranscriptMode
		wantErr bool
	}{
		{"oid4vp", wallet.SessionTranscriptOID4VP, false},
		{"", wallet.SessionTranscriptOID4VP, false},
		{"iso", wallet.SessionTranscriptISO, false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run("mode="+tt.mode, func(t *testing.T) {
			w := &wallet.Wallet{}
			err := applySessionTranscriptMode(w, tt.mode)
			if (err != nil) != tt.wantErr {
				t.Fatalf("applySessionTranscriptMode(%q) error = %v, wantErr %v", tt.mode, err, tt.wantErr)
			}
			if !tt.wantErr && w.SessionTranscript != tt.want {
				t.Errorf("got transcript mode %q, want %q", w.SessionTranscript, tt.want)
			}
		})
	}
}

func TestApplyValidationMode(t *testing.T) {
	tests := []struct {
		mode    string
		want    wallet.ValidationMode
		wantErr bool
	}{
		{"debug", wallet.ValidationModeDebug, false},
		{"", wallet.ValidationModeDebug, false},
		{"strict", wallet.ValidationModeStrict, false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run("mode="+tt.mode, func(t *testing.T) {
			w := &wallet.Wallet{}
			err := applyValidationMode(w, tt.mode)
			if (err != nil) != tt.wantErr {
				t.Fatalf("applyValidationMode(%q) error = %v, wantErr %v", tt.mode, err, tt.wantErr)
			}
			if !tt.wantErr && w.ValidationMode != tt.want {
				t.Errorf("got validation mode %q, want %q", w.ValidationMode, tt.want)
			}
		})
	}
}

func TestSetLocalPresentationIssuerURL(t *testing.T) {
	w := &wallet.Wallet{IssuerURL: "https://localhost:8086"}

	setLocalPresentationIssuerURL(w, 31127, false)

	if got, want := w.IssuerURL, "https://localhost:31128"; got != want {
		t.Fatalf("setLocalPresentationIssuerURL() = %q, want %q", got, want)
	}
}

func TestSetLocalPresentationIssuerURL_Docker(t *testing.T) {
	w := &wallet.Wallet{}

	setLocalPresentationIssuerURL(w, 31127, true)

	if got, want := w.IssuerURL, "https://host.docker.internal:31128"; got != want {
		t.Fatalf("setLocalPresentationIssuerURL(docker) = %q, want %q", got, want)
	}
}

func TestEffectivePresentationPort(t *testing.T) {
	if got, want := effectivePresentationPort(0), config.DefaultWalletPort; got != want {
		t.Fatalf("effectivePresentationPort(0) = %d, want %d", got, want)
	}
	if got, want := effectivePresentationPort(31127), 31127; got != want {
		t.Fatalf("effectivePresentationPort(31127) = %d, want %d", got, want)
	}
}

func TestRegisteredWalletListenerBaseURL(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	handlerDir := filepath.Join(home, ".eudi-dev")
	if err := os.MkdirAll(handlerDir, 0755); err != nil {
		t.Fatal(err)
	}
	handler := `#!/bin/bash
LISTENER="http://localhost:8091"
PORT="8091"
`
	if err := os.WriteFile(filepath.Join(handlerDir, "url-handler.sh"), []byte(handler), 0755); err != nil {
		t.Fatal(err)
	}

	if got, want := registeredWalletListenerBaseURL(), "http://localhost:8091"; got != want {
		t.Fatalf("registeredWalletListenerBaseURL() = %q, want %q", got, want)
	}
	if got, want := registeredWalletListenerPort(), 8091; got != want {
		t.Fatalf("registeredWalletListenerPort() = %d, want %d", got, want)
	}
	if got, want := defaultWalletCommandPort(), 8091; got != want {
		t.Fatalf("defaultWalletCommandPort() = %d, want %d", got, want)
	}
}

func TestLocalHostHelpersShareOneDefinition(t *testing.T) {
	for _, hostport := range []string{"LOCALHOST:8085", "127.0.0.2:8085", "[::1]:8085", "host.docker.internal:8085"} {
		if !isLocalTestHostPort(hostport) {
			t.Errorf("isLocalTestHostPort(%q) = false, want true", hostport)
		}
	}
	if isLocalTestHostPort("issuer.example:443") {
		t.Error("a public host counts as local")
	}
	if !isLocalhostIssuerURL("https://LOCALHOST:8086") {
		t.Error("an uppercase localhost issuer URL is not realigned")
	}
	if isLocalhostIssuerURL("https://host.docker.internal:8086") {
		t.Error("a Docker host issuer URL is realigned")
	}
}

func TestResolvePresentationPortUsesFreePairWhenDefaultBusy(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port

	got, err := resolvePresentationPort(busyPort, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if got == busyPort {
		t.Fatalf("resolvePresentationPort() = busy port %d", got)
	}

	httpCheck, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", got))
	if err != nil {
		t.Fatalf("fallback HTTP port %d is not free: %v", got, err)
	}
	_ = httpCheck.Close()
	httpsCheck, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", got+1))
	if err != nil {
		t.Fatalf("fallback HTTPS port %d is not free: %v", got+1, err)
	}
	_ = httpsCheck.Close()
}

func TestIsHTTPURL(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"https://example.com", true},
		{"http://example.com", true},
		{"HTTP://EXAMPLE.COM", true},
		{"HTTPS://EXAMPLE.COM", true},
		{"openid4vp://authorize", false},
		{"eyJhbGci...", false},
		{"", false},
	}

	for _, tt := range tests {
		got := isHTTPURL(tt.input)
		if got != tt.want {
			t.Errorf("isHTTPURL(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestWalletRegisterOptions(t *testing.T) {
	args := []string{
		"--port", "9123",
		"--auto-accept",
		"--haip",
		"--vci-client-id", "wallet-client",
		"--credential", "cred1.json",
	}

	opts, err := walletRegisterOptions(args)
	if err != nil {
		t.Fatalf("walletRegisterOptions() error = %v", err)
	}
	if opts.ListenerPort != 9123 {
		t.Fatalf("ListenerPort = %d, want 9123", opts.ListenerPort)
	}
	if !opts.AutoAccept {
		t.Fatal("AutoAccept = false, want true")
	}
	if !slices.Equal(opts.ServeArgs, args) {
		t.Fatalf("ServeArgs = %#v, want %#v", opts.ServeArgs, args)
	}
}

func TestWalletRegisterOptions_Defaults(t *testing.T) {
	opts, err := walletRegisterOptions(nil)
	if err != nil {
		t.Fatalf("walletRegisterOptions() error = %v", err)
	}
	if opts.ListenerPort != config.DefaultWalletPort {
		t.Fatalf("ListenerPort = %d, want %d", opts.ListenerPort, config.DefaultWalletPort)
	}
	if opts.AutoAccept {
		t.Fatal("AutoAccept = true, want false")
	}
	if len(opts.ServeArgs) != 0 {
		t.Fatalf("ServeArgs = %#v, want empty", opts.ServeArgs)
	}
}

// The URL handler must pass the registration flags to the server it starts.
func TestWalletRegisterInheritedServeArgs(t *testing.T) {
	parent := &cobra.Command{Use: "wallet"}
	parent.PersistentFlags().String("wallet-dir", "", "")
	parent.PersistentFlags().String("mode", "debug", "")
	parent.PersistentFlags().String("storage", "", "")
	parent.PersistentFlags().Bool("tls-verify", true, "")
	parent.PersistentFlags().String("tls-ca", "", "")
	var got []string
	parent.AddCommand(&cobra.Command{Use: "register", Run: func(cmd *cobra.Command, _ []string) {
		got = walletRegisterInheritedServeArgs(cmd)
	}})
	parent.SetArgs([]string{"register", "--wallet-dir", "/tmp/isolated-wallet", "--mode", "strict", "--storage", "memory", "--tls-verify=false", "--tls-ca", "/tmp/ca.pem"})
	if err := parent.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"--wallet-dir", "/tmp/isolated-wallet"}, {"--mode", "strict"}, {"--storage", "memory"}, {"--tls-ca", "/tmp/ca.pem"}} {
		if !argPairPresent(got, pair[0], pair[1]) {
			t.Fatalf("walletRegisterInheritedServeArgs() = %#v, missing %s", got, pair[0])
		}
	}
	if !slices.Contains(got, "--tls-verify=false") {
		t.Fatalf("explicit false TLS override lost: %#v", got)
	}
}

// A detached server inherits wallet settings but skips URL registration. The seed
// stays in the environment.
func TestSerializeWalletServeArgs(t *testing.T) {
	parent := &cobra.Command{Use: "wallet"}
	parent.PersistentFlags().String("wallet-dir", "", "")
	parent.PersistentFlags().String("storage", "", "")
	parent.PersistentFlags().String("templates-dir", "", "")
	parent.PersistentFlags().String("seed", "", "")
	cmd := &cobra.Command{Use: "serve"}
	parent.AddCommand(cmd)
	flags := cmd.Flags()
	flags.Int("port", config.DefaultWalletPort, "")
	flags.Bool("auto-accept", false, "")
	flags.String("base-url", "", "")
	flags.StringSlice("credential", nil, "")
	flags.Bool("register", false, "")
	flags.Bool("no-register", false, "")
	flags.Bool("detached", false, "")
	var got []string
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		var err error
		got, err = serializeWalletServeArgs(cmd)
		return err
	}
	parent.SetArgs([]string{"serve", "--port", "9123", "--detached", "--auto-accept", "--base-url", "http://localhost:9123",
		"--credential", "first.json", "--credential", "second.json", "--register",
		"--wallet-dir", "/tmp/isolated-wallet", "--storage", "memory", "--templates-dir", "/custom/templates", "--seed", "secret"})
	if err := parent.Execute(); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"--auto-accept=true",
		"--base-url", "http://localhost:9123",
		"--credential", "first.json",
		"--credential", "second.json",
		"--port", "9123",
		"--storage", "memory",
		"--templates-dir", "/custom/templates",
		"--wallet-dir", "/tmp/isolated-wallet",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("serializeWalletServeArgs() = %#v, want %#v", got, want)
	}
	if !slices.Contains(detachedChildEnv("secret"), wallet.SeedEnvVar+"=secret") {
		t.Fatal("the detached server's environment lacks the seed")
	}
}

func TestSerializeWalletServeArgs_UnchangedBoolOmitted(t *testing.T) {
	cmd := &cobra.Command{Use: "serve"}
	flags := cmd.Flags()
	flags.Bool("auto-accept", false, "")
	flags.Bool("register", false, "")
	flags.Bool("no-register", false, "")

	got, err := serializeWalletServeArgs(cmd)
	if err != nil {
		t.Fatalf("serializeWalletServeArgs() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("serializeWalletServeArgs() = %#v, want empty", got)
	}
}

func TestSerializeWalletServeArgs_ExplicitBoolFalsePreserved(t *testing.T) {
	cmd := &cobra.Command{Use: "serve"}
	flags := cmd.Flags()
	flags.Bool("haip", true, "")
	if err := flags.Set("haip", "false"); err != nil {
		t.Fatalf("set haip: %v", err)
	}

	got, err := serializeWalletServeArgs(cmd)
	if err != nil {
		t.Fatalf("serializeWalletServeArgs() error = %v", err)
	}
	want := []string{"--haip=false"}
	if !slices.Equal(got, want) {
		t.Fatalf("serializeWalletServeArgs() = %#v, want %#v", got, want)
	}
}

func argPairPresent(args []string, flag string, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

// Every command that talks to a running wallet refuses --mode, not only accept
// and scan.
func TestEveryRemoteCommandRefusesMode(t *testing.T) {
	resetRemoteTestState(t)
	url, _ := startRemoteTestWallet(t)
	remoteFlag = url
	mode := walletCmd.PersistentFlags().Lookup("mode")
	if err := mode.Value.Set("strict"); err != nil {
		t.Fatal(err)
	}
	mode.Changed = true
	t.Cleanup(func() { _ = mode.Value.Set(mode.DefValue); mode.Changed = false })
	if _, err := managedWallet(); err == nil || !strings.Contains(err.Error(), "'eudi trust'") {
		t.Fatalf("err = %v, want the refusal that points to eudi trust", err)
	}
}

// trust show prints the list of trusted lists under the ID of its URL.
func TestTrustListPrintsTheListOfTrustedLists(t *testing.T) {
	resetRemoteTestState(t)
	rootCmd.SetArgs([]string{"trust", "show", "lists"})
	out := captureStdout(t, func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatal(err)
		}
	})
	list, err := trustlist.Parse(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("parsing %q: %v", out, err)
	}
	if len(list.SchemeInfo.Pointers) == 0 {
		t.Error("the list of trusted lists has no pointers")
	}
}
