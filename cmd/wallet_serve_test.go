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
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/spf13/pflag"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/remote"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

func newServingTestWallet(t *testing.T) *wallet.Wallet {
	t.Helper()
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	w := wallet.New(holderKey, issuerKey, false)
	w.Templates = credtemplate.FileLocation(t.TempDir())
	w.BaseURL = "http://localhost:8085"
	w.IssuerURL = "https://localhost:8086"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	return w
}

func TestServingConfigWarnings(t *testing.T) {
	w := newServingTestWallet(t)

	// Credentials match the serving config: no warnings.
	if warns := servingConfigWarnings(w, 8085, false); len(warns) != 0 {
		t.Fatalf("expected no warnings, got %v", warns)
	}

	// The serving config moved to other ports: the credentials still embed
	// the old URLs and get flagged.
	w.BaseURL = "http://localhost:9085"
	w.IssuerURL = "https://localhost:9086"
	warns := servingConfigWarnings(w, 9085, false)
	if len(warns) != 1 || !strings.Contains(warns[0], "credential") {
		t.Fatalf("expected a stale-credential warning, got %v", warns)
	}

	// A Docker hostname outside Docker is flagged (in addition to the
	// credential mismatch this creates).
	w.IssuerURL = "https://host.docker.internal:9086"
	warns = servingConfigWarnings(w, 9085, false)
	joined := strings.Join(warns, "\n")
	if !strings.Contains(joined, "Docker hostname") {
		t.Fatalf("expected a Docker hostname warning, got %v", warns)
	}
	// With --docker the same config is intentional.
	warns = servingConfigWarnings(w, 9085, true)
	if strings.Contains(strings.Join(warns, "\n"), "Docker hostname") {
		t.Fatalf("did not expect a Docker hostname warning with --docker, got %v", warns)
	}
}

func TestServingConfigWarningsIgnoreForeignIssuers(t *testing.T) {
	w := newServingTestWallet(t)

	// A credential from a foreign issuer keeps its own URLs and is never
	// flagged, even though they do not match the serving config.
	foreignKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:        "https://issuer.example.com",
		VCT:           "urn:example:foreign",
		Claims:        map[string]any{"a": "1"},
		Key:           foreignKey,
		StatusListURI: "https://issuer.example.com/status/1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ImportCredential(raw); err != nil {
		t.Fatal(err)
	}

	if warns := servingConfigWarnings(w, 8085, false); len(warns) != 0 {
		t.Fatalf("expected no warnings for foreign issuer URLs, got %v", warns)
	}
}

func TestWalletOriginIssuerURL(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		baseURL string
		docker  bool
		want    string
	}{
		{name: "no base URL", port: 8085, want: "https://localhost:8086"},
		{name: "no base URL docker", port: 8085, docker: true, want: "https://host.docker.internal:8086"},
		{name: "http base URL keeps port+1 listener", port: 8085, baseURL: "http://localhost:8085", want: "https://localhost:8086"},
		{name: "http base URL custom host", port: 9085, baseURL: "http://wallet:9085", want: "https://wallet:9086"},
		{name: "https base URL becomes the issuer origin", port: 8085, baseURL: "https://eudi-test.dev", want: "https://eudi-test.dev"},
		{name: "https base URL trailing slash trimmed", port: 8085, baseURL: "https://eudi-test.dev/", want: "https://eudi-test.dev"},
		{name: "https base URL with port kept verbatim", port: 8085, baseURL: "https://example.com:8443", want: "https://example.com:8443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := walletOrigin(tt.port, tt.baseURL, tt.docker)
			if err != nil {
				t.Fatalf("walletOrigin: %v", err)
			}
			if got.Issuer != tt.want {
				t.Fatalf("issuer URL = %q, want %q", got.Issuer, tt.want)
			}
		})
	}
}

func TestIssuerServedByBaseURL(t *testing.T) {
	if !issuerServedByBaseURL("https://eudi-test.dev", "https://eudi-test.dev/") {
		t.Fatal("expected issuer to be served by base URL")
	}
	if issuerServedByBaseURL("https://localhost:8086", "http://localhost:8085") {
		t.Fatal("expected separate issuer listener for http base URL")
	}
	if issuerServedByBaseURL("", "") {
		t.Fatal("empty URLs must not count as served by base URL")
	}
}

// --serve-tls binds the base URL's port itself, so the URL has to be https
// and include that port.
func TestValidateServeTLSBaseURL(t *testing.T) {
	if err := validateServeTLSBaseURL("https://localhost:8443"); err != nil {
		t.Fatalf("https base URL with a port: %v", err)
	}
	for name, baseURL := range map[string]string{
		"empty":        "",
		"http scheme":  "http://localhost:8443",
		"no port":      "https://eudi-test.dev",
		"not a URL":    "://",
		"host missing": "https://",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateServeTLSBaseURL(baseURL); err == nil {
				t.Fatalf("expected %q to be refused", baseURL)
			}
		})
	}
}

func TestLoadVerifierTrustAnchors(t *testing.T) {
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatalf("generating CA certificate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "anchor.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	if err := os.WriteFile(path, append(block, block...), 0o600); err != nil {
		t.Fatalf("writing anchor file: %v", err)
	}

	anchors, err := loadVerifierTrustAnchors([]string{path})
	if err != nil {
		t.Fatalf("loadVerifierTrustAnchors: %v", err)
	}
	if len(anchors) != 2 {
		t.Fatalf("anchors = %d, want both certificates of the file", len(anchors))
	}

	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not pem"), 0o600); err != nil {
		t.Fatalf("writing empty file: %v", err)
	}
	if _, err := loadVerifierTrustAnchors([]string{empty}); err == nil {
		t.Fatal("expected a file without certificates to be refused")
	}
}

func TestWalletServeDemoResetRequiresDemo(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	walletDir = ""

	rootCmd.SetArgs([]string{"wallet", "serve", "--wallet-dir", filepath.Join(tmpDir, "wallet"), "--demo-reset", "5m"})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--demo-reset requires --demo") {
		t.Fatalf("expected --demo-reset validation error, got %v", err)
	}
}

func TestWalletServeRejectsBasePathOnWalletRoute(t *testing.T) {
	serveCmd, _, err := rootCmd.Find([]string{"wallet", "serve"})
	if err != nil {
		t.Fatal(err)
	}
	// Earlier tests leave flag values on the shared command.
	serveCmd.Flags().VisitAll(func(f *pflag.Flag) {
		if slice, ok := f.Value.(pflag.SliceValue); ok {
			_ = slice.Replace(nil)
		} else {
			_ = f.Value.Set(f.DefValue)
		}
		f.Changed = false
	})
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	walletDir = ""

	rootCmd.SetArgs([]string{"wallet", "serve", "--wallet-dir", filepath.Join(tmpDir, "wallet"), "--no-register", "--base-url", "https://mydomain.de/verifier"})
	err = rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "cannot start with /verifier") {
		t.Fatalf("expected a base path error, got %v", err)
	}
}

// The local ports answer under every local host name. A credential that
// names [::1] reaches the same server as one that names localhost.
func TestServingConfigWarningsAcceptEveryLocalHostName(t *testing.T) {
	w := newServingTestWallet(t)
	w.BaseURL = "http://[::1]:8085"
	w.IssuerURL = "https://[::1]:8086"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatal(err)
	}
	w.BaseURL = "http://localhost:8085"
	w.IssuerURL = "https://127.0.0.1:8086"
	if warns := servingConfigWarnings(w, 8085, false); len(warns) != 0 {
		t.Fatalf("credentials on [::1] were flagged: %v", warns)
	}
}

// wallet serve keeps the base URL a previous run stored unless a flag
// replaces it (ADR-0019).
func TestServeBaseURLKeepsTheStoredBaseURL(t *testing.T) {
	for _, tc := range []struct {
		name               string
		stored, flag       string
		flagSet, dockerSet bool
		want               string
	}{
		{"stored", "https://wallet.example", "", false, false, "https://wallet.example"},
		{"flag", "https://wallet.example", "https://other.example", true, false, "https://other.example"},
		{"docker", "http://localhost:8085", "", false, true, ""},
		{"none", "", "", false, false, ""},
	} {
		if got := serveBaseURL(tc.stored, tc.flag, tc.flagSet, tc.dockerSet); got != tc.want {
			t.Errorf("%s: base URL %q, want %q", tc.name, got, tc.want)
		}
	}
	origin, err := walletOrigin(8085, serveBaseURL("https://wallet.example", "", false, false), false)
	if err != nil || origin.Base != "https://wallet.example" || origin.Issuer != "https://wallet.example" {
		t.Fatalf("origin from the stored base URL: %+v %v", origin, err)
	}
}

// EUDI_DEV_CATALOG sets --catalog, and a bad entry stops the start with the
// file and the entry in the message.
func TestWalletServeStopsOnABadCatalogueEntry(t *testing.T) {
	serveCmd, _, err := rootCmd.Find([]string{"wallet", "serve"})
	if err != nil {
		t.Fatal(err)
	}
	// Earlier tests leave flag values on the shared command.
	serveCmd.Flags().VisitAll(func(f *pflag.Flag) {
		if slice, ok := f.Value.(pflag.SliceValue); ok {
			_ = slice.Replace(nil)
		} else {
			_ = f.Value.Set(f.DefValue)
		}
		f.Changed = false
	})
	clearFlagEnv(t)
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	walletDir = ""
	catalog := filepath.Join(tmpDir, "catalog.yaml")
	if err := os.WriteFile(catalog, []byte("name: Diploma\ncredentials: [{format: jwt_vc_json, type: urn:example:diploma:1}]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EUDI_DEV_CATALOG", catalog)

	rootCmd.SetArgs([]string{"wallet", "serve", "--wallet-dir", filepath.Join(tmpDir, "wallet"), "--no-register"})
	err = rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), catalog) || !strings.Contains(err.Error(), `"Diploma"`) {
		t.Fatalf("error = %v, want one naming the file and the entry", err)
	}
}

// A container with a read-only home still serves. Only the instance
// registration fails there, and wallet serve leaves out the warning for it.
func TestReadOnlyHomeRecognizesARegistrationTheHomeRefuses(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
	t.Setenv(config.HomeEnvVar, home)

	err := remote.RegisterInstance(remote.Instance{PID: os.Getpid(), Port: 1})
	if err == nil {
		t.Skip("the home is writable, as for root")
	}
	if !readOnlyHome(err) {
		t.Errorf("readOnlyHome(%v) = false, want true", err)
	}
	if !readOnlyHome(fmt.Errorf("registering: %w", syscall.EROFS)) {
		t.Error("a read-only file system does not count")
	}
	if readOnlyHome(fmt.Errorf("registering: %w", syscall.ENOSPC)) {
		t.Error("a full disk counts as a read-only home")
	}
}
