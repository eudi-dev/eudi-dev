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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/eudi-dev/eudi-dev/v2/internal/config"
	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

func TestWalletGeneratePID_SetsIssuerURLForSDJWT(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	wDir := filepath.Join(tmpDir, "wallet")
	if err := os.MkdirAll(wDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	walletDir = wDir

	rootCmd.SetArgs([]string{"wallet", "generate-pid"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet generate-pid: %v", err)
	}

	store := wallet.NewWalletStore(wDir)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("load wallet: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) == 0 {
		t.Fatal("expected generated credentials")
	}

	token, err := sdjwt.Parse(creds[0].Raw)
	if err != nil {
		t.Fatalf("parse generated SD-JWT: %v", err)
	}

	want := wallet.LocalIssuerURL(config.DefaultWalletPort+1, false)
	if token.Payload["iss"] != want {
		t.Fatalf("expected iss %s, got %v", want, token.Payload["iss"])
	}
	status, ok := token.Payload["status"].(map[string]any)
	if !ok {
		t.Fatal("expected generated SD-JWT to contain status claim")
	}
	statusList, ok := status["status_list"].(map[string]any)
	if !ok {
		t.Fatal("expected generated SD-JWT to contain status_list reference")
	}
	if got := statusList["uri"]; got != "https://localhost:8086/api/statuslist" {
		t.Fatalf("expected status list uri https://localhost:8086/api/statuslist, got %v", got)
	}
	if len(w.StatusEntries) != 2 {
		t.Fatalf("expected generated PID credentials to register 2 status entries, got %d", len(w.StatusEntries))
	}
}

func TestWalletGeneratePID_UsesRegisteredWalletPort(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	handlerDir := filepath.Join(tmpDir, ".oid4vc-dev")
	if err := os.MkdirAll(handlerDir, 0755); err != nil {
		t.Fatalf("mkdir handler dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(handlerDir, "url-handler.sh"), []byte(`LISTENER="http://localhost:8091"`), 0755); err != nil {
		t.Fatalf("write handler: %v", err)
	}

	wDir := filepath.Join(tmpDir, "wallet")
	if err := os.MkdirAll(wDir, 0755); err != nil {
		t.Fatalf("mkdir wallet dir: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	walletDir = wDir

	rootCmd.SetArgs([]string{"wallet", "generate-pid"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet generate-pid: %v", err)
	}

	store := wallet.NewWalletStore(wDir)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("load wallet: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) == 0 {
		t.Fatal("expected generated credentials")
	}

	token, err := sdjwt.Parse(creds[0].Raw)
	if err != nil {
		t.Fatalf("parse generated SD-JWT: %v", err)
	}

	if token.Payload["iss"] != "https://localhost:8092" {
		t.Fatalf("expected iss https://localhost:8092, got %v", token.Payload["iss"])
	}
	status, ok := token.Payload["status"].(map[string]any)
	if !ok {
		t.Fatal("expected generated SD-JWT to contain status claim")
	}
	statusList, ok := status["status_list"].(map[string]any)
	if !ok {
		t.Fatal("expected generated SD-JWT to contain status_list reference")
	}
	if got := statusList["uri"]; got != "https://localhost:8092/api/statuslist" {
		t.Fatalf("expected status list uri https://localhost:8092/api/statuslist, got %v", got)
	}
}

func TestWalletGeneratePID_PreservesPersistedServingConfig(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("OID4VC_DEV_HOME", tmpDir)
	wDir := filepath.Join(tmpDir, "wallet")
	if err := os.MkdirAll(wDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	walletDir = wDir
	t.Cleanup(func() {
		walletDir = ""
		if c, _, err := rootCmd.Find([]string{"wallet", "generate-pid"}); err == nil {
			c.Flags().VisitAll(func(f *pflag.Flag) {
				_ = f.Value.Set(f.DefValue)
				f.Changed = false
			})
		}
	})

	store := wallet.NewWalletStore(wDir)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	w.BaseURL = "http://localhost:9085"
	w.IssuerURL = "https://localhost:9086"
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"wallet", "generate-pid"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet generate-pid: %v", err)
	}
	w, err = store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if w.BaseURL != "http://localhost:9085" || w.IssuerURL != "https://localhost:9086" {
		t.Fatalf("serving config rewritten: base %q issuer %q", w.BaseURL, w.IssuerURL)
	}
	token, err := sdjwt.Parse(w.GetCredentials()[0].Raw)
	if err != nil {
		t.Fatal(err)
	}
	if token.Payload["iss"] != "https://localhost:9086" {
		t.Fatalf("expected iss https://localhost:9086, got %v", token.Payload["iss"])
	}

	rootCmd.SetArgs([]string{"wallet", "generate-pid", "--base-url", "http://localhost:7085"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet generate-pid --base-url: %v", err)
	}
	w, err = store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if w.BaseURL != "http://localhost:7085" || w.IssuerURL != "https://localhost:7086" {
		t.Fatalf("explicit base url not applied: base %q issuer %q", w.BaseURL, w.IssuerURL)
	}
}

func TestWalletTLSCert_ExportsPersistentCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	wDir := filepath.Join(tmpDir, "wallet")
	outPath := filepath.Join(tmpDir, "wallet-tls-cert.pem")
	if err := os.MkdirAll(wDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	walletDir = wDir

	rootCmd.SetArgs([]string{"wallet", "tls-cert", "--out", outPath})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet tls-cert: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading exported certificate: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("expected PEM CERTIFICATE, got %q", block.Type)
	}

	store := wallet.NewWalletStore(wDir)
	want, err := store.LoadOrCreateIssuerTLSLeafCertificatePEM("localhost")
	if err != nil {
		t.Fatalf("LoadOrCreateIssuerTLSLeafCertificatePEM: %v", err)
	}
	if !bytes.Equal(data, want) {
		t.Fatal("expected exported certificate to match persisted issuer TLS leaf certificate")
	}
}

func TestWalletCACert_ExportsSharedCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	wDir := filepath.Join(tmpDir, "wallet")
	outPath := filepath.Join(tmpDir, "wallet-ca-cert.pem")
	if err := os.MkdirAll(wDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	walletDir = wDir

	rootCmd.SetArgs([]string{"wallet", "ca-cert", "--out", outPath})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet ca-cert: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading exported certificate: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("expected PEM CERTIFICATE, got %q", block.Type)
	}

	store := wallet.NewWalletStore(wDir)
	want, err := store.LoadOrCreateSharedCACertificatePEM()
	if err != nil {
		t.Fatalf("LoadOrCreateSharedCACertificatePEM: %v", err)
	}
	if !bytes.Equal(data, want) {
		t.Fatal("expected exported certificate to match persisted shared wallet CA certificate")
	}
}

func TestWalletTLSCert_PrintsSingleLeafCertificateToStdout(t *testing.T) {
	tmpDir := t.TempDir()
	wDir := filepath.Join(tmpDir, "wallet")
	if err := os.MkdirAll(wDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	walletDir = wDir

	rootCmd.SetArgs([]string{"wallet", "tls-cert", "--out="})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet tls-cert: %v", err)
	}

	out := buf.String()
	block, rest := pem.Decode([]byte(out))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("expected PEM CERTIFICATE on stdout, got %q", out)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("expected exactly one PEM certificate on stdout, got trailing data %q", string(rest))
	}

	store := wallet.NewWalletStore(wDir)
	want, err := store.LoadOrCreateIssuerTLSLeafCertificatePEM("localhost")
	if err != nil {
		t.Fatalf("LoadOrCreateIssuerTLSLeafCertificatePEM: %v", err)
	}
	if out != string(want) {
		t.Fatal("expected stdout to contain only the wallet TLS leaf certificate")
	}
}

func TestWalletCACert_PrintsSingleCertificateToStdout(t *testing.T) {
	tmpDir := t.TempDir()
	wDir := filepath.Join(tmpDir, "wallet")
	if err := os.MkdirAll(wDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	walletDir = wDir

	rootCmd.SetArgs([]string{"wallet", "ca-cert", "--out="})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet ca-cert: %v", err)
	}

	out := buf.String()
	block, rest := pem.Decode([]byte(out))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("expected PEM CERTIFICATE on stdout, got %q", out)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("expected exactly one PEM certificate on stdout, got trailing data %q", string(rest))
	}

	store := wallet.NewWalletStore(wDir)
	want, err := store.LoadOrCreateSharedCACertificatePEM()
	if err != nil {
		t.Fatalf("LoadOrCreateSharedCACertificatePEM: %v", err)
	}
	if out != string(want) {
		t.Fatal("expected stdout to contain only the shared wallet CA certificate")
	}
}

func resetCertFormatFlags(t *testing.T, subcommand string) {
	t.Helper()
	t.Cleanup(func() {
		cmd, _, err := rootCmd.Find([]string{"wallet", subcommand})
		if err != nil {
			return
		}
		_ = cmd.Flags().Set("jwks", "false")
		_ = cmd.Flags().Set("pem", "false")
	})
}

func TestWalletCACert_ExportsJWKS(t *testing.T) {
	tmpDir := t.TempDir()
	wDir := filepath.Join(tmpDir, "wallet")
	if err := os.MkdirAll(wDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	resetCertFormatFlags(t, "ca-cert")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	walletDir = wDir

	rootCmd.SetArgs([]string{"wallet", "ca-cert", "--out=", "--jwks"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet ca-cert --jwks: %v", err)
	}

	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(buf.Bytes(), &jwks); err != nil {
		t.Fatalf("parsing JWKS output: %v\n%s", err, buf.String())
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key in JWKS, got %d", len(jwks.Keys))
	}
	jwk := jwks.Keys[0]
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["alg"] != "ES256" {
		t.Fatalf("unexpected JWK: %v", jwk)
	}
	if _, hasD := jwk["d"]; hasD {
		t.Fatal("JWKS output must not contain private key material")
	}

	store := wallet.NewWalletStore(wDir)
	certPEM, err := store.LoadOrCreateSharedCACertificatePEM()
	if err != nil {
		t.Fatalf("LoadOrCreateSharedCACertificatePEM: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	x5c, ok := jwk["x5c"].([]any)
	if !ok || len(x5c) != 1 {
		t.Fatalf("expected x5c with 1 entry, got %v", jwk["x5c"])
	}
	if x5c[0] != base64.StdEncoding.EncodeToString(block.Bytes) {
		t.Fatal("x5c entry does not match the shared wallet CA certificate")
	}
}

func TestWalletTLSCert_ExportsJWKS(t *testing.T) {
	tmpDir := t.TempDir()
	wDir := filepath.Join(tmpDir, "wallet")
	if err := os.MkdirAll(wDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	resetCertFormatFlags(t, "tls-cert")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	walletDir = wDir

	rootCmd.SetArgs([]string{"wallet", "tls-cert", "--out=", "--jwks"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet tls-cert --jwks: %v", err)
	}

	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(buf.Bytes(), &jwks); err != nil {
		t.Fatalf("parsing JWKS output: %v\n%s", err, buf.String())
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key in JWKS, got %d", len(jwks.Keys))
	}
	jwk := jwks.Keys[0]
	if jwk["kty"] != "EC" {
		t.Fatalf("unexpected JWK: %v", jwk)
	}

	store := wallet.NewWalletStore(wDir)
	certPEM, err := store.LoadOrCreateIssuerTLSLeafCertificatePEM("localhost")
	if err != nil {
		t.Fatalf("LoadOrCreateIssuerTLSLeafCertificatePEM: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	x5c, ok := jwk["x5c"].([]any)
	if !ok || len(x5c) != 1 {
		t.Fatalf("expected x5c with 1 entry, got %v", jwk["x5c"])
	}
	if x5c[0] != base64.StdEncoding.EncodeToString(block.Bytes) {
		t.Fatal("x5c entry does not match the wallet TLS leaf certificate")
	}
}

func TestWalletCACert_PEMAndJWKSAreMutuallyExclusive(t *testing.T) {
	tmpDir := t.TempDir()
	wDir := filepath.Join(tmpDir, "wallet")
	if err := os.MkdirAll(wDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	resetCertFormatFlags(t, "ca-cert")

	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	walletDir = wDir

	rootCmd.SetArgs([]string{"wallet", "ca-cert", "--out=", "--pem", "--jwks"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected error when both --pem and --jwks are set")
	}
}

func TestWalletGeneratePID_PrintsDeprecationWarning(t *testing.T) {
	wDir := t.TempDir()
	prevDir := walletDir
	walletDir = wDir
	t.Cleanup(func() { walletDir = prevDir })

	errBuf := new(bytes.Buffer)
	rootCmd.SetErr(errBuf)
	t.Cleanup(func() { rootCmd.SetErr(nil) })

	rootCmd.SetArgs([]string{"wallet", "generate-pid", "--claims", `{"given_name":"MAX"}`})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("generate-pid: %v", err)
	}

	out := errBuf.String()
	if !strings.Contains(out, "deprecated") {
		t.Errorf("expected deprecation warning, got %q", out)
	}
	if !strings.Contains(out, "issue sdjwt --wallet --template pid-sdjwt --claims '{\"given_name\":\"MAX\"}'") {
		t.Errorf("expected equivalent sdjwt command with claims, got %q", out)
	}
	if !strings.Contains(out, "issue mdoc --wallet --template pid-mdoc") {
		t.Errorf("expected equivalent mdoc command, got %q", out)
	}
}

// The equivalent command has to list the templates the requested PID type is
// generated from. Otherwise following it produces a different credential.
func TestWalletGeneratePID_DeprecationWarningNamesTheGermanTemplates(t *testing.T) {
	wDir := t.TempDir()
	prevDir := walletDir
	walletDir = wDir
	t.Cleanup(func() { walletDir = prevDir })

	errBuf := new(bytes.Buffer)
	rootCmd.SetErr(errBuf)
	t.Cleanup(func() { rootCmd.SetErr(nil) })

	rootCmd.SetArgs([]string{"wallet", "generate-pid", "--vct", mock.GermanPIDVCT})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("generate-pid: %v", err)
	}

	out := errBuf.String()
	if !strings.Contains(out, "issue sdjwt --wallet --template german-pid-sdjwt") {
		t.Errorf("expected the German sdjwt template, got %q", out)
	}
	if !strings.Contains(out, "issue mdoc --wallet --template german-pid-mdoc") {
		t.Errorf("expected the German mdoc template, got %q", out)
	}
	// The template carries the vct, so repeating the flag would suggest the
	// flag is what picks the claim set.
	if strings.Contains(out, "--vct") {
		t.Errorf("the equivalent command should not repeat --vct, got %q", out)
	}
}
