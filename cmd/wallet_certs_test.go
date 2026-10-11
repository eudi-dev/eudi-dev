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

	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

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

	rootCmd.SetArgs([]string{"trust", "ca-cert", "--out", outPath})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("trust ca-cert: %v", err)
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

	rootCmd.SetArgs([]string{"trust", "ca-cert", "--out="})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("trust ca-cert: %v", err)
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

	rootCmd.SetArgs([]string{"trust", "ca-cert", "--out=", "--jwks"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("trust ca-cert --jwks: %v", err)
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

	rootCmd.SetArgs([]string{"trust", "ca-cert", "--out=", "--pem", "--jwks"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected error when both --pem and --jwks are set")
	}
}
