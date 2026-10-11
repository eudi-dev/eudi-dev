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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/remote"
	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

func runWalletListWithMode(t *testing.T, mode string) error {
	t.Helper()
	t.Cleanup(func() {
		walletValidationMode = string(wallet.ValidationModeDebug)
		walletCmd.PersistentFlags().Lookup("mode").Changed = false
	})
	rootCmd.SetArgs([]string{"wallet", "list", "--mode", mode})
	return rootCmd.Execute()
}

// A running wallet applies its settings to every step of a flow. A flag with
// the wallet's own value changes nothing, so only a differing flag fails.
func TestRunningWalletRefusesOnlyDifferingModeOnTheRemoteRoute(t *testing.T) {
	resetRemoteTestState(t)
	url, _ := startRemoteTestWallet(t)
	if _, err := remote.SetActive(url); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = remote.SetActive("") })

	if err := runWalletListWithMode(t, "debug"); err != nil {
		t.Fatalf("the wallet's own mode was refused: %v", err)
	}
	err := runWalletListWithMode(t, "strict")
	if err == nil || !strings.Contains(err.Error(), "--mode is debug on the running wallet") {
		t.Fatalf("a differing mode: %v", err)
	}
}

// The outbound HTTP flags follow the same rule as --mode on every managed
// command.
func TestRunningWalletRefusesOnlyDifferingTLSVerify(t *testing.T) {
	resetRemoteTestState(t)
	url, _ := startRemoteTestWallet(t)
	flag := walletCmd.PersistentFlags().Lookup("tls-verify")
	t.Cleanup(func() { _ = flag.Value.Set(flag.DefValue); flag.Changed = false })
	run := func(value string) error {
		flag.Changed = false
		rootCmd.SetArgs([]string{"wallet", "list", "--remote", url, "--tls-verify=" + value})
		return rootCmd.Execute()
	}
	if err := run("false"); err != nil {
		t.Fatalf("the wallet's own --tls-verify was refused: %v", err)
	}
	if err := run("true"); err == nil || !strings.Contains(err.Error(), "--tls-verify is off on the running wallet") {
		t.Fatalf("a differing --tls-verify: %v", err)
	}
}

func TestRunningWalletRefusesOnlyDifferingModeOnTheLocalServerRoute(t *testing.T) {
	resetRemoteTestState(t)
	useLocalTestWallet(t)
	url, _ := startRemoteTestWallet(t)
	if err := remote.RegisterInstance(remote.Instance{
		PID: os.Getpid(), Port: portFromURL(t, url), URL: url,
		WalletDir: wallet.NewWalletStore(walletDir).Dir, StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	if err := runWalletListWithMode(t, "debug"); err != nil {
		t.Fatalf("the wallet's own mode was refused: %v", err)
	}
	if err := runWalletListWithMode(t, "strict"); err == nil || !strings.Contains(err.Error(), "--mode is debug") {
		t.Fatalf("a differing mode: %v", err)
	}
}

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test RP CA"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// The conformance flags of accept and scan compare with the running wallet's
// settings and trusted lists.
func TestRunningWalletComparesConformanceFlags(t *testing.T) {
	resetRemoteTestState(t)
	trusted := testCAPEM(t)
	holderKey, _ := mock.GenerateKey()
	issuerKey, _ := mock.GenerateKey()
	w := wallet.New(holderKey, issuerKey, false)
	w.RequireHAIP = true
	w.RelyingPartyCAPEM = trusted
	srv := wallet.NewServer(w, 0, nil)
	srv.ShutdownFunc = func() {}
	addr, err := srv.ListenAndServeBackground()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Shutdown)
	c := remote.NewClient(addr)

	same := walletConformance{settings: wallet.ConformanceSettings{ValidationMode: wallet.ValidationModeDebug, RequireHAIP: true}, relyingPartyCAPEM: trusted}
	if err := checkRemoteSettings(c, []string{"--haip", "--relying-party-ca"}, same); err != nil {
		t.Fatalf("flags with the wallet's own values were refused: %v", err)
	}

	differ := walletConformance{settings: wallet.ConformanceSettings{ValidationMode: wallet.ValidationModeDebug}, relyingPartyCAPEM: testCAPEM(t)}
	err = checkRemoteSettings(c, []string{"--haip", "--relying-party-ca"}, differ)
	if err == nil || !strings.Contains(err.Error(), "--haip is set on the running wallet") || !strings.Contains(err.Error(), "--relying-party-ca names 1 CA certificates the running wallet does not trust") {
		t.Fatalf("differing flags: %v", err)
	}
}

// accept, scan and serve share the conformance flags, and the flags apply
// every setting to the wallet.
func TestConformanceFlagsApplyEverySetting(t *testing.T) {
	for _, cmd := range []*cobra.Command{walletAcceptCmd(), walletScanCmd(), walletServeCmd()} {
		for _, name := range conformanceFlagNames {
			if cmd.Flags().Lookup(name) == nil {
				t.Errorf("%s has no --%s", cmd.Name(), name)
			}
		}
	}

	cmd := &cobra.Command{Use: "accept"}
	flags := addConformanceFlags(cmd)
	if err := cmd.ParseFlags([]string{"--haip", "--arf", "--require-encrypted-request", "--client-attestation", "--vci-version", "1.1", "--key-attestation-level", "none"}); err != nil {
		t.Fatal(err)
	}
	conformance, err := flags.resolve()
	if err != nil {
		t.Fatal(err)
	}
	w := newTestServeWallet(t)
	conformance.apply(w)
	got := w.Conformance()
	if !got.RequireHAIP || !got.RequireARF || !got.RequireEncryptedRequest || !got.ForceClientAttestation || got.VCIVersion != wallet.VCIVersion11 || got.KeyAttestationLevel != "none" {
		t.Errorf("applied %+v", got)
	}
}
