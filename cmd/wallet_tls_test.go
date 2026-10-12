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
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

func TestWalletTLSFlags(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	flag := walletCmd.PersistentFlags().Lookup("tls-verify")
	originalVerify, originalCA, originalChanged := walletTLSVerify, walletTLSCA, flag.Changed
	t.Cleanup(func() { walletTLSVerify, walletTLSCA, flag.Changed = originalVerify, originalCA, originalChanged })
	for _, tc := range []struct {
		name   string
		mode   wallet.ValidationMode
		flag   string
		ca     string
		reject bool
	}{
		{name: "strict default", mode: wallet.ValidationModeStrict, reject: true},
		{name: "debug default", mode: wallet.ValidationModeDebug},
		{name: "strict false", mode: wallet.ValidationModeStrict, flag: "false"},
		{name: "debug true", mode: wallet.ValidationModeDebug, flag: "true", reject: true},
		{name: "strict CA", mode: wallet.ValidationModeStrict, ca: caPath},
		{name: "debug true CA", mode: wallet.ValidationModeDebug, flag: "true", ca: caPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flag.Changed = false
			walletTLSCA = tc.ca
			if tc.flag != "" {
				if err := walletCmd.PersistentFlags().Set("tls-verify", tc.flag); err != nil {
					t.Fatal(err)
				}
			}
			w := &wallet.Wallet{ValidationMode: tc.mode}
			if err := applyWalletOutbound(w); err != nil {
				t.Fatal(err)
			}
			defer w.HTTPClient().CloseIdleConnections()
			resp, err := w.HTTPClient().Get(server.URL)
			if resp != nil {
				resp.Body.Close()
			}
			if tc.reject {
				var certErr *tls.CertificateVerificationError
				if !errors.As(err, &certErr) {
					t.Fatalf("expected TLS rejection, got %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, tc := range []struct{ name, bundle string }{{"missing", ""}, {"empty", ""}, {"invalid", "not a certificate"}} {
		t.Run(tc.name, func(t *testing.T) {
			walletTLSCA = filepath.Join(t.TempDir(), "invalid.pem")
			if tc.name != "missing" {
				if err := os.WriteFile(walletTLSCA, []byte(tc.bundle), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := applyWalletOutbound(&wallet.Wallet{}); err == nil {
				t.Fatal("invalid CA bundle accepted")
			}
		})
	}
}

func TestRemoteWalletTLSFlagsAreNotIgnored(t *testing.T) {
	var calls atomic.Int32
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = io.WriteString(w, `{}`) }))
	defer remoteServer.Close()
	flag := walletCmd.PersistentFlags().Lookup("tls-verify")
	originalVerify, originalChanged, originalRemote := walletTLSVerify, flag.Changed, remoteFlag
	t.Cleanup(func() { walletTLSVerify, flag.Changed, remoteFlag = originalVerify, originalChanged, originalRemote })
	remoteFlag = remoteServer.URL
	if err := walletCmd.PersistentFlags().Set("tls-verify", "false"); err != nil {
		t.Fatal(err)
	}
	err := acceptOID4URI("openid-credential-offer://?credential_offer_uri=https://issuer.example/offer", dispatchOID4Opts{})
	if err == nil || !strings.Contains(err.Error(), "running wallet uses its own TLS settings") {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("forwarded a flow without applying its explicit TLS configuration")
	}
}
