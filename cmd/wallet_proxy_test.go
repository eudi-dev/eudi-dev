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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

func TestWalletProxyFlags(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("NO_PROXY", "")
	var proxied atomic.Int32
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer proxyServer.Close()
	originalHTTP, originalNo := walletHTTPProxy, walletNoProxy
	t.Cleanup(func() { walletHTTPProxy, walletNoProxy = originalHTTP, originalNo })

	for _, tc := range []struct {
		name, noProxy string
		wantProxied   bool
	}{
		{name: "proxied", wantProxied: true},
		{name: "bypassed", noProxy: "issuer.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxied.Store(0)
			walletHTTPProxy, walletNoProxy = proxyServer.URL, tc.noProxy
			w := &wallet.Wallet{}
			if err := applyWalletOutbound(w); err != nil {
				t.Fatal(err)
			}
			defer w.HTTPClient().CloseIdleConnections()
			resp, err := w.HTTPClient().Get("http://issuer.example/offer")
			if resp != nil {
				resp.Body.Close()
			}
			if tc.wantProxied {
				if err != nil || proxied.Load() != 1 {
					t.Fatalf("request did not go through the proxy: %v", err)
				}
			} else if proxied.Load() != 0 {
				t.Fatal("--no-proxy host went through the proxy")
			}
		})
	}

	walletHTTPProxy, walletNoProxy = "ftp://proxy.example", ""
	if err := applyWalletOutbound(&wallet.Wallet{}); err == nil {
		t.Fatal("invalid proxy URL accepted")
	}
}

func TestRemoteWalletProxyFlagsAreNotIgnored(t *testing.T) {
	var calls atomic.Int32
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/config" {
			calls.Add(1)
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer remoteServer.Close()
	flag := walletCmd.PersistentFlags().Lookup("https-proxy")
	originalProxy, originalChanged, originalRemote := walletHTTPSProxy, flag.Changed, remoteFlag
	t.Cleanup(func() { walletHTTPSProxy, flag.Changed, remoteFlag = originalProxy, originalChanged, originalRemote })
	remoteFlag = remoteServer.URL
	if err := walletCmd.PersistentFlags().Set("https-proxy", "http://proxy.example:3128"); err != nil {
		t.Fatal(err)
	}
	err := acceptOID4URI("openid-credential-offer://?credential_offer_uri=https://issuer.example/offer", dispatchOID4Opts{})
	if err == nil || !strings.Contains(err.Error(), "proxy settings of the running wallet") {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("forwarded a flow without applying its explicit proxy configuration")
	}
}
