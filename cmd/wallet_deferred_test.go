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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// stillPendingIssuer answers every Deferred Credential Request with 202 and
// the transaction id (OpenID4VCI 1.0 §9.2).
func stillPendingIssuer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-credential-issuer" {
			issuer := "http://" + r.Host
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":            issuer,
				"credential_endpoint":          issuer + "/credential",
				"deferred_credential_endpoint": issuer + "/deferred",
			})
			return
		}
		rw.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(rw).Encode(map[string]any{"transaction_id": "tx-cli", "interval": 45})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestWalletDeferredCommandsPrintJSON(t *testing.T) {
	resetRemoteTestState(t)
	issuer := stillPendingIssuer(t)
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	w := wallet.New(holderKey, issuerKey, false)
	w.AddDeferredIssuance(&wallet.DeferredIssuance{
		ID: "deferred-cli", TransactionID: "tx-cli", DeferredEndpoint: issuer.URL + "/deferred",
		CredentialRenewal: wallet.CredentialRenewal{Issuer: issuer.URL, ConfigurationID: "pid"},
		Format:            "dc+sd-jwt", AccessToken: "token", AuthScheme: "Bearer",
		IntervalSeconds: 45,
		// The server's poller leaves the record alone until then.
		NextAttemptAt: time.Now().Add(time.Hour),
	})
	srv := wallet.NewServer(w, 0, nil)
	srv.ShutdownFunc = func() {}
	url, err := srv.ListenAndServeBackground()
	if err != nil {
		t.Fatal(err)
	}

	text := captureStdout(t, func() {
		resetFlags(rootCmd)
		rootCmd.SetArgs([]string{"wallet", "deferred", "--remote", url})
		if err := rootCmd.Execute(); err != nil {
			t.Errorf("wallet deferred: %v", err)
		}
	})
	resetFlags(rootCmd)
	for _, want := range []string{"pid", "deferred-cli", "tx-cli", issuer.URL} {
		if !strings.Contains(text, want) {
			t.Errorf("wallet deferred printed %q, want it to mention %q", text, want)
		}
	}

	checked := runJSON(t, "wallet", "deferred", "check", "deferred-cli", "--remote", url)
	if checked["pending"] != true || checked["collected"] != false || checked["interval"] != "45s" || checked["next_attempt_at"] == nil {
		t.Errorf("wallet deferred check <id> printed %v, want a pending result with the issuer's interval", checked)
	}

	var all []map[string]any
	runJSONInto(t, &all, "wallet", "deferred", "check", "--remote", url)
	if len(all) != 1 || all[0]["pending"] != true {
		t.Errorf("wallet deferred check printed %v, want one pending result", all)
	}

	abandoned := runJSON(t, "wallet", "deferred", "abandon", "deferred-cli", "--remote", url)
	if abandoned["abandoned"] != true || abandoned["issuer"] != issuer.URL || abandoned["transaction_id"] != "tx-cli" {
		t.Errorf("wallet deferred abandon printed %v, want the issuer and transaction it stopped collecting", abandoned)
	}

	var none []any
	runJSONInto(t, &none, "wallet", "deferred", "check", "--remote", url)
	if len(none) != 0 {
		t.Errorf("wallet deferred check with nothing deferred printed %v, want []", none)
	}
}
