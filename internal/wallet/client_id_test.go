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

package wallet

import (
	"encoding/json"
	"net/http"
	"testing"
)

// OpenID4VCI 1.0 Appendix E: "this value is the same across Wallet instances of
// that Wallet Provider".
func TestTheAttestationClientIDIsStableAndDependsOnTheWalletProviderKey(t *testing.T) {
	first := newTestServer(t, true)
	id, err := first.wallet.attestationClientID()
	if err != nil {
		t.Fatal(err)
	}
	again, err := first.wallet.attestationClientID()
	if err != nil || again != id || len(id) != 24 {
		t.Fatalf("id %q then %q (%v)", id, again, err)
	}
	other, err := newTestServer(t, true).wallet.attestationClientID()
	if err != nil {
		t.Fatal(err)
	}
	if other == id {
		t.Error("two wallet providers share a client ID")
	}
}

func TestAConfiguredClientIDReplacesTheDerivedOne(t *testing.T) {
	srv := newTestServer(t, true)
	fixed := "wallet-client"
	if err := srv.wallet.UpdateConformance(ConformancePatch{VCIClientID: &fixed}); err != nil {
		t.Fatal(err)
	}
	if id, err := srv.wallet.attestationClientID(); err != nil || id != fixed {
		t.Errorf("id %q (%v)", id, err)
	}
}

func TestTheConfigShowsTheAttestationClientID(t *testing.T) {
	srv := newTestServer(t, true)
	want, err := srv.wallet.attestationClientID()
	if err != nil {
		t.Fatal(err)
	}
	rec := serverRequest(t, srv, http.MethodGet, "/api/config", "")
	var config map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if config["attestation_client_id"] != want {
		t.Errorf("config has %v, want %s", config["attestation_client_id"], want)
	}
}
