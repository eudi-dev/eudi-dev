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

package web

import (
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

func trustCheck(t *testing.T, raw string, store *wallet.WalletStore) CheckResult {
	t.Helper()
	result, err := Validate(raw, ValidateOpts{WalletStore: store})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range result["validation"].(map[string]any)["checks"].([]CheckResult) {
		if c.Name == "trust" {
			return c
		}
	}
	t.Fatal("no trust check")
	return CheckResult{}
}

// The decoder validates a credential with the trusted lists of its entry in
// the attestation catalogue, as the wallet does on issuance.
func TestTheDecoderAnchorsACatalogueTypeWithItsTrustedLists(t *testing.T) {
	store := wallet.NewWalletStore(t.TempDir())
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}
	for _, cred := range w.GetCredentials() {
		check := trustCheck(t, cred.Raw, store)
		if check.Status != "pass" || check.Anchor == nil || !strings.HasSuffix(check.Anchor.ListURL, "/api/trustlists/pid") || check.Anchor.Service != "issuance" {
			t.Errorf("%s: %+v, want anchored by the issuance service of the PID list", cred.Format, check)
		}
	}
}

func TestTheDecoderSkipsTheTrustCheckForATypeOutsideTheCatalogue(t *testing.T) {
	store := wallet.NewWalletStore(t.TempDir())
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}
	key, _ := mock.GenerateKey()
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{Issuer: "https://issuer.example", VCT: "urn:example:unknown:1", ExpiresIn: time.Hour, Claims: map[string]any{"a": 1}, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if check := trustCheck(t, raw, store); check.Status != "skipped" || !strings.Contains(check.Detail, "no entry") {
		t.Errorf("%+v, want skipped without a catalogue entry", check)
	}
}

// Trust comes only from an existing wallet. A store without a wallet gives
// the decoder no catalogue, and the decoder leaves the store empty.
func TestTheDecoderCreatesNoWallet(t *testing.T) {
	store := wallet.NewWalletStore(t.TempDir())
	key, _ := mock.GenerateKey()
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{Issuer: "https://issuer.example", VCT: "urn:example:unknown:1", ExpiresIn: time.Hour, Claims: map[string]any{"a": 1}, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if check := trustCheck(t, raw, store); check.Status != "skipped" || check.Detail != "No wallet with an attestation catalogue" {
		t.Errorf("%+v, want skipped without a wallet", check)
	}
	if exists, err := store.Exists(); err != nil || exists {
		t.Errorf("the decoder created a wallet (%v)", err)
	}
}
