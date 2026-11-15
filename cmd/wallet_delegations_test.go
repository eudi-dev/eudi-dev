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
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// addDelegations stores an active and an expired delegation record on the
// credential.
func addDelegations(t *testing.T, wDir, credID string) {
	t.Helper()
	store := wallet.NewWalletStore(wDir)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	past := time.Now().Add(-time.Hour).Truncate(time.Second)
	for i := range w.Credentials {
		if w.Credentials[i].ID != credID {
			continue
		}
		w.Credentials[i].Delegations = []wallet.DelegationRecord{
			{
				ID: "active", Name: "Acme Shop", Format: "dSD-JWT+KB", SignedAt: past,
				Delegates: []wallet.DelegationDelegate{{
					KeyThumbprint: "rezr_f2zQx1aBcDeFgHiJkLmNoPhsKj0U",
					Payload:       map[string]any{"currency": "EUR", "max_amount": 400, "agent": map[string]any{"id": "urn:example:agent:1"}, "exp": future.Unix()},
					ExpiresAt:     &future,
				}},
			},
			{
				ID: "ended", Name: "Bolt Travel", Format: "dSD-JWT", SignedAt: past.Add(-time.Hour),
				Delegates: []wallet.DelegationDelegate{{
					Payload:   map[string]any{"purpose": "Book a train", "exp": past.Unix()},
					ExpiresAt: &past,
				}},
			},
		}
	}
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}
}

func runWallet(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() {
		rootCmd.SetArgs(append(args, "--remote", "local"))
		err = rootCmd.Execute()
	})
	return out, err
}

func TestWalletDelegationsListsTheActiveRecords(t *testing.T) {
	wDir, credID := setupWalletWithCredential(t)
	walletDir = wDir
	t.Cleanup(func() { jsonOutput = false })

	out, err := runWallet(t, "wallet", "delegations", credID)
	if err != nil {
		t.Fatal(err)
	}
	if out != "This credential has no active delegation.\n" {
		t.Errorf("without records: %q", out)
	}
	out, err = runWallet(t, "wallet", "delegations", credID, "--all")
	if err != nil {
		t.Fatal(err)
	}
	if out != "This credential has no delegation records.\n" {
		t.Errorf("without records, with --all: %q", out)
	}

	addDelegations(t, wDir, credID)
	out, err = runWallet(t, "wallet", "delegations", credID, "--all=false")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(out, "\n")
	if len(lines) != 4 || lines[0] != "Acme Shop" || !strings.HasPrefix(lines[1], "  Until ") ||
		lines[2] != "  agent, currency: EUR, max_amount: 400, key: rezr_f2z…hsKj0U" {
		t.Errorf("active records:\n%s", out)
	}

	out, err = runWallet(t, "wallet", "delegations", credID, "--all")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "Acme Shop\n") || !strings.Contains(out, "\n\nBolt Travel\n  Expired ") || !strings.HasSuffix(out, "  purpose: Book a train\n") {
		t.Errorf("--all:\n%s", out)
	}

	out, err = runWallet(t, "wallet", "delegations", credID, "--all=false", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var records []map[string]any
	if err := json.Unmarshal([]byte(out), &records); err != nil {
		t.Fatalf("--json: %v\n%s", err, out)
	}
	if len(records) != 1 || records[0]["id"] != "active" || records[0]["expired"] != false {
		t.Errorf("--json: %s", out)
	}
}

func TestWalletDelegationsRefusesAnUnknownCredential(t *testing.T) {
	wDir, _ := setupWalletWithCredential(t)
	walletDir = wDir
	_, showErr := runWallet(t, "wallet", "show", "unknown")
	_, err := runWallet(t, "wallet", "delegations", "unknown")
	if err == nil || showErr == nil || err.Error() != showErr.Error() {
		t.Errorf("delegations: %v, show: %v", err, showErr)
	}
}

func TestWalletListCountsActiveDelegations(t *testing.T) {
	wDir, credID := setupWalletWithCredential(t)
	walletDir = wDir
	out, err := runWallet(t, "wallet", "list")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "delegation") {
		t.Errorf("without records:\n%s", out)
	}
	addDelegations(t, wDir, credID)
	out, err = runWallet(t, "wallet", "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out, "  1 active delegation\n") {
		t.Errorf("with records:\n%s", out)
	}
	out, err = runWallet(t, "wallet", "show", credID, "--decoded")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "\nDelegations: 1 active delegation\n") {
		t.Errorf("show --decoded:\n%s", out)
	}
	stderr := captureStderr(t, func() { _, err = runWallet(t, "wallet", "show", credID, "--decoded=false") })
	if err != nil || stderr != "1 active delegation. See eudi wallet delegations "+credID+".\n" {
		t.Errorf("show: %v, stderr %q", err, stderr)
	}
}

func TestPrintDelegations(t *testing.T) {
	until := time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)
	records := []delegationListing{
		{Name: "Acme Shop", ExpiresAt: &until},
		{Name: "Bolt Travel"},
		{Name: "Crate Rentals", Revoked: true, ExpiresAt: &until},
	}
	var out strings.Builder
	printDelegations(&out, records, false, time.UTC)
	want := "Acme Shop\n  Until Fri, 20 Nov 2026 09:30:00 UTC\n\nBolt Travel\n  No expiry\n\nCrate Rentals\n  Credential revoked\n"
	if out.String() != want {
		t.Errorf("got\n%s\nwant\n%s", out.String(), want)
	}
}
