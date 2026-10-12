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
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

func protectedStatusIndex(t *testing.T, srv *Server) (string, int) {
	t.Helper()
	for _, c := range srv.wallet.GetCredentials() {
		if entry, ok := srv.wallet.StatusEntryFor(c.ID); ok {
			return c.ID, entry.Index
		}
	}
	t.Fatal("no credential on the wallet's status list")
	return "", 0
}

// A status change applies to every credential on an index. A visitor must
// not get a credential on the index of another one, such as the shared PID.
func TestIssueRefusesTheStatusIndexOfAnotherCredential(t *testing.T) {
	srv := newTestServerWithStatusList(t)
	_, taken := protectedStatusIndex(t, srv)

	resp := serverRequest(t, srv, http.MethodPost, "/api/issue",
		fmt.Sprintf(`{"format":"sdjwt","vct":"urn:test:status","claims":{"a":"b"},"status_list_idx":%d}`, taken))
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("issuing on a taken index answered %d: %s", resp.Code, resp.Body.String())
	}
}

// The list covers only the indices the wallet assigned. A revocation on any
// other index would report success and change nothing.
func TestIssueRefusesAStatusIndexTheWalletDidNotAssign(t *testing.T) {
	srv := newTestServerWithStatusList(t)
	beyond := srv.wallet.statusIndexFor(srv.wallet.StatusListCounter + 5)

	resp := serverRequest(t, srv, http.MethodPost, "/api/issue",
		fmt.Sprintf(`{"format":"sdjwt","vct":"urn:test:status","claims":{"a":"b"},"status_list_idx":%d}`, beyond))
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("issuing on an unassigned index answered %d: %s", resp.Code, resp.Body.String())
	}
}

// Naming the wallet's own list without an index takes a fresh index.
func TestIssueOnTheOwnStatusListAssignsAFreshIndex(t *testing.T) {
	srv := newTestServerWithStatusList(t)
	next := srv.wallet.statusIndexFor(srv.wallet.StatusListCounter)
	uri := srv.wallet.StatusListURL()

	summary, err := srv.management().Issue(IssueAPIRequest{Format: "sdjwt", VCT: "urn:test:status", Claims: map[string]any{"a": "b"}, StatusListURI: &uri})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	if got := summary["status_list_idx"]; got != next {
		t.Fatalf("status_list_idx = %v, want the fresh index %d", got, next)
	}
}

// An imported credential that names the index of another credential on the
// wallet's list does not take over that index.
func TestImportDoesNotTakeOverTheStatusIndexOfAnotherCredential(t *testing.T) {
	srv := newTestServerWithStatusList(t)
	ownerID, taken := protectedStatusIndex(t, srv)
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:        "https://issuer.example",
		VCT:           "urn:test:status",
		ExpiresIn:     3600,
		Claims:        map[string]any{"a": "b"},
		Key:           srv.wallet.IssuerKey,
		StatusListURI: srv.wallet.StatusListURL(),
		StatusListIdx: taken,
	})
	if err != nil {
		t.Fatal(err)
	}
	imported, err := srv.management().ImportCredential(raw)
	if err != nil {
		t.Fatalf("importing: %v", err)
	}
	if _, managed := srv.wallet.StatusEntryFor(imported["id"].(string)); managed {
		t.Fatal("the import took over the status index of another credential")
	}
	if entry, ok := srv.wallet.StatusEntryFor(ownerID); !ok || entry.Index != taken {
		t.Fatalf("the owner's status entry changed: %+v %v", entry, ok)
	}
}

// HAIP 1.0 §6.1: "Each Credential MUST have its own unique, unpredictable
// status list index". Each wallet keys its own order, and the list stays at
// most twice as long as the indices it assigned.
func TestStatusIndicesAreUniqueAndUnpredictable(t *testing.T) {
	const count = 300
	sequences := make([][]int, 2)
	for i := range sequences {
		w := generateTestWallet(t)
		seen := map[int]bool{}
		for range count {
			idx, err := w.NextStatusIndex()
			if err != nil {
				t.Fatal(err)
			}
			if seen[idx] {
				t.Fatalf("index %d was assigned twice", idx)
			}
			if idx < 0 || idx >= statusListSize(w.StatusListCounter) {
				t.Fatalf("index %d lies outside the list of %d entries", idx, statusListSize(w.StatusListCounter))
			}
			if err := w.statusIndexFree(idx, ""); err != nil {
				t.Fatalf("the assigned index %d reads as unassigned: %v", idx, err)
			}
			seen[idx] = true
			sequences[i] = append(sequences[i], idx)
		}
		if size := statusListSize(w.StatusListCounter); size > 2*count {
			t.Errorf("the list has %d entries for %d indices", size, count)
		}
	}
	if slices.Equal(sequences[0], sequences[1]) {
		t.Error("two wallets assign their indices in the same order")
	}
	if slices.IsSorted(sequences[0]) {
		t.Error("the indices follow the order of assignment")
	}
}
