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
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
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
	beyond := srv.wallet.StatusListCounter + 5

	resp := serverRequest(t, srv, http.MethodPost, "/api/issue",
		fmt.Sprintf(`{"format":"sdjwt","vct":"urn:test:status","claims":{"a":"b"},"status_list_idx":%d}`, beyond))
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("issuing on an unassigned index answered %d: %s", resp.Code, resp.Body.String())
	}
}

// Naming the wallet's own list without an index takes a fresh index.
func TestIssueOnTheOwnStatusListAssignsAFreshIndex(t *testing.T) {
	srv := newTestServerWithStatusList(t)
	next := srv.wallet.StatusListCounter
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
