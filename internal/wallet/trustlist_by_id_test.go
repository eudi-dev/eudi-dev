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
	"net/http"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
)

func servedList(t *testing.T, srv *Server, path string) (*lote.List, string) {
	t.Helper()
	resp := serverRequest(t, srv, "GET", path, "")
	if resp.Code != http.StatusOK || resp.Header().Get("Content-Type") != "application/jwt" {
		t.Fatalf("GET %s: %d %s %s", path, resp.Code, resp.Header().Get("Content-Type"), resp.Body.String())
	}
	list, err := lote.Parse(resp.Body.String())
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return list, resp.Body.String()
}

// Each list published by the wallet has its own URL. That URL serves the first
// instance in the list's history.
func TestTrustListByIDServesEachList(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"
	srv := NewServer(w, 0, nil)

	groups := w.TrustedLists().Groups()
	if len(groups) < 3 {
		t.Fatalf("groups %v, want the lists of every category", groups)
	}
	for _, group := range groups {
		path := "/api/trustlists/" + group.ID
		list, raw := servedList(t, srv, path)
		if list.SchemeInfo.LoTEType != group.List.LoTEType {
			t.Errorf("%s: type %q, want %q", path, list.SchemeInfo.LoTEType, group.List.LoTEType)
		}
		if history := serverRequest(t, srv, "GET", path+"/history/1", ""); history.Body.String() != raw {
			t.Errorf("%s/history/1: %d, want the served instance", path, history.Code)
		}
	}
}

func TestTrustListByIDServesTheListOfLists(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"
	srv := NewServer(w, 0, nil)

	list, _ := servedList(t, srv, "/api/trustlists/"+trustedlists.ListOfListsID)
	if list.SchemeInfo.LoTEType != trustedlists.ListOfListsType {
		t.Errorf("type %q, want %q", list.SchemeInfo.LoTEType, trustedlists.ListOfListsType)
	}
	locations := map[string]bool{}
	for _, p := range list.SchemeInfo.Pointers {
		locations[p.Location] = true
	}
	for _, entry := range w.TrustedLists().IndexEntries(w.IssuerURL) {
		if !locations[w.IssuerURL+entry.Path] {
			t.Errorf("pointers %v, want %s", locations, entry.Path)
		}
	}
}

func TestTrustListByIDAnswersAnUnknownListWithNotFound(t *testing.T) {
	srv := NewServer(generateTestWallet(t), 0, nil)
	if resp := serverRequest(t, srv, "GET", "/api/trustlists/no-such-list", ""); resp.Code != http.StatusNotFound {
		t.Errorf("GET an unknown list: %d, want 404", resp.Code)
	}
}

func TestTrustListByIDNeedsTheWalletCA(t *testing.T) {
	holderKey, _ := mock.GenerateKey()
	issuerKey, _ := mock.GenerateKey()
	srv := NewServer(newWallet(holderKey, issuerKey, false), 0, nil)
	for _, id := range []string{"pid", trustedlists.ListOfListsID} {
		if resp := serverRequest(t, srv, "GET", "/api/trustlists/"+id, ""); resp.Code != http.StatusInternalServerError {
			t.Errorf("GET %s without a CA: %d, want 500", id, resp.Code)
		}
	}
}
