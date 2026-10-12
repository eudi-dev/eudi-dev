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
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
)

// A reload must wait until a mutation has been saved. Otherwise it could replace the
// changed state with the old stored state.
func TestSaveMutationFencesOutAReload(t *testing.T) {
	srv := newTestServer(t, true)
	store := NewWalletStore(t.TempDir())
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatalf("initializing store: %v", err)
	}
	srv.SetStore(store)
	srv.onSave = func() {}

	inside := make(chan struct{})
	release := make(chan struct{})
	reloadDone := make(chan struct{})

	go srv.saveMutation(func() bool {
		close(inside)
		<-release
		return true
	})

	<-inside
	go func() {
		_ = srv.reloadFromStore()
		close(reloadDone)
	}()

	select {
	case <-reloadDone:
		t.Fatal("a reload ran while a mutation held the store lock")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-reloadDone
}

// batchIssuer issues a batch bound to the proof keys of each credential
// request. Its notification endpoint runs onNotify after the wallet stored a
// credential response.
func batchIssuer(t *testing.T, w *Wallet, onNotify func()) (*httptest.Server, string) {
	t.Helper()
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":         serverURL,
				"credential_endpoint":       serverURL + "/credential",
				"token_endpoint":            serverURL + "/token",
				"nonce_endpoint":            serverURL + "/nonce",
				"notification_endpoint":     serverURL + "/notification",
				"batch_credential_issuance": map[string]any{"batch_size": 3},
				"credential_configurations_supported": map[string]any{
					"cfg": map[string]any{"format": "dc+sd-jwt", "vct": "TestBoundCred"},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/token"):
			_ = json.NewEncoder(rw).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "refresh_token": "rt"})
		case strings.HasSuffix(r.URL.Path, "/nonce"):
			_ = json.NewEncoder(rw).Encode(map[string]any{"c_nonce": "n"})
		case strings.HasSuffix(r.URL.Path, "/credential"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			proofs, _ := body["proofs"].(map[string]any)
			jwts, _ := proofs["jwt"].([]any)
			credentials := make([]any, 0, len(jwts))
			for _, proof := range jwts {
				jwk, _ := decodeJWTPart(t, proof.(string), 0)["jwk"].(map[string]any)
				pub, _, err := ecdsaPublicKeyFromJWK(ValidationModeDebug, jwk["x"].(string), jwk["y"].(string))
				if err != nil {
					t.Errorf("proof key: %v", err)
					return
				}
				credentials = append(credentials, map[string]any{"credential": sdJWTBoundTo(t, w, pub)})
			}
			_ = json.NewEncoder(rw).Encode(map[string]any{"credentials": credentials, "notification_id": "note"})
		case strings.HasSuffix(r.URL.Path, "/notification"):
			onNotify()
			rw.WriteHeader(http.StatusNoContent)
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	serverURL = srv.URL
	offer, _ := json.Marshal(map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"cfg"},
		"grants": map[string]any{
			preAuthorizedCodeGrant: map[string]any{"pre-authorized_code": "code"},
		},
	})
	return srv, "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offer))
}

// storedBatch reads the batch of id from the store as a fresh process would.
func storedBatch(t *testing.T, store *WalletStore, id string) []StoredCredential {
	t.Helper()
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	cred, ok := w.GetCredential(id)
	if !ok {
		t.Fatalf("credential %s is not stored", id)
	}
	var batch []StoredCredential
	for _, c := range w.GetCredentials() {
		if c.BatchGroup == cred.BatchGroup {
			batch = append(batch, c)
		}
	}
	return batch
}

// Two servers share one database. Another visitor stores a credential while
// this server waits for the issuer, and this server then reloads. A batch
// issuance and a renewal keep every copy they received.
func TestIssuanceAndRenewalSurviveAReloadFromAnotherServer(t *testing.T) {
	dir, backend := t.TempDir(), storage.NewMemory()
	open := func() *Server {
		store := NewWalletStoreOn(dir, backend)
		w, err := store.LoadOrCreate()
		if err != nil {
			t.Fatal(err)
		}
		srv := NewServer(w, 0, nil)
		srv.SetStore(store)
		return srv
	}
	srv, other := open(), open()
	_, offer := batchIssuer(t, srv.wallet, func() {
		if err := other.reloadFromStore(); err != nil {
			t.Error(err)
		}
		other.saveMutation(func() bool {
			other.wallet.PutCredential(StoredCredential{ID: newCredentialID(), Format: "dc+sd-jwt", Raw: generateTestCredential(t, other.wallet)})
			return true
		})
		if err := srv.reloadFromStore(); err != nil {
			t.Error(err)
		}
	})

	result, _, err := srv.runOffer(offer, OfferOptions{})
	if err != nil {
		t.Fatalf("issuance: %v", err)
	}
	issued := storedBatch(t, NewWalletStoreOn(dir, backend), result.CredentialID)
	if len(issued) != 3 {
		t.Fatalf("the store holds %d copies of the batch, want 3", len(issued))
	}

	if _, err := srv.RenewCredential(result.CredentialID); err != nil {
		t.Fatalf("renewal: %v", err)
	}
	renewed := storedBatch(t, NewWalletStoreOn(dir, backend), result.CredentialID)
	if len(renewed) != 3 {
		t.Fatalf("the store holds %d copies of the renewed batch, want 3", len(renewed))
	}
	old := map[string]bool{}
	for _, c := range issued {
		old[c.Raw] = true
	}
	for _, c := range renewed {
		if old[c.Raw] {
			t.Errorf("copy %s holds the credential from before the renewal", c.ID)
		}
	}
}

// A reload replaces the holder key under the wallet lock while flows read
// it. Run with -race.
func TestHolderKeyReadsHoldTheWalletLock(t *testing.T) {
	w := generateTestWallet(t)
	metadata := map[string]any{"credential_configurations_supported": map[string]any{"cfg": map[string]any{
		"proof_types_supported": map[string]any{"jwt": map[string]any{
			"key_attestations_required": map[string]any{"key_storage": []any{"iso_18045_high"}},
		}},
	}}}
	key := w.HolderKeyPair()
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				w.mu.Lock()
				w.HolderKey = key
				w.mu.Unlock()
			}
		}
	}()
	defer func() {
		close(stop)
		<-done
	}()
	for range 20 {
		if _, err := createClientAttestationHeaders(w, &ClientAuthentication{}, "client", ""); err != nil {
			t.Fatal(err)
		}
		if _, err := createKeyAttestation(w, metadata, "cfg", "n", nil); err != nil {
			t.Fatal(err)
		}
		if _, err := w.IssueCredential(IssueOptions{Format: "sdjwt", VCT: "urn:test:race", Claims: map[string]any{"a": "b"}}); err != nil {
			t.Fatal(err)
		}
	}
}
