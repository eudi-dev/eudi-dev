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
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

func TestSetCredentialStatus(t *testing.T) {
	w := generateTestWallet(t)
	w.StatusEntries = map[string]StatusEntry{
		"cred-1": {Index: 0, Status: 0},
	}

	entry, ok := w.SetCredentialStatus("cred-1", 1)
	if !ok {
		t.Fatal("expected to find credential status entry")
	}
	if entry.Status != 1 {
		t.Errorf("expected status 1, got %d", entry.Status)
	}
	if entry.Index != 0 {
		t.Errorf("expected index 0, got %d", entry.Index)
	}

	if w.StatusEntries["cred-1"].Status != 1 {
		t.Error("status not updated in map")
	}
}

func TestSetCredentialStatus_NotFound(t *testing.T) {
	w := generateTestWallet(t)

	_, ok := w.SetCredentialStatus("nonexistent", 1)
	if ok {
		t.Error("expected false for nonexistent credential")
	}
}

func TestSetCredentialStatus_Unrevoke(t *testing.T) {
	w := generateTestWallet(t)
	w.StatusEntries = map[string]StatusEntry{
		"cred-1": {Index: 0, Status: 1},
	}

	entry, ok := w.SetCredentialStatus("cred-1", 0)
	if !ok {
		t.Fatal("expected to find credential status entry")
	}
	if entry.Status != 0 {
		t.Errorf("expected status 0 after un-revoke, got %d", entry.Status)
	}
}

func TestBuildStatusList_Empty(t *testing.T) {
	w := generateTestWallet(t)

	_, bs := w.BuildStatusList()
	if len(bs) < 1 {
		t.Fatal("expected at least 1 byte")
	}
	for i, b := range bs {
		if b != 0 {
			t.Errorf("expected byte %d to be 0, got %d", i, b)
		}
	}
}

func TestBuildStatusList_WithEntries(t *testing.T) {
	w := generateTestWallet(t)
	w.StatusListCounter = 4
	w.StatusEntries = map[string]StatusEntry{
		"cred-0": {Index: 0, Status: 0},
		"cred-1": {Index: 1, Status: 1}, // revoked
		"cred-2": {Index: 2, Status: 0},
		"cred-3": {Index: 3, Status: 1}, // revoked
	}

	_, bs := w.BuildStatusList()

	// Index 1: bit 1 = 0b00000010
	// Index 3: bit 3 = 0b00001000
	// Combined: 0b00001010 = 0x0A
	if bs[0] != 0x0A {
		t.Errorf("expected byte 0 = 0x0A, got 0x%02X", bs[0])
	}
}

func TestBuildStatusList_MinimumSize(t *testing.T) {
	w := generateTestWallet(t)
	w.StatusListCounter = 1
	w.StatusEntries = map[string]StatusEntry{
		"cred-0": {Index: 0, Status: 0},
	}

	_, bs := w.BuildStatusList()
	// The spec sets no minimum size. This wallet uses at least 16 bytes.
	if len(bs) < 16 {
		t.Errorf("expected minimum 16 bytes, got %d", len(bs))
	}
}

func TestGenerateDefaultCredentials_WithStatusList(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "http://localhost:8085"
	w.IssuerURL = "https://localhost:8086"

	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("GenerateDefaultCredentials: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(creds))
	}

	if len(w.StatusEntries) != 2 {
		t.Fatalf("expected 2 status entries, got %d", len(w.StatusEntries))
	}

	if w.StatusListCounter != 2 {
		t.Errorf("expected counter=2, got %d", w.StatusListCounter)
	}

	sdCred := creds[0]
	token, err := sdjwt.Parse(sdCred.Raw)
	if err != nil {
		t.Fatalf("parsing SD-JWT: %v", err)
	}
	status, ok := token.Payload["status"].(map[string]any)
	if !ok {
		t.Fatal("expected status claim in SD-JWT payload")
	}
	sl, ok := status["status_list"].(map[string]any)
	if !ok {
		t.Fatal("expected status_list in status claim")
	}
	if sl["uri"] != "https://localhost:8086/api/statuslist" {
		t.Errorf("expected status list URI, got %v", sl["uri"])
	}
	if want := float64(w.statusIndexFor(0)); sl["idx"] != want {
		t.Errorf("expected idx=%v, got %v", want, sl["idx"])
	}

	for credID, entry := range w.StatusEntries {
		if entry.Status != 0 {
			t.Errorf("credential %s: expected status 0, got %d", credID, entry.Status)
		}
	}
}

func TestGenerateDefaultCredentials_WithoutStatusList(t *testing.T) {
	w := generateTestWallet(t)

	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("GenerateDefaultCredentials: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(creds))
	}

	if len(w.StatusEntries) != 0 {
		t.Errorf("expected 0 status entries, got %d", len(w.StatusEntries))
	}

	sdCred := creds[0]
	token, err := sdjwt.Parse(sdCred.Raw)
	if err != nil {
		t.Fatalf("parsing SD-JWT: %v", err)
	}
	if _, ok := token.Payload["status"]; ok {
		t.Error("expected no status claim when status list is disabled")
	}
}

func TestGenerateDefaultCredentials_StatusIndexIncrement(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "http://localhost:8085"
	w.IssuerURL = "https://localhost:8086"

	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("first GenerateDefaultCredentials: %v", err)
	}
	if w.StatusListCounter != 2 {
		t.Errorf("expected counter=2 after first generation, got %d", w.StatusListCounter)
	}

	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("second GenerateDefaultCredentials: %v", err)
	}
	if w.StatusListCounter != 4 {
		t.Errorf("expected counter=4 after second generation, got %d", w.StatusListCounter)
	}
}

func TestStatusListAPI(t *testing.T) {
	srv := newTestServer(t, false)

	w := serverRequest(t, srv, "GET", "/api/statuslist", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/statuslist+jwt" {
		t.Errorf("expected Content-Type application/statuslist+jwt, got %s", ct)
	}

	jwt := w.Body.String()
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}

	if _, ok := payload["status_list"]; !ok {
		t.Error("expected status_list in JWT payload")
	}
}

func TestStatusListAPI_WithRevokedCredential(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "http://localhost:8085"
	w.IssuerURL = "https://localhost:8086"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	srv := NewServer(w, 0, nil)

	creds := w.GetCredentials()
	w.SetCredentialStatus(creds[0].ID, 1)

	resp := serverRequest(t, srv, "GET", "/api/statuslist", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}

	jwt := resp.Body.String()
	parts := strings.SplitN(jwt, ".", 3)
	payloadBytes, _ := format.DecodeBase64URL(parts[1])
	var payload map[string]any
	json.Unmarshal(payloadBytes, &payload)

	sl := payload["status_list"].(map[string]any)
	if sl["bits"] != float64(1) {
		t.Errorf("expected bits=1, got %v", sl["bits"])
	}
	if _, ok := sl["lst"].(string); !ok {
		t.Fatal("missing lst")
	}
	if payload["sub"] != "https://localhost:8086/api/statuslist" {
		t.Errorf("expected sub=https://localhost:8086/api/statuslist, got %v", payload["sub"])
	}
	if payload["iss"] != "https://localhost:8086" {
		t.Errorf("expected iss=https://localhost:8086, got %v", payload["iss"])
	}
}

func TestSetCredentialStatusAPI(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "http://localhost:8085"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	srv := NewServer(w, 0, nil)

	creds := w.GetCredentials()
	credID := creds[0].ID

	resp := serverRequest(t, srv, "POST", "/api/credentials/"+credID+"/status", `{"status":1}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	var entry StatusEntry
	if err := json.Unmarshal(resp.Body.Bytes(), &entry); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if entry.Status != 1 {
		t.Errorf("expected status 1, got %d", entry.Status)
	}

	resp = serverRequest(t, srv, "POST", "/api/credentials/"+credID+"/status", `{"status":0}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	json.Unmarshal(resp.Body.Bytes(), &entry)
	if entry.Status != 0 {
		t.Errorf("expected status 0 after un-revoke, got %d", entry.Status)
	}
}

func TestSetCredentialStatusAPI_NotFound(t *testing.T) {
	srv := newTestServer(t, false)

	resp := serverRequest(t, srv, "POST", "/api/credentials/nonexistent/status", `{"status":1}`)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.Code)
	}
}

func TestSetCredentialStatusAPI_InvalidJSON(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "http://localhost:8085"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	srv := NewServer(w, 0, nil)

	creds := w.GetCredentials()
	resp := serverRequest(t, srv, "POST", "/api/credentials/"+creds[0].ID+"/status", "not-json")
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.Code)
	}
}

func TestWalletStore_StatusEntriesPersistence(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	w.BaseURL = "http://localhost:8085"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}

	creds := w.GetCredentials()
	w.SetCredentialStatus(creds[0].ID, 1)

	if err := store.Save(w); err != nil {
		t.Fatalf("Save: %v", err)
	}

	w2, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate after save: %v", err)
	}

	if len(w2.StatusEntries) != len(w.StatusEntries) {
		t.Fatalf("expected %d status entries, got %d", len(w.StatusEntries), len(w2.StatusEntries))
	}
	if w2.StatusListCounter != w.StatusListCounter {
		t.Errorf("expected counter=%d, got %d", w.StatusListCounter, w2.StatusListCounter)
	}

	entry := w2.StatusEntries[creds[0].ID]
	if entry.Status != 1 {
		t.Errorf("expected status 1 after reload, got %d", entry.Status)
	}
}

func TestGenerateSDJWT_WithStatusList(t *testing.T) {
	key, _ := mock.GenerateKey()

	cfg := mock.SDJWTConfig{
		Issuer:        "https://issuer.example",
		VCT:           "test",
		ExpiresIn:     3600,
		Claims:        map[string]any{"name": "Test"},
		Key:           key,
		StatusListURI: "http://localhost:8085/api/statuslist",
		StatusListIdx: 42,
	}

	result, err := mock.GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	// The status claim must be readable without any disclosure.
	status, ok := token.Payload["status"].(map[string]any)
	if !ok {
		t.Fatal("expected status in payload")
	}
	sl, ok := status["status_list"].(map[string]any)
	if !ok {
		t.Fatal("expected status_list in status")
	}
	if sl["uri"] != "http://localhost:8085/api/statuslist" {
		t.Errorf("expected URI, got %v", sl["uri"])
	}
	if sl["idx"] != float64(42) {
		t.Errorf("expected idx=42, got %v", sl["idx"])
	}
}

func TestGenerateSDJWT_WithoutStatusList(t *testing.T) {
	key, _ := mock.GenerateKey()

	cfg := mock.SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "test",
		ExpiresIn: 3600,
		Claims:    map[string]any{"name": "Test"},
		Key:       key,
	}

	result, err := mock.GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	if _, ok := token.Payload["status"]; ok {
		t.Error("expected no status claim when not configured")
	}
}

// Import adopts status entries that reference this wallet's own list. Without a
// local entry the wallet cannot revoke those credentials.
func TestImportAdoptsOwnStatusListEntry(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "http://localhost:8085"
	// The wallet assigned its eighth index when it issued the credential.
	w.StatusListCounter = 8
	assigned := w.statusIndexFor(7)

	for _, tc := range []struct {
		name  string
		uri   string
		want  bool
		index int
	}{
		{"own status list", "http://localhost:8085/api/statuslist", true, assigned},
		{"someone else's status list", "https://issuer.example/statuslist", false, assigned},
		{"no status list", "", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
				Issuer:        "https://issuer.example",
				VCT:           "test",
				ExpiresIn:     3600,
				Claims:        map[string]any{"name": "Test"},
				Key:           w.IssuerKey,
				StatusListURI: tc.uri,
				StatusListIdx: tc.index,
			})
			if err != nil {
				t.Fatalf("generating the credential: %v", err)
			}
			imported, err := w.ImportCredential(raw)
			if err != nil {
				t.Fatalf("importing: %v", err)
			}
			entry, managed := w.StatusEntryFor(imported.ID)
			if managed != tc.want {
				t.Fatalf("managed = %v, want %v", managed, tc.want)
			}
			if managed && entry.Index != tc.index {
				t.Errorf("adopted index = %d, want %d", entry.Index, tc.index)
			}
		})
	}
}

// A wallet without its own status list cannot manage imported status entries.
func TestImportAdoptsNothingWithoutAStatusList(t *testing.T) {
	w := generateTestWallet(t)
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:        "https://issuer.example",
		VCT:           "test",
		ExpiresIn:     3600,
		Claims:        map[string]any{"name": "Test"},
		Key:           w.IssuerKey,
		StatusListURI: "http://localhost:8085/api/statuslist",
		StatusListIdx: 3,
	})
	if err != nil {
		t.Fatalf("generating the credential: %v", err)
	}
	imported, err := w.ImportCredential(raw)
	if err != nil {
		t.Fatalf("importing: %v", err)
	}
	if _, managed := w.StatusEntryFor(imported.ID); managed {
		t.Error("a wallet with no status list URL adopted a status entry")
	}
}

// Imported credentials supply their own status index. Reject negative indices before
// building the list, where a negative shift would panic.
func TestStatusBitstring_SurvivesANegativeAdoptedIndex(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("building the status bitstring panicked: %v", r)
		}
	}()

	w := generateTestWallet(t)
	w.StatusListCounter = 4
	w.RegisterStatusEntry("hostile", -3)
	w.RegisterStatusEntry("honest", 2)
	w.SetCredentialStatus("hostile", 1)
	w.SetCredentialStatus("honest", 1)

	_, bitstring := w.BuildStatusList()
	if len(bitstring) == 0 {
		t.Fatal("no bitstring was produced")
	}

	if _, ok := w.StatusEntries["hostile"]; ok {
		t.Error("a negative index was stored")
	}
	if bitstring[0]&(1<<2) == 0 {
		t.Error("the valid entry did not reach the bitstring")
	}
}

// Report an invalid status value separately from an unknown credential.
func TestSetCredentialStatusRejectsAnOutOfRangeValueClearly(t *testing.T) {
	srv := newTestServer(t, true)

	creds := srv.wallet.GetCredentials()
	if len(creds) == 0 {
		t.Fatal("test wallet holds no credentials")
	}
	// Register the credential explicitly so the test always exercises the range check.
	id := creds[0].ID
	idx, err := srv.wallet.NextStatusIndex()
	if err != nil {
		t.Fatal(err)
	}
	srv.wallet.RegisterStatusEntry(id, idx)

	req := httptest.NewRequest("POST", "/api/credentials/"+id+"/status", strings.NewReader(`{"status":256}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "0 to 255") {
		t.Errorf("body = %s, want it to name the permitted range", rec.Body.String())
	}
}

// A credential leaves the wallet with its entry on the wallet's own status
// list, whether the user deletes it or a full wallet makes room.
func TestRemovedCredentialsLeaveTheirStatusEntries(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "https://wallet.example"
	issue := func() string {
		t.Helper()
		result, err := w.IssueCredential(IssueOptions{Format: "sdjwt", VCT: "urn:test:status", Claims: map[string]any{"a": "b"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := w.StatusEntryFor(result.Credential.ID); !ok {
			t.Fatal("the issued credential has no status entry")
		}
		return result.Credential.ID
	}

	deleted := issue()
	w.RemoveCredential(deleted)
	if _, ok := w.StatusEntryFor(deleted); ok {
		t.Error("the deleted credential kept its status entry")
	}

	w.SetCapacity(Capacity{Credentials: 1})
	evicted := issue()
	issue()
	if _, ok := w.GetCredential(evicted); ok {
		t.Fatal("the full wallet kept the oldest credential")
	}
	if _, ok := w.StatusEntryFor(evicted); ok {
		t.Error("the credential dropped to make room kept its status entry")
	}
}
