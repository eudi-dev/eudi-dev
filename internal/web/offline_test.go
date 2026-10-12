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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/statuslist"
)

func checkByName(t *testing.T, w *httptest.ResponseRecorder, name string) map[string]any {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	result := decodeResponse(t, w)
	val, ok := result["validation"].(map[string]any)
	if !ok {
		t.Fatalf("response carries no validation object: %s", w.Body.String())
	}
	checks, ok := val["checks"].([]any)
	if !ok {
		t.Fatalf("validation carries no checks: %s", w.Body.String())
	}
	for _, c := range checks {
		cm := c.(map[string]any)
		if cm["name"] == name {
			return cm
		}
	}
	t.Fatalf("no %s check in %s", name, w.Body.String())
	return nil
}

func postValidate(t *testing.T, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return apiPostTo(t, "/api/validate", string(raw))
}

// Offline validation must not fetch status lists before displaying the credential.
func TestHandleValidate_OfflineLeavesTheStatusListUnfetched(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	var hits atomic.Int32
	bitstring := make([]byte, 16)
	var statusSrv *httptest.Server
	statusSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		jwt, err := statuslist.GenerateStatusListJWT(bitstring, key, statuslist.StatusListConfig{
			URI: statusSrv.URL,
		})
		if err != nil {
			t.Errorf("GenerateStatusListJWT: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		_, _ = w.Write([]byte(jwt))
	}))
	defer statusSrv.Close()

	credential := makeSDJWT(
		map[string]any{
			"iss":     "https://issuer.example",
			"_sd_alg": "sha-256",
			"_sd":     nil,
			"exp":     float64(4102444800),
			"status": map[string]any{
				"status_list": map[string]any{
					"uri": statusSrv.URL,
					"idx": 0,
				},
			},
		},
		[][]any{{"salt1", "given_name", "Erika"}},
	)

	offline := checkByName(t, postValidate(t, map[string]any{
		"input":   credential,
		"offline": true,
	}), "status")
	if offline["status"] != "skipped" {
		t.Errorf("offline status check: got %v, want skipped", offline["status"])
	}
	if offline["needsNetwork"] != true {
		t.Errorf("offline status check should be marked as needing the network, got %v", offline)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("offline pass fetched the status list %d times", got)
	}

	online := checkByName(t, postValidate(t, map[string]any{
		"input":       credential,
		"checkStatus": true,
	}), "status")
	if online["status"] != "pass" {
		t.Fatalf("online status check: got %v (%v)", online["status"], online["detail"])
	}
	if online["needsNetwork"] == true {
		t.Errorf("an answered check should not be marked as needing the network: %v", online)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("online pass fetched the status list %d times, want 1", got)
	}
}

// A credential without a status reference gets its status result without a
// network lookup.
func TestHandleValidate_OfflineAnswersStatusWithoutAReference(t *testing.T) {
	credential := makeSDJWT(
		map[string]any{
			"iss":     "https://issuer.example",
			"_sd_alg": "sha-256",
			"_sd":     nil,
			"exp":     float64(4102444800),
		},
		[][]any{{"salt1", "given_name", "Erika"}},
	)

	status := checkByName(t, postValidate(t, map[string]any{
		"input":   credential,
		"offline": true,
	}), "status")
	if status["status"] != "skipped" {
		t.Errorf("status check: got %v, want skipped", status["status"])
	}
	if status["needsNetwork"] == true {
		t.Errorf("a credential without a status reference leaves nothing to fetch: %v", status)
	}
}

func TestHandleValidate_OfflineLeavesTheIssuerMetadataUnfetched(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	var hits atomic.Int32
	var metadataSrv *httptest.Server
	metadataSrv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwt-vc-issuer" {
			http.NotFound(w, r)
			return
		}
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": metadataSrv.URL,
			"jwks":   map[string]any{"keys": []any{mock.SigningJWKMap(&key.PublicKey)}},
		})
	}))
	defer metadataSrv.Close()

	credential, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    metadataSrv.URL,
		VCT:       "urn:test",
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "Erika"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	offline := checkByName(t, postValidate(t, map[string]any{
		"input":   credential,
		"offline": true,
	}), "signature")
	if offline["status"] != "skipped" {
		t.Errorf("offline signature check: got %v (%v)", offline["status"], offline["detail"])
	}
	if offline["needsNetwork"] != true {
		t.Errorf("offline signature check should be marked as needing the network, got %v", offline)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("offline pass fetched the issuer metadata %d times", got)
	}

	online := checkByName(t, postValidate(t, map[string]any{
		"input":       credential,
		"checkStatus": true,
	}), "signature")
	if online["status"] != "pass" {
		t.Fatalf("online signature check: got %v (%v)", online["status"], online["detail"])
	}
	if got := hits.Load(); got == 0 {
		t.Fatal("online pass never reached the issuer metadata endpoint")
	}
}
