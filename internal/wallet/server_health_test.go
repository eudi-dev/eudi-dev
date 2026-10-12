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
	"errors"
	"net/http"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
)

type unreachableStore struct {
	storage.Store
	down bool
}

func (s *unreachableStore) List(prefix string) ([]string, error) {
	if s.down {
		return nil, errors.New("connection refused")
	}
	return s.Store.List(prefix)
}

func TestHealthAndReadiness(t *testing.T) {
	backend := &unreachableStore{Store: storage.NewMemory()}
	srv := newTestServer(t, true)
	srv.SetStore(NewWalletStoreOn(t.TempDir(), backend))

	for _, path := range []string{"/healthz", "/readyz"} {
		if rec := serverRequest(t, srv, http.MethodGet, path, ""); rec.Code != http.StatusOK {
			t.Errorf("%s = %d, want 200: %s", path, rec.Code, rec.Body)
		}
	}

	backend.down = true
	if rec := serverRequest(t, srv, http.MethodGet, "/healthz", ""); rec.Code != http.StatusOK {
		t.Errorf("/healthz with storage down = %d, want 200", rec.Code)
	}
	rec := serverRequest(t, srv, http.MethodGet, "/readyz", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz with storage down = %d, want 503", rec.Code)
	}
	if body := decodeJSON(t, rec); body["error"] != "storage: connection refused" {
		t.Errorf("/readyz error = %v", body["error"])
	}
}

func TestHealthUnderPathPrefix(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.BaseURL = "https://example.com/some/context"
	for _, path := range []string{"/healthz", "/some/context/healthz", "/readyz", "/some/context/readyz"} {
		if rec := serverRequest(t, srv, http.MethodGet, path, ""); rec.Code != http.StatusOK {
			t.Errorf("%s = %d, want 200", path, rec.Code)
		}
	}
}
