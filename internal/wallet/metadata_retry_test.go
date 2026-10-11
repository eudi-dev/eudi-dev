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
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Retry transient metadata failures before reporting unavailable metadata.
func TestMetadataFetchRetriesATransientFailure(t *testing.T) {
	previous := metadataRetryDelay
	metadataRetryDelay = time.Millisecond
	t.Cleanup(func() { metadataRetryDelay = previous })

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"ok"}`))
	}))
	defer srv.Close()

	resp, err := fetchMetadataDocument(func() (*http.Request, error) {
		return http.NewRequest("GET", srv.URL, nil)
	}, srv.Client())
	if err != nil {
		t.Fatalf("fetchMetadataDocument: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("server was called %d times, want 2 (one failure then the retry)", got)
	}
}

// Do not retry 404 responses because well-known endpoint probes can legitimately miss.
func TestMetadataFetchDoesNotRetryANotFound(t *testing.T) {
	previous := metadataRetryDelay
	metadataRetryDelay = time.Millisecond
	t.Cleanup(func() { metadataRetryDelay = previous })

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	resp, err := fetchMetadataDocument(func() (*http.Request, error) {
		return http.NewRequest("GET", srv.URL, nil)
	}, srv.Client())
	if err != nil {
		t.Fatalf("fetchMetadataDocument: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server was called %d times, want 1", got)
	}
}

// After retry exhaustion, report the failed metadata fetch instead of missing document
// fields.
func TestMetadataFetchGivesUpAfterTheAttempts(t *testing.T) {
	previous := metadataRetryDelay
	metadataRetryDelay = time.Millisecond
	t.Cleanup(func() { metadataRetryDelay = previous })

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	if _, err := fetchMetadataDocument(func() (*http.Request, error) {
		return http.NewRequest("GET", srv.URL, nil)
	}, srv.Client()); err == nil {
		t.Fatal("expected an error once the attempts were used up")
	}
	if got := calls.Load(); got != int32(metadataFetchAttempts) {
		t.Errorf("server was called %d times, want %d", got, metadataFetchAttempts)
	}
}
