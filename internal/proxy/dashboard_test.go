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

package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/webui/webuitest"
)

func TestHandleHAR(t *testing.T) {
	store := NewStore(100)
	store.Add(&TrafficEntry{
		Timestamp:       time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC),
		Method:          "GET",
		URL:             "http://example.com/test",
		RequestHeaders:  http.Header{"Accept": {"*/*"}},
		StatusCode:      200,
		ResponseHeaders: http.Header{"Content-Type": {"text/plain"}},
		ResponseBody:    "hello",
		DurationMS:      10,
	})

	d := NewDashboard(store)

	req := httptest.NewRequest("GET", "/api/har", nil)
	w := httptest.NewRecorder()
	d.handleHAR(w, req)

	resp := w.Result()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != `attachment; filename="eudi-dev.har"` {
		t.Errorf("unexpected Content-Disposition: %s", cd)
	}

	var har map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&har); err != nil {
		t.Fatalf("failed to decode HAR JSON: %v", err)
	}

	log, ok := har["log"].(map[string]any)
	if !ok {
		t.Fatal("expected log object in HAR")
	}
	entries, ok := log["entries"].([]any)
	if !ok {
		t.Fatal("expected entries array in HAR log")
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 HAR entry, got %d", len(entries))
	}
}

func TestHandleHAREmpty(t *testing.T) {
	store := NewStore(100)
	d := NewDashboard(store)

	req := httptest.NewRequest("GET", "/api/har", nil)
	w := httptest.NewRecorder()
	d.handleHAR(w, req)

	var har map[string]any
	json.NewDecoder(w.Result().Body).Decode(&har)
	log := har["log"].(map[string]any)
	entries := log["entries"].([]any)
	if len(entries) != 0 {
		t.Errorf("expected 0 HAR entries for empty store, got %d", len(entries))
	}
}

func TestHandleEntries(t *testing.T) {
	store := NewStore(100)
	store.Add(&TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/test",
		StatusCode: 200,
	})

	d := NewDashboard(store)

	req := httptest.NewRequest("GET", "/api/entries", nil)
	w := httptest.NewRecorder()
	d.handleEntries(w, req)

	resp := w.Result()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var entries []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		t.Fatalf("failed to decode entries JSON: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

func TestHandleEntriesEmpty(t *testing.T) {
	store := NewStore(100)
	d := NewDashboard(store)

	req := httptest.NewRequest("GET", "/api/entries", nil)
	w := httptest.NewRecorder()
	d.handleEntries(w, req)

	var entries []map[string]any
	json.NewDecoder(w.Result().Body).Decode(&entries)
	if len(entries) != 0 {
		t.Errorf("expected empty entries, got %d", len(entries))
	}
}

func TestHandleEntriesMultiple(t *testing.T) {
	store := NewStore(100)
	for i := 0; i < 5; i++ {
		store.Add(&TrafficEntry{Method: "GET", URL: "http://example.com/", StatusCode: 200})
	}

	d := NewDashboard(store)
	req := httptest.NewRequest("GET", "/api/entries", nil)
	w := httptest.NewRecorder()
	d.handleEntries(w, req)

	var entries []map[string]any
	json.NewDecoder(w.Result().Body).Decode(&entries)
	if len(entries) != 5 {
		t.Errorf("expected 5 entries, got %d", len(entries))
	}
}

func TestHandleStream(t *testing.T) {
	store := NewStore(100)
	d := NewDashboard(store)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/stream", d.handleStream)
	srv := httptest.NewServer(mux)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/stream", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("expected Content-Type text/event-stream, got %s", ct)
	}

	// The handler subscribes before it sends the response head.
	store.Add(&TrafficEntry{Method: "GET", URL: "http://example.com/test", StatusCode: 200})

	scanner := bufio.NewScanner(resp.Body)
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			jsonData := strings.TrimPrefix(line, "data: ")
			var entry map[string]any
			if err := json.Unmarshal([]byte(jsonData), &entry); err != nil {
				t.Errorf("failed to parse SSE JSON: %v", err)
			}
			if entry["method"] != "GET" {
				t.Errorf("expected method GET, got %v", entry["method"])
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("no SSE data line found")
	}

	// The body closes before the server, so unsubscribe does not hang.
	resp.Body.Close()
	srv.Close()
}

// Captured traffic carries tokens, so a page on another origin must not read
// the stream.
func TestHandleStreamIsReadableOnlyFromTheDashboardOrigin(t *testing.T) {
	srv := httptest.NewServer(NewDashboard(NewStore(10)).Handler())
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/stream", nil)
	req.Header.Set("Origin", "https://other.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if corsAllows(resp.Header, "https://other.example") {
		t.Errorf("the stream grants https://other.example read access (Access-Control-Allow-Origin %q)", resp.Header.Get("Access-Control-Allow-Origin"))
	}
}

func corsAllows(h http.Header, origin string) bool {
	allowed := h.Get("Access-Control-Allow-Origin")
	return allowed == "*" || allowed == origin
}

func TestHandleHARExportsTheRecordedTraffic(t *testing.T) {
	store := NewStore(100)
	store.Add(&TrafficEntry{
		Timestamp:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Method:     "GET",
		URL:        "http://example.com/authorize?client_id=test&response_type=vp_token&state=s1",
		StatusCode: 200,
	})

	w := httptest.NewRecorder()
	NewDashboard(store).handleHAR(w, httptest.NewRequest("GET", "/api/har", nil))

	if got := w.Header().Get("Content-Disposition"); got != `attachment; filename="eudi-dev.har"` {
		t.Errorf("Content-Disposition %q", got)
	}
	var har struct {
		Log struct {
			Version string `json:"version"`
			Entries []struct {
				Request struct {
					Method string `json:"method"`
					URL    string `json:"url"`
				} `json:"request"`
				Response struct {
					Status int `json:"status"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.NewDecoder(w.Body).Decode(&har); err != nil {
		t.Fatal(err)
	}
	if har.Log.Version != "1.2" || len(har.Log.Entries) != 1 {
		t.Fatalf("HAR %+v", har)
	}
	e := har.Log.Entries[0]
	if e.Request.Method != "GET" || e.Request.URL != "http://example.com/authorize?client_id=test&response_type=vp_token&state=s1" || e.Response.Status != 200 {
		t.Errorf("HAR entry %+v", e)
	}
}

func TestDashboardBelowPathPrefix(t *testing.T) {
	store := NewStore(10)
	store.Add(&TrafficEntry{Method: "GET", URL: "http://example.com/x", StatusCode: 200})
	for _, tc := range []struct {
		name, baseURL, prefixPath string
		headers                   map[string]string
	}{
		{name: "base URL, prefix kept", baseURL: "https://mydomain.de/eudi-proxy", prefixPath: "/eudi-proxy"},
		{name: "base URL, prefix stripped", baseURL: "https://mydomain.de/eudi-proxy"},
		{name: "forwarded prefix", headers: map[string]string{"X-Forwarded-Prefix": "/eudi-proxy"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDashboard(store)
			if err := d.SetBaseURL(tc.baseURL); err != nil {
				t.Fatal(err)
			}
			h := d.Handler()
			get := func(path string) *httptest.ResponseRecorder {
				req := httptest.NewRequest("GET", tc.prefixPath+path, nil)
				req.Host = "mydomain.de"
				for k, v := range tc.headers {
					req.Header.Set(k, v)
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				return rec
			}
			if rec := get("/"); !strings.Contains(rec.Body.String(), `<base href="/eudi-proxy/">`) {
				t.Fatalf("index: %d %.200s", rec.Code, rec.Body.String())
			}
			if rec := get("/api/entries"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "example.com") {
				t.Fatalf("entries: %d %s", rec.Code, rec.Body.String())
			}
			if rec := get("/decode"); rec.Header().Get("Location") != "/eudi-proxy/decode/" {
				t.Fatalf("decoder redirect: %d %q", rec.Code, rec.Header().Get("Location"))
			}
		})
	}
}

func TestDashboardAtRootUnchanged(t *testing.T) {
	h := NewDashboard(NewStore(10)).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "<base") {
		t.Fatalf("index: %d", rec.Code)
	}
}

func TestDashboardRejectsBasePathOnItsRoutes(t *testing.T) {
	for _, path := range []string{"/api", "/decode/x", "/app.js"} {
		if err := NewDashboard(NewStore(10)).SetBaseURL("https://mydomain.de" + path); err == nil {
			t.Errorf("base path %s accepted", path)
		}
	}
}

// The dashboard and its decoder load the bundled fonts, at the root and below
// a path prefix.
func TestDashboardPagesLoadTheFonts(t *testing.T) {
	h := NewDashboard(NewStore(10)).Handler()
	for _, prefix := range []string{"", "/eudi-proxy"} {
		for _, page := range []string{"/", "/decode/"} {
			t.Run(prefix+page, func(t *testing.T) {
				webuitest.CheckFonts(t, h, prefix, page)
			})
		}
	}
}
