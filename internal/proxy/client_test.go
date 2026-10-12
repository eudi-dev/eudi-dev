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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewDashboardClientNormalizesTheURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"http://localhost:9091", "http://localhost:9091"},
		{"http://localhost:9091/", "http://localhost:9091"},
		{"localhost:9091", "http://localhost:9091"},
		{"https://proxy.example", "https://proxy.example"},
		{"https://proxy.example/inspect/", "https://proxy.example/inspect"},
	}
	for _, tc := range cases {
		client, err := NewDashboardClient(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if client.BaseURL != tc.want {
			t.Errorf("%s → %s, want %s", tc.in, client.BaseURL, tc.want)
		}
	}

	for _, bad := range []string{"", "   ", "ftp://proxy.example", "://nope"} {
		if _, err := NewDashboardClient(bad); err == nil {
			t.Errorf("%q was accepted as a dashboard URL", bad)
		}
	}
}

func TestDashboardClientEntries(t *testing.T) {
	store := NewStore(10)
	store.Add(&TrafficEntry{Method: "GET", URL: "http://target/one"})
	store.Add(&TrafficEntry{Method: "POST", URL: "http://target/two"})
	srv := httptest.NewServer(NewDashboard(store).Handler())
	defer srv.Close()

	client, err := NewDashboardClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := client.Entries(context.Background())
	if err != nil {
		t.Fatalf("reading entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].URL != "http://target/one" || entries[1].Method != "POST" {
		t.Errorf("entries came back wrong: %+v", entries)
	}
}

// A connection failure must report an error.
func TestDashboardClientReportsAnUnreachableProxy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()

	client, _ := NewDashboardClient(srv.URL)
	if _, err := client.Entries(context.Background()); err == nil {
		t.Fatal("a 404 dashboard was read as an empty one")
	}
}

// A stream has no overall deadline, but a dashboard that never answers must
// not hold `proxy logs --follow` forever.
func TestDashboardClientStopsWaitingForAResponseHead(t *testing.T) {
	previous := entriesTimeout
	entriesTimeout = 100 * time.Millisecond
	t.Cleanup(func() { entriesTimeout = previous })
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	client, _ := NewDashboardClient(srv.URL)
	done := make(chan error, 1)
	go func() {
		_, err := client.Stream(context.Background())
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a silent dashboard opened a stream")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the client still waits for a dashboard that never answers")
	}
}

// The subscription is active when Stream returns. A client that reads the
// recorded traffic afterwards misses no entry.
func TestDashboardClientStreamSubscribesBeforeItReturns(t *testing.T) {
	store := NewStore(10)
	srv := httptest.NewServer(NewDashboard(store).Handler())
	defer srv.Close()

	client, err := NewDashboardClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.Stream(context.Background())
	if err != nil {
		t.Fatalf("opening the stream: %v", err)
	}
	defer stream.Close()

	if got := store.SubscriberCount(); got != 1 {
		t.Fatalf("subscriber count = %d, want the stream subscribed before it returned", got)
	}

	store.Add(&TrafficEntry{Method: "GET", URL: "http://target/live"})
	entry, err := stream.Next()
	if err != nil {
		t.Fatalf("reading the streamed entry: %v", err)
	}
	if entry.URL != "http://target/live" {
		t.Errorf("streamed %s, want the entry just recorded", entry.URL)
	}
}

// Keepalive comments and malformed events are skipped.
func TestEntryStreamSkipsKeepalivesAndMalformedEvents(t *testing.T) {
	body := ": keepalive\n\n" +
		"data: not json\n\n" +
		"data: {\"id\":7,\"method\":\"GET\",\"url\":\"http://target/seven\"}\n\n"
	stream := &EntryStream{
		body:   io.NopCloser(strings.NewReader(body)),
		reader: bufio.NewReader(strings.NewReader(body)),
	}

	entry, err := stream.Next()
	if err != nil {
		t.Fatalf("reading past the keepalive: %v", err)
	}
	if entry.ID != 7 || entry.URL != "http://target/seven" {
		t.Errorf("read %+v, want entry 7", entry)
	}

	if _, err := stream.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("end of stream reported as %v, want io.EOF", err)
	}
}

// An idle stream sends keepalives, so a proxy or load balancer keeps the
// connection open.
func TestDashboardStreamSendsKeepalives(t *testing.T) {
	original := streamKeepaliveInterval
	streamKeepaliveInterval = 10 * time.Millisecond
	defer func() { streamKeepaliveInterval = original }()

	srv := httptest.NewServer(NewDashboard(NewStore(10)).Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/stream", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 64)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, err := resp.Body.Read(buf)
		if err != nil {
			t.Fatalf("reading the stream: %v", err)
		}
		if strings.Contains(string(buf[:n]), ": keepalive") {
			return
		}
	}
	t.Fatal("no keepalive arrived on an idle stream")
}
