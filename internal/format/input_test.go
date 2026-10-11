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

package format

import (
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestReadInputRaw_RawString(t *testing.T) {
	raw, err := ReadInputRaw("eyJhbGciOiJFUzI1NiJ9.test.sig")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != "eyJhbGciOiJFUzI1NiJ9.test.sig" {
		t.Errorf("expected raw string back, got %q", raw)
	}
}

func TestReadInputRaw_URIPassthrough(t *testing.T) {
	uri := "openid4vp://authorize?client_id=test"
	raw, err := ReadInputRaw(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != uri {
		t.Errorf("expected URI passthrough, got %q", raw)
	}
}

func TestReadInputRaw_HTTPURLPassthrough(t *testing.T) {
	url := "https://example.com/credential"
	raw, err := ReadInputRaw(url)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != url {
		t.Errorf("expected URL passthrough, got %q", raw)
	}
}

func TestReadInputRaw_FileRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cred.txt")
	if err := os.WriteFile(path, []byte("  test-credential-data  \n"), 0644); err != nil {
		t.Fatal(err)
	}

	raw, err := ReadInputRaw(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != "test-credential-data" {
		t.Errorf("expected trimmed file content, got %q", raw)
	}
}

func TestReadInputRaw_JSONNotTreatedAsFile(t *testing.T) {
	raw, err := ReadInputRaw(`{"credential_issuer":"https://example.com"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != `{"credential_issuer":"https://example.com"}` {
		t.Errorf("expected JSON passthrough, got %q", raw)
	}
}

func TestReadInputRaw_Whitespace(t *testing.T) {
	raw, err := ReadInputRaw("  some-token  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != "some-token" {
		t.Errorf("expected trimmed input, got %q", raw)
	}
}

func TestReadInput_RawString(t *testing.T) {
	raw, err := ReadInput("eyJhbGciOiJFUzI1NiJ9.test.sig")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != "eyJhbGciOiJFUzI1NiJ9.test.sig" {
		t.Errorf("expected raw string back, got %q", raw)
	}
}

func TestReadInput_FileRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cred.txt")
	if err := os.WriteFile(path, []byte("  file-content  \n"), 0644); err != nil {
		t.Fatal(err)
	}

	raw, err := ReadInput(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != "file-content" {
		t.Errorf("expected trimmed file content, got %q", raw)
	}
}

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("  content  \n"), 0644); err != nil {
		t.Fatal(err)
	}

	content, err := readFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content != "content" {
		t.Errorf("expected trimmed content, got %q", content)
	}
}

func TestReadFile_NotFound(t *testing.T) {
	_, err := readFile("/nonexistent/path/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestHTTPClientForURLHostDockerInternalFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]

	// host.docker.internal does not resolve on most hosts. The client must
	// fall back to localhost, which serves the same endpoint.
	url := "http://host.docker.internal:" + port + "/"
	client := HTTPClient()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("expected localhost fallback to succeed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// A remote read that got no answer is tried again. OpenID4VP 1.0 §5.10.2 says
// of the request_uri fetch: "If the Verifier responds with any HTTP error
// response, the Wallet MUST terminate the process." A connection without a
// response is no HTTP error response.
func TestFetchURLRetriesWhenTheServerDoesNotAnswer(t *testing.T) {
	previous := fetchRetryDelay
	fetchRetryDelay = time.Millisecond
	t.Cleanup(func() { fetchRetryDelay = previous })

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			// The client sees a connection closed without an answer.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("test server does not support hijacking")
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			conn.Close()
			return
		}
		_, _ = w.Write([]byte("second-time-lucky"))
	}))
	defer srv.Close()

	got, err := FetchURL(srv.URL)
	if err != nil {
		t.Fatalf("FetchURL: %v", err)
	}
	if got != "second-time-lucky" {
		t.Errorf("body = %q", got)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("server was called %d times, want 2", n)
	}
}

// An HTTP error is an answer. §5.10.2 says to terminate on it.
func TestFetchURLDoesNotRetryAnHTTPError(t *testing.T) {
	previous := fetchRetryDelay
	fetchRetryDelay = time.Millisecond
	t.Cleanup(func() { fetchRetryDelay = previous })

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := FetchURL(srv.URL); err == nil {
		t.Fatal("expected an error for HTTP 500")
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("server was called %d times, want 1", n)
	}
}

type failingTransport struct {
	calls atomic.Int32
	err   error
}

func (f *failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.calls.Add(1)
	return nil, f.err
}

// A failed name lookup, a refused certificate or a blocked address fails the
// same way on every try, so the fetch reports it at once.
func TestFetchURLRetriesOnlyUnansweredRequests(t *testing.T) {
	previous := fetchRetryDelay
	fetchRetryDelay = time.Millisecond
	t.Cleanup(func() { fetchRetryDelay = previous })

	for _, tc := range []struct {
		name  string
		err   error
		calls int32
	}{
		{"unknown host", &net.DNSError{Err: "no such host", Name: "nowhere.invalid", IsNotFound: true}, 1},
		{"certificate", x509.UnknownAuthorityError{}, 1},
		{"blocked address", errors.New("dial blocked: 10.0.0.1 is a private address"), 1},
		{"timeout", &net.DNSError{Err: "i/o timeout", IsTimeout: true}, fetchAttempts},
		{"connection reset", syscall.ECONNRESET, fetchAttempts},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &failingTransport{err: tc.err}
			if _, err := FetchURL("https://issuer.example/x", &http.Client{Transport: transport}); err == nil {
				t.Fatal("expected an error")
			}
			if n := transport.calls.Load(); n != tc.calls {
				t.Errorf("tried %d times, want %d", n, tc.calls)
			}
		})
	}
}

// A slow peer may need a longer timeout. An invalid value must keep the default.
func TestResolveRemoteTimeout(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want time.Duration
	}{
		{"unset", "", DefaultRemoteTimeout},
		{"blank", "   ", DefaultRemoteTimeout},
		{"seconds", "45s", 45 * time.Second},
		{"minutes", "2m", 2 * time.Minute},
		{"surrounding space", " 30s ", 30 * time.Second},
		{"not a duration", "soon", DefaultRemoteTimeout},
		{"bare number", "45", DefaultRemoteTimeout},
		{"zero", "0s", DefaultRemoteTimeout},
		{"negative", "-5s", DefaultRemoteTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveRemoteTimeout(tc.raw); got != tc.want {
				t.Errorf("resolveRemoteTimeout(%q) = %s, want %s", tc.raw, got, tc.want)
			}
		})
	}
}
