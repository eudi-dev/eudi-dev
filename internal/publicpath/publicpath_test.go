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

package publicpath

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestFirstSegment(t *testing.T) {
	for in, want := range map[string]string{"": "", "https://example.com": "", "https://example.com/some/context": "some"} {
		if got, err := FirstSegment(in); err != nil || got != want {
			t.Errorf("FirstSegment(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
}

func TestBasePath(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"https://example.com", ""},
		{"https://example.com/", ""},
		{"https://example.com/some/context", "/some/context"},
		{"https://example.com/some/context/", "/some/context"},
		{"http://localhost:8085/eudi", "/eudi"},
	} {
		got, err := BasePath(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("BasePath(%q) = %q, %v, want %q", tc.in, got, err, tc.want)
		}
	}
	for _, in := range []string{"https://example.com/a?x=1", "https://example.com/a#f", "https://example.com/a//b", "https://example.com/a/../b", "https://example.com/a b"} {
		if _, err := BasePath(in); err == nil {
			t.Errorf("BasePath(%q) accepted", in)
		}
	}
}

type seen struct {
	path, prefix string
}

func serve(t *testing.T, opts Options, req *http.Request, handler func(http.ResponseWriter, *http.Request)) (*httptest.ResponseRecorder, seen) {
	t.Helper()
	var got seen
	h := Wrap(opts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = seen{path: r.URL.Path, prefix: Prefix(r)}
		if handler != nil {
			handler(w, r)
		}
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, got
}

func newRequest(target, host string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Host = host
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func TestWrapRouting(t *testing.T) {
	const base = "https://mydomain.de/some/context"
	for _, tc := range []struct {
		name       string
		baseURL    string
		target     string
		host       string
		headers    map[string]string
		wantPath   string
		wantPrefix string
	}{
		{name: "root deployment", baseURL: "https://mydomain.de", target: "/api/credentials", host: "mydomain.de", wantPath: "/api/credentials"},
		{name: "no base URL", target: "/api/credentials", host: "localhost:8085", wantPath: "/api/credentials"},
		{name: "proxy keeps prefix", baseURL: base, target: "/some/context/api/credentials", host: "mydomain.de", wantPath: "/api/credentials", wantPrefix: "/some/context"},
		{name: "proxy keeps bare prefix", baseURL: base, target: "/some/context", host: "mydomain.de", wantPath: "/", wantPrefix: "/some/context"},
		{name: "proxy strips prefix, host matches", baseURL: base, target: "/api/credentials", host: "mydomain.de", wantPath: "/api/credentials", wantPrefix: "/some/context"},
		{name: "host matches with default port", baseURL: base, target: "/", host: "mydomain.de:443", headers: map[string]string{"X-Forwarded-Proto": "https"}, wantPath: "/", wantPrefix: "/some/context"},
		{name: "envoy double slash", baseURL: base, target: "//api/credentials", host: "mydomain.de", wantPath: "/api/credentials", wantPrefix: "/some/context"},
		{name: "direct access", baseURL: base, target: "/api/credentials", host: "eudi-dev.default.svc:8085", wantPath: "/api/credentials"},
		{name: "forwarded prefix", baseURL: base, target: "/api/credentials", host: "eudi-dev:8085", headers: map[string]string{"X-Forwarded-Prefix": "/some/context/"}, wantPath: "/api/credentials", wantPrefix: "/some/context"},
		{name: "forwarded prefix without base URL", target: "/", host: "localhost:9091", headers: map[string]string{"X-Forwarded-Prefix": "/proxy"}, wantPath: "/", wantPrefix: "/proxy"},
		{name: "outer prefix plus kept base", baseURL: base, target: "/some/context/x", host: "mydomain.de", headers: map[string]string{"X-Forwarded-Prefix": "/outer"}, wantPath: "/x", wantPrefix: "/outer/some/context"},
		{name: "forwarded host decides", baseURL: base, target: "/x", host: "eudi-dev:8085", headers: map[string]string{"X-Forwarded-Host": "mydomain.de"}, wantPath: "/x", wantPrefix: "/some/context"},
		{name: "rfc 7239 host decides", baseURL: base, target: "/x", host: "eudi-dev:8085", headers: map[string]string{"Forwarded": `for=10.0.0.1;host="mydomain.de";proto=https`}, wantPath: "/x", wantPrefix: "/some/context"},
		{name: "similar path is not the prefix", baseURL: base, target: "/some/contextual", host: "other", wantPath: "/some/contextual"},
		{name: "well-known issuer metadata", baseURL: base, target: "/.well-known/openid-credential-issuer/some/context/issuer", host: "mydomain.de", wantPath: "/.well-known/openid-credential-issuer/issuer", wantPrefix: "/some/context"},
		{name: "well-known authorization server", baseURL: base, target: "/.well-known/oauth-authorization-server/some/context/issuer", host: "mydomain.de", wantPath: "/.well-known/oauth-authorization-server/issuer", wantPrefix: "/some/context"},
		{name: "well-known for the base itself", baseURL: base, target: "/.well-known/jwt-vc-issuer/some/context", host: "mydomain.de", wantPath: "/.well-known/jwt-vc-issuer", wantPrefix: "/some/context"},
		{name: "well-known root stays", baseURL: "https://mydomain.de", target: "/.well-known/openid-credential-issuer/issuer", host: "mydomain.de", wantPath: "/.well-known/openid-credential-issuer/issuer"},
		{name: "well-known of another path", baseURL: base, target: "/.well-known/jwt-vc-issuer/other", host: "x", wantPath: "/.well-known/jwt-vc-issuer/other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, got := serve(t, Options{BaseURL: tc.baseURL}, newRequest(tc.target, tc.host, tc.headers), nil)
			if got.path != tc.wantPath || got.prefix != tc.wantPrefix {
				t.Fatalf("got path %q prefix %q, want %q %q", got.path, got.prefix, tc.wantPath, tc.wantPrefix)
			}
		})
	}
}

func TestWrapIgnoresUnsafeForwardedPrefix(t *testing.T) {
	for _, value := range []string{"//evil.example", "https://evil.example", "/a/../b", "relative", `/a"><script>`, "/a\\b"} {
		_, got := serve(t, Options{}, newRequest("/", "localhost", map[string]string{"X-Forwarded-Prefix": value}), nil)
		if got.prefix != "" {
			t.Errorf("X-Forwarded-Prefix %q produced prefix %q", value, got.prefix)
		}
	}
}

func TestWrapPrefixesRootRelativeLocations(t *testing.T) {
	for _, tc := range []struct {
		name, prefixHeader, location, want string
	}{
		{"root relative", "/p", "/?focus=overview", "/p/?focus=overview"},
		{"subpath", "/p", "/decoder/", "/p/decoder/"},
		{"absolute", "/p", "https://issuer.example/cb", "https://issuer.example/cb"},
		{"scheme relative", "/p", "//issuer.example/cb", "//issuer.example/cb"},
		{"relative to the server path", "/p", "./", "/p/"},
		{"no prefix", "", "/?focus=overview", "/?focus=overview"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{}
			if tc.prefixHeader != "" {
				headers["X-Forwarded-Prefix"] = tc.prefixHeader
			}
			rec, _ := serve(t, Options{}, newRequest("/", "localhost", headers), func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tc.location, http.StatusSeeOther)
			})
			if got := rec.Header().Get("Location"); got != tc.want {
				t.Fatalf("Location = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWrapKeepsStreamingWriter(t *testing.T) {
	rec, _ := serve(t, Options{BaseURL: "https://mydomain.de/p"}, newRequest("/p/stream", "mydomain.de", nil), func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("flush through the wrapper: %v", err)
		}
		_, _ = w.Write([]byte("data: x\n\n"))
	})
	if !rec.Flushed || rec.Body.String() != "data: x\n\n" {
		t.Fatalf("flushed=%v body=%q", rec.Flushed, rec.Body.String())
	}
}

func TestWrapReportsMismatchesOnce(t *testing.T) {
	var reports []string
	h := Wrap(Options{BaseURL: "https://mydomain.de/some/context", OnMismatch: func(s string) { reports = append(reports, s) }},
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	send := func(headers map[string]string) {
		h.ServeHTTP(httptest.NewRecorder(), newRequest("/", "eudi-dev:8085", headers))
	}
	for _, headers := range []map[string]string{
		{"X-Forwarded-Host": "other.example"},
		{"X-Forwarded-Host": "other.example"},
		{"X-Forwarded-Host": "mydomain.de", "X-Forwarded-Prefix": "/wrong"},
		{"X-Forwarded-Host": "mydomain.de", "X-Forwarded-Prefix": "/some/context"},
		{},
	} {
		send(headers)
	}
	want := []string{`host "other.example"`, `path prefix "/wrong"`}
	if fmt.Sprint(reports) != fmt.Sprint(want) {
		t.Fatalf("reports = %q, want %q", reports, want)
	}
	for i := 0; i < 2*maxMismatches; i++ {
		send(map[string]string{"X-Forwarded-Host": fmt.Sprintf("h%d.example", i)})
	}
	if len(reports) != maxMismatches {
		t.Fatalf("reported %d mismatches, want %d", len(reports), maxMismatches)
	}
}

func TestInjectBase(t *testing.T) {
	page := []byte("<!DOCTYPE html>\n<html>\n<head>\n<title>x</title></head></html>")
	got := string(injectBase(page, "/some/context"))
	if !strings.Contains(got, "<head>\n  <base href=\"/some/context/\">\n<title>") {
		t.Fatalf("base not injected: %s", got)
	}
	// A forwarded prefix may contain any path character.
	if got := string(injectBase(page, "/a'&b")); !strings.Contains(got, `<base href="/a&#39;&amp;b/">`) {
		t.Fatalf("prefix not escaped: %s", got)
	}
}

// rootAbsolutePath matches links such as href="/api" that point outside a path prefix.
var rootAbsolutePath = regexp.MustCompile("(?:href|src|action)=\\?\"/[^/]|[('\"`]/(?:api|decoder|decode|issuer|verifier|imprint|\\.well-known)\\b")

// The pages served under a path prefix must link relative to their own location.
func TestUIsUseRelativePaths(t *testing.T) {
	var files []string
	for _, pattern := range []string{
		"../wallet/static/*.html", "../wallet/static/*.js",
		"../demorp/static/*", "../demorp/issuer_authcode.go",
		"../proxy/static/*.html", "../proxy/static/*.js",
		"../imprint/imprint.go",
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			t.Fatalf("no files for %s: %v", pattern, err)
		}
		files = append(files, matches...)
	}
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if rootAbsolutePath.MatchString(line) {
				t.Errorf("%s:%d uses a root-absolute path: %s", name, i+1, strings.TrimSpace(line))
			}
		}
	}
}

type headerCounter struct {
	*httptest.ResponseRecorder
	headers int
}

func (c *headerCounter) WriteHeader(code int) {
	c.headers++
	c.ResponseRecorder.WriteHeader(code)
}

// An event stream writes and flushes many times. net/http logs every
// WriteHeader after the first one as superfluous.
func TestWrapWritesTheHeaderOnce(t *testing.T) {
	counter := &headerCounter{ResponseRecorder: httptest.NewRecorder()}
	handler := Wrap(Options{BaseURL: "https://mydomain.de/p"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for range 3 {
			_, _ = w.Write([]byte("data: x\n\n"))
			_ = http.NewResponseController(w).Flush()
		}
	}))
	handler.ServeHTTP(counter, newRequest("/p/stream", "mydomain.de", nil))
	if counter.headers != 1 {
		t.Fatalf("WriteHeader reached the response %d times, want 1", counter.headers)
	}
}
