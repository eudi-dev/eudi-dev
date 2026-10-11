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

// Package publicpath serves an application under a path prefix behind a reverse proxy,
// such as https://example.com/some/context. The proxy may strip the prefix before
// forwarding a request or keep it.
//
// All URLs in protocol messages come from the base URL. Forwarded headers only affect
// redirects, the page's <base href> and the cookie path.
// See docs/adr/0019-the-base-url-is-the-public-identity.md.
package publicpath

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// prefixPattern accepts absolute paths of URL path characters only. Other
// characters could turn a redirect or base href into a link to another site.
var prefixPattern = regexp.MustCompile(`^(/[A-Za-z0-9\-._~!$&'()*+,;=:@%]+)+$`)

// BasePath returns the path of baseURL without a trailing slash, or "" for a URL
// without a path.
func BasePath(baseURL string) (string, error) {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return "", nil
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parsing base URL: %w", err)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("base URL %q must not have a query or fragment", baseURL)
	}
	p, ok := cleanPrefix(u.Path)
	if !ok {
		return "", fmt.Errorf("base URL %q has an invalid path", baseURL)
	}
	return p, nil
}

// FirstSegment returns the first segment of the base URL's path, such as "some" for
// https://example.com/some/context. A server must not route that segment itself.
// Its own /some/... paths would look like requests where the proxy kept the prefix.
func FirstSegment(baseURL string) (string, error) {
	p, err := BasePath(baseURL)
	if err != nil {
		return "", err
	}
	first, _, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/")
	return first, nil
}

func cleanPrefix(p string) (string, bool) {
	p = strings.TrimRight(p, "/")
	if p == "" {
		return "", true
	}
	if !prefixPattern.MatchString(p) || strings.Contains(p+"/", "/./") || strings.Contains(p+"/", "/../") {
		return "", false
	}
	return p, true
}

type Options struct {
	// BaseURL is the public URL. Callers check it with BasePath at startup. An invalid
	// value is treated like one without a path.
	BaseURL string
	// OnMismatch is called once for each distinct forwarded host or prefix that does
	// not match BaseURL. Such a mismatch points to a wrong proxy route or BaseURL.
	OnMismatch func(observed string)
}

type contextKey struct{}

// Prefix returns the browser's path prefix for the request, without a trailing
// slash. It is "" when the server is reached at the root.
func Prefix(r *http.Request) string {
	prefix, _ := r.Context().Value(contextKey{}).(string)
	return prefix
}

// Wrap passes requests to next as if the server ran at the root. It removes
// the base path when the proxy kept it. It maps metadata URLs that put the
// well-known name before the base path (RFC 8414 §3.1, OpenID4VCI 1.0 §12.2.2)
// to the root well-known paths. It adds the request's prefix to root-relative
// redirects.
func Wrap(opts Options, next http.Handler) http.Handler {
	basePath, _ := BasePath(opts.BaseURL)
	publicHost := ""
	if u, err := url.Parse(strings.TrimSpace(opts.BaseURL)); err == nil {
		publicHost = normalizeHost(u.Host, u.Scheme)
	}
	m := &mismatches{report: opts.OnMismatch, basePath: basePath, publicHost: publicHost, seen: map[string]bool{}}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := collapseLeadingSlashes(r.URL.Path)
		keptBase := false
		if basePath != "" {
			if rest, ok := cutPrefix(path, basePath); ok {
				path, keptBase = rest, true
			} else if rest, ok := cutWellKnown(path, basePath); ok {
				path = rest
			}
		}
		if path != r.URL.Path {
			r = r.Clone(r.Context())
			r.URL.Path, r.URL.RawPath = path, ""
		}

		prefix := publicPrefix(r, basePath, publicHost, keptBase)
		m.check(r, prefix)

		r = r.WithContext(context.WithValue(r.Context(), contextKey{}, prefix))
		if prefix != "" {
			w = &locationWriter{ResponseWriter: w, prefix: prefix}
		}
		next.ServeHTTP(w, r)
	})
}

// publicPrefix determines the browser's path prefix. X-Forwarded-Prefix holds the
// part stripped by the proxy, and a base path kept by the proxy is appended to
// it. Without either header, a request for the public host came through a proxy
// that stripped the base path. Any other request reached the server directly.
func publicPrefix(r *http.Request, basePath, publicHost string, keptBase bool) string {
	removed := forwardedPrefix(r)
	switch {
	case keptBase:
		return removed + basePath
	case removed != "":
		return removed
	case basePath != "" && browserHost(r) == publicHost:
		return basePath
	}
	return ""
}

func collapseLeadingSlashes(p string) string {
	// Envoy rewrites /some/context/x to //x when a route replaces the prefix with "/".
	for strings.HasPrefix(p, "//") {
		p = p[1:]
	}
	return p
}

// cutPrefix removes prefix from path when it is a whole number of segments.
func cutPrefix(path, prefix string) (string, bool) {
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok || (rest != "" && !strings.HasPrefix(rest, "/")) {
		return "", false
	}
	if rest == "" {
		rest = "/"
	}
	return rest, true
}

// cutWellKnown turns /.well-known/{name}{basePath}{rest} into /.well-known/{name}{rest}.
func cutWellKnown(path, basePath string) (string, bool) {
	rest, ok := strings.CutPrefix(path, "/.well-known/")
	if !ok {
		return "", false
	}
	name, suffix, found := strings.Cut(rest, "/")
	if !found || name == "" {
		return "", false
	}
	tail, ok := cutPrefix("/"+suffix, basePath)
	if !ok {
		return "", false
	}
	return "/.well-known/" + name + strings.TrimSuffix(tail, "/"), true
}

func forwardedPrefix(r *http.Request) string {
	p, ok := cleanPrefix(firstValue(r.Header.Get("X-Forwarded-Prefix")))
	if !ok {
		return ""
	}
	return p
}

func browserHost(r *http.Request) string {
	host, proto := forwardedHostAndProto(r)
	if host == "" {
		host = r.Host
	}
	if proto == "" {
		proto = "http"
		if r.TLS != nil {
			proto = "https"
		}
	}
	return normalizeHost(host, proto)
}

// forwardedHostAndProto reads the RFC 7239 Forwarded header and falls back to
// X-Forwarded-Host and X-Forwarded-Proto.
func forwardedHostAndProto(r *http.Request) (host, proto string) {
	for _, pair := range strings.Split(firstValue(r.Header.Get("Forwarded")), ";") {
		key, value, _ := strings.Cut(strings.TrimSpace(pair), "=")
		switch strings.ToLower(key) {
		case "host":
			host = strings.Trim(value, `"`)
		case "proto":
			proto = strings.Trim(value, `"`)
		}
	}
	if host == "" {
		host = firstValue(r.Header.Get("X-Forwarded-Host"))
	}
	if proto == "" {
		proto = firstValue(r.Header.Get("X-Forwarded-Proto"))
	}
	return host, strings.ToLower(proto)
}

// firstValue returns the first entry of a comma separated header. The proxy
// closest to the browser added that entry.
func firstValue(v string) string {
	first, _, _ := strings.Cut(v, ",")
	return strings.TrimSpace(first)
}

// normalizeHost lowercases host and drops the scheme's default port, so
// example.com:443 over https equals example.com.
func normalizeHost(host, scheme string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	h, port, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	if (port == "443" && scheme == "https") || (port == "80" && scheme == "http") {
		if strings.Contains(h, ":") {
			return "[" + h + "]"
		}
		return h
	}
	return host
}

// Clients choose the forwarded headers, so the number of reports is capped.
const maxMismatches = 32

type mismatches struct {
	report     func(string)
	basePath   string
	publicHost string
	mu         sync.Mutex
	seen       map[string]bool
}

func (m *mismatches) check(r *http.Request, prefix string) {
	if m.report == nil || m.publicHost == "" {
		return
	}
	var observed []string
	if host, _ := forwardedHostAndProto(r); host != "" && browserHost(r) != m.publicHost {
		observed = append(observed, fmt.Sprintf("host %q", browserHost(r)))
	}
	if r.Header.Get("X-Forwarded-Prefix") != "" && prefix != m.basePath {
		observed = append(observed, fmt.Sprintf("path prefix %q", prefix))
	}
	if len(observed) == 0 {
		return
	}
	key := strings.Join(observed, " and ")
	m.mu.Lock()
	report := !m.seen[key] && len(m.seen) < maxMismatches
	m.seen[key] = m.seen[key] || report
	m.mu.Unlock()
	if report {
		m.report(key)
	}
}

// locationWriter adds the prefix to redirects like "/decoder/", so handlers can write
// them as if the server ran at the root. Full URLs and "//host/..." stay unchanged.
type locationWriter struct {
	http.ResponseWriter
	prefix      string
	wroteHeader bool
}

func (w *locationWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		h := w.ResponseWriter.Header()
		if loc := h.Get("Location"); strings.HasPrefix(loc, "/") && !strings.HasPrefix(loc, "//") {
			h.Set("Location", w.prefix+loc)
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *locationWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Flush passes flushes through so event streams keep working.
func (w *locationWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *locationWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ServeIndex serves index for "/" and files for everything else. Under a path prefix
// the index gets a <base href>. Its relative links then also work for a browser URL
// without a trailing slash, such as /some/context.
func ServeIndex(index []byte, files http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := Prefix(r)
		if prefix == "" || r.URL.Path != "/" {
			files.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		//nolint:gosec // G705: prefix matches prefixPattern and injectBase escapes it.
		_, _ = w.Write(injectBase(index, prefix))
	})
}

func injectBase(page []byte, prefix string) []byte {
	head := []byte("<head>")
	i := bytes.Index(page, head)
	if i < 0 {
		return page
	}
	i += len(head)
	tag := "\n  <base href=\"" + html.EscapeString(prefix+"/") + "\">"
	return append(append(append([]byte{}, page[:i]...), tag...), page[i:]...)
}
