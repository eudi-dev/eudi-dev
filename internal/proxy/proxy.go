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
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/netaddr"
)

type proxyContextKey struct{}

// proxiedRequest is what ServeHTTP learns about a request before the Rewrite
// hook points it at the target. modifyResponse reads it from the context.
type proxiedRequest struct {
	start         time.Time
	body          string
	bodyTruncated bool
	originalURL   string
	debugJWEKey   string
}

// maxCapturedBody caps what the proxy keeps of a request or response body for
// the dashboard. The target and the client still get the whole body. Tests
// lower it.
var maxCapturedBody = 1 << 20

type Config struct {
	TargetURL     *url.URL
	ListenHost    string
	ProxyPort     int
	DashboardPort int
	NoDashboard   bool
	AllTraffic    bool // show all traffic including non-OID4VP/VCI requests
}

type Server struct {
	config   Config
	store    *Store
	rewriter *Rewriter
	proxy    *httputil.ReverseProxy
	writer   EntryWriter
	classify *StatefulClassifier
	scanner  *OutputScanner // optional: scans subprocess stdout for keys/credentials
}

func NewServer(cfg Config, writer EntryWriter) *Server {
	s := &Server{
		config:   cfg,
		store:    NewStore(1000),
		writer:   writer,
		classify: NewStatefulClassifier(),
	}

	proxyHost := strings.TrimPrefix(netaddr.LocalURL(cfg.ListenHost, cfg.ProxyPort), "http://")
	targetHost := cfg.TargetURL.Host
	s.rewriter = NewRewriter(targetHost, proxyHost)

	s.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			in, out := pr.In, pr.Out
			forwardedHost := in.Header.Get("X-Forwarded-Host")
			if forwardedHost == "" {
				forwardedHost = in.Host
			}
			forwardedProto := in.Header.Get("X-Forwarded-Proto")
			if forwardedProto == "" {
				if in.TLS != nil {
					forwardedProto = "https"
				} else {
					forwardedProto = "http"
				}
			}
			forwardedPort := in.Header.Get("X-Forwarded-Port")
			if forwardedPort == "" {
				forwardedPort = forwardedPortForProto(forwardedProto)
			}
			// SetXForwarded adds X-Forwarded-For. Values from a proxy in front of
			// this one then set the host, proto and port.
			pr.SetXForwarded()
			out.URL.Scheme = cfg.TargetURL.Scheme
			out.URL.Host = cfg.TargetURL.Host
			out.Host = cfg.TargetURL.Host
			out.Header.Set("X-Forwarded-Host", forwardedHost)
			out.Header.Set("X-Forwarded-Proto", forwardedProto)
			out.Header.Set("X-Forwarded-Port", forwardedPort)
			// The transport then negotiates gzip and decodes it, so the proxy
			// can read and rewrite the body.
			out.Header.Del("Accept-Encoding")
		},
		ModifyResponse: s.modifyResponse,
		// Each chunk of an event stream or of a body over the capture limit
		// goes to the client as it arrives.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy: backend error for %q %q: %v", r.Method, r.URL.Path, err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}

	return s
}

func (s *Server) SetScanner(scanner *OutputScanner) {
	s.scanner = scanner
}

func (s *Server) Store() *Store {
	return s.store
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req := proxiedRequest{start: time.Now(), originalURL: originalURL(r)}

	if r.Body != nil {
		head, err := io.ReadAll(io.LimitReader(r.Body, int64(maxCapturedBody)+1))
		if err != nil {
			log.Printf("proxy: reading the request body of %q %q: %v", r.Method, r.URL.Path, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		req.body = string(head)
		if len(head) > maxCapturedBody {
			req.body, req.bodyTruncated = string(head[:maxCapturedBody]), true
			r.Body = readCloser{io.MultiReader(bytes.NewReader(head), r.Body), r.Body}
		} else {
			r.Body = io.NopCloser(bytes.NewReader(head))
		}
	}

	// The debug JWE key header is meant for the proxy, so the target never
	// sees it.
	req.debugJWEKey = r.Header.Get("X-Debug-JWE-CEK")
	r.Header.Del("X-Debug-JWE-CEK")

	r = r.WithContext(context.WithValue(r.Context(), proxyContextKey{}, req))
	s.proxy.ServeHTTP(newDeadlineWriter(w), r)
}

type readCloser struct {
	io.Reader
	io.Closer
}

// deadlineWriter gives every write to the client a fresh deadline. A long poll
// or an event stream then outlasts the server's write timeout, and a client
// that stops reading still releases the connection.
type deadlineWriter struct {
	http.ResponseWriter
	rc *http.ResponseController
}

func newDeadlineWriter(w http.ResponseWriter) *deadlineWriter {
	return &deadlineWriter{ResponseWriter: w, rc: http.NewResponseController(w)}
}

// A writer without deadlines, such as a test recorder, keeps none.
func (d *deadlineWriter) extend() {
	_ = d.rc.SetWriteDeadline(time.Now().Add(streamWriteTimeout))
}

func (d *deadlineWriter) WriteHeader(code int) {
	d.extend()
	d.ResponseWriter.WriteHeader(code)
}

func (d *deadlineWriter) Write(p []byte) (int, error) {
	d.extend()
	return d.ResponseWriter.Write(p)
}

func (d *deadlineWriter) FlushError() error {
	d.extend()
	return d.rc.Flush()
}

func (d *deadlineWriter) Unwrap() http.ResponseWriter {
	return d.ResponseWriter
}

// originalURL reconstructs the URL that the client requested. Behind another
// reverse proxy it uses X-Forwarded-Host and X-Forwarded-Proto. Otherwise it
// uses the Host header and request URI.
func originalURL(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}

	return scheme + "://" + host + r.RequestURI
}

func forwardedPortForProto(proto string) string {
	if strings.EqualFold(proto, "https") {
		return "443"
	}
	return "80"
}

func (s *Server) modifyResponse(resp *http.Response) error {
	req, ok := resp.Request.Context().Value(proxyContextKey{}).(proxiedRequest)
	if !ok {
		req.start = time.Now()
	}
	debugJWEKey := req.debugJWEKey

	respBody, respTruncated, err := s.captureResponseBody(resp)
	if err != nil {
		return err
	}
	s.rewriter.RewriteHeaders(resp.Header)

	start := req.start
	duration := time.Since(start)

	displayURL := req.originalURL
	if displayURL == "" {
		displayURL = resp.Request.URL.String()
	}

	if debugJWEKey == "" && s.scanner != nil {
		debugJWEKey = s.scanner.LastCEK()
	}

	var debugJWK string
	if s.scanner != nil {
		debugJWK = s.scanner.LastJWK()
	}

	entry := &TrafficEntry{
		Timestamp:         start,
		Method:            resp.Request.Method,
		URL:               displayURL,
		RequestHeaders:    resp.Request.Header.Clone(),
		RequestBody:       req.body,
		RequestTruncated:  req.bodyTruncated,
		StatusCode:        resp.StatusCode,
		ResponseHeaders:   resp.Header.Clone(),
		ResponseBody:      respBody,
		ResponseTruncated: respTruncated,
		Duration:          duration,
		DurationMS:        duration.Milliseconds(),
		DebugJWEKey:       debugJWEKey,
		DebugJWK:          debugJWK,
	}

	s.classify.Classify(entry)
	if !shouldEmitEntry(entry, s.config.AllTraffic) {
		return nil
	}

	s.store.Add(entry)

	if s.writer != nil {
		s.writer.WriteEntry(entry)
	}

	return nil
}

// captureResponseBody reads the body for the entry and rewrites target host
// references in it. It reports whether it kept only the first
// maxCapturedBody bytes. An event stream passes through unread because it
// ends only when the connection does. A body in an encoding the proxy cannot
// decode passes through unchanged because a text rewrite would corrupt it.
// The rest of a body over the limit also passes through unchanged. The proxy
// never holds such a body whole.
func (s *Server) captureResponseBody(resp *http.Response) (string, bool, error) {
	if resp.Body == nil || isEventStream(resp.Header) {
		return "", false, nil
	}
	var reader io.Reader
	switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
	case "", "identity":
		reader = resp.Body
	case "gzip":
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return "", false, fmt.Errorf("reading the gzip response body: %w", err)
		}
		reader = gz
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
	default:
		return "", false, nil
	}

	head, err := io.ReadAll(io.LimitReader(reader, int64(maxCapturedBody)+1))
	if err != nil {
		resp.Body.Close()
		return "", false, fmt.Errorf("reading the response body: %w", err)
	}
	if len(head) > maxCapturedBody {
		resp.Body = readCloser{io.MultiReader(bytes.NewReader(head), reader), resp.Body}
		return string(head[:maxCapturedBody]), true, nil
	}
	resp.Body.Close()
	body := string(head)
	rewritten := s.rewriter.RewriteBody(body)
	resp.Body = io.NopCloser(strings.NewReader(rewritten))
	resp.ContentLength = int64(len(rewritten))
	resp.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
	return body, false, nil
}

func isEventStream(h http.Header) bool {
	mediaType, _, _ := mime.ParseMediaType(h.Get("Content-Type"))
	return mediaType == "text/event-stream"
}

func shouldEmitEntry(entry *TrafficEntry, allTraffic bool) bool {
	return allTraffic || entry.Class != ClassUnknown
}
