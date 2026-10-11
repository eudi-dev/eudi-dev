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
)

type proxyContextKey string

const (
	proxyStartContextKey       proxyContextKey = "proxy-start"
	proxyRequestBodyContextKey proxyContextKey = "proxy-request-body"
	proxyOriginalURLContextKey proxyContextKey = "proxy-original-url"
	proxyDebugJWEKeyContextKey proxyContextKey = "proxy-debug-jwe-key"
)

type Config struct {
	TargetURL     *url.URL
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

	proxyHost := fmt.Sprintf("localhost:%d", cfg.ProxyPort)
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
	start := time.Now()

	// Read the original URL now, because the Rewrite hook points it at the target.
	origURL := originalURL(r)

	var reqBody string
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err == nil {
			reqBody = string(bodyBytes)
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	// The debug JWE key header is meant for the proxy, so the target never
	// sees it.
	debugJWEKey := r.Header.Get("X-Debug-JWE-CEK")
	r.Header.Del("X-Debug-JWE-CEK")

	ctx := r.Context()
	ctx = context.WithValue(ctx, proxyStartContextKey, start)
	ctx = context.WithValue(ctx, proxyRequestBodyContextKey, reqBody)
	ctx = context.WithValue(ctx, proxyOriginalURLContextKey, origURL)
	ctx = context.WithValue(ctx, proxyDebugJWEKeyContextKey, debugJWEKey)
	r = r.WithContext(ctx)

	s.proxy.ServeHTTP(w, r)
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
	start := time.Now()
	if value, ok := resp.Request.Context().Value(proxyStartContextKey).(time.Time); ok {
		start = value
	}
	reqBody, _ := resp.Request.Context().Value(proxyRequestBodyContextKey).(string)
	origURL, _ := resp.Request.Context().Value(proxyOriginalURLContextKey).(string)
	debugJWEKey, _ := resp.Request.Context().Value(proxyDebugJWEKeyContextKey).(string)

	respBody, err := s.captureResponseBody(resp)
	if err != nil {
		return err
	}
	s.rewriter.RewriteHeaders(resp.Header)

	duration := time.Since(start)

	displayURL := origURL
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
		Timestamp:       start,
		Method:          resp.Request.Method,
		URL:             displayURL,
		RequestHeaders:  resp.Request.Header.Clone(),
		RequestBody:     reqBody,
		StatusCode:      resp.StatusCode,
		ResponseHeaders: resp.Header.Clone(),
		ResponseBody:    respBody,
		Duration:        duration,
		DurationMS:      duration.Milliseconds(),
		DebugJWEKey:     debugJWEKey,
		DebugJWK:        debugJWK,
	}

	if s.classify != nil {
		s.classify.Classify(entry)
	} else {
		Classify(entry)
	}
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
// references in it. An event stream passes through unread because it ends
// only when the connection does. A body in an encoding the proxy cannot decode
// passes through unchanged because a text rewrite would corrupt it.
func (s *Server) captureResponseBody(resp *http.Response) (string, error) {
	if resp.Body == nil || isEventStream(resp.Header) {
		return "", nil
	}
	var reader io.Reader
	switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
	case "", "identity":
		reader = resp.Body
	case "gzip":
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return "", fmt.Errorf("reading the gzip response body: %w", err)
		}
		reader = gz
		resp.Header.Del("Content-Encoding")
	default:
		return "", nil
	}

	bodyBytes, err := io.ReadAll(reader)
	resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("reading the response body: %w", err)
	}
	body := string(bodyBytes)
	rewritten := s.rewriter.RewriteBody(body)
	resp.Body = io.NopCloser(strings.NewReader(rewritten))
	resp.ContentLength = int64(len(rewritten))
	resp.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
	return body, nil
}

func isEventStream(h http.Header) bool {
	mediaType, _, _ := mime.ParseMediaType(h.Get("Content-Type"))
	return mediaType == "text/event-stream"
}

func shouldEmitEntry(entry *TrafficEntry, allTraffic bool) bool {
	return allTraffic || entry.Class != ClassUnknown
}
