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

package httpsec

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHeaders(t *testing.T) {
	handler := Headers(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest("GET", "/", nil))

	csp := resp.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("no Content-Security-Policy")
	}
	// An injected handler or script tag must not run. An injection must not
	// reach another origin.
	if strings.Contains(csp, "unsafe-inline") && strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Error("script-src allows inline script, which defeats the point")
	}
	for _, want := range []string{
		"script-src 'self'", "object-src 'none'", "base-uri 'self'",
		"frame-ancestors 'none'", "form-action 'self'", "connect-src 'self'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP is missing %q: %s", want, csp)
		}
	}
	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := resp.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

// --adhoc-display-images keeps an issuer's https image URL. The card then
// loads the image from the issuer.
func TestHeadersWithRemoteImagesLoadsHTTPSImages(t *testing.T) {
	resp := httptest.NewRecorder()
	HeadersWithRemoteImages(http.NotFoundHandler()).ServeHTTP(resp, httptest.NewRequest("GET", "/", nil))
	if csp := resp.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "img-src 'self' data: https:;") || !strings.Contains(csp, "script-src 'self';") {
		t.Fatalf("CSP = %s", csp)
	}
}

// An SVG opened on its own must not run scripts on the wallet's origin.
func TestServeImageSandboxesTheImage(t *testing.T) {
	resp := httptest.NewRecorder()
	ServeImage(resp, httptest.NewRequest("GET", "/logo", nil), "image/svg+xml", []byte("<svg/>"))
	if csp := resp.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "sandbox") || !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP = %q", csp)
	}
	if got := resp.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	if resp.Header().Get("Content-Type") != "image/svg+xml" || resp.Body.String() != "<svg/>" {
		t.Errorf("served %q as %q", resp.Body.String(), resp.Header().Get("Content-Type"))
	}

	again := httptest.NewRequest("GET", "/logo", nil)
	again.Header.Set("If-None-Match", resp.Header().Get("ETag"))
	revalidated := httptest.NewRecorder()
	ServeImage(revalidated, again, "image/svg+xml", []byte("<svg/>"))
	if revalidated.Code != http.StatusNotModified {
		t.Errorf("revalidation answered %d, want 304", revalidated.Code)
	}
}
