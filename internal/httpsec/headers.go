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

// Package httpsec applies browser security headers to pages that display untrusted
// credentials, metadata and protocol messages. The headers limit the damage of an
// escaping bug.
package httpsec

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
)

// contentSecurityPolicy restricts scripts and styles to this origin. With
// inline scripts blocked, injected event handlers cannot run.
func contentSecurityPolicy(imgSrc string) string {
	return "default-src 'self'; " +
		"script-src 'self'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src " + imgSrc + "; " +
		"font-src 'self'; " +
		"connect-src 'self'; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"frame-ancestors 'none'"
}

// Headers wraps a handler with the browser security headers. A stored
// credential served as JSON must never be sniffed as HTML. The referrer must
// not leak URLs to a verifier or issuer.
func Headers(next http.Handler) http.Handler {
	return headers(next, "'self' data:")
}

// HeadersWithRemoteImages also lets pages load https images. A wallet that
// keeps an issuer's image URL shows the card image from the issuer.
func HeadersWithRemoteImages(next http.Handler) http.Handler {
	return headers(next, "'self' data: https:")
}

func headers(next http.Handler, imgSrc string) http.Handler {
	policy := contentSecurityPolicy(imgSrc)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", policy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// ServeImage writes an image that a visitor or an issuer supplied. Opened on
// its own, an SVG could run scripts on this origin, so the image gets a
// sandboxed policy of its own. Its content ETag lets the browser revalidate
// an image that changed under the same URL.
func ServeImage(w http.ResponseWriter, r *http.Request, contentType string, data []byte) {
	sum := sha256.Sum256(data)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	h := w.Header()
	h.Set("ETag", etag)
	h.Set("Cache-Control", "no-cache")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	h.Set("X-Content-Type-Options", "nosniff")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Type", contentType)
	h.Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}
