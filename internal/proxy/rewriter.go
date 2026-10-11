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
	"net/http"
	"strings"
)

// Rewriter replaces target host references with the proxy host in response bodies and headers.
type Rewriter struct {
	targetHost string
	proxyHost  string
}

func NewRewriter(targetHost, proxyHost string) *Rewriter {
	return &Rewriter{
		targetHost: targetHost,
		proxyHost:  proxyHost,
	}
}

// RewriteBody replaces the target host with the proxy host in body content.
func (rw *Rewriter) RewriteBody(body string) string {
	// Rewriting a signed JWT would invalidate its signature.
	if isJWTBody(body) {
		return body
	}
	return strings.ReplaceAll(body, rw.targetHost, rw.proxyHost)
}

func (rw *Rewriter) RewriteHeaders(h http.Header) {
	for _, key := range []string{"Location", "Content-Location"} {
		if v := h.Get(key); v != "" {
			h.Set(key, strings.ReplaceAll(v, rw.targetHost, rw.proxyHost))
		}
	}
}
