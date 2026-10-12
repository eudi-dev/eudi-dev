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
	"net/url"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
)

// GuardAPI rejects requests under /api/ that carry a foreign Origin. CORS only
// blocks reading the response, so a foreign page could still trigger a
// presentation. CLI tools send no Origin and pass. ownOrigins adds public
// origins for proxies that rewrite Host. Protocol endpoints stay open.
func GuardAPI(next http.Handler, ownOrigins ...string) http.Handler {
	return GuardAPIExcept(next, nil, ownOrigins...)
}

// GuardAPIExcept lets selected endpoints receive requests from other origins. The
// Digital Credentials API identifies unsigned callers by their origin and asks
// for consent.
func GuardAPIExcept(next http.Handler, crossOriginByContract []string, ownOrigins ...string) http.Handler {
	allowed := hostSet(ownOrigins)
	exempt := make(map[string]bool, len(crossOriginByContract))
	for _, p := range crossOriginByContract {
		exempt[p] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") && !exempt[r.URL.Path] && isCrossOrigin(r, allowed) {
			apierror.WriteStatus(w, http.StatusForbidden, "cross-origin API requests are not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isCrossOrigin(r *http.Request, allowed map[string]bool) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		// A sandboxed frame or a file:// page sends the literal "null".
		return true
	}
	host := strings.ToLower(u.Host)
	// A TLS terminator can forward HTTPS requests over HTTP, so only hosts are compared.
	if host == strings.ToLower(r.Host) {
		return false
	}
	return !allowed[host]
}

func hostSet(origins []string) map[string]bool {
	set := make(map[string]bool, len(origins))
	for _, raw := range origins {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" {
			continue
		}
		set[strings.ToLower(u.Host)] = true
	}
	return set
}
