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

package wallet

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/publicpath"
)

// Identifies the browser that owns a request. It does not authenticate users
// (ADR-0002). See docs/public-demo.md for the demo's cookie notice.
const sessionCookieName = "eudi_session"

// OwnerHeader carries the same browser ID as the page URL opened by the client. This
// associates the submitted request with that page.
const OwnerHeader = config.OwnerHeader

// The page URL and event stream carry the browser ID as a query parameter.
const ownerParam = "owner"

// Only browser handlers create sessions. API clients that discard cookies could
// otherwise create requests they cannot retrieve.
func newBrowserSession(w http.ResponseWriter, r *http.Request, secure bool) string {
	if existing := browserSession(r); existing != "" {
		return existing
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	id := base64.RawURLEncoding.EncodeToString(raw)
	//nolint:gosec // G124: Secure is set for TLS. Localhost also supports plain HTTP, and secure cookies need HTTPS.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     cookiePath(r),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	})
	return id
}

// Scope the cookie to the public prefix so apps sharing the host do not receive it.
func cookiePath(r *http.Request) string {
	if prefix := publicpath.Prefix(r); prefix != "" {
		return prefix
	}
	return "/"
}

func browserSession(r *http.Request) string {
	if r == nil {
		return ""
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie == nil {
		return ""
	}
	return cookie.Value
}

func namedOwner(r *http.Request) string {
	if r == nil {
		return ""
	}
	return boundedOwner(r.Header.Get(OwnerHeader))
}

// Bound caller-supplied IDs because they become map keys.
const maxOwnerLength = 128

func boundedOwner(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > maxOwnerLength {
		return ""
	}
	return value
}

// EventSource cannot set custom headers, so the event stream also accepts the owner in
// its query.
func presentedOwner(r *http.Request) string {
	if token := namedOwner(r); token != "" {
		return token
	}
	if r == nil {
		return ""
	}
	return boundedOwner(r.URL.Query().Get(ownerParam))
}

// Prefer the explicit browser ID. Clients submitting for a browser do not have its
// session cookie.
func requestOwner(r *http.Request) string {
	// Only accept the header here. Issuers and verifiers construct protocol URLs and
	// must not select the browser that owns the resulting request.
	if token := namedOwner(r); token != "" {
		return token
	}
	return browserSession(r)
}

// A page opened by a client can have both its own session cookie and the browser ID
// from the client.
func callerOwners(r *http.Request) []string {
	var owners []string
	if session := browserSession(r); session != "" {
		owners = append(owners, session)
	}
	if token := presentedOwner(r); token != "" && !consent.OwnedBy(owners, token) {
		owners = append(owners, token)
	}
	return owners
}

// Use X-Forwarded-Proto when a proxy terminates TLS. Setting Secure for plain HTTP
// would prevent the browser from keeping the session cookie.
func (s *Server) browserSecure(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if comma := strings.IndexByte(proto, ','); comma >= 0 {
		proto = proto[:comma]
	}
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

func (s *Server) withBrowserSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPageRequest(r) {
			newBrowserSession(w, r, s.browserSecure(r))
		}
		next.ServeHTTP(w, r)
	})
}

func isPageRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	return r.URL.Path == "/" || r.URL.Path == "/index.html"
}

// The wallet includes the request ID in the browser's redirect URL.
func namedRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.URL.Query().Get("request")
}

// Presentations requested during issuance belong to the offer's browser. For unowned
// offers, use the browser that approved consent.
func approvingOwner(offerOwner, approverOwner string) string {
	if offerOwner != "" {
		return offerOwner
	}
	return approverOwner
}
