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

func reached(hit *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hit = true
		w.WriteHeader(http.StatusOK)
	})
}

func TestGuardAPI(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		path       string
		origin     string
		ownOrigins []string
		want       bool
	}{
		// A page on another site sends a request that CORS does not preflight.
		{name: "foreign origin on the API", method: "POST", path: "/api/presentations", origin: "https://evil.example", want: false},
		{name: "foreign origin reading credentials", method: "GET", path: "/api/credentials", origin: "https://evil.example", want: false},
		// A CLI, curl or a test harness sends no Origin.
		{name: "no origin", method: "POST", path: "/api/presentations", want: true},
		{name: "same origin", method: "POST", path: "/api/presentations", origin: "http://wallet.test", want: true},
		{name: "same origin, other scheme", method: "POST", path: "/api/presentations", origin: "https://wallet.test", want: true},
		// A deployment whose public URL is not the Host it receives.
		{name: "configured own origin", method: "POST", path: "/api/issue", origin: "https://eudi-test.dev", ownOrigins: []string{"https://eudi-test.dev"}, want: true},
		{name: "own origin does not admit others", method: "POST", path: "/api/issue", origin: "https://evil.example", ownOrigins: []string{"https://eudi-test.dev"}, want: false},
		// A sandboxed frame or a file:// page sends "null".
		{name: "null origin", method: "POST", path: "/api/issue", origin: "null", want: false},
		{name: "unparseable origin", method: "POST", path: "/api/issue", origin: "://", want: false},
		// Other sites must reach protocol endpoints.
		{name: "foreign origin off the API", method: "GET", path: "/authorize", origin: "https://evil.example", want: true},
		{name: "verifier posting a response", method: "POST", path: "/callback", origin: "https://verifier.example", want: true},
		{name: "static asset", method: "GET", path: "/app.js", origin: "https://evil.example", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit := false
			guard := GuardAPI(reached(&hit), tc.ownOrigins...)

			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Host = "wallet.test"
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			guard.ServeHTTP(rec, req)

			if hit != tc.want {
				t.Errorf("reached handler = %v, want %v (status %d)", hit, tc.want, rec.Code)
			}
			if tc.want {
				return
			}
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			if body := rec.Body.String(); !strings.Contains(body, `"error":"forbidden"`) || !strings.Contains(body, "cross-origin") {
				t.Errorf("body %q is not the forbidden error object that says why", body)
			}
		})
	}
}

// The port is part of an origin. Another service on the same host is a foreign
// origin. This is common on a developer machine.
func TestGuardAPIComparesPorts(t *testing.T) {
	for _, origin := range []string{"http://localhost:3000", "http://localhost"} {
		hit := false
		guard := GuardAPI(reached(&hit))
		req := httptest.NewRequest("POST", "/api/issue", nil)
		req.Host = "localhost:8085"
		req.Header.Set("Origin", origin)
		guard.ServeHTTP(httptest.NewRecorder(), req)
		if hit {
			t.Errorf("Origin %q reached the API of localhost:8085", origin)
		}
	}
}
