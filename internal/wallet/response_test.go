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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestFormatDirectPostResult_Success(t *testing.T) {
	result := &DirectPostResult{
		StatusCode: 200,
	}
	got := FormatDirectPostResult(result)
	if got != "Response: 200" {
		t.Errorf("expected 'Response: 200', got %s", got)
	}
}

func TestFormatDirectPostResult_WithRedirect(t *testing.T) {
	result := &DirectPostResult{
		StatusCode:  200,
		RedirectURI: "https://verifier.example/success",
	}
	got := FormatDirectPostResult(result)
	expected := "Response: 200 → https://verifier.example/success"
	if got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}

func TestFormatDirectPostResult_Error(t *testing.T) {
	result := &DirectPostResult{
		StatusCode: 400,
		Body:       `{"error": "invalid_request"}`,
	}
	got := FormatDirectPostResult(result)
	if got != "Response: 400" {
		t.Errorf("expected 'Response: 400', got %s", got)
	}
}

func TestBuildFragmentRedirect(t *testing.T) {
	tests := []struct {
		name        string
		redirectURI string
		state       string
		vpToken     any
		wantContain []string
	}{
		{
			name:        "basic redirect with state",
			redirectURI: "https://verifier.example/callback",
			state:       "abc123",
			vpToken:     map[string][]string{"pid": {"token1"}},
			wantContain: []string{"https://verifier.example/callback#", "state=abc123", "vp_token="},
		},
		{
			name:        "redirect without state",
			redirectURI: "https://verifier.example/callback",
			state:       "",
			vpToken:     map[string][]string{"pid": {"token1"}},
			wantContain: []string{"https://verifier.example/callback#", "vp_token="},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildFragmentRedirect(tt.redirectURI, tt.state, tt.vpToken, "")
			if err != nil {
				t.Fatalf("BuildFragmentRedirect() error: %v", err)
			}
			for _, want := range tt.wantContain {
				if !strings.Contains(got, want) {
					t.Errorf("expected URL to contain %q, got: %s", want, got)
				}
			}
			if tt.state == "" && strings.Contains(got, "state=") {
				t.Errorf("expected no state parameter, got: %s", got)
			}
		})
	}
}

func TestSubmitDirectPost_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"redirect_uri": "https://example.com/done"})
	}))
	defer ts.Close()

	result, err := SubmitDirectPostObject(ts.URL, buildPlainAuthorizationResponse(map[string][]string{"pid": {"token1"}}, "", "state123"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.StatusCode)
	}
	if result.RedirectURI != "https://example.com/done" {
		t.Errorf("expected redirect URI 'https://example.com/done', got %q", result.RedirectURI)
	}
}

func TestSubmitDirectPost_WithIDToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		if r.FormValue("vp_token") == "" {
			t.Error("expected vp_token in form")
		}
		if r.FormValue("id_token") != "eyJ.test.token" {
			t.Errorf("expected id_token 'eyJ.test.token', got %q", r.FormValue("id_token"))
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]string{"redirect_uri": "https://example.com/cb"})
	}))
	defer ts.Close()

	result, err := SubmitDirectPostObject(ts.URL, buildPlainAuthorizationResponse(map[string][]string{"pid": {"tok"}}, "eyJ.test.token", "s1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected 200, got %d", result.StatusCode)
	}
}

func TestSubmitDirectPost_LocationHeader(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.com/redirect-via-header")
		w.WriteHeader(200)
		w.Write([]byte("no json"))
	}))
	defer ts.Close()

	result, err := SubmitDirectPostObject(ts.URL, buildPlainAuthorizationResponse(map[string][]string{"pid": {"tok"}}, "", "state1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RedirectURI != "https://example.com/redirect-via-header" {
		t.Errorf("expected redirect from Location header, got %q", result.RedirectURI)
	}
}

func TestSubmitDirectPost_NoVPToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		if r.FormValue("vp_token") != "" {
			t.Error("expected no vp_token in form")
		}
		if r.FormValue("state") != "onlystate" {
			t.Errorf("expected state 'onlystate', got %q", r.FormValue("state"))
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	result, err := SubmitDirectPostObject(ts.URL, buildPlainAuthorizationResponse(nil, "", "onlystate"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected 200, got %d", result.StatusCode)
	}
}

func TestSubmitDirectPostError_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		if r.FormValue("error") != "access_denied" {
			t.Errorf("expected error 'access_denied', got %q", r.FormValue("error"))
		}
		if r.FormValue("error_description") != "testing" {
			t.Errorf("expected error_description 'testing', got %q", r.FormValue("error_description"))
		}
		if r.FormValue("state") != "state123" {
			t.Errorf("expected state 'state123', got %q", r.FormValue("state"))
		}
		if r.FormValue("response") != "" {
			t.Errorf("expected no response field, got %q", r.FormValue("response"))
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]string{"redirect_uri": "https://example.com/error-done"})
	}))
	defer ts.Close()

	result, err := SubmitDirectPostObject(ts.URL, buildPlainAuthorizationErrorResponse("access_denied", "testing", "state123"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected 200, got %d", result.StatusCode)
	}
	if result.RedirectURI != "https://example.com/error-done" {
		t.Errorf("expected redirect URI, got %q", result.RedirectURI)
	}
}

func TestSubmitDirectPostJWT_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		if r.FormValue("response") != "jwe.compact.token" {
			t.Errorf("expected response 'jwe.compact.token', got %q", r.FormValue("response"))
		}
		if r.FormValue("state") != "" {
			t.Errorf("expected no top-level state form field, got %q", r.FormValue("state"))
		}
		if r.FormValue("vp_token") != "" {
			t.Errorf("expected no top-level vp_token form field, got %q", r.FormValue("vp_token"))
		}
		if r.FormValue("id_token") != "" {
			t.Errorf("expected no top-level id_token form field, got %q", r.FormValue("id_token"))
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]string{"redirect_uri": "https://example.com/jwt-done"})
	}))
	defer ts.Close()

	result, err := SubmitDirectPostJWT(ts.URL, "jwe.compact.token", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected 200, got %d", result.StatusCode)
	}
	if result.RedirectURI != "https://example.com/jwt-done" {
		t.Errorf("expected redirect URI, got %q", result.RedirectURI)
	}
}

func TestSubmitDirectPostJWT_WithCEK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cekHeader := r.Header.Get("X-Debug-JWE-CEK")
		if cekHeader == "" {
			t.Error("expected X-Debug-JWE-CEK header to be present")
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	result, err := SubmitDirectPostJWT(ts.URL, "jwe.token", []byte("0123456789abcdef"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected 200, got %d", result.StatusCode)
	}
}

func TestSubmitDirectPost_RejectsRelativeRedirectURI(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"redirect_uri": "/relative"})
	}))
	defer ts.Close()

	_, err := SubmitDirectPostObject(ts.URL, buildPlainAuthorizationResponse(map[string][]string{"pid": {"token1"}}, "", "state123"))
	if err == nil {
		t.Fatal("expected error for relative redirect_uri")
	}
	if !strings.Contains(err.Error(), "redirect_uri") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// url.Parse accepts javascript: and data: as absolute URIs. Navigating to them could
// execute script on the wallet's origin.
func TestSubmitDirectPost_RejectsScriptRedirectURI(t *testing.T) {
	for _, redirect := range []string{
		"javascript:window.__pwned=1",
		"JavaScript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
	} {
		t.Run(redirect, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"redirect_uri": redirect})
			}))
			defer ts.Close()

			_, err := SubmitDirectPostObject(ts.URL, buildPlainAuthorizationResponse(map[string][]string{"pid": {"token1"}}, "", "state123"))
			if err == nil {
				t.Fatalf("a %q redirect_uri was accepted", redirect)
			}
			if !strings.Contains(err.Error(), "http or https") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSubmitDirectPost_RejectsScriptLocationHeader(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "javascript:window.__pwned=1")
		w.WriteHeader(http.StatusFound)
	}))
	defer ts.Close()

	if _, err := SubmitDirectPostObject(ts.URL, buildPlainAuthorizationResponse(map[string][]string{"pid": {"token1"}}, "", "state123")); err == nil {
		t.Fatal("a javascript: Location header was accepted")
	}
}

func TestBuildFragmentRedirect_WithIDTokenAndVPToken(t *testing.T) {
	got, err := BuildFragmentRedirect("https://verifier.example/callback", "s1", map[string][]string{"pid": {"tok1"}}, "eyJ.id.token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "id_token=") {
		t.Errorf("expected id_token in fragment, got: %s", got)
	}
	if !strings.Contains(got, "vp_token=") {
		t.Errorf("expected vp_token in fragment, got: %s", got)
	}
	if !strings.Contains(got, "state=s1") {
		t.Errorf("expected state in fragment, got: %s", got)
	}
}

func TestBuildFragmentRedirect_NilVPToken(t *testing.T) {
	got, err := BuildFragmentRedirect("https://verifier.example/callback", "s1", nil, "eyJ.id.token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(got, "vp_token=") {
		t.Errorf("expected no vp_token in fragment, got: %s", got)
	}
	if !strings.Contains(got, "id_token=") {
		t.Errorf("expected id_token in fragment, got: %s", got)
	}
	if !strings.Contains(got, "state=s1") {
		t.Errorf("expected state in fragment, got: %s", got)
	}
}

// OID4VP 1.0 §5.6 follows RFC 6749 §4.2.2. Response parameters must be added to the
// existing fragment. A second # would become part of its value.
func TestFragmentResponsesMergeIntoAnExistingFragment(t *testing.T) {
	got, err := BuildFragmentRedirect("https://verifier.example/callback#session=abc", "s1", map[string][]string{"pid": {"tok1"}}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Count(got, "#") != 1 {
		t.Fatalf("expected exactly one fragment separator, got: %s", got)
	}
	fragment := got[strings.Index(got, "#")+1:]
	values, err := url.ParseQuery(fragment)
	if err != nil {
		t.Fatalf("parsing fragment %q: %v", fragment, err)
	}
	if values.Get("session") != "abc" {
		t.Errorf("existing fragment parameter lost, got: %s", fragment)
	}
	if values.Get("state") != "s1" {
		t.Errorf("expected state in fragment, got: %s", fragment)
	}
	if values.Get("vp_token") == "" {
		t.Errorf("expected vp_token in fragment, got: %s", fragment)
	}
}

func TestFragmentErrorResponsesMergeIntoAnExistingFragment(t *testing.T) {
	got := BuildFragmentErrorRedirect("https://verifier.example/callback#session=abc", "s1", "access_denied", "User denied presentation")
	if strings.Count(got, "#") != 1 {
		t.Fatalf("expected exactly one fragment separator, got: %s", got)
	}
	fragment := got[strings.Index(got, "#")+1:]
	values, err := url.ParseQuery(fragment)
	if err != nil {
		t.Fatalf("parsing fragment %q: %v", fragment, err)
	}
	if values.Get("session") != "abc" {
		t.Errorf("existing fragment parameter lost, got: %s", fragment)
	}
	if values.Get("error") != "access_denied" {
		t.Errorf("expected error in fragment, got: %s", fragment)
	}
	if values.Get("state") != "s1" {
		t.Errorf("expected state in fragment, got: %s", fragment)
	}
}

func TestSubmitDirectPost_ReportsUndefinedResponseMembers(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"redirect_uri": "https://example.com/done", "status": "OK"})
	}))
	defer ts.Close()

	result, err := SubmitDirectPostObject(ts.URL, buildPlainAuthorizationResponse(map[string][]string{"pid": {"token1"}}, "", "state123"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := undefinedResponseMembers(result); len(got) != 1 || got[0] != "status" {
		t.Errorf("undefined members = %v, want [status]", got)
	}
}
