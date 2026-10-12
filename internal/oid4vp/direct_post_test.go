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

package oid4vp

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The form carries the vp_token as JSON (OID4VP 1.0 §8.1). The other response
// parameters are plain strings, and empty ones are left out.
func TestDirectPostForm(t *testing.T) {
	form, err := DirectPostForm(map[string]any{
		"vp_token":          map[string]any{"pid": []any{"eyJ"}},
		"id_token":          "id.token.sig",
		"state":             "s-1",
		"error_description": "",
		"presentation":      "ignored",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := url.Values{"vp_token": {`{"pid":["eyJ"]}`}, "id_token": {"id.token.sig"}, "state": {"s-1"}}
	if form.Encode() != want.Encode() {
		t.Errorf("form = %v, want %v", form, want)
	}

	errorForm, err := DirectPostForm(map[string]any{"error": "access_denied", "error_description": "user declined", "state": "s-2"})
	if err != nil {
		t.Fatal(err)
	}
	if errorForm.Get("error") != "access_denied" || errorForm.Get("error_description") != "user declined" || errorForm.Get("state") != "s-2" {
		t.Errorf("error form = %v", errorForm)
	}

	if _, err := DirectPostForm(map[string]any{"vp_token": func() {}}); err == nil {
		t.Error("an unencodable vp_token was posted")
	}
}

type verifierEndpoint struct {
	form    url.Values
	headers http.Header
}

// verifier answers each POST with status, body and an optional Location.
func verifier(t *testing.T, status int, body, location string) (*httptest.Server, *verifierEndpoint) {
	t.Helper()
	seen := &verifierEndpoint{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		seen.form, seen.headers = r.PostForm, r.Header.Clone()
		if location != "" {
			w.Header().Set("Location", location)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

// The verifier may answer with a redirect_uri (OID4VP 1.0 §8.2), and the
// wallet sends the user there.
func TestSubmitDirectPostObjectFollowsTheVerifierRedirect(t *testing.T) {
	srv, seen := verifier(t, http.StatusOK, `{"redirect_uri":"https://verifier.example/done#code"}`, "")
	result, err := SubmitDirectPostObject(srv.URL, map[string]any{"vp_token": map[string]any{"pid": []any{"eyJ"}}, "state": "s-1"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusOK || result.RedirectURI != "https://verifier.example/done#code" || result.Body != `{"redirect_uri":"https://verifier.example/done#code"}` {
		t.Errorf("result = %+v", result)
	}
	if seen.form.Get("vp_token") != `{"pid":["eyJ"]}` || seen.form.Get("state") != "s-1" {
		t.Errorf("posted form = %v", seen.form)
	}
	if ct := seen.headers.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want a form post", ct)
	}
}

func TestSubmitDirectPostObjectReadsTheLocationHeader(t *testing.T) {
	srv, _ := verifier(t, http.StatusOK, `{"redirect_uri":"https://verifier.example/body"}`, "https://verifier.example/header")
	result, err := SubmitDirectPostObject(srv.URL, map[string]any{"state": "s"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if result.RedirectURI != "https://verifier.example/header" {
		t.Errorf("redirect = %q, want the Location header", result.RedirectURI)
	}
}

// A verifier error keeps its status and body for the caller.
func TestSubmitDirectPostObjectKeepsAVerifierError(t *testing.T) {
	srv, _ := verifier(t, http.StatusBadRequest, `{"error":"invalid_request"}`, "")
	result, err := SubmitDirectPostObject(srv.URL, map[string]any{"error": "access_denied"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusBadRequest || result.Body != `{"error":"invalid_request"}` || result.RedirectURI != "" {
		t.Errorf("result = %+v", result)
	}
}

func TestSubmitDirectPostRejectsANonHTTPRedirect(t *testing.T) {
	for name, tt := range map[string]struct{ body, location, want string }{
		"redirect_uri": {`{"redirect_uri":"javascript:alert(1)"}`, "", `redirect_uri must use http or https, got scheme "javascript"`},
		"Location":     {`{}`, "/relative", "Location must be an absolute URI"},
	} {
		t.Run(name, func(t *testing.T) {
			srv, _ := verifier(t, http.StatusOK, tt.body, tt.location)
			for submit, call := range map[string]func() error{
				"object": func() error {
					_, err := SubmitDirectPostObject(srv.URL, map[string]any{"state": "s"}, srv.Client())
					return err
				},
				"jwt": func() error { _, err := SubmitDirectPostJWT(srv.URL, "a.b.c.d.e", nil, srv.Client()); return err },
			} {
				err := call()
				var verr *VerifierResponseError
				if !errors.As(err, &verr) {
					t.Fatalf("%s: err = %v, want a VerifierResponseError", submit, err)
				}
				if verr.Error() != tt.want || verr.Body() != tt.body || errors.Unwrap(verr) == nil {
					t.Errorf("%s: error %q body %q, want %q with the verifier body", submit, verr.Error(), verr.Body(), tt.want)
				}
			}
		})
	}
}

// OID4VP 1.0 §8.3.1: direct_post.jwt sends the encrypted response in the
// response form parameter.
func TestSubmitDirectPostJWT(t *testing.T) {
	srv, seen := verifier(t, http.StatusOK, `{"redirect_uri":"https://verifier.example/done"}`, "")
	cek := []byte{1, 2, 3, 4}
	result, err := SubmitDirectPostJWT(srv.URL, "h.k.iv.ct.tag", cek, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if result.RedirectURI != "https://verifier.example/done" || result.StatusCode != http.StatusOK {
		t.Errorf("result = %+v", result)
	}
	if len(seen.form) != 1 || seen.form.Get("response") != "h.k.iv.ct.tag" {
		t.Errorf("posted form = %v, want only the response", seen.form)
	}
	if got := seen.headers.Get("X-Debug-JWE-CEK"); got != base64.RawURLEncoding.EncodeToString(cek) {
		t.Errorf("X-Debug-JWE-CEK = %q", got)
	}

	if _, err := SubmitDirectPostJWT(srv.URL, "h.k.iv.ct.tag", nil, srv.Client()); err != nil {
		t.Fatal(err)
	}
	if got := seen.headers.Get("X-Debug-JWE-CEK"); got != "" {
		t.Errorf("X-Debug-JWE-CEK = %q without a CEK", got)
	}
}

func TestSubmitDirectPostReportsAnUnreachableVerifier(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	unreachable := srv.URL
	client := srv.Client()
	srv.Close()
	if _, err := SubmitDirectPostObject(unreachable, map[string]any{"state": "s"}, client); err == nil || !strings.HasPrefix(err.Error(), "posting to response_uri") {
		t.Errorf("err = %v, want the failed post", err)
	}
	if _, err := SubmitDirectPostJWT(unreachable, "a.b.c.d.e", nil, client); err == nil || !strings.HasPrefix(err.Error(), "posting to response_uri") {
		t.Errorf("err = %v, want the failed post", err)
	}
	if _, err := SubmitDirectPostJWT("://bad", "a.b.c.d.e", nil, client); err == nil || !strings.HasPrefix(err.Error(), "creating request") {
		t.Errorf("err = %v, want the unparseable response_uri", err)
	}
}
