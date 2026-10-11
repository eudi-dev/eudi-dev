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
	"testing"
)

func TestRewriteBodyReplacesHost(t *testing.T) {
	rw := NewRewriter("target.example.com", "localhost:9090")

	body := `{"redirect_uri":"http://target.example.com/callback","other":"value"}`
	got := rw.RewriteBody(body)
	want := `{"redirect_uri":"http://localhost:9090/callback","other":"value"}`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRewriteBodySkipsJWT(t *testing.T) {
	rw := NewRewriter("target.example.com", "localhost:9090")

	jwt := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0YXJnZXQuZXhhbXBsZS5jb20ifQ.signature"
	got := rw.RewriteBody(jwt)
	if got != jwt {
		t.Errorf("expected JWT to be unchanged, got %q", got)
	}
}

func TestRewriteBodyNoMatch(t *testing.T) {
	rw := NewRewriter("target.example.com", "localhost:9090")

	body := `{"key":"value"}`
	got := rw.RewriteBody(body)
	if got != body {
		t.Errorf("expected body unchanged, got %q", got)
	}
}

func TestRewriteBodyMultipleOccurrences(t *testing.T) {
	rw := NewRewriter("target.example.com", "localhost:9090")

	body := "http://target.example.com/a and http://target.example.com/b"
	got := rw.RewriteBody(body)
	want := "http://localhost:9090/a and http://localhost:9090/b"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRewriteHeadersLocation(t *testing.T) {
	rw := NewRewriter("target.example.com", "localhost:9090")

	h := http.Header{}
	h.Set("Location", "http://target.example.com/callback?code=123")
	rw.RewriteHeaders(h)

	want := "http://localhost:9090/callback?code=123"
	if got := h.Get("Location"); got != want {
		t.Errorf("Location: got %q, want %q", got, want)
	}
}

func TestRewriteHeadersContentLocation(t *testing.T) {
	rw := NewRewriter("target.example.com", "localhost:9090")

	h := http.Header{}
	h.Set("Content-Location", "http://target.example.com/resource")
	rw.RewriteHeaders(h)

	want := "http://localhost:9090/resource"
	if got := h.Get("Content-Location"); got != want {
		t.Errorf("Content-Location: got %q, want %q", got, want)
	}
}

func TestRewriteHeadersNoOp(t *testing.T) {
	rw := NewRewriter("target.example.com", "localhost:9090")

	h := http.Header{}
	h.Set("Content-Type", "application/json")
	rw.RewriteHeaders(h)

	if got := h.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type should be unchanged, got %q", got)
	}
}
