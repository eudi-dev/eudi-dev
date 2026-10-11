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
	"net/url"
	"strings"
	"testing"
)

func TestBuildFragmentRedirect_WithIDToken(t *testing.T) {
	vpToken := map[string][]string{"pid": {"token1"}}
	got, err := BuildFragmentRedirect("https://verifier.example/cb", "state1", vpToken, "eyJhbGciOiJFUzI1NiJ9.test.sig")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, want := range []string{"vp_token=", "id_token=", "state=state1"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected URL to contain %q, got: %s", want, got)
		}
	}
}

func TestBuildFragmentRedirect_IDTokenOnly(t *testing.T) {
	got, err := BuildFragmentRedirect("https://verifier.example/cb", "state1", nil, "eyJhbGciOiJFUzI1NiJ9.test.sig")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(got, "id_token=") {
		t.Errorf("expected id_token in URL, got: %s", got)
	}
	if strings.Contains(got, "vp_token=") {
		t.Errorf("expected no vp_token when nil, got: %s", got)
	}
}

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
