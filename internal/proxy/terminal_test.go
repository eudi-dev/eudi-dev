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
	"bytes"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/fatih/color"
)

func TestTerminalWriterImplementsEntryWriter(t *testing.T) {
	var _ EntryWriter = &TerminalWriter{}
}

func TestTerminalWriterAllTrafficFalseSkipsUnknown(t *testing.T) {
	tw := &TerminalWriter{AllTraffic: false}
	entry := &TrafficEntry{
		Class:      ClassUnknown,
		ClassLabel: "Unknown",
		Method:     "GET",
		URL:        "http://example.com/favicon.ico",
		StatusCode: 200,
	}

	output := captureOutput(t, func() { tw.WriteEntry(entry) })
	if output != "" {
		t.Fatalf("expected no terminal output for unknown traffic by default, got %q", output)
	}
}

func TestTerminalWriterAllTrafficTrueIncludesUnknown(t *testing.T) {
	tw := &TerminalWriter{AllTraffic: true}
	entry := &TrafficEntry{
		Class:      ClassUnknown,
		ClassLabel: "Unknown",
		Method:     "GET",
		URL:        "http://example.com/other",
		StatusCode: 200,
	}

	output := captureOutput(t, func() { tw.WriteEntry(entry) })
	if !strings.Contains(output, "[Unknown]") {
		t.Fatalf("expected unknown traffic to be printed when allTraffic=true, got %q", output)
	}
}

func captureOutput(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	oldColor := color.Output
	r, w, _ := os.Pipe()
	os.Stdout = w
	color.Output = w

	fn()

	w.Close()
	os.Stdout = oldStdout
	color.Output = oldColor

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestPrintEntryIncludesDecodeHints(t *testing.T) {
	entry := &TrafficEntry{
		Method:           "POST",
		URL:              "http://example.com/response",
		StatusCode:       200,
		Class:            ClassVPAuthResponse,
		ClassLabel:       "VP auth response",
		Credentials:      []string{"eyJhbGciOiJFUzI1NiJ9.test.sig"},
		CredentialLabels: []string{"vp_token"},
	}

	output := captureOutput(t, func() { PrintEntry(entry, "") })

	if !strings.Contains(output, "eudi decode") {
		t.Error("expected decode hint in output")
	}
	if !strings.Contains(output, "decode:") {
		t.Error("expected decode section in output")
	}
}

func TestPrintDecodeHintWithLabel(t *testing.T) {
	output := captureOutput(t, func() { printDecodeHint("cred-value", "id_token", "") })

	if !strings.Contains(output, "eudi decode") {
		t.Errorf("expected decode command, got %q", output)
	}
	if !strings.Contains(output, "id_token: eudi decode") {
		t.Errorf("expected label in output, got %q", output)
	}
}

func TestPrintDecodeHintWithoutLabel(t *testing.T) {
	output := captureOutput(t, func() { printDecodeHint("cred-value", "", "") })

	if !strings.Contains(output, "eudi decode") {
		t.Errorf("expected decode command, got %q", output)
	}
	if strings.Contains(output, "(") {
		t.Errorf("expected no label parens, got %q", output)
	}
}

func TestPrintDecodeHintWithDashboardPort(t *testing.T) {
	output := captureOutput(t, func() { printDecodeHint("cred-value", "vp_token", "http://localhost:9091") })

	if !strings.Contains(output, "http://localhost:9091/decode/#credential=cred-value") {
		t.Errorf("expected decode URL in output, got %q", output)
	}
	if !strings.Contains(output, "vp_token") {
		t.Errorf("expected label in output, got %q", output)
	}
}

func TestPrintEntryWithDashboardPortRendersDecodeLinkPerCredential(t *testing.T) {
	entry := &TrafficEntry{
		Method:           "POST",
		URL:              "http://example.com/response",
		StatusCode:       200,
		Class:            ClassVPAuthResponse,
		ClassLabel:       "VP auth response",
		Credentials:      []string{"cred-a", "cred-b"},
		CredentialLabels: []string{"vp_token.pid[0]", "vp_token.mdl[0]"},
	}

	output := captureOutput(t, func() { PrintEntry(entry, "http://localhost:9091") })

	if strings.Count(output, "http://localhost:9091/decode/#credential=") != 2 {
		t.Errorf("expected 2 decode links, got %q", output)
	}
	if !strings.Contains(output, "http://localhost:9091/decode/#credential=cred-a") {
		t.Errorf("expected decode link for cred-a, got %q", output)
	}
	if !strings.Contains(output, "http://localhost:9091/decode/#credential=cred-b") {
		t.Errorf("expected decode link for cred-b, got %q", output)
	}
}

func TestPrintDecodeHintEscapesCredentialQueryParam(t *testing.T) {
	credential := `{"cred1":["mdoc-credential"],"cred2":"jwt-credential"}`

	output := captureOutput(t, func() { printDecodeHint(credential, "vp_token", "http://localhost:9091") })

	if !strings.Contains(output, "http://localhost:9091/decode/#credential="+url.QueryEscape(credential)) {
		t.Errorf("expected escaped decode URL in output, got %q", output)
	}
}

func TestPrintEntryGroupsRequestResponseAndDecodeSections(t *testing.T) {
	longURL := "http://issuer.example/oauth/token?client_id=wallet-app&request_uri=https%3A%2F%2Fverifier.example%2Frequest%2Fabc123&state=state-with-debug-value&nonce=nonce-with-debug-value"
	entry := &TrafficEntry{
		Method:     "POST",
		URL:        longURL,
		StatusCode: 200,
		FlowID:     "flow-7",
		Class:      ClassVCITokenRequest,
		ClassLabel: "VCI token request",
		RequestHeaders: http.Header{
			"Content-Type": {"application/x-www-form-urlencoded"},
		},
		RequestBody: "grant_type=authorization_code&code=abc123",
		Decoded: map[string]any{
			"client_id":     "wallet-app",
			"grant_type":    "authorization_code",
			"code":          "abc123",
			"redirect_uri":  "app://callback",
			"code_verifier": "verifier",
			"response": map[string]any{
				"access_token":  "token-value",
				"token_type":    "DPoP",
				"expires_in":    300,
				"refresh_token": "refresh-value",
			},
		},
		Credentials:      []string{"token-value", "refresh-value"},
		CredentialLabels: []string{"access_token", "refresh_token"},
	}

	output := captureOutput(t, func() { PrintEntry(entry, "http://localhost:9091") })

	if !strings.Contains(output, longURL) {
		t.Fatalf("expected full URL in entry header, got %q", output)
	}
	if strings.Contains(output, "http://issuer.example/oauth/token?...") {
		t.Fatalf("expected URL not to be truncated, got %q", output)
	}
	if !strings.Contains(output, "[flow-7 / VCI token request]") {
		t.Fatalf("expected flow and class in entry header, got %q", output)
	}

	requestIndex := strings.Index(output, "  request:\n")
	responseIndex := strings.Index(output, "  response:\n")
	decodeIndex := strings.Index(output, "  decode:\n")
	if requestIndex < 0 || responseIndex < 0 || decodeIndex < 0 {
		t.Fatalf("expected request/response/decode sections, got %q", output)
	}
	if !(requestIndex < responseIndex && responseIndex < decodeIndex) {
		t.Fatalf("expected request, response, then decode order, got %q", output)
	}
	for _, unwanted := range []string{"  classification:\n", "class:", "flow_type:", "flow_id:", "correlation_keys:"} {
		if strings.Contains(output, unwanted) {
			t.Fatalf("expected no classification detail %q, got %q", unwanted, output)
		}
	}
	if !strings.Contains(output, "\n\n  response:\n") {
		t.Fatalf("expected blank line between request and response sections, got %q", output)
	}
	if !strings.Contains(output, "\n\n  decode:\n") {
		t.Fatalf("expected blank line before decode section, got %q", output)
	}
	if !strings.Contains(output, "  request headers:\n") || !strings.Contains(output, "  request body:\n") {
		t.Fatalf("expected raw request sections for POST, got %q", output)
	}
	if strings.Index(output, "grant_type: authorization_code") > strings.Index(output, "code_verifier: verifier") {
		t.Fatalf("expected prioritized request field order, got %q", output)
	}
	if strings.Index(output, "token_type: DPoP") > strings.Index(output, "access_token: token-value") {
		t.Fatalf("expected prioritized response field order, got %q", output)
	}
	if !strings.Contains(output, "access_token: http://localhost:9091/decode/#credential=token-value") {
		t.Fatalf("expected working decode URL for access token, got %q", output)
	}
	if !strings.Contains(output, "refresh_token: http://localhost:9091/decode/#credential=refresh-value") {
		t.Fatalf("expected working decode URL for refresh token, got %q", output)
	}
}

func TestPrintEntryShowsPostHeadersAndBodyButFiltersInternalHeaders(t *testing.T) {
	entry := &TrafficEntry{
		Method:     "POST",
		URL:        "http://issuer.example/credential",
		StatusCode: 200,
		Class:      ClassVCICredentialRequest,
		ClassLabel: "VCI credential request",
		RequestHeaders: http.Header{
			"Authorization":   {"DPoP token-123"},
			"Content-Type":    {"application/json"},
			"X-Proxy-ReqBody": {"internal"},
		},
		RequestBody: `{"credential_identifier":"membership-credential_0000"}`,
	}

	output := captureOutput(t, func() { PrintEntry(entry, "") })

	if !strings.Contains(output, "  request headers:\n") {
		t.Fatalf("expected request headers section, got %q", output)
	}
	if !strings.Contains(output, "Authorization: DPoP token-123") {
		t.Fatalf("expected authorization header in output, got %q", output)
	}
	if !strings.Contains(output, "  request body:\n") || !strings.Contains(output, `body: {"credential_identifier":"membership-credential_0000"}`) {
		t.Fatalf("expected request body section, got %q", output)
	}
	if strings.Contains(output, "X-Proxy-ReqBody") {
		t.Fatalf("expected internal proxy headers to be hidden, got %q", output)
	}
}

func TestTerminalWriterLogsEntriesWithoutFlowSummary(t *testing.T) {
	tw := &TerminalWriter{}

	first := &TrafficEntry{
		Method:      "POST",
		URL:         "http://issuer.example/token",
		RequestBody: "grant_type=authorization_code&code=issued-code",
		StatusCode:  200,
		Class:       ClassVCITokenRequest,
		ClassLabel:  "VCI token request",
		FlowID:      "flow-7",
		Decoded: map[string]any{
			"grant_type": "authorization_code",
			"code":       "issued-code",
			"response": map[string]any{
				"access_token": "token-123",
			},
		},
	}
	second := &TrafficEntry{
		Method:     "POST",
		URL:        "http://issuer.example/credential",
		StatusCode: 200,
		Class:      ClassVCICredentialRequest,
		ClassLabel: "VCI credential request",
		FlowID:     "flow-7",
		Decoded: map[string]any{
			"request": map[string]any{
				"credential_identifier": "membership-credential_0000",
			},
		},
	}

	output := captureOutput(t, func() {
		tw.WriteEntry(first)
		tw.WriteEntry(second)
	})

	if strings.Contains(output, "═══ [flow-7]") {
		t.Fatalf("expected no separate flow header, got %q", output)
	}
	if strings.Contains(output, "code=issued-code  access_token=token-123") {
		t.Fatalf("expected no flow summary line, got %q", output)
	}
	for _, unwanted := range []string{"  classification:\n", "VCI Authorization Code Flow", "flow_id: flow-7", "correlation_keys:"} {
		if strings.Contains(output, unwanted) {
			t.Fatalf("expected no classification detail %q, got %q", unwanted, output)
		}
	}
	if strings.Count(output, "[flow-7 / ") != 2 {
		t.Fatalf("expected flow id and class in each entry header, got %q", output)
	}
}

func TestPrintEntryShowsRedirectLocationAsResponseHeader(t *testing.T) {
	entry := &TrafficEntry{
		Method: "GET",
		URL:    "http://issuer.example/auth?client_id=wallet-app&state=s1",
		ResponseHeaders: http.Header{
			"Location": {"https://wallet.example/callback?code=abc&state=s1"},
		},
		StatusCode: 302,
		Class:      ClassOIDCCallback,
		ClassLabel: "OIDC callback",
		FlowID:     "flow-redirect",
	}

	output := captureOutput(t, func() { PrintEntry(entry, "") })

	if strings.Contains(output, "302 https://wallet.example/callback?code=abc&state=s1") {
		t.Fatalf("expected redirect location not to be adjacent to status in header, got %q", output)
	}
	if !strings.Contains(output, "  response headers:\n") {
		t.Fatalf("expected response headers section for redirect location, got %q", output)
	}
	if !strings.Contains(output, "Location: https://wallet.example/callback?code=abc&state=s1") {
		t.Fatalf("expected redirect Location in response headers, got %q", output)
	}
	if !strings.Contains(output, "[flow-redirect / OIDC callback]") {
		t.Fatalf("expected flow and class in redirect header, got %q", output)
	}
	if strings.Contains(output, "  request:\n") || strings.Contains(output, "  response:\n") {
		t.Fatalf("expected redirect-only entry to avoid empty request/response body sections, got %q", output)
	}
}
