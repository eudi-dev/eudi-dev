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

package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

func TestWalletLogsCompactOneLinePerEntry(t *testing.T) {
	entries := []wallet.LogEntry{
		{
			Time:    time.Date(2026, 6, 5, 10, 15, 30, 0, time.UTC),
			Action:  "presentation",
			Detail:  "Presented to verifier.example: Response: 200",
			Success: true,
			Details: map[string]any{
				"client_id":      "verifier.example",
				"response_mode":  "direct_post",
				"nonce":          "n-1",
				"request_object": map[string]any{"nonce": "n-1"},
				"dcql_query":     map[string]any{"credentials": []any{map[string]any{"id": "pid"}}},
				"sent_credentials": []any{
					map[string]any{
						"id":        "cred-1",
						"format":    "dc+sd-jwt",
						"disclosed": []any{"given_name", "family_name"},
					},
				},
				"status_code": 200,
			},
		},
		{
			Time:    time.Date(2026, 6, 5, 10, 16, 0, 0, time.UTC),
			Action:  "issuance",
			Detail:  "Failed: token exchange failed\nwith more detail",
			Success: false,
		},
	}

	var buf bytes.Buffer
	if err := printWalletLogs(&buf, entries, walletLogPrintOptions{}); err != nil {
		t.Fatalf("printWalletLogs: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 compact log lines, got %d:\n%s", len(lines), buf.String())
	}
	for _, want := range []string{
		"client_id=verifier.example",
		"response_mode=direct_post",
		"nonce=n-1",
		"request_object=yes",
		"dcql_query=yes",
		"sent_credentials=cred-1(dc+sd-jwt:given_name,family_name)",
		"status_code=200",
	} {
		if !strings.Contains(lines[0], want) {
			t.Fatalf("compact output missing %q: %s", want, lines[0])
		}
	}
	if strings.Contains(lines[0], `"credentials"`) {
		t.Fatalf("compact output should not include full DCQL payload: %s", lines[0])
	}
	if strings.Contains(lines[1], "\n") {
		t.Fatalf("compact output should keep each entry on one line: %q", lines[1])
	}
	if !strings.Contains(lines[0], "✓ presentation Presented to verifier.example: Response: 200") {
		t.Fatalf("unexpected compact success line: %s", lines[0])
	}
	if !strings.Contains(lines[1], "✗ issuance Failed: token exchange failed with more detail") {
		t.Fatalf("unexpected compact failure line: %s", lines[1])
	}
}

func TestWalletLogsVerboseExpandsDetails(t *testing.T) {
	entries := []wallet.LogEntry{
		{
			Time:    time.Date(2026, 6, 5, 10, 15, 30, 0, time.UTC),
			Action:  "presentation",
			Detail:  "Presented to verifier.example: Response: 200",
			Success: true,
			Details: map[string]any{
				"client_id": "verifier.example",
				"request_object": map[string]any{
					"nonce":         "n-1",
					"response_mode": "direct_post",
				},
				"sent_credentials": []any{
					map[string]any{
						"id":     "cred-1",
						"format": "dc+sd-jwt",
						"claims": []any{"given_name", "family_name"},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := printWalletLogs(&buf, entries, walletLogPrintOptions{Verbose: true}); err != nil {
		t.Fatalf("printWalletLogs: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"details:", "client_id", "request_object", "response_mode", "sent_credentials", "given_name"} {
		if !strings.Contains(out, want) {
			t.Fatalf("verbose output missing %q:\n%s", want, out)
		}
	}
}

func TestWalletLogsJSON(t *testing.T) {
	entries := []wallet.LogEntry{
		{
			Time:    time.Date(2026, 6, 5, 10, 15, 30, 0, time.UTC),
			Action:  "issuance",
			Detail:  "Received credential",
			Success: true,
		},
	}

	var buf bytes.Buffer
	if err := printWalletLogs(&buf, entries, walletLogPrintOptions{JSON: true}); err != nil {
		t.Fatalf("printWalletLogs: %v", err)
	}
	var decoded []wallet.LogEntry
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal JSON output: %v\n%s", err, buf.String())
	}
	if len(decoded) != 1 || decoded[0].Action != "issuance" {
		t.Fatalf("unexpected JSON output: %+v", decoded)
	}
}

// Every command prints a URL with & as it is, in JSON and in the verbose
// details.
func TestWalletLogsKeepAmpersands(t *testing.T) {
	entries := []wallet.LogEntry{{
		Action:  "presentation",
		Detail:  "https://verifier.example/cb?a=1&b=2",
		Details: map[string]any{"request": map[string]any{"uris": []any{"https://verifier.example/cb?a=1&b=2"}}},
	}}
	for _, opts := range []walletLogPrintOptions{{JSON: true}, {Verbose: true}} {
		var buf bytes.Buffer
		if err := printWalletLogs(&buf, entries, opts); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(buf.String(), `\u0026`) || !strings.Contains(buf.String(), "a=1&b=2") {
			t.Errorf("output with %+v:\n%s", opts, buf.String())
		}
	}
}

func TestActivityPayloadDoesNotChangeCLIOutput(t *testing.T) {
	entry := wallet.LogEntry{Time: time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC), Action: "presentation", Detail: "Sending presentation", Success: true, Details: map[string]any{"vp_token": "token"}}
	for _, opts := range []walletLogPrintOptions{{}, {Verbose: true}, {JSON: true}} {
		var before, after bytes.Buffer
		if err := printWalletLogs(&before, []wallet.LogEntry{entry}, opts); err != nil {
			t.Fatal(err)
		}
		withPayload := entry
		withPayload.Payload = &wallet.LogPayload{Label: "Response", Body: "plaintext", Encrypted: true, Wire: "ciphertext"}
		if err := printWalletLogs(&after, []wallet.LogEntry{withPayload}, opts); err != nil {
			t.Fatal(err)
		}
		if before.String() != after.String() {
			t.Fatalf("CLI output changed for %+v:\nbefore: %s\nafter: %s", opts, before.String(), after.String())
		}
	}
}

func TestWalletLogsCommandClean(t *testing.T) {
	tmpDir := t.TempDir()
	wDir := filepath.Join(tmpDir, "wallet")
	if err := os.MkdirAll(wDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	store := wallet.NewWalletStore(wDir)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("load wallet: %v", err)
	}
	w.AddLog("issuance", "Received credential", true)
	if err := store.Save(w); err != nil {
		t.Fatalf("save wallet: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	walletDir = wDir
	rootCmd.SetArgs([]string{"wallet", "logs", "clean"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet logs clean: %v", err)
	}

	reloaded, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("reload wallet: %v", err)
	}
	if got := len(reloaded.GetLog()); got != 0 {
		t.Fatalf("expected logs clean to remove all entries, got %d", got)
	}
}

func TestDeferredExchangeEntriesDoNotChangeCLIOutput(t *testing.T) {
	entry := wallet.LogEntry{Time: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC), Action: "issuance", Detail: "Collected deferred credential", Success: true}
	for _, opts := range []walletLogPrintOptions{{}, {Verbose: true}, {JSON: true}} {
		var before, after bytes.Buffer
		if err := printWalletLogs(&before, []wallet.LogEntry{entry}, opts); err != nil {
			t.Fatal(err)
		}
		entries := []wallet.LogEntry{
			{Action: "issuance", Details: map[string]any{"event": "deferred_credential_request"}, Payload: &wallet.LogPayload{Label: "Request", Body: "transaction"}},
			{Action: "issuance", Details: map[string]any{"event": "deferred_credential_response"}, Payload: &wallet.LogPayload{Label: "Response", Body: "credential"}},
			entry,
		}
		if err := printWalletLogs(&after, entries, opts); err != nil {
			t.Fatal(err)
		}
		if after.String() != before.String() {
			t.Fatalf("CLI output changed for %+v", opts)
		}
		if len(entries) != 3 || entries[0].Payload == nil || entries[1].Payload == nil {
			t.Fatal("printing mutated the activity log")
		}
	}
}
