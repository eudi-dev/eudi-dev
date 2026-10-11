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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/v3/internal/output"
	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

type walletLogPrintOptions struct {
	Verbose bool
	JSON    bool
}

func walletLogsCmd() *cobra.Command {
	var follow bool

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show the wallet activity log",
		Long:  "Show persisted interactions received by the wallet and sent from the wallet. By default each log entry is printed on one line.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonOutput && follow {
				return fmt.Errorf("--json cannot be combined with --follow")
			}
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			if follow && svc.URL() != "" {
				return fmt.Errorf("--follow is not supported with a remote wallet")
			}

			out := cmd.OutOrStdout()
			entries, err := svc.Logs()
			if err != nil {
				return err
			}
			if err := printWalletLogs(out, entries, walletLogPrintOptions{Verbose: verbose, JSON: jsonOutput}); err != nil {
				return err
			}
			if !follow {
				return nil
			}
			store, err := openStore()
			if err != nil {
				return err
			}
			var last *wallet.LogEntry
			if len(entries) > 0 {
				last = &entries[len(entries)-1]
			}
			return followWalletLogs(cmd.Context(), out, store, last, walletLogPrintOptions{Verbose: verbose})
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow wallet logs and print new entries as they are persisted")
	cmd.AddCommand(walletLogsCleanCmd())
	return cmd
}

func walletLogsCleanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clean",
		Short: "Remove old wallet logs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			if err := svc.ClearLogs(); err != nil {
				return fmt.Errorf("cleaning wallet logs: %w", err)
			}
			if jsonOutput {
				return output.WriteJSON(cmd.OutOrStdout(), map[string]bool{"cleared": true})
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Cleared wallet logs.")
			return nil
		},
	}
}

func printWalletLogs(w io.Writer, entries []wallet.LogEntry, opts walletLogPrintOptions) error {
	if entries != nil {
		visible := make([]wallet.LogEntry, 0, len(entries))
		for _, entry := range entries {
			// Deferred polling logs a request and a response on every retry. The
			// CLI log leaves them out.
			if event := entry.Details["event"]; event == "deferred_credential_request" || event == "deferred_credential_response" {
				continue
			}
			if opts.JSON {
				entry.Payload = nil
			}
			visible = append(visible, entry)
		}
		entries = visible
	}
	if opts.JSON {
		if entries == nil {
			entries = []wallet.LogEntry{}
		}
		data, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling wallet logs: %w", err)
		}
		_, err = fmt.Fprintln(w, string(data))
		return err
	}
	for _, entry := range entries {
		printWalletLogEntry(w, entry, opts.Verbose)
	}
	return nil
}

func printWalletLogEntry(w io.Writer, entry wallet.LogEntry, verbose bool) {
	status := "✓"
	if !entry.Success {
		status = "✗"
	}
	timestamp := entry.Time.Local().Format("2006-01-02 15:04:05")
	detail := oneLine(entry.Detail)
	if !verbose {
		detail = appendCompactWalletLogDetails(detail, entry.Details)
	}
	fmt.Fprintf(w, "%s %s %s %s\n", timestamp, status, entry.Action, detail)
	if !verbose || len(entry.Details) == 0 {
		return
	}
	fmt.Fprintln(w, "  details:")
	for _, key := range sortedWalletLogDetailKeys(entry.Details) {
		printWalletLogDetail(w, key, entry.Details[key], 2)
	}
}

func printWalletLogDetail(w io.Writer, key string, value any, depth int) {
	prefix := strings.Repeat("  ", depth)
	switch typed := value.(type) {
	case map[string]any:
		fmt.Fprintf(w, "%s┌ %s:\n", prefix, key)
		for _, nestedKey := range sortedWalletLogDetailKeys(typed) {
			printWalletLogDetail(w, nestedKey, typed[nestedKey], depth+1)
		}
	default:
		fmt.Fprintf(w, "%s┌ %s: %s\n", prefix, key, walletLogValueString(value, prefix+"  "))
	}
}

func walletLogValueString(value any, prefix string) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		data, err := json.MarshalIndent(value, prefix, "  ")
		if err != nil {
			return fmt.Sprintf("%v", value)
		}
		return string(data)
	}
}

func appendCompactWalletLogDetails(detail string, details map[string]any) string {
	parts := compactWalletLogDetails(details)
	if len(parts) == 0 {
		return detail
	}
	return detail + " [" + strings.Join(parts, " ") + "]"
}

func compactWalletLogDetails(details map[string]any) []string {
	if len(details) == 0 {
		return nil
	}
	var parts []string
	for _, key := range []string{
		"event",
		"direction",
		"source",
		"method",
		"endpoint",
		"url",
		"client_id",
		"issuer",
		"response_type",
		"response_mode",
		"nonce",
		"state",
		"request_uri_method",
		"request_origin",
		"submission_uri",
		"status_code",
		"grant_type",
		"credential_configuration_id",
		"credential_identifier",
		"credential_id",
		"format",
	} {
		if value := compactScalar(details[key]); value != "" {
			parts = append(parts, key+"="+value)
		}
	}
	for _, key := range []string{"request", "response", "request_object", "response_body", "dcql_query", "client_metadata", "vp_token", "id_token", "browser_api_result", "wallet_metadata", "raw_credential", "proof_jwt", "proof_attestation", "access_token"} {
		if details[key] != nil {
			parts = append(parts, key+"=yes")
		}
	}
	if value := compactCredentialList(details["sent_credentials"]); value != "" {
		parts = append(parts, "sent_credentials="+value)
	}
	if value := compactCredentialList(details["presented_credentials"]); value != "" {
		parts = append(parts, "presented_credentials="+value)
	}
	return parts
}

func compactScalar(value any) string {
	switch typed := value.(type) {
	case string:
		return oneLine(typed)
	case int:
		return fmt.Sprintf("%d", typed)
	case int64:
		return fmt.Sprintf("%d", typed)
	case float64:
		if typed == float64(int64(typed)) {
			return fmt.Sprintf("%d", int64(typed))
		}
		return fmt.Sprintf("%g", typed)
	default:
		return ""
	}
}

func compactCredentialList(value any) string {
	items, ok := value.([]any)
	if !ok {
		if typed, ok := value.([]map[string]any); ok {
			items = make([]any, 0, len(typed))
			for _, item := range typed {
				items = append(items, item)
			}
		}
	}
	if len(items) == 0 {
		return ""
	}
	parts := make([]string, 0, len(items))
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		id := compactScalar(item["id"])
		if id == "" {
			id = compactScalar(item["credential_id"])
		}
		if id == "" {
			id = compactScalar(item["query_id"])
		}
		format := compactScalar(item["format"])
		disclosed := compactStringList(item["disclosed"])
		part := id
		if format != "" || disclosed != "" {
			part += "("
			if format != "" {
				part += format
			}
			if disclosed != "" {
				if format != "" {
					part += ":"
				}
				part += disclosed
			}
			part += ")"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ",")
}

func compactStringList(value any) string {
	switch typed := value.(type) {
	case []string:
		return strings.Join(typed, ",")
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			if text := compactScalar(item); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, ",")
	default:
		return ""
	}
}

func sortedWalletLogDetailKeys(details map[string]any) []string {
	keys := make([]string, 0, len(details))
	for key := range details {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func oneLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func followWalletLogs(ctx context.Context, out io.Writer, store *wallet.WalletStore, last *wallet.LogEntry, opts walletLogPrintOptions) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			w, err := store.LoadOrCreate()
			if err != nil {
				return fmt.Errorf("loading wallet: %w", err)
			}
			entries := w.GetLog()
			if fresh := logEntriesAfter(entries, last); len(fresh) > 0 {
				if err := printWalletLogs(out, fresh, opts); err != nil {
					return err
				}
				last = &fresh[len(fresh)-1]
			}
		}
	}
}

// logEntriesAfter returns the entries after last. The wallet drops its oldest
// entries and can clear the log, so the length of the log can't tell what is
// new.
func logEntriesAfter(entries []wallet.LogEntry, last *wallet.LogEntry) []wallet.LogEntry {
	if last == nil {
		return entries
	}
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if e.Time.Equal(last.Time) && e.Action == last.Action && e.Detail == last.Detail {
			return entries[i+1:]
		}
	}
	for i, e := range entries {
		if e.Time.After(last.Time) {
			return entries[i:]
		}
	}
	return nil
}
