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
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/v3/internal/output"
	"github.com/dominikschlosser/eudi-dev/v3/internal/remote"
)

func walletDeferredCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deferred",
		Short: "List the credentials an issuer deferred",
		Long: `Lists the credentials an issuer accepted but was not ready to hand over.

A deferred credential comes with a transaction id and an interval to come back
after. A running wallet server collects it on that interval by itself, and the
entry disappears once the credential arrives.

Use "check" to ask an issuer now instead of at the next scheduled attempt, and
"abandon" to stop collecting one. All of these need a running wallet server,
which is where the collecting happens.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := deferredClient()
			if err != nil {
				return err
			}
			pending, err := c.DeferredIssuances()
			if err != nil {
				return err
			}
			if jsonOutput {
				data, err := json.MarshalIndent(pending, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(data))
				return nil
			}
			if len(pending) == 0 {
				fmt.Println("No deferred credentials.")
				return nil
			}
			for _, p := range pending {
				printDeferred(p)
			}
			return nil
		},
	}
	cmd.AddCommand(walletDeferredCheckCmd())
	cmd.AddCommand(walletDeferredAbandonCmd())
	return cmd
}

func walletDeferredCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check [id]",
		Short: "Ask the issuer for a deferred credential now",
		Long: `Makes one deferred credential request now, instead of waiting for the next
scheduled attempt.

Without an id, every deferred credential is checked. A checked entry's next
attempt then moves on by its interval, as if the poller had made it.`,
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: completeDeferredIDs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := deferredClient()
			if err != nil {
				return err
			}
			ids := args
			if len(ids) == 0 {
				pending, err := c.DeferredIssuances()
				if err != nil {
					return err
				}
				if len(pending) == 0 {
					printResult([]any{}, func() { fmt.Println("No deferred credentials.") })
					return nil
				}
				for _, p := range pending {
					if id, ok := p["id"].(string); ok {
						ids = append(ids, id)
					}
				}
			}
			// With --json an id argument prints its result. Without one, the
			// results of every deferred credential print as an array.
			results := []map[string]any{}
			var checkErr error
			for _, id := range ids {
				result, err := c.CollectDeferred(id)
				if err != nil {
					checkErr = fmt.Errorf("checking %s: %w", id, err)
					break
				}
				if jsonOutput {
					results = append(results, result)
					continue
				}
				switch {
				case result["collected"] == true:
					fmt.Printf("Collected %v credential (ID: %v)\n", result["format"], result["credential_id"])
				case result["abandoned"] == true:
					fmt.Printf("Gave up on %s: %v\n", id, result["reason"])
				default:
					fmt.Printf("Still pending. Next attempt in %v", result["interval"])
					if reason, ok := result["reason"].(string); ok && reason != "" {
						fmt.Printf(" (%s)", reason)
					}
					fmt.Println()
				}
			}
			// Results collected before a failure still print (ADR 0020).
			if jsonOutput {
				if len(args) == 1 && len(results) == 1 {
					output.PrintJSON(results[0])
				} else if len(args) == 0 {
					output.PrintJSON(results)
				}
			}
			if checkErr != nil {
				return checkErr
			}
			return nil
		},
	}
}

func walletDeferredAbandonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "abandon <id>",
		Short: "Stop collecting a deferred credential",
		Long: `Drops a deferred credential from the wallet's collection schedule.

The transaction stays valid at the issuer, the wallet just stops asking. Use
it for an issuance you no longer want, instead of waiting out the 24 hours
after which the wallet gives up on its own.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeDeferredIDs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := deferredClient()
			if err != nil {
				return err
			}
			result, err := c.AbandonDeferred(args[0])
			if err != nil {
				return err
			}
			if jsonOutput {
				data, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(data))
				return nil
			}
			fmt.Printf("Stopped collecting the credential from %v (transaction %v)\n",
				result["issuer"], result["transaction_id"])
			return nil
		},
	}
}

func deferredClient() (*remote.Client, error) {
	c, err := remoteClientIfConfigured()
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("no wallet server is running: deferred credentials are collected by 'eudi wallet serve'")
	}
	return c, nil
}

func printDeferred(p map[string]any) {
	name, _ := p["credential_configuration_id"].(string)
	if name == "" {
		name, _ = p["format"].(string)
	}
	fmt.Printf("%s\n", name)
	fmt.Printf("  ID:             %v\n", p["id"])
	fmt.Printf("  Issuer:         %v\n", p["issuer"])
	fmt.Printf("  Transaction:    %v\n", p["transaction_id"])
	fmt.Printf("  Retry interval: %v\n", p["interval"])
	if next, ok := p["next_attempt_at"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339, next); err == nil {
			fmt.Printf("  Next attempt:   %s\n", parsed.Local().Format(time.Kitchen))
		}
	}
	if attempts, ok := docNumber(p, "attempts"); ok && attempts > 0 {
		fmt.Printf("  Attempts:       %d\n", int(attempts))
	}
	if lastErr, ok := p["last_error"].(string); ok && lastErr != "" {
		fmt.Printf("  Last error:     %s\n", lastErr)
	}
}
