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
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/output"
	"github.com/eudi-dev/eudi-dev/v3/internal/remote"
)

const requestsLong = `A wallet server asks for consent before it presents or accepts a credential.
These commands answer that consent dialog from the command line.

The CLI lists requests that came from API calls, the CLI and tests. Requests
opened in a browser are visible only in that browser. Pass the id of any
request to answer it directly.`

func walletRequestsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "requests",
		Short: "List pending consent requests",
		Long:  requestsLong,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := requestsClient()
			if err != nil {
				return err
			}
			pending, err := c.ConsentRequests()
			if err != nil {
				return err
			}
			if jsonOutput {
				return output.WriteJSON(os.Stdout, pending)
			}
			if len(pending) == 0 {
				fmt.Println("No pending consent requests.")
				return nil
			}
			sortByCreation(pending)
			for _, r := range pending {
				fmt.Printf("%s  %s  %s  %s\n", r["id"], r["type"], r["created_at"], r["client_id"])
			}
			return nil
		},
	}
	cmd.AddCommand(walletRequestsAnswerCmd("approve"), walletRequestsAnswerCmd("deny"))
	return cmd
}

func walletRequestsAnswerCmd(action string) *cobra.Command {
	var requestType, body string
	cmd := &cobra.Command{
		Use:   action + " [id]",
		Short: map[string]string{"approve": "Approve a consent request", "deny": "Deny a consent request"}[action],
		Long: requestsLong + `

Without an id, the command answers the newest pending request. --type limits
this to one type: presentation, issuance or issuance_presentation.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := requestsClient()
			if err != nil {
				return err
			}
			id := ""
			if len(args) == 1 {
				id = args[0]
			} else if id, err = newestRequest(c, requestType); err != nil {
				return err
			}
			var choices any
			if body != "" {
				raw, err := format.ReadInput(body)
				if err != nil {
					return fmt.Errorf("reading --body: %w", err)
				}
				if err := json.Unmarshal([]byte(raw), &choices); err != nil {
					return fmt.Errorf("parsing --body: %w", err)
				}
			}
			result, err := c.AnswerConsentRequest(id, action, choices)
			if err != nil {
				return err
			}
			if jsonOutput {
				return output.WriteJSON(os.Stdout, result)
			}
			fmt.Printf("%s %s\n", id, result["status"])
			if redirect, _ := result["redirect_uri"].(string); redirect != "" {
				fmt.Printf("Redirect: %s\n", redirect)
			}
			// The answer went through, but the submission to the verifier or
			// issuer can still fail.
			if msg, _ := result["error"].(string); msg != "" {
				return fmt.Errorf("the %s submission failed: %s", action, msg)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&requestType, "type", "", "Without an id, answer the newest request of this type: presentation, issuance or issuance_presentation")
	if action == "approve" {
		cmd.Flags().StringVar(&body, "body", "", "The choices as JSON, as in POST /api/requests/{id}/approve (file, JSON or '-' for stdin). Without it the wallet sends its automatic selection")
	}
	return cmd
}

func requestsClient() (*remote.Client, error) {
	c, err := remoteClientIfConfigured()
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("no wallet server is running. Start one with 'eudi wallet serve'")
	}
	return c, nil
}

// newestRequest picks the newest pending request, of requestType if set.
func newestRequest(c *remote.Client, requestType string) (string, error) {
	pending, err := c.ConsentRequests()
	if err != nil {
		return "", err
	}
	sortByCreation(pending)
	for i := len(pending) - 1; i >= 0; i-- {
		if requestType == "" || pending[i]["type"] == requestType {
			id, _ := pending[i]["id"].(string)
			return id, nil
		}
	}
	if requestType != "" {
		return "", fmt.Errorf("no %s request waits for an answer", requestType)
	}
	return "", fmt.Errorf("no consent request waits for an answer")
}

// sortByCreation orders requests from the oldest to the newest. created_at is
// RFC 3339, so its text order is its time order within one time zone.
func sortByCreation(requests []map[string]any) {
	sort.SliceStable(requests, func(i, j int) bool {
		a, _ := requests[i]["created_at"].(string)
		b, _ := requests[j]["created_at"].(string)
		return a < b
	})
}
