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
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v3/internal/delegatepayload"
	"github.com/eudi-dev/eudi-dev/v3/internal/output"
)

// delegations is the delegations member of a credential in the wallet API.
type delegations struct {
	Active  int                 `json:"active"`
	Records []delegationListing `json:"records"`
}

type delegationListing struct {
	Name      string     `json:"name"`
	Expired   bool       `json:"expired"`
	Revoked   bool       `json:"revoked"`
	ExpiresAt *time.Time `json:"expires_at"`
	Delegates []struct {
		KeyThumbprint string                  `json:"key_thumbprint"`
		Limits        []delegatepayload.Limit `json:"limits"`
	} `json:"delegates"`
}

func (d delegationListing) ended() bool { return d.Expired || d.Revoked }

// credentialDelegations reads the delegations member of a credential. A
// local wallet passes Go values and a remote wallet passes decoded JSON, so
// it goes through JSON for both.
func credentialDelegations(cred map[string]any) (delegations, []json.RawMessage, error) {
	var parsed delegations
	var raw struct {
		Records []json.RawMessage `json:"records"`
	}
	member, ok := cred["delegations"]
	if !ok || member == nil {
		return parsed, nil, nil
	}
	data, err := json.Marshal(member)
	if err != nil {
		return parsed, nil, err
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return parsed, nil, fmt.Errorf("reading the delegations: %w", err)
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return parsed, nil, fmt.Errorf("reading the delegations: %w", err)
	}
	return parsed, raw.Records, nil
}

// activeDelegationsLabel is the text of the credential card badge. It is
// empty for a credential without active delegations.
func activeDelegationsLabel(cred map[string]any) string {
	parsed, _, err := credentialDelegations(cred)
	if err != nil || parsed.Active == 0 {
		return ""
	}
	if parsed.Active == 1 {
		return "1 active delegation"
	}
	return fmt.Sprintf("%d active delegations", parsed.Active)
}

func walletDelegationsCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "delegations <credential-id>",
		Short: "Experimental. List the delegations of a credential",
		Long: "Experimental. Lists the active delegations of a credential: the verifier, the end of the\n" +
			"delegation, its limits and the delegate key. --all adds the delegations that ended.\n" +
			"The wallet records a delegation for each Delegate SD-JWT it signs\n" +
			"(draft-ietf-oauth-delegate-sd-jwt-00).",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeCredentialIDs,
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			cred, err := svc.Credential(args[0])
			if err != nil {
				return err
			}
			parsed, raw, err := credentialDelegations(cred)
			if err != nil {
				return err
			}
			var shown []delegationListing
			shownRaw := []json.RawMessage{}
			// The API lists the active records first.
			for i, record := range parsed.Records {
				if all || !record.ended() {
					shown = append(shown, record)
					shownRaw = append(shownRaw, raw[i])
				}
			}
			if jsonOutput {
				output.PrintJSON(shownRaw)
				return nil
			}
			printDelegations(os.Stdout, shown, all, time.Local)
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "Also list the delegations that ended")
	return cmd
}

func printDelegations(w io.Writer, records []delegationListing, all bool, loc *time.Location) {
	switch {
	case len(records) == 0 && all:
		_, _ = fmt.Fprintln(w, "This credential has no delegation records.")
		return
	case len(records) == 0:
		_, _ = fmt.Fprintln(w, "This credential has no active delegation.")
		return
	}
	for i, record := range records {
		if i > 0 {
			_, _ = fmt.Fprintln(w)
		}
		_, _ = fmt.Fprintf(w, "%s\n  %s\n", record.Name, delegationEnd(record, loc))
		for _, delegated := range record.Delegates {
			if line := delegateLine(delegated.Limits, delegated.KeyThumbprint); line != "" {
				_, _ = fmt.Fprintf(w, "  %s\n", line)
			}
		}
	}
}

func delegationEnd(record delegationListing, loc *time.Location) string {
	switch {
	case record.Revoked:
		return "Credential revoked"
	case record.ExpiresAt == nil:
		return "No expiry"
	case record.Expired:
		return "Expired " + record.ExpiresAt.In(loc).Format(time.RFC1123)
	default:
		return "Until " + record.ExpiresAt.In(loc).Format(time.RFC1123)
	}
}

// delegateLine is the short summary of the Delegations dialog. It shows an
// object or array limit by its name alone.
func delegateLine(limits []delegatepayload.Limit, thumbprint string) string {
	parts := make([]string, 0, len(limits)+1)
	for _, limit := range limits {
		if limit.JSON {
			parts = append(parts, limit.Name)
		} else {
			parts = append(parts, limit.Name+": "+limit.Value)
		}
	}
	if thumbprint != "" {
		parts = append(parts, "key: "+shortThumbprint(thumbprint))
	}
	return strings.Join(parts, ", ")
}

func shortThumbprint(value string) string {
	runes := []rune(value)
	if len(runes) <= 16 {
		return value
	}
	return string(runes[:8]) + "…" + string(runes[len(runes)-6:])
}
