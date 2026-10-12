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

// Local and remote management return the same API documents and use these shared
// output helpers. Remote flow handling also lives here.

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/config"
	"github.com/eudi-dev/eudi-dev/v2/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v2/internal/output"
	"github.com/eudi-dev/eudi-dev/v2/internal/remote"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
)

func docString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// Remote documents decode JSON numbers as float64. Local documents retain their Go
// number types.
func docNumber(m map[string]any, key string) (float64, bool) {
	switch v := m[key].(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case json.Number:
		parsed, err := v.Float64()
		return parsed, err == nil
	}
	return 0, false
}

func docCredLabel(cred map[string]any) string {
	if vct := docString(cred, "vct"); vct != "" {
		return vct
	}
	if doctype := docString(cred, "doctype"); doctype != "" {
		return doctype
	}
	return docString(cred, "format")
}

// Imported credentials may have an unavailable holder key or an unresolved DID issuer
// key. Print those warnings to stderr to preserve JSON output on stdout.
func warnAboutCredential(cred map[string]any) {
	if notHeld, _ := cred["key_binding_not_held"].(bool); notHeld {
		fmt.Fprintln(os.Stderr, "Warning: this credential is bound to a holder key the wallet does not hold. It can be listed and decoded, but presenting it fails the verifier's key binding check.")
	}
	if did, _ := cred["issuer_key_did"].(string); did != "" {
		fmt.Fprintf(os.Stderr, "Warning: this credential names its issuer key by the DID %s. Nothing here resolves a DID (HAIP 1.0 §6.1.1 puts the issuer's signing certificate in x5c), so its issuer signature is not verified.\n", did)
	}
}

func printCredentialList(creds []map[string]any, deferred []map[string]any) error {
	if len(creds) == 0 && len(deferred) == 0 {
		fmt.Println("No credentials stored.")
		return nil
	}
	if jsonOutput {
		out := map[string]any{"credentials": creds}
		if len(deferred) > 0 {
			out["deferred"] = deferred
		}
		data, err := json.Marshal(out)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tFORMAT\tTYPE\tCLAIMS\tVALID\tSTATUS")
	for _, cred := range creds {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			docString(cred, "id"), orDash(credDisplayName(cred)), docString(cred, "format"), docCredLabel(cred),
			credClaimCount(cred), credValidityLabel(cred), credStatusLabel(cred))
	}
	for _, entry := range deferred {
		// Prefer the credential type over the issuer's internal configuration ID, just
		// as for stored credentials.
		label := docCredLabel(entry)
		if label == "" {
			label = docString(entry, "credential_configuration_id")
		}
		if label == "" {
			label = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t-\t-\t%s\n",
			docString(entry, "id"), orDash(credDisplayName(entry)), docString(entry, "format"), label, "deferred")
	}
	return tw.Flush()
}

func printDeferredDoc(entry map[string]any) error {
	if jsonOutput {
		data, err := json.MarshalIndent(entry, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}
	fmt.Println("Status:         deferred (the issuer has not handed it over yet)")
	fmt.Printf("Issuer:         %s\n", docString(entry, "issuer"))
	if credType := docCredLabel(entry); credType != "" && credType != docString(entry, "format") {
		fmt.Printf("Type:           %s\n", credType)
	}
	if configID := docString(entry, "credential_configuration_id"); configID != "" {
		fmt.Printf("Configuration:  %s\n", configID)
	}
	if credFormat := docString(entry, "format"); credFormat != "" {
		fmt.Printf("Format:         %s\n", credFormat)
	}
	fmt.Printf("Transaction:    %s\n", docString(entry, "transaction_id"))
	fmt.Printf("Retry interval: %s\n", docString(entry, "interval"))
	if next := docString(entry, "next_attempt_at"); next != "" {
		if parsed, err := time.Parse(time.RFC3339, next); err == nil {
			fmt.Printf("Next attempt:   %s\n", parsed.Local().Format(time.Kitchen))
		}
	}
	if attempts, ok := docNumber(entry, "attempts"); ok && attempts > 0 {
		fmt.Printf("Attempts:       %d\n", int(attempts))
	}
	if lastErr := docString(entry, "last_error"); lastErr != "" {
		fmt.Printf("Last error:     %s\n", lastErr)
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// credDisplay reads the display the issuer declared for the credential. A
// remote wallet sends it as a JSON object and a local wallet passes the
// struct value, so it accepts both.
func credDisplay(cred map[string]any) map[string]any {
	raw, ok := cred["display"]
	if !ok || raw == nil {
		return nil
	}
	if m, ok := raw.(map[string]any); ok {
		return m
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return m
}

func credDisplayName(cred map[string]any) string {
	name, _ := credDisplay(cred)["name"].(string)
	return name
}

func credDisplayDescription(cred map[string]any) string {
	desc, _ := credDisplay(cred)["description"].(string)
	return desc
}

// credClaimCount returns the subject attribute count the server reports,
// which leaves out protocol members. Without that field it returns the full
// claim count.
func credClaimCount(cred map[string]any) int {
	if n, ok := docNumber(cred, "claim_count"); ok {
		return int(n)
	}
	claims, _ := cred["claims"].(map[string]any)
	return len(claims)
}

func credStatusLabel(cred map[string]any) string {
	var parts []string
	if status, ok := cred["status"].(map[string]any); ok {
		value, hasValue := docNumber(status, "status")
		switch {
		case hasValue && value == 1:
			parts = append(parts, "revoked")
		case hasValue:
			parts = append(parts, "active")
		case status["uri"] != nil:
			parts = append(parts, "external")
		}
	}
	if protected, _ := cred["protected"].(bool); protected {
		parts = append(parts, "protected")
	}
	// Show the batch size because the wallet rotates copies while the listing shows
	// only the holder copy.
	if batch, _ := cred["batch"].(bool); batch {
		if size, ok := docNumber(cred, "batch_size"); ok && size >= 2 {
			parts = append(parts, fmt.Sprintf("batch of %d", int(size)))
		} else {
			parts = append(parts, "batch")
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// credExpiry reads the expiry from a credential listing. A credential that
// states no lifetime has no expiry and is never reported as expired.
func credExpiry(cred map[string]any) (time.Time, bool) {
	raw := docString(cred, "expires_at")
	if raw == "" {
		return time.Time{}, false
	}
	when, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return when, true
}

// Floor the remaining lifetime so the label never overstates how long the credential
// is valid.
func credValidityLabel(cred map[string]any) string {
	when, ok := credExpiry(cred)
	if !ok {
		return "-"
	}
	remaining := time.Until(when)
	if remaining <= 0 {
		return "expired"
	}
	switch {
	case remaining >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(remaining.Hours()/24))
	case remaining >= 2*time.Hour:
		return fmt.Sprintf("%dh", int(remaining.Hours()))
	case remaining >= time.Minute:
		return fmt.Sprintf("%dm", int(remaining.Minutes()))
	default:
		return "<1m"
	}
}

func printCredentialDoc(cred map[string]any, decoded bool) error {
	raw := docString(cred, "raw")
	if !decoded {
		// This form prints only the credential string so it can be piped.
		fmt.Println(raw)
		return nil
	}
	// Show a readable validity label because the decoded payload uses Unix timestamps.
	if !jsonOutput {
		printed := false
		if name := credDisplayName(cred); name != "" {
			fmt.Printf("Name:     %s\n", name)
			printed = true
		}
		when, hasExpiry := credExpiry(cred)
		if hasExpiry {
			validity := "expired " + when.Local().Format(time.RFC1123)
			if time.Until(when) > 0 {
				validity = "valid for " + credValidityLabel(cred) + ", until " + when.Local().Format(time.RFC1123)
			}
			fmt.Printf("Validity: %s\n", validity)
			printed = true
		}
		if isBatch, _ := cred["batch"].(bool); isBatch {
			copies := "several copies"
			if size, ok := docNumber(cred, "batch_size"); ok && size >= 2 {
				copies = fmt.Sprintf("%d copies", int(size))
			}
			fmt.Printf("Batch:    yes (the wallet holds %s and presents an unused one each time)\n", copies)
			printed = true
		}
		// The issuer's description can be long, so it shows only with -v.
		if verbose {
			if desc := credDisplayDescription(cred); desc != "" {
				fmt.Printf("Description: %s\n", desc)
				printed = true
			}
		}
		if printed {
			fmt.Println()
		}
	}
	opts := output.Options{JSON: jsonOutput, NoColor: noColor, Verbose: verbose}
	switch docString(cred, "format") {
	case "dc+sd-jwt":
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return err
		}
		output.PrintSDJWT(token, opts)
	case "mso_mdoc":
		doc, err := mdoc.Parse(raw)
		if err != nil {
			return err
		}
		output.PrintMDOC(doc, opts)
	case "jwt_vc_json":
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return err
		}
		output.PrintJWT(token, opts)
	}
	return nil
}

func remoteGeneratePID(c *remote.Client, claims map[string]any, vct string) error {
	if err := c.GeneratePID(claims, vct); err != nil {
		return err
	}
	fmt.Println("Generated default EUDI PID credentials (SD-JWT + mdoc)")
	return nil
}

func remoteAccept(c *remote.Client, uri, txCode string, interactive bool) error {
	isVCI := isCredentialOfferURI(uri)
	// Assign an owner so this tab receives the consent request on a shared wallet.
	if interactive && !noOpen {
		owner := remote.NewOwnerToken()
		target := strings.TrimRight(c.BaseURL, "/") + "/?focus=overview&owner=" + url.QueryEscape(owner)
		if openBrowser(target) {
			c.ActingFor(owner)
		} else {
			fmt.Printf("Waiting for consent at: %s\n", strings.TrimRight(c.BaseURL, "/"))
		}
	}
	var result map[string]any
	var err error
	if isVCI {
		result, err = c.AcceptOffer(uri, txCode, interactive)
	} else {
		result, err = c.Present(uri, interactive)
	}
	if err != nil {
		return err
	}
	if status, _ := result["status"].(string); status == "authorization_required" {
		result, err = completeSignIn(c, result)
		if err != nil {
			return err
		}
	}
	data, marshalErr := json.MarshalIndent(result, "", "  ")
	if marshalErr != nil {
		return marshalErr
	}
	fmt.Println(string(data))
	return nil
}

// signInPollInterval is how often the CLI polls the sign-in status.
// config.AuthorizationCallbackWait bounds the total wait, as it does for the
// flow itself.
const signInPollInterval = 2 * time.Second

// The hosted wallet returns a sign-in URL for the local browser. After sign-in, the
// issuer redirects to the wallet and issuance resumes.
func completeSignIn(c *remote.Client, pending map[string]any) (map[string]any, error) {
	authURL, _ := pending["authorization_url"].(string)
	offerID, _ := pending["offer_id"].(string)
	if authURL == "" || offerID == "" {
		return nil, fmt.Errorf("wallet asked for a sign-in but did not say where")
	}

	fmt.Fprintf(os.Stderr, "Sign in to continue: %s\n", authURL)
	if opensSignInHere(c) {
		openBrowser(authURL)
	}

	deadline := time.Now().Add(config.AuthorizationCallbackWait)
	for {
		time.Sleep(signInPollInterval)
		status, err := c.OfferStatus(offerID)
		if err != nil {
			return nil, fmt.Errorf("checking the offer: %w", err)
		}
		switch state, _ := status["status"].(string); state {
		case "authorization_required":
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("gave up waiting for the sign-in at %s", authURL)
			}
		case "failed":
			msg, _ := status["error"].(string)
			return nil, fmt.Errorf("issuance failed after sign-in: %s", msg)
		default:
			if result, ok := status["result"].(map[string]any); ok {
				return result, nil
			}
			return status, nil
		}
	}
}

func isCredentialOfferURI(uri string) bool {
	return strings.Contains(uri, "credential_offer") ||
		strings.HasPrefix(uri, "openid-credential-offer://") ||
		strings.HasPrefix(uri, "haip-vci://") ||
		strings.HasPrefix(uri, "eu-eaa-offer://")
}

// A browser tab with an owner receives the sign-in URL from the wallet. Opening it
// here too would use the authorization request twice.
func opensSignInHere(c *remote.Client) bool {
	return navigatesHere(c.ActsForAPage())
}
