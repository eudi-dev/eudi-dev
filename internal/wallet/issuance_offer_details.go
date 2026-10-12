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

package wallet

import (
	"fmt"
	"sort"
	"strings"

	"github.com/eudi-dev/eudi-dev/v2/internal/oid4vc"
)

type OfferedCredential struct {
	ID          string   `json:"id"`
	Format      string   `json:"format,omitempty"`
	VCT         string   `json:"vct,omitempty"`
	DocType     string   `json:"doctype,omitempty"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Claims      []string `json:"claims,omitempty"`
	// Display images get the same address checks as images of issued
	// credentials. --adhoc-display-images can keep HTTPS URLs for the browser.
	Display *CredentialDisplay `json:"display,omitempty"`
}

// IssuanceOfferDetails combines the offer with optional issuer metadata for the
// consent dialog. Fields stay empty when metadata is missing.
type IssuanceOfferDetails struct {
	Issuer     string `json:"issuer"`
	IssuerName string `json:"issuer_name,omitempty"`
	IssuerLogo string `json:"issuer_logo,omitempty"`
	Grant      string `json:"grant,omitempty"`
	TxCode     bool   `json:"tx_code,omitempty"`
	TxCodeHint string `json:"tx_code_hint,omitempty"`
	// OID4VCI 1.0 defines these three members on tx_code. The dialog uses them
	// to size and type its input and to show the issuer's wording.
	TxCodeInputMode   string              `json:"tx_code_input_mode,omitempty"`
	TxCodeLength      int                 `json:"tx_code_length,omitempty"`
	TxCodeDescription string              `json:"tx_code_description,omitempty"`
	Credentials       []OfferedCredential `json:"credentials,omitempty"`
	MetadataError     string              `json:"metadata_error,omitempty"`
	// OfferURI and ResolveError are set when an offer passed by reference
	// could not be fetched. The dialog then shows the host and the reason.
	OfferURI     string `json:"offer_uri,omitempty"`
	ResolveError string `json:"resolve_error,omitempty"`
}

// describeCredentialOffer shows the offer's own details even when issuer
// metadata cannot be fetched.
func (w *Wallet) describeCredentialOffer(offer *oid4vc.CredentialOffer) *IssuanceOfferDetails {
	if offer == nil {
		return nil
	}
	details := &IssuanceOfferDetails{
		Issuer: offer.CredentialIssuer,
		Grant:  describeOfferGrant(offer.Grants),
	}
	if len(offer.Grants.TxCode) > 0 {
		details.TxCode = true
		details.TxCodeHint = describeTxCode(offer.Grants.TxCode)
		details.TxCodeInputMode, _ = offer.Grants.TxCode["input_mode"].(string)
		details.TxCodeDescription, _ = offer.Grants.TxCode["description"].(string)
		if length, ok := numericValue(offer.Grants.TxCode["length"]); ok {
			details.TxCodeLength = int(length)
		}
	}

	metadata, err := fetchIssuerMetadata(w.HTTPClient(), offer.CredentialIssuer)
	if err != nil {
		details.MetadataError = err.Error()
	} else {
		details.IssuerName, details.IssuerLogo = issuerDisplay(metadata)
		details.IssuerLogo = w.embedDisplayImage(details.IssuerLogo, "issuer_logo")
	}

	for _, id := range offer.CredentialConfigurationIDs {
		details.Credentials = append(details.Credentials, w.describeConfiguration(metadata, id))
	}
	return details
}

func describeOfferGrant(grants oid4vc.OfferGrants) string {
	switch {
	case grants.PreAuthorizedCode != "":
		return "pre-authorized code"
	case grants.AuthorizationCode != "" || grants.IssuerState != "":
		return "authorization code"
	default:
		return ""
	}
}

func describeTxCode(txCode map[string]any) string {
	description, _ := txCode["description"].(string)
	if strings.TrimSpace(description) != "" {
		return description
	}
	mode, _ := txCode["input_mode"].(string)
	length, hasLength := numericValue(txCode["length"])
	switch {
	case hasLength && mode != "":
		return fmt.Sprintf("%d %s characters", int(length), mode)
	case hasLength:
		return fmt.Sprintf("%d characters", int(length))
	case mode != "":
		return mode
	}
	return ""
}

func numericValue(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	}
	return 0, false
}

func issuerDisplay(metadata map[string]any) (name, logo string) {
	entry, ok := firstDisplayEntry(metadata["display"])
	if !ok {
		return "", ""
	}
	name, _ = entry["name"].(string)
	if logoObj, ok := entry["logo"].(map[string]any); ok {
		logo, _ = logoObj["uri"].(string)
	}
	return name, logo
}

// describeConfiguration keeps unknown configuration IDs, so consent still shows
// everything offered.
func (w *Wallet) describeConfiguration(metadata map[string]any, id string) OfferedCredential {
	out := OfferedCredential{ID: id}
	configs, _ := metadata["credential_configurations_supported"].(map[string]any)
	config, _ := configs[id].(map[string]any)
	if config == nil {
		return out
	}
	out.Format, _ = config["format"].(string)
	out.VCT, _ = config["vct"].(string)
	out.DocType, _ = config["doctype"].(string)
	// OID4VCI 1.0 §12.2.4 puts the display array and the claims array under
	// credential_metadata, one level below the configuration.
	credentialMetadata, _ := config["credential_metadata"].(map[string]any)
	if entry, ok := firstDisplayEntry(credentialMetadata["display"]); ok {
		out.Name, _ = entry["name"].(string)
		out.Description, _ = entry["description"].(string)
	}
	out.Claims = configurationClaimNames(credentialMetadata["claims"])
	out.Display = w.resolveCredentialDisplay(metadata, id)
	return out
}

// firstDisplayEntry returns the issuer's first display entry. It does no locale
// negotiation.
func firstDisplayEntry(raw any) (map[string]any, bool) {
	entries, ok := raw.([]any)
	if !ok || len(entries) == 0 {
		return nil, false
	}
	entry, ok := entries[0].(map[string]any)
	return entry, ok
}

// configurationClaimNames lists the claims a configuration declares. OID4VCI
// 1.0 uses an array of objects with a "path". Earlier drafts used a nested
// object keyed by claim name. Issuers still publish both.
func configurationClaimNames(raw any) []string {
	switch claims := raw.(type) {
	case []any:
		var names []string
		for _, entry := range claims {
			claim, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			path, ok := claim["path"].([]any)
			if !ok || len(path) == 0 {
				continue
			}
			names = append(names, claimPathString(path))
		}
		return names
	case map[string]any:
		names := make([]string, 0, len(claims))
		for name := range claims {
			names = append(names, name)
		}
		sort.Strings(names)
		return names
	}
	return nil
}
