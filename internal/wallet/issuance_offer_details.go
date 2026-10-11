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
	"sort"

	"github.com/dominikschlosser/eudi-dev/v3/internal/consent"
	"github.com/dominikschlosser/eudi-dev/v3/internal/dcql"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
)

// describeCredentialOffer shows the offer's own details even when issuer
// metadata cannot be fetched. refusal holds the ARF findings when every
// offered configuration has some. The user picks one configuration, so an
// offer with one acceptable configuration is still shown.
func (w *Wallet) describeCredentialOffer(offer *oid4vc.CredentialOffer) (details *consent.OfferDetails, refusal []string) {
	if offer == nil {
		return nil, nil
	}
	details = &consent.OfferDetails{
		Issuer: offer.CredentialIssuer,
		Grant:  describeOfferGrant(offer.Grants),
	}
	if offer.Grants.RequiresTxCode() {
		details.TxCode = true
		details.TxCodeHint = offer.Grants.TxCodeHint()
		details.TxCodeInputMode, _ = offer.Grants.TxCode["input_mode"].(string)
		details.TxCodeDescription, _ = offer.Grants.TxCode["description"].(string)
		if length, ok := numericValue(offer.Grants.TxCode["length"]); ok {
			details.TxCodeLength = int(length)
		}
	}

	// The dialog lists the metadata problems. The flow reports them and, in
	// strict mode, refuses.
	var freshness []string
	collect := func(problem string) error { freshness = append(freshness, problem); return nil }
	metadata, signerChain, err := fetchIssuerMetadataDocument(w.HTTPClient(), offer.CredentialIssuer, w.ARFChecks(), collect)
	if err != nil {
		details.MetadataError = err.Error()
	} else {
		details.IssuerName, details.IssuerLogo = issuerDisplay(metadata)
		details.IssuerLogo = w.embedDisplayImage(details.IssuerLogo, "issuer_logo")
		details.ARFFindings = w.issuerARFCheck(metadata, signerChain, offer.CredentialConfigurationIDs)
		refusal = details.ARFFindings
		for _, id := range offer.CredentialConfigurationIDs {
			if len(w.issuerARFCheck(metadata, signerChain, []string{id})) == 0 {
				refusal = nil
			}
		}
		details.Findings = append(append(freshness, details.ARFFindings...), w.catalogueFindings(metadata, offer.CredentialConfigurationIDs)...)
	}

	for _, id := range offer.CredentialConfigurationIDs {
		details.Credentials = append(details.Credentials, w.describeConfiguration(metadata, id))
	}
	return details, refusal
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
func (w *Wallet) describeConfiguration(metadata map[string]any, id string) consent.OfferedCredential {
	out := consent.OfferedCredential{ID: id}
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

// configurationClaimNames lists the claim names of a configuration. OID4VCI
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
			names = append(names, dcql.ClaimPathString(path))
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
