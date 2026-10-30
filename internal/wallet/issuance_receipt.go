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
	"maps"
	"reflect"
	"slices"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/statuslist"
	"github.com/eudi-dev/eudi-dev/v3/internal/validity"
)

// requestedTypeFindings reports received credentials of another type than
// the requested configuration. ARF ISSU_06: the Wallet Unit "SHALL verify
// that the PID or attestation it received matches the PID or attestation
// requested by the Wallet Unit". OpenID4VCI 1.0 §5.1.1: the configuration
// "conveys the details of the requested Credential, such as the format and
// format-specific parameters like vct for SD-JWT VC or doctype for ISO mdoc".
func requestedTypeFindings(received []StoredCredential, metadata map[string]any, configID string) findings.List {
	if configID == "" {
		return nil
	}
	requested := offeredAttestations(metadata, []string{configID}, nil)[0]
	if len(requested.types) == 0 {
		return nil
	}
	var list findings.List
	for _, cred := range received {
		got := cred.VCT
		if cred.Format == credtype.FormatMDOC {
			got = cred.DocType
		}
		if !slices.Contains(requested.types, got) {
			list = append(list, findings.ARF.Protocol("ISSU_06").Newf("the wallet requested %s (credential configuration %q) and received a credential of type %q", requested.types[0], configID, got))
		}
	}
	return list
}

// tokenClaims are the claims that describe the token, not the person: those
// of draft-ietf-oauth-sd-jwt-vc §2.2.2 and the JWT ID of RFC 7519 §4.1.7. Each
// copy of a batch has its own identifier, binding key and status entry, so
// they stay out of the dataset.
var tokenClaims = []string{"iat", "nbf", "exp", "cnf", "status", "_sd_alg", "jti"}

// credentialDataset returns the attribute values of a received credential:
// the claims of an SD-JWT VC without its token claims, or the data elements
// of an mdoc.
func credentialDataset(cred StoredCredential) map[string]any {
	dataset := maps.Clone(cred.Claims)
	if cred.Format != credtype.FormatMDOC {
		for _, claim := range tokenClaims {
			delete(dataset, claim)
		}
	}
	return dataset
}

// batchDatasetFindings reports copies of a batch with other attribute values
// than the first copy. OpenID4VCI 1.0 §3.3.2: "the batch of issued
// Credentials sent in response MUST share the same Credential Format and
// Credential Dataset". ARF ISSU_11a asks the same of the wallet.
func batchDatasetFindings(received []StoredCredential) findings.List {
	if len(received) < 2 {
		return nil
	}
	first := received[0]
	firstDataset := credentialDataset(first)
	var list findings.List
	for i, cred := range received[1:] {
		if cred.Format != first.Format || !reflect.DeepEqual(credentialDataset(cred), firstDataset) {
			list = append(list, findings.OID4VCI.Protocol("§3.3.2").Cited("OID4VCI 1.0 §3.3.2 (ARF ISSU_11a)").Newf("credential %d of the batch has another format or other attribute values than credential 1, and a batch MUST share the same Credential Format and Credential Dataset", i+2))
		}
	}
	return list
}

// batchValidityFindings reports copies of a batch with another technical
// validity period than the first copy. ARF ISSU_11a: "the Wallet Unit SHALL
// verify that all PIDs and attestations in a batch have the same attribute
// values and the same technical validity period".
func batchValidityFindings(received []StoredCredential) findings.List {
	if len(received) < 2 {
		return nil
	}
	notBefore, expiry := CredentialValidity(received[0])
	var list findings.List
	for i, cred := range received[1:] {
		nb, exp := CredentialValidity(cred)
		if !nb.Equal(notBefore) || !exp.Equal(expiry) {
			list = append(list, findings.ARF.Protocol("ISSU_11a").Newf("credential %d of the batch is valid %s, and credential 1 %s. A batch has one technical validity period", i+2, validityPeriod(nb, exp), validityPeriod(notBefore, expiry)))
		}
	}
	return list
}

func validityPeriod(notBefore, expiry time.Time) string {
	bound := func(t time.Time, missing string) string {
		if t.IsZero() {
			return missing
		}
		return t.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("from %s until %s", bound(notBefore, "any time"), bound(expiry, "no expiry"))
}

// receivedValidityFindings reports a received credential that is expired,
// not yet valid or revoked. CIR (EU) 2024/2982 Article 4(3)(d): "wallet units
// shall verify the authenticity and validity of person identification data
// and electronic attestations of attributes".
func (w *Wallet) receivedValidityFindings(received []StoredCredential, now time.Time) findings.List {
	rule := findings.CIR20242982.Protocol("Article 4(3)(d)")
	var list findings.List
	for _, cred := range received {
		label := credentialLabel(cred)
		notBefore, expiry := CredentialValidity(cred)
		if !expiry.IsZero() && validity.Expired(&expiry, now) {
			list = append(list, rule.Newf("the received %s expired at %s", label, expiry.UTC().Format(time.RFC3339)))
		}
		if !notBefore.IsZero() && validity.NotYet(&notBefore, now) {
			list = append(list, rule.Newf("the received %s is valid only from %s", label, notBefore.UTC().Format(time.RFC3339)))
		}
		if finding := w.receivedStatusFinding(cred); finding != "" {
			list = append(list, rule.New(finding))
		}
	}
	return list
}

// receivedStatusFinding reads the status of a received credential. An
// unreadable status list is a finding: draft-ietf-oauth-status-list §8.3
// says that then "no statement about the status of the Referenced Token can
// be made and the Referenced Token SHOULD be rejected".
func (w *Wallet) receivedStatusFinding(cred StoredCredential) string {
	ref := CredentialStatusRef(cred)
	if ref == nil {
		return ""
	}
	label := credentialLabel(cred)
	// The wallet reads its own list from its state, even before the
	// server publishing it runs.
	if own := w.ownStatusRef(cred); own != nil {
		if status := w.ownStatusAt(own.Idx); status != 0 {
			return fmt.Sprintf("the received %s is %s on its status list (index %d)", label, statuslist.StatusName(status), own.Idx)
		}
		return ""
	}
	anchors := w.StatusListAnchors(cred.Raw)
	result, err := w.checkStatusWithAnchors(cred, ref, anchors)
	if err != nil {
		return fmt.Sprintf("the status of the received %s cannot be read: %v", label, err)
	}
	if len(anchors) > 0 && !result.TrustAnchored {
		return fmt.Sprintf("the status list %s of the received %s does not chain to a revocation service on the trusted list of its issuer", ref.URI, label)
	}
	if !result.IsValid {
		return fmt.Sprintf("the received %s is %s on its status list %s (index %d)", label, result.StatusName, ref.URI, ref.Idx)
	}
	return ""
}
