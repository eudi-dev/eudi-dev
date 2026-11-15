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

package demorp

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/delegatepayload"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt/delegate"
)

// delegateLifetime is the lifetime of a delegation with no exp in its
// delegate_payload.
const delegateLifetime = time.Hour

// delegationKey returns the result key for the delegation of presentation i.
// Each presentation of a multiple query gets its own key, as in the checks.
func (q credentialQuery) delegationKey(i int) string {
	if q.multiple {
		return fmt.Sprintf("%s[%d]", q.label(), i)
	}
	return q.label()
}

// encodeDelegatePayloads turns the delegate_payload object of each delegate
// entry into delegate_payload_disclosure (draft-ietf-oauth-delegate-sd-jwt-00
// §5.1.3). The payload gets the key of the verifier as cnf and an exp, unless
// it has its own. An entry with a delegate_payload_disclosure stays as given.
func (d *DemoRP) encodeDelegatePayloads(entries []map[string]any) error {
	for i, entry := range entries {
		payload, isObject := entry["delegate_payload"].(map[string]any)
		_, encoded := entry["delegate_payload_disclosure"]
		if entry["type"] != oid4vp.DelegateTransactionDataType || !isObject || encoded {
			continue
		}
		payload = maps.Clone(payload)
		if _, ok := payload["cnf"]; !ok {
			jwk, err := keys.PublicJWK(&d.delegateKey.PublicKey)
			if err != nil {
				return fmt.Errorf("transaction_data[%d]: %w", i, err)
			}
			payload["cnf"] = map[string]any{"jwk": jwk}
		}
		if _, ok := payload["exp"]; !ok {
			payload["exp"] = time.Now().Add(delegateLifetime).Unix()
		}
		disclosure, err := json.Marshal([]any{randToken(), payload})
		if err != nil {
			return fmt.Errorf("transaction_data[%d]: %w", i, err)
		}
		entry["delegate_payload_disclosure"] = format.EncodeBase64URL(disclosure)
		delete(entry, "delegate_payload")
	}
	return nil
}

// parsePresentedSDJWT reads an SD-JWT+KB, or a Delegate SD-JWT when delegates
// is true. chain is nil for an SD-JWT+KB. token is the credential in both
// cases.
func parsePresentedSDJWT(presentation string, delegates bool) (token *sdjwt.Token, chain *delegate.Chain, err error) {
	if !delegates || !delegate.IsChain(presentation) {
		token, err = sdjwt.Parse(presentation)
		return token, nil, err
	}
	chain, err = delegate.Parse(presentation)
	if err != nil {
		return nil, nil, err
	}
	return chain.Credential, chain, nil
}

// checkDelegation verifies a Delegate SD-JWT (§6) and returns the payload of
// its last signed component. That component carries aud, nonce and the
// transaction data hashes.
func (d *DemoRP) checkDelegation(req *requestState, q credentialQuery, chain *delegate.Chain, check func(string, error) error) (map[string]any, error) {
	last := chain.Links[len(chain.Links)-1]
	signed := last.Token.Payload
	if chain.KeyBindingJWT != nil {
		signed = chain.KeyBindingJWT.Payload
	}
	// The credential checks before this one verified the issuer signature.
	aud, _ := signed["aud"].(string)
	err := chain.Verify(delegate.Options{Audience: expectedAudience(req, aud), Nonce: req.nonce, MaxAge: freshnessWindow})
	if err = check("Delegate SD-JWT chain verifies (draft-ietf-oauth-delegate-sd-jwt-00 §6)", err); err != nil {
		return nil, err
	}
	if err = check("audience is this verifier", checkPresentationAudience(req, aud)); err != nil {
		return nil, err
	}
	if err = check("the KB-SD-JWT carries each requested Delegate Payload", delegatePayloadsError(req.transactionData, q.id, last)); err != nil {
		return nil, err
	}
	return signed, nil
}

// expectedAudience is the audience for chain.Verify. delegate.Options takes
// one audience, and Interactive Authorization accepts two: the full endpoint
// and its origin, both with the ia: prefix. An accepted aud is passed as it
// is. Otherwise it is the audience that this verifier requests.
func expectedAudience(req *requestState, aud string) string {
	switch {
	case checkPresentationAudience(req, aud) == nil:
		return aud
	case req.dcAPIOrigin != "":
		return "origin:" + req.dcAPIOrigin
	case req.interactiveEndpoint != "":
		return "ia:" + req.interactiveEndpoint
	default:
		return req.clientID
	}
}

// delegatePayloadsError checks that the delegate_payload of the KB-SD-JWT has
// the digest of each delegate entry for query queryID. §7.1: "The KB-JWT
// includes the digest of the delegate_payload in the delegate_payload claim
// of the KB-JWT."
func delegatePayloadsError(entries []oid4vp.TransactionData, queryID string, link *delegate.Link) error {
	var digests []string
	elements, _ := link.Token.Payload["delegate_payload"].([]any)
	for _, element := range elements {
		object, _ := element.(map[string]any)
		digests = append(digests, jsonutil.GetString(object, "..."))
	}
	for i, entry := range entries {
		if !delegatesFor(entry, queryID) {
			continue
		}
		delegation, _ := entry.Delegation()
		digest, err := sdjwt.SDHash(delegation.PayloadDisclosure, link.Token.SDAlg())
		if err != nil {
			return err
		}
		if !slices.Contains(digests, digest) {
			return fmt.Errorf("delegate_payload has no %s digest for transaction_data[%d]", link.Token.SDAlg(), i)
		}
	}
	return nil
}

// delegatesFor reports whether entry asks query queryID for a delegation.
func delegatesFor(entry oid4vp.TransactionData, queryID string) bool {
	_, ok := entry.Delegation()
	return ok && slices.Contains(entry.CredentialIDs, queryID)
}

// bindDelegateEntries marks the delegate entries for query queryID in bound.
// Their digests are in delegate_payload of the KB-SD-JWT. They count as bound
// even without transaction_data_hashes.
func bindDelegateEntries(entries []oid4vp.TransactionData, queryID string, bound []bool) {
	for i, entry := range entries {
		if delegatesFor(entry, queryID) {
			bound[i] = true
		}
	}
}

// warnWithoutDelegation warns when the request asked query q for a delegation
// and the wallet answered with an SD-JWT+KB. A wallet without Delegate SD-JWT
// support signs only the hash of the entry.
func warnWithoutDelegation(req *requestState, q credentialQuery, label string, log *checklist) {
	asked := slices.ContainsFunc(req.transactionData, func(entry oid4vp.TransactionData) bool { return delegatesFor(entry, q.id) })
	if asked {
		log.warn(label+"the wallet answers with a Delegate SD-JWT", fmt.Errorf("the wallet answered with an SD-JWT+KB and did not delegate the credential"))
	}
}

// delegationResult describes the last KB-SD-JWT of a verified chain for the
// result page. The typ of the KB-SD-JWT sets the presentation format for the
// Delegate Holder (draft-ietf-oauth-delegate-sd-jwt-00 §5.1.4).
func (d *DemoRP) delegationResult(chain *delegate.Chain) map[string]any {
	last := chain.Links[len(chain.Links)-1]
	payload := last.Payload
	delegateFormat := delegate.FormatDSDJWT
	if typ, _ := last.Token.Header["typ"].(string); format.JOSETypeIs(typ, delegate.TypeKBSDJWTKB) {
		delegateFormat = delegate.FormatDSDJWTKB
	}
	result := map[string]any{"format": chain.Format(), "format for the Delegate Holder": delegateFormat, "valid until": "no expiry", "payload": payload}
	if exp, ok := delegatepayload.Expiry(payload); ok {
		result["valid until"] = exp.Format("2006-01-02 15:04 UTC")
	}
	thumbprint := delegatepayload.KeyThumbprint(payload)
	if thumbprint == "" {
		return result
	}
	result["delegate key"] = thumbprint
	if own, err := keys.PublicKeyThumbprint(&d.delegateKey.PublicKey); err == nil && format.EncodeBase64URL(own) == thumbprint {
		result["key holder"] = "this verifier"
	}
	return result
}
