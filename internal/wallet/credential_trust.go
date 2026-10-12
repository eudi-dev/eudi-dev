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
	"github.com/eudi-dev/eudi-dev/v2/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v2/internal/validate"
)

// Holder binding states in a credential summary. Only this_wallet is
// presentable. The wallet holds no key for the other two.
const (
	holderBindingThisWallet = "this_wallet"
	holderBindingOtherKey   = "other_key"
	holderBindingNone       = "none"
)

func credentialIssuerIdentity(c StoredCredential) map[string]any {
	if c.Format == "mso_mdoc" {
		if identity := mdocIssuerCertIdentity(c.Raw); identity != nil {
			return identity
		}
	} else if iss := jwtIssuerClaim(c.Raw); iss != "" {
		return map[string]any{"kind": "iss", "value": iss}
	}
	// The wallet does not resolve DIDs, so a DID is the last resort.
	if did := credentialIssuerDID(c.Raw); did != "" {
		return map[string]any{"kind": "did", "value": did}
	}
	return nil
}

func jwtIssuerClaim(raw string) string {
	token, err := sdjwt.ParseLenient(raw)
	if err != nil || token == nil {
		return ""
	}
	iss, _ := token.Payload["iss"].(string)
	return iss
}

// mdocIssuerCertIdentity shows the document signer's CommonName, or its full
// subject when the CommonName is empty.
func mdocIssuerCertIdentity(raw string) map[string]any {
	doc, err := mdoc.Parse(raw)
	if err != nil {
		return nil
	}
	certs, err := extractMDOCX5Chain(doc)
	if err != nil || len(certs) == 0 {
		return nil
	}
	value := certs[0].Subject.CommonName
	if value == "" {
		value = certs[0].Subject.String()
	}
	if value == "" {
		return nil
	}
	return map[string]any{"kind": "cert", "value": value}
}

// credentialSignatureState reports self_consistent when the signature
// verifies against the embedded key. That is no issuer trust (ADR-0009). It
// returns nil when the algorithm is unknown.
func credentialSignatureState(c StoredCredential) map[string]any {
	if c.Format == "mso_mdoc" {
		return mdocSignatureState(c.Raw)
	}
	return jwtSignatureState(c.Raw)
}

// jwtSignatureState uses only the embedded key, because a credential summary
// must not fetch issuer metadata.
func jwtSignatureState(raw string) map[string]any {
	token, err := sdjwt.ParseLenient(raw)
	if err != nil || token == nil {
		return nil
	}
	result, _, err := validate.VerifyJWTSignatureOffline(token, nil, nil)
	if err != nil || result == nil || result.Algorithm == "" {
		return nil
	}
	return map[string]any{
		"algorithm":       result.Algorithm,
		"self_consistent": result.SignatureValid,
	}
}

// mdocSignatureState verifies an mdoc against its document signer leaf.
// Without an x5chain it still reports the algorithm from the COSE header.
func mdocSignatureState(raw string) map[string]any {
	doc, err := mdoc.Parse(raw)
	if err != nil {
		return nil
	}
	certs, err := extractMDOCX5Chain(doc)
	if err == nil && len(certs) > 0 {
		res := mdoc.Verify(doc, certs[0].PublicKey)
		if res.Algorithm == "" {
			return nil
		}
		return map[string]any{
			"algorithm":       res.Algorithm,
			"self_consistent": res.SignatureValid,
		}
	}
	// Verify reads the algorithm from the protected header before it needs
	// the key, so a nil key still yields the algorithm.
	res := mdoc.Verify(doc, nil)
	if res.Algorithm == "" {
		return nil
	}
	return map[string]any{
		"algorithm":       res.Algorithm,
		"self_consistent": false,
	}
}

// credentialHolderBindingState reports whether this wallet holds the key a
// credential is bound to.
func (w *Wallet) credentialHolderBindingState(c StoredCredential) string {
	binding := credentialHolderBinding(c.Raw)
	if !binding.Bound {
		return holderBindingNone
	}
	// A batch copy is bound to its own key, which the wallet also holds.
	signingKey, err := w.batchSigningKey(c)
	if err != nil || signingKey == nil {
		return holderBindingOtherKey
	}
	if binding.heldBy(&signingKey.PublicKey) {
		return holderBindingThisWallet
	}
	return holderBindingOtherKey
}
