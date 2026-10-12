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
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

// holderBinding is the holder key that the issuer put in a credential. It
// signs the KB-JWT of an SD-JWT (RFC 9901 §4.3) and the DeviceSigned of an
// mdoc (ISO 18013-5 §9.1.3). Bound with a nil Key means that this wallet
// cannot hold the key type, for example a cnf with only a kid or a JWK on
// another curve.
type holderBinding struct {
	Bound bool
	Key   *ecdsa.PublicKey
}

func (b holderBinding) heldBy(pub *ecdsa.PublicKey) bool {
	return b.Key != nil && pub != nil && b.Key.Equal(pub)
}

func credentialHolderBinding(raw string) holderBinding {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "~") || strings.Count(raw, ".") == 2 {
		return sdJWTHolderBinding(raw)
	}
	if format.Detect(raw) == format.FormatMDOC {
		return mdocHolderBinding(raw)
	}
	return holderBinding{}
}

func credentialBindsToKey(raw string, pub *ecdsa.PublicKey) bool {
	return credentialHolderBinding(raw).heldBy(pub)
}

func sdJWTHolderBinding(raw string) holderBinding {
	jwtPart := raw
	if idx := strings.Index(raw, "~"); idx >= 0 {
		jwtPart = raw[:idx]
	}
	parts := strings.Split(jwtPart, ".")
	if len(parts) != 3 {
		return holderBinding{}
	}
	payloadJSON, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		return holderBinding{}
	}
	var payload struct {
		Cnf *struct {
			JWK *confirmationJWK `json:"jwk"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil || payload.Cnf == nil {
		return holderBinding{}
	}
	if payload.Cnf.JWK == nil {
		return holderBinding{Bound: true}
	}
	return holderBinding{Bound: true, Key: payload.Cnf.JWK.publicKey()}
}

func mdocHolderBinding(raw string) holderBinding {
	doc, err := mdoc.Parse(raw)
	if err != nil {
		return holderBinding{}
	}
	key, err := mdoc.DeviceKey(doc)
	if err != nil {
		return holderBinding{Bound: mdocNamesDeviceKey(doc)}
	}
	return holderBinding{Bound: true, Key: key}
}

// mdocNamesDeviceKey reports whether the MSO contains a device key. It tells an
// mdoc without holder binding apart from an mdoc with an unreadable device key.
func mdocNamesDeviceKey(doc *mdoc.Document) bool {
	if doc == nil || doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
		return false
	}
	_, ok := doc.IssuerAuth.MSO.DeviceKeyInfo["deviceKey"]
	return ok
}

type confirmationJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// Accept only P-256 keys because this wallet cannot hold other curves.
func (j confirmationJWK) publicKey() *ecdsa.PublicKey {
	if j.Kty != "EC" || j.Crv != "P-256" || j.X == "" || j.Y == "" {
		return nil
	}
	x, err := format.DecodeBase64URL(j.X)
	if err != nil {
		return nil
	}
	y, err := format.DecodeBase64URL(j.Y)
	if err != nil {
		return nil
	}
	pub, err := format.ECPublicKeyFromCoords(elliptic.P256(), x, y)
	if err != nil {
		return nil
	}
	return pub
}

func (w *Wallet) keyBindingNotHeld(cred *StoredCredential) bool {
	if cred == nil {
		return false
	}
	// Each batch copy is bound to its own key, so the check uses that copy's key.
	signingKey, err := w.batchSigningKey(*cred)
	if err != nil || signingKey == nil {
		return false
	}
	binding := credentialHolderBinding(cred.Raw)
	return binding.Bound && !binding.heldBy(&signingKey.PublicKey)
}

// Log unavailable holder keys on import, issuance and renewal so the user sees
// the problem before presenting.
func (w *Wallet) noteUnheldKeyBinding(cred *StoredCredential) {
	if !w.keyBindingNotHeld(cred) {
		return
	}
	details := map[string]any{
		"credential_id": cred.ID,
		"format":        cred.Format,
		"wallet_key":    mock.KeyIDForPublicKey(&w.HolderKeyPair().PublicKey),
	}
	addStringDetail(details, "vct", cred.VCT)
	addStringDetail(details, "doctype", cred.DocType)
	if binding := credentialHolderBinding(cred.Raw); binding.Key != nil {
		details["binding_key"] = mock.KeyIDForPublicKey(binding.Key)
	}
	detail := fmt.Sprintf(
		"Credential %s is bound to a holder key that is not in this wallet. It can be shown and decoded. A presentation would carry a key binding signature from the wrong key, and a verifier rejects that.",
		credentialLabel(*cred))
	w.addProtocolWarning("wallet", "credential_key_binding_not_held", detail, details)
	log.Printf("[Wallet] WARNING: %s", detail)
}
