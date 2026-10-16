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
	"crypto/ecdsa"
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
)

// KeyAttestationMode controls whether the demo issuer requires a key
// attestation in every credential request.
type KeyAttestationMode string

const (
	// KeyAttestationOptional is the default. The jwt proof type works without
	// a key attestation, so wallets without one can collect credentials. A key
	// attestation that a wallet sends is always verified.
	KeyAttestationOptional KeyAttestationMode = "optional"
	// KeyAttestationRequired adds key_attestations_required to the jwt proof
	// type too, as CIR (EU) 2024/2979 Annex Ib TR_KA-4 asks of an issuer of
	// device-bound credentials, and refuses a proof without a key attestation.
	KeyAttestationRequired KeyAttestationMode = "required"
)

func ParseKeyAttestationMode(value string) (KeyAttestationMode, error) {
	switch KeyAttestationMode(strings.TrimSpace(value)) {
	case "", KeyAttestationOptional:
		return KeyAttestationOptional, nil
	case KeyAttestationRequired:
		return KeyAttestationRequired, nil
	}
	return "", fmt.Errorf("unknown key attestation mode %q, want %q or %q", value, KeyAttestationOptional, KeyAttestationRequired)
}

// SetKeyAttestationMode sets whether the credential endpoint requires a key
// attestation. Call it before serving because the metadata publishes it.
func (d *DemoRP) SetKeyAttestationMode(mode KeyAttestationMode) {
	d.keyAttestation = mode
}

func (d *DemoRP) keyAttestationRequired() bool {
	return d.keyAttestation == KeyAttestationRequired
}

// wscdLevel is the key_storage value of a key attestation that mentions a
// WSCD. CIR (EU) 2024/2979 Annex Ib C_KA-1: "The 'key_storage' and
// 'user_authentication' attributes shall have value 'iso_18045_high' where a
// key attestation mentions a WSCD".
const wscdLevel = "iso_18045_high"

// requiresWSCD reports whether a configuration must be bound to a key in a
// WSCD. CIR (EU) 2024/2979 Annex Ib TR_KA-8: "A provider of person
// identification data shall ensure that person identification data is bound
// to a public key that originates from a key attestation mentioning a WSCD."
// It is an ARF rule, so it applies with --arf only.
func (d *DemoRP) requiresWSCD(cfg templateConfiguration) bool {
	return cfg.template.Category == credtemplate.CategoryPID && d.wallet.ARFChecks()
}

// keyAttestationRequirement is the key_attestations_required object of
// OpenID4VCI 1.0 §12.2.4 for a configuration.
func (d *DemoRP) keyAttestationRequirement(cfg templateConfiguration) map[string]any {
	if !d.requiresWSCD(cfg) {
		return map[string]any{}
	}
	return map[string]any{"key_storage": []string{wscdLevel}, "user_authentication": []string{wscdLevel}}
}

// proofTypesSupported lists the jwt proof type and the attestation proof
// type. CIR (EU) 2024/2979 Annex Ib TR_KA-4 asks for both. The attestation
// proof type always carries a key attestation, so it always names the
// requirement. The jwt proof type names it only when the issuer requires a key
// attestation. OpenID4VCI 1.0 §12.2.4: "If the Credential Issuer does not
// require a key attestation, this parameter MUST NOT be present".
func (d *DemoRP) proofTypesSupported(cfg templateConfiguration) map[string]any {
	requirement := d.keyAttestationRequirement(cfg)
	jwtProof := map[string]any{"proof_signing_alg_values_supported": walletSigningAlgs}
	if d.keyAttestationRequired() {
		jwtProof["key_attestations_required"] = requirement
	}
	return map[string]any{
		"jwt": jwtProof,
		"attestation": map[string]any{
			"proof_signing_alg_values_supported": walletSigningAlgs,
			"key_attestations_required":          requirement,
		},
	}
}

// keyAttestation is a verified key attestation of OpenID4VCI 1.0 Appendix D.1.
type keyAttestation struct {
	attestedKeys []*ecdsa.PublicKey
	keyStorage   []string
	attester     attestationSigner
	name         string
}

// boundKeys are the keys that one key proof binds credentials to: the proof
// key, or the attested keys of its key attestation.
type boundKeys struct {
	keys        []*ecdsa.PublicKey
	attestation *keyAttestation
}

// verifyKeyAttestation checks a key attestation from the key_attestation
// header of a jwt proof or from an attestation proof. Appendix D.1 requires
// exp when the attestation comes with the jwt proof type. Appendix F.1 and F.3
// both require the c_nonce of this issuer's Nonce Endpoint in it.
func (d *DemoRP) verifyKeyAttestation(raw string, inJWTProof bool) (*keyAttestation, *proofError) {
	attestation, err := parseCompactJWT(raw)
	if err != nil {
		return nil, invalidProof("parsing key attestation: %v", err)
	}
	if typ, _ := attestation.header["typ"].(string); !format.JOSETypeIs(typ, format.TypeKeyAttestation) {
		return nil, invalidProof("key attestation typ is %q, want %s", typ, format.TypeKeyAttestation)
	}
	if alg, _ := attestation.header["alg"].(string); !slices.Contains(walletSigningAlgs, alg) {
		return nil, invalidProof("key attestation alg %q is not among the supported algorithms (%s)", alg, strings.Join(walletSigningAlgs, ", "))
	}
	// CIR (EU) 2024/2979 Annex Ib TR_KA-5 verifies the key attestation "under
	// the public key in the signing certificate included in the 'x5c'
	// parameter".
	attester, err := d.attestationSigner(attestation.header)
	if err != nil {
		return nil, invalidProof("key attestation: %v", err)
	}
	if !jws.Valid(attestation.raw(), attester.key) {
		return nil, invalidProof("key attestation signature does not verify with its x5c certificate")
	}
	if _, ok := attestation.payload["iat"].(float64); !ok {
		return nil, invalidProof("key attestation has no numeric iat claim")
	}
	if err := checkTimeClaims(attestation.payload, false, inJWTProof); err != nil {
		return nil, invalidProof("key attestation %v", err)
	}
	rawKeys, _ := attestation.payload["attested_keys"].([]any)
	if len(rawKeys) == 0 {
		return nil, invalidProof("key attestation has no attested_keys")
	}
	attested := make([]*ecdsa.PublicKey, 0, len(rawKeys))
	for i, rawKey := range rawKeys {
		jwk, _ := rawKey.(map[string]any)
		key, err := holderKeyFromJWK(jwk)
		if err != nil {
			return nil, invalidProof("key attestation attested_keys[%d]: %v", i, err)
		}
		attested = append(attested, key)
	}
	nonce, _ := attestation.payload["nonce"].(string)
	if nonce == "" {
		return nil, invalidProof("key attestation carries no nonce: request one from the nonce endpoint")
	}
	if !d.nonceIssued(nonce) {
		return nil, &proofError{code: "invalid_nonce", description: "key attestation nonce is not one this issuer handed out"}
	}
	verified := &keyAttestation{
		attestedKeys: attested,
		keyStorage:   jsonutil.Strings(attestation.payload["key_storage"]),
		attester:     attester,
		name:         attester.name(attestation.payload),
	}
	if !attester.trusted {
		log.Printf("[Demo issuer] key attestation from %q accepted on its own certificate, which does not chain to a wallet provider CA this issuer knows", verified.name)
	}
	return verified, nil
}

// mentionsWSCD reports whether the key attestation attests keys in a WSCD
// (C_KA-1).
func (a *keyAttestation) mentionsWSCD() bool {
	return slices.Contains(a.keyStorage, wscdLevel)
}

// verifyAttestationProof checks a proof of the attestation proof type
// (OpenID4VCI 1.0 Appendix F.3). It binds every attested key.
func (d *DemoRP) verifyAttestationProof(raw string) (boundKeys, *proofError) {
	attestation, err := d.verifyKeyAttestation(raw, false)
	if err != nil {
		return boundKeys{}, err
	}
	return boundKeys{keys: attestation.attestedKeys, attestation: attestation}, nil
}

// checkKeyAttestations applies the issuer's key attestation policy to the
// verified proofs of a credential request.
func (d *DemoRP) checkKeyAttestations(proofs []boundKeys, cfg templateConfiguration) *proofError {
	for _, proof := range proofs {
		switch {
		case proof.attestation == nil && d.keyAttestationRequired():
			return invalidProof("this issuer requires a key attestation (key_attestations_required): send it in the key_attestation header of the jwt proof or as an attestation proof")
		case proof.attestation != nil && d.requiresWSCD(cfg) && !proof.attestation.mentionsWSCD():
			return invalidProof("the key attestation claims key_storage %v, not %s, so it does not mention a WSCD. A PID is bound only to a key in a WSCD (CIR (EU) 2024/2979 Annex Ib TR_KA-8)", proof.attestation.keyStorage, wscdLevel)
		}
	}
	return nil
}

// issuedKeys returns the keys to sign credentials for. A key attestation
// binds a credential to each attested key: ETSI TS 119 472-3 V1.1.1
// CRED-REQ-PROC-4.6.2.1-04 "shall generate as many PIDs/EAAs as elements
// present in the attested_keys array", and OpenID4VCI 1.0 Appendix F.1 and
// F.3 say the same with SHOULD. Without one, the offer's batch size decides.
// The batch_size of the metadata caps both.
func issuedKeys(proofs []boundKeys, batchSize int) []*ecdsa.PublicKey {
	var keys []*ecdsa.PublicKey
	attested := false
	for _, proof := range proofs {
		keys = append(keys, proof.keys...)
		attested = attested || proof.attestation != nil
	}
	want := max(batchSize, 1)
	if attested {
		want = demoBatchSize
	}
	if len(keys) > want {
		keys = keys[:want]
	}
	return keys
}
