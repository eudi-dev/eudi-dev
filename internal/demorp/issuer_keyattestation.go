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
	"github.com/eudi-dev/eudi-dev/v3/internal/statuslist"
)

// KeyAttestationMode controls whether the demo issuer requires a key
// attestation in every credential request.
type KeyAttestationMode string

const (
	// KeyAttestationOptional is the default. The jwt proof type works without
	// a key attestation, so wallets without one can collect credentials. A key
	// attestation sent by a wallet is always verified.
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
// proof type always carries a key attestation, so it always carries the
// requirement. The jwt proof type carries it only when the issuer requires a
// key attestation. OpenID4VCI 1.0 §12.2.4: "If the Credential Issuer does not
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
	attestedKeys       []*ecdsa.PublicKey
	keyStorage         []string
	userAuthentication []string
}

// boundKeys are the keys bound by one key proof: the proof key, or the
// attested keys of its key attestation.
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
		return nil, &proofError{code: "invalid_nonce", description: "key attestation nonce was not issued by this issuer"}
	}
	if _, refused := d.checkAttestationStatus("key attestation", attestation.payload, "key_storage_status"); refused != nil {
		return nil, invalidProof("%v", refused)
	}
	if !attester.trusted {
		log.Printf("[Demo issuer] key attestation from %q accepted as untrusted. Its certificate does not chain to a known wallet provider CA.", attester.name(attestation.payload))
	}
	return &keyAttestation{
		attestedKeys:       attested,
		keyStorage:         jsonutil.Strings(attestation.payload["key_storage"]),
		userAuthentication: jsonutil.Strings(attestation.payload["user_authentication"]),
	}, nil
}

// wscdProblem says why a proof does not show a key in a WSCD. It is empty when
// the key attestation mentions a WSCD with both claims at iso_18045_high
// (C_KA-1).
func wscdProblem(attestation *keyAttestation) string {
	switch {
	case attestation == nil:
		return "the proof carries no key attestation"
	case !slices.Contains(attestation.keyStorage, wscdLevel):
		return fmt.Sprintf("the key attestation claims key_storage %v, not %s, so it does not mention a WSCD", attestation.keyStorage, wscdLevel)
	case !slices.Contains(attestation.userAuthentication, wscdLevel):
		return fmt.Sprintf("the key attestation claims user_authentication %v, not %s, as C_KA-1 requires for a WSCD", attestation.userAuthentication, wscdLevel)
	}
	return ""
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
// verified proofs of a credential request. Required mode refuses a PID proof
// without a WSCD key. Optional mode accepts it and logs it.
func (d *DemoRP) checkKeyAttestations(proofs []boundKeys, cfg templateConfiguration) *proofError {
	for _, proof := range proofs {
		if proof.attestation == nil && d.keyAttestationRequired() {
			return invalidProof("this issuer requires a key attestation (key_attestations_required): send it in the key_attestation header of the jwt proof or as an attestation proof")
		}
		if !d.requiresWSCD(cfg) {
			continue
		}
		problem := wscdProblem(proof.attestation)
		switch {
		case problem == "":
		case d.keyAttestationRequired():
			return invalidProof("%s. A PID is bound only to a key in a WSCD (CIR (EU) 2024/2979 Annex Ib TR_KA-8)", problem)
		default:
			log.Printf("[Demo issuer] PID proof accepted without a WSCD key (CIR (EU) 2024/2979 Annex Ib TR_KA-8): %s", problem)
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

// checkAttestationStatus fetches the status lists referenced by a wallet
// instance attestation or a key attestation. OpenID4VCI 1.0 Appendix D.1
// and E define a status claim. CIR (EU) 2024/2979 Annex Ib C_WIA-1 and
// C_KA-1, as amended by CIR (EU) 2026/1731, put the reference in the status
// member of client_status or key_storage_status (cirClaim). ARF WUA_25 and
// WUA_11a: the provider "SHALL validate that the WIA [KA] is not revoked", so
// a status other than VALID refuses the attestation.
//
// A status that cannot be established (an unreachable or unreadable list, an
// expired list, an index out of range, a list for another uri) does not
// refuse it. draft-ietf-oauth-status-list-21 §8.3 says that then "no
// statement about the status of the Referenced Token can be made and the
// Referenced Token SHOULD be rejected". This issuer accepts it anyway,
// because the public demo cannot reach the status lists of a wallet on
// localhost. Then established is false. The attestation is accepted and
// logged as untrusted.
func (d *DemoRP) checkAttestationStatus(kind string, payload map[string]any, cirClaim string) (established bool, refused error) {
	refs := []*statuslist.StatusRef{statuslist.ExtractStatusRef(payload)}
	if nested, ok := payload[cirClaim].(map[string]any); ok {
		refs = append(refs, statuslist.ExtractStatusRef(nested))
	}
	established = true
	for _, ref := range refs {
		if ref == nil {
			continue
		}
		result, err := statuslist.CheckWithOptions(ref, statuslist.CheckOptions{HTTPClient: d.wallet.HTTPClient(), Prefer: statuslist.FormatJWT})
		if err != nil {
			log.Printf("[Demo issuer] the status of the %s cannot be established, so it is accepted as untrusted: %v", kind, err)
			established = false
			continue
		}
		if !result.IsValid {
			return false, fmt.Errorf("the %s is %s at index %d of %s", kind, result.StatusName, ref.Idx, ref.URI)
		}
	}
	return established, nil
}
