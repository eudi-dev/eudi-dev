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

import "fmt"

// ProofKeyReference is how a jwt proof with a key attestation names its
// signing key, the first attested key (OpenID4VCI 1.0 Appendix F.1).
type ProofKeyReference string

const (
	// ProofKeyKID sends kid "0", the key's position in attested_keys, as in
	// the Appendix F.1 example and the EUDI reference wallet.
	ProofKeyKID ProofKeyReference = "kid"
	// ProofKeyJWK sends the key itself as jwk.
	ProofKeyJWK ProofKeyReference = "jwk"
	// ProofKeyNone sends neither kid nor jwk. Appendix F.1 requires one of
	// kid, jwk and x5c, so this checks whether an issuer enforces the rule.
	ProofKeyNone ProofKeyReference = "none"
)

func ParseProofKeyReference(raw string) (ProofKeyReference, error) {
	switch ProofKeyReference(raw) {
	case "", ProofKeyKID:
		return ProofKeyKID, nil
	case ProofKeyJWK, ProofKeyNone:
		return ProofKeyReference(raw), nil
	default:
		return "", fmt.Errorf("invalid proof key reference %q (must be 'kid', 'jwk' or 'none')", raw)
	}
}
