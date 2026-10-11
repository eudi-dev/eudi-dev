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

package mdoc

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// The holder signs a session transcript in DeviceAuth and the verifier
// rebuilds it. Each is [null, null, Handover]. A nil jwkThumbprint encodes
// as null.

// OID4VPSessionTranscript builds the transcript of OID4VP 1.0 Appendix
// B.2.6.1: Handover = ["OpenID4VPHandover", SHA-256(CBOR([clientId, nonce,
// jwkThumbprint, responseUri]))].
func OID4VPSessionTranscript(clientID, nonce string, jwkThumbprint []byte, responseURI string) ([]byte, error) {
	return handoverTranscript("OpenID4VPHandover", clientID, nonce, thumbprintOrNull(jwkThumbprint), responseURI)
}

// OID4VPDCAPISessionTranscript builds the transcript of OID4VP 1.0 Appendix
// B.2.6.2: Handover = ["OpenID4VPDCAPIHandover", SHA-256(CBOR([origin, nonce,
// jwkThumbprint]))].
func OID4VPDCAPISessionTranscript(origin, nonce string, jwkThumbprint []byte) ([]byte, error) {
	return handoverTranscript("OpenID4VPDCAPIHandover", origin, nonce, thumbprintOrNull(jwkThumbprint))
}

// OID4VCIIAESessionTranscript builds the transcript of OpenID4VCI 1.1 Appendix
// A.2.5: Handover = ["OpenID4VCIIAEHandover", SHA-256(CBOR([iae, nonce,
// jwkThumbprint]))]. iae is the challenge endpoint and "MUST NOT be prefixed
// with ia:", unlike a Key Binding JWT audience.
func OID4VCIIAESessionTranscript(challengeEndpoint, nonce string, jwkThumbprint []byte) ([]byte, error) {
	if strings.TrimSpace(challengeEndpoint) == "" {
		return nil, fmt.Errorf("interactive authorization session transcript needs the authorization challenge endpoint")
	}
	return handoverTranscript("OpenID4VCIIAEHandover", challengeEndpoint, nonce, thumbprintOrNull(jwkThumbprint))
}

// ISOSessionTranscript builds the transcript of ISO 18013-7 Annex B.4.4:
// Handover = [SHA-256(CBOR([clientId, mdocGeneratedNonce])),
// SHA-256(CBOR([responseUri, mdocGeneratedNonce])), nonce].
func ISOSessionTranscript(clientID, responseURI, nonce, mdocNonce string) ([]byte, error) {
	clientIDToHash, err := cbor.Marshal([]string{clientID, mdocNonce})
	if err != nil {
		return nil, fmt.Errorf("encoding clientIdToHash: %w", err)
	}
	responseURIToHash, err := cbor.Marshal([]string{responseURI, mdocNonce})
	if err != nil {
		return nil, fmt.Errorf("encoding responseUriToHash: %w", err)
	}
	clientIDHash := sha256.Sum256(clientIDToHash)
	responseURIHash := sha256.Sum256(responseURIToHash)
	return cbor.Marshal([]any{nil, nil, []any{clientIDHash[:], responseURIHash[:], nonce}})
}

func handoverTranscript(name string, info ...any) ([]byte, error) {
	handoverInfo, err := cbor.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("encoding %sInfo: %w", name, err)
	}
	hash := sha256.Sum256(handoverInfo)
	return cbor.Marshal([]any{nil, nil, []any{name, hash[:]}})
}

func thumbprintOrNull(jwkThumbprint []byte) any {
	if len(jwkThumbprint) == 0 {
		return nil
	}
	return jwkThumbprint
}
