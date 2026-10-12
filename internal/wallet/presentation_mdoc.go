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
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
)

// An empty mdocNonce makes this document generate the nonce for its response.
// Documents in a shared response receive the same nonce.
func (w *Wallet) createMDocPresentation(cred StoredCredential, selectedKeys []string, params PresentationParams, mdocNonce string, signingKey *ecdsa.PrivateKey) (VPTokenResult, error) {
	// ISO 18013-5 §9.1.2.4 requires deviceKey in the MSO. Without it, the issuer has
	// not bound the credential to the key used for DeviceSigned. Debug mode still
	// builds the response and warns, so the verifier can report the problem. See
	// docs/adr/0001-debug-by-default-validation-with-opt-in-strict-mode.md.
	if !credentialHolderBinding(cred.Raw).Bound {
		detail := fmt.Sprintf(
			"mdoc %s names no MSO deviceKey (ISO 18013-5 §9.1.2.4 makes it mandatory), so its DeviceSigned binds to a key the issuer never vouched for and the verifier refuses this presentation.",
			credentialLabel(cred))
		w.addProtocolWarning("presentation", "mdoc_names_no_device_key", detail, map[string]any{
			"credential_id": cred.ID,
			"doctype":       cred.DocType,
		})
		log.Printf("[VP] WARNING: %s", detail)
	}

	selected := make(map[string]bool, len(selectedKeys))
	for _, k := range selectedKeys {
		selected[k] = true
	}

	rawBytes, err := format.DecodeHexOrBase64URL(cred.Raw)
	if err != nil {
		return VPTokenResult{}, fmt.Errorf("decoding mdoc: %w", err)
	}

	var issuerSigned map[string]cbor.RawMessage
	if err := cbor.Unmarshal(rawBytes, &issuerSigned); err != nil {
		return VPTokenResult{}, fmt.Errorf("parsing IssuerSigned CBOR: %w", err)
	}

	// RawCBOR preserves the exact Tag-24 bytes covered by the MSO digest. The parser
	// skips invalid items and duplicate element identifiers, so positions in the
	// parsed list may differ from the raw array.
	filteredNS := make(map[string][]cbor.RawMessage)
	for ns, items := range cred.NameSpaces {
		var filtered []cbor.RawMessage
		for _, item := range items {
			if selected[ns+":"+item.ElementIdentifier] && len(item.RawCBOR) > 0 {
				filtered = append(filtered, cbor.RawMessage(item.RawCBOR))
			}
		}
		if len(filtered) > 0 {
			filteredNS[ns] = filtered
		}
	}

	docType := cred.DocType

	mode := w.SessionTranscript
	if mode == "" {
		mode = SessionTranscriptOID4VP
	}

	switch {
	case mode != SessionTranscriptISO:
		// Only the ISO transcript uses the generated nonce.
		mdocNonce = ""
	case mdocNonce == "":
		generated, err := newMDocGeneratedNonce()
		if err != nil {
			return VPTokenResult{}, err
		}
		mdocNonce = generated
	}

	jwkThumbprint := extractJWKThumbprint(params.RequestObject, params.ClientMetadata)
	sessionTranscriptBytes, err := w.buildSessionTranscript(params, mdocNonce, jwkThumbprint)
	if err != nil {
		return VPTokenResult{}, fmt.Errorf("building SessionTranscript: %w", err)
	}

	deviceAuthBytes, err := w.createDeviceAuth(sessionTranscriptBytes, docType, signingKey)
	if err != nil {
		return VPTokenResult{}, fmt.Errorf("creating DeviceAuth: %w", err)
	}

	deviceNamespacesBytes, err := emptyDeviceNamespacesBytes()
	if err != nil {
		return VPTokenResult{}, fmt.Errorf("encoding DeviceNameSpaces: %w", err)
	}

	document := map[string]any{
		"docType": docType,
		"issuerSigned": map[string]any{
			"nameSpaces": filteredNS,
			"issuerAuth": issuerSigned["issuerAuth"],
		},
		"deviceSigned": map[string]any{
			"nameSpaces": cbor.RawMessage(deviceNamespacesBytes),
			"deviceAuth": map[string]any{
				"deviceSignature": cbor.RawMessage(deviceAuthBytes),
			},
		},
	}

	deviceResponse := map[string]any{
		"version":   "1.0",
		"documents": []any{document},
		"status":    0,
	}

	responseBytes, err := cbor.Marshal(deviceResponse)
	if err != nil {
		return VPTokenResult{}, fmt.Errorf("encoding DeviceResponse: %w", err)
	}

	return VPTokenResult{
		Token:     format.EncodeBase64URL(responseBytes),
		MDocNonce: mdocNonce,
	}, nil
}

// ISO 18013-7 Annex B uses one generated nonce per response. Every document includes
// it in its session transcript. The encrypted response carries it once in apu.
func newMDocGeneratedNonce() (string, error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	return format.EncodeBase64URL(nonceBytes), nil
}

// buildSessionTranscript constructs the SessionTranscript CBOR bytes using the
// configured mode (ISO 18013-7 or OID4VP).
func (w *Wallet) buildSessionTranscript(params PresentationParams, mdocNonce string, jwkThumbprint []byte) ([]byte, error) {
	// Interactive Authorization uses the challenge endpoint in its handover regardless
	// of the configured transcript mode (OpenID4VCI 1.1 Appendix A.2.5).
	if isInteractiveAuthorizationResponseMode(params.ResponseMode) {
		// A.2.5: "If the Response Mode is ia_post, the third element MUST be
		// null", even where client_metadata carried an encryption key.
		if params.ResponseMode == "ia_post" {
			jwkThumbprint = nil
		}
		return buildSessionTranscriptOID4VCIIAE(params.InteractiveAuthorizationEndpoint, params.Nonce, jwkThumbprint)
	}

	mode := w.SessionTranscript
	if mode == "" {
		mode = SessionTranscriptOID4VP
	}

	switch mode {
	case SessionTranscriptISO:
		return buildSessionTranscriptISO(params.ClientID, params.ResponseURI, params.Nonce, mdocNonce)
	case SessionTranscriptOID4VP:
		if params.ResponseMode == "dc_api" || params.ResponseMode == "dc_api.jwt" {
			return buildSessionTranscriptOID4VPDCAPI(params.RequestOrigin, params.Nonce, jwkThumbprint)
		}
		return buildSessionTranscriptOID4VP(params.ClientID, params.Nonce, jwkThumbprint, params.ResponseURI)
	default:
		return nil, fmt.Errorf("unknown session transcript mode: %s", mode)
	}
}

func BuildOID4VCIIAESessionTranscript(challengeEndpoint, nonce string, jwkThumbprint []byte) ([]byte, error) {
	return buildSessionTranscriptOID4VCIIAE(challengeEndpoint, nonce, jwkThumbprint)
}

// buildSessionTranscriptOID4VCIIAE builds the session transcript of OpenID4VCI
// 1.1 Appendix A.2.5.
//
//	OpenID4VCIIAEHandoverInfo = [iae, nonce, jwkThumbprint]
//	OpenID4VCIIAEHandover     = ["OpenID4VCIIAEHandover", SHA256(HandoverInfo)]
//	SessionTranscript         = [null, null, OpenID4VCIIAEHandover]
//
// iae is the challenge endpoint and "MUST NOT be prefixed with ia:", unlike a
// Key Binding JWT audience.
func buildSessionTranscriptOID4VCIIAE(challengeEndpoint, nonce string, jwkThumbprint []byte) ([]byte, error) {
	if strings.TrimSpace(challengeEndpoint) == "" {
		return nil, fmt.Errorf("interactive authorization session transcript needs the authorization challenge endpoint")
	}
	var thumbprintValue any
	if len(jwkThumbprint) > 0 {
		thumbprintValue = jwkThumbprint
	}
	handoverInfo, err := cbor.Marshal([]any{challengeEndpoint, nonce, thumbprintValue})
	if err != nil {
		return nil, fmt.Errorf("encoding OpenID4VCIIAEHandoverInfo: %w", err)
	}
	hash := sha256.Sum256(handoverInfo)

	handover := []any{"OpenID4VCIIAEHandover", hash[:]}
	sessionTranscript := []any{nil, nil, handover}
	return cbor.Marshal(sessionTranscript)
}

// buildSessionTranscriptISO builds the ISO 18013-7 Annex B.4.4 session transcript.
// Hash inputs are CBOR-encoded [value, mdocGeneratedNonce] arrays.
func buildSessionTranscriptISO(clientID, responseURI, nonce, mdocNonce string) ([]byte, error) {
	// clientIdToHash = CBOR_encode([clientId, mdocGeneratedNonce])
	clientIDToHash, err := cbor.Marshal([]string{clientID, mdocNonce})
	if err != nil {
		return nil, fmt.Errorf("encoding clientIdToHash: %w", err)
	}
	clientIDHash := sha256.Sum256(clientIDToHash)

	// responseUriToHash = CBOR_encode([responseUri, mdocGeneratedNonce])
	responseURIToHash, err := cbor.Marshal([]string{responseURI, mdocNonce})
	if err != nil {
		return nil, fmt.Errorf("encoding responseUriToHash: %w", err)
	}
	responseURIHash := sha256.Sum256(responseURIToHash)

	// Handover = [clientIdHash, responseUriHash, nonce]
	handover := []any{
		clientIDHash[:],
		responseURIHash[:],
		nonce,
	}

	// SessionTranscript = [null, null, Handover]
	sessionTranscript := []any{nil, nil, handover}
	return cbor.Marshal(sessionTranscript)
}

func BuildOID4VPSessionTranscript(clientID, nonce string, jwkThumbprint []byte, responseURI string) ([]byte, error) {
	return buildSessionTranscriptOID4VP(clientID, nonce, jwkThumbprint, responseURI)
}

// buildSessionTranscriptOID4VP builds the OID4VP 1.0 session transcript.
// OID4VPHandover = ["OpenID4VPHandover", SHA256(HandoverInfo)]
// SessionTranscript = [null, null, OID4VPHandover]
func buildSessionTranscriptOID4VP(clientID, nonce string, jwkThumbprint []byte, responseURI string) ([]byte, error) {
	// HandoverInfo = CBOR([clientId, nonce, jwkThumbprint|null, responseUri])
	var thumbprintValue any
	if len(jwkThumbprint) > 0 {
		thumbprintValue = jwkThumbprint
	}
	handoverInfo, err := cbor.Marshal([]any{clientID, nonce, thumbprintValue, responseURI})
	if err != nil {
		return nil, fmt.Errorf("encoding HandoverInfo: %w", err)
	}
	hash := sha256.Sum256(handoverInfo)

	// OID4VPHandover = ["OpenID4VPHandover", hash]
	oid4vpHandover := []any{"OpenID4VPHandover", hash[:]}

	// SessionTranscript = [null, null, OID4VPHandover]
	sessionTranscript := []any{nil, nil, oid4vpHandover}
	return cbor.Marshal(sessionTranscript)
}

// buildSessionTranscriptOID4VPDCAPI builds the OID4VP DC API session transcript.
// HandoverInfo = CBOR([origin, nonce, jwkThumbprint|null])
// OID4VPDCAPIHandover = ["OpenID4VPDCAPIHandover", SHA256(HandoverInfo)]
// SessionTranscript = [null, null, OID4VPDCAPIHandover]
func buildSessionTranscriptOID4VPDCAPI(origin, nonce string, jwkThumbprint []byte) ([]byte, error) {
	var thumbprintValue any
	if len(jwkThumbprint) > 0 {
		thumbprintValue = jwkThumbprint
	}
	handoverInfo, err := cbor.Marshal([]any{origin, nonce, thumbprintValue})
	if err != nil {
		return nil, fmt.Errorf("encoding DC API HandoverInfo: %w", err)
	}
	hash := sha256.Sum256(handoverInfo)

	oid4vpHandover := []any{"OpenID4VPDCAPIHandover", hash[:]}
	sessionTranscript := []any{nil, nil, oid4vpHandover}
	return cbor.Marshal(sessionTranscript)
}

func emptyDeviceNamespacesBytes() ([]byte, error) {
	encodedEmptyMap, err := cbor.Marshal(map[string]any{})
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(cbor.Tag{Number: 24, Content: encodedEmptyMap})
}

// createDeviceAuth signs the DeviceAuthentication structure into a COSE_Sign1 DeviceAuth.
// DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]
// The payload is Tag24(CBOR(DeviceAuthentication)).
func (w *Wallet) createDeviceAuth(sessionTranscriptBytes []byte, docType string, signingKey *ecdsa.PrivateKey) ([]byte, error) {
	signer, err := cose.NewSigner(cose.AlgorithmES256, signingKey)
	if err != nil {
		return nil, fmt.Errorf("creating COSE signer: %w", err)
	}

	var sessionTranscript cbor.RawMessage = sessionTranscriptBytes

	deviceNamespacesBytes, err := emptyDeviceNamespacesBytes()
	if err != nil {
		return nil, fmt.Errorf("encoding DeviceNameSpaces: %w", err)
	}

	deviceAuth := []any{
		"DeviceAuthentication",
		sessionTranscript,
		docType,
		cbor.RawMessage(deviceNamespacesBytes),
	}

	deviceAuthBytes, err := cbor.Marshal(deviceAuth)
	if err != nil {
		return nil, fmt.Errorf("encoding DeviceAuthentication: %w", err)
	}

	tag24Payload, err := cbor.Marshal(cbor.Tag{Number: 24, Content: deviceAuthBytes})
	if err != nil {
		return nil, fmt.Errorf("encoding Tag24(DeviceAuthentication): %w", err)
	}

	msg := cose.UntaggedSign1Message{
		Headers: cose.Headers{
			Protected:   cose.ProtectedHeader{},
			Unprotected: cose.UnprotectedHeader{},
		},
		Payload: tag24Payload,
	}
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)

	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("COSE signing: %w", err)
	}
	msg.Payload = nil

	sign1Bytes, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("encoding COSE_Sign1: %w", err)
	}

	return sign1Bytes, nil
}
