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
	"fmt"
	"log"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

// An empty mdocNonce makes this document generate the nonce for its response.
// Documents in a shared response receive the same nonce.
func (w *Wallet) createMDocPresentation(cred StoredCredential, selectedKeys []string, params *oid4vp.Request, mdocNonce string, signingKey *ecdsa.PrivateKey) (VPTokenResult, error) {
	// ISO 18013-5 §9.1.2.4 requires deviceKey in the MSO. In strict mode such an
	// mdoc matches no query, so it only gets here when the user picked it. The
	// wallet presents it with a warning.
	if !credentialHolderBinding(cred.Raw).Bound {
		finding := findings.ISO180135.Protocol("§9.1.2.4").Newf(
			"mdoc %s has no MSO deviceKey. The issuer signed no device key, so the verifier can't check DeviceSigned and should refuse this presentation",
			credentialLabel(cred))
		w.warnFinding("presentation", "mdoc_names_no_device_key", subjectPresentation, finding, map[string]any{
			"credential_id": cred.ID,
			"doctype":       cred.DocType,
		})
		log.Printf("[Wallet] WARNING: %s", finding)
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

	mode := w.sessionTranscriptFor(params)
	if mode == "" {
		mode = oid4vp.SessionTranscriptOID4VP
	}

	switch {
	case mode != oid4vp.SessionTranscriptISO:
		// Only the ISO transcript uses the generated nonce.
		mdocNonce = ""
	case mdocNonce == "":
		generated, err := newMDocGeneratedNonce()
		if err != nil {
			return VPTokenResult{}, err
		}
		mdocNonce = generated
	}

	sessionTranscriptBytes, err := w.buildSessionTranscript(params, mdocNonce, w.handoverJWKThumbprint(params))
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
func (w *Wallet) buildSessionTranscript(params *oid4vp.Request, mdocNonce string, jwkThumbprint []byte) ([]byte, error) {
	// Interactive Authorization uses the challenge endpoint in its handover regardless
	// of the configured transcript mode (OpenID4VCI 1.1 Appendix A.2.5).
	// A.2.5: "If the Response Mode is ia_post, the third element MUST be
	// null". handoverJWKThumbprint gives null for every unencrypted mode.
	if oid4vp.IsInteractiveAuthorizationResponseMode(params.ResponseMode) {
		return mdoc.OID4VCIIAESessionTranscript(params.InteractiveAuthorizationEndpoint, params.Nonce, jwkThumbprint)
	}

	mode := w.sessionTranscriptFor(params)
	if mode == "" {
		mode = oid4vp.SessionTranscriptOID4VP
	}

	switch mode {
	case oid4vp.SessionTranscriptISO:
		return mdoc.ISOSessionTranscript(params.ClientID, params.ResponseDestination(), params.Nonce, mdocNonce)
	case oid4vp.SessionTranscriptOID4VP:
		if params.ResponseMode == "dc_api" || params.ResponseMode == "dc_api.jwt" {
			return mdoc.OID4VPDCAPISessionTranscript(params.RequestOrigin, params.Nonce, jwkThumbprint)
		}
		return mdoc.OID4VPSessionTranscript(params.ClientID, params.Nonce, jwkThumbprint, params.ResponseDestination())
	default:
		return nil, fmt.Errorf("unknown session transcript mode: %s", mode)
	}
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
