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
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"

	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
)

// extractJWKThumbprint returns the RFC 7638 SHA-256 thumbprint of the request
// object's encryption JWK. It returns nil when there is no encryption key.
func extractJWKThumbprint(reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any) []byte {
	jwk := findEncryptionJWK(reqObj, clientMetadata)
	if jwk == nil {
		return nil
	}
	return computeJWKThumbprint(jwk)
}

// findEncryptionJWK returns the first encryption JWK in client_metadata.jwks
// (OID4VP 1.0).
func findEncryptionJWK(reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any) map[string]any {
	return firstJWK(encryptionJWKS(reqObj, clientMetadata))
}

func encryptionJWKS(reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any) any {
	if reqObj != nil && reqObj.Payload != nil {
		if clientMeta, ok := reqObj.Payload["client_metadata"].(map[string]any); ok {
			return clientMeta["jwks"]
		}
	}
	if clientMetadata != nil {
		return clientMetadata["jwks"]
	}
	return nil
}

// firstSigningOnlyEncryptionJWK returns the first usable key marked "use":"sig".
// Debug mode encrypts to it when the verifier published no encryption key.
func firstSigningOnlyEncryptionJWK(jwksVal any) map[string]any {
	jwks, ok := jwksVal.(map[string]any)
	if !ok {
		return nil
	}
	keysSlice, ok := jwks["keys"].([]any)
	if !ok {
		return nil
	}
	for _, entry := range keysSlice {
		jwk, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if use, _ := jwk["use"].(string); use == "sig" && encryptableKeyMaterial(jwk) {
			return jwk
		}
	}
	return nil
}

// firstJWK returns the first usable encryption key in a JWKS ({"keys": [...]}).
// It skips keys with an unsupported kty or curve and keys marked for signing
// (RFC 7517 §5).
func firstJWK(jwksVal any) map[string]any {
	jwks, ok := jwksVal.(map[string]any)
	if !ok {
		return nil
	}
	keysSlice, ok := jwks["keys"].([]any)
	if !ok || len(keysSlice) == 0 {
		return nil
	}
	// Prefer an EC key. ECDH-ES on P-256 is the OID4VP baseline and the only
	// option HAIP allows. RSA-OAEP is the fallback.
	var fallback map[string]any
	for _, entry := range keysSlice {
		jwk, ok := entry.(map[string]any)
		if !ok || !usableEncryptionJWK(jwk) {
			continue
		}
		if kty, _ := jwk["kty"].(string); kty == "EC" {
			return jwk
		}
		if fallback == nil {
			fallback = jwk
		}
	}
	return fallback
}

func usableEncryptionJWK(jwk map[string]any) bool {
	if use, ok := jwk["use"].(string); ok && use != "enc" {
		return false
	}
	return encryptableKeyMaterial(jwk)
}

func encryptableKeyMaterial(jwk map[string]any) bool {
	switch kty, _ := jwk["kty"].(string); kty {
	case "EC":
		if crv, ok := jwk["crv"].(string); ok && crv != "P-256" {
			return false
		}
		x, _ := jwk["x"].(string)
		y, _ := jwk["y"].(string)
		return x != "" && y != ""
	case "RSA":
		n, _ := jwk["n"].(string)
		e, _ := jwk["e"].(string)
		return n != "" && e != ""
	default:
		return false
	}
}

// computeJWKThumbprint returns the RFC 7638 JWK Thumbprint using SHA-256, or
// nil for a JWK without its required members.
func computeJWKThumbprint(jwk map[string]any) []byte {
	sum, err := keys.Thumbprint(jwk)
	if err != nil {
		return nil
	}
	return sum
}

// encryptionKeyInfo holds the encryption key parameters of a JWK.
// Exactly one of Key (ECDH-ES) or RSAKey (RSA-OAEP) is set.
type encryptionKeyInfo struct {
	Key    *ecdsa.PublicKey
	RSAKey *rsa.PublicKey
	Kid    string
	Alg    string // JWE algorithm (e.g. "ECDH-ES" or "RSA-OAEP"), required by OID4VP 1.0
	// Finding records a specification violation accepted in debug mode. Strict mode
	// rejects the document.
	Finding string
}

// extractEncryptionKey reads the verifier's public key, kid, and alg from
// client_metadata.jwks per OID4VP 1.0. An EC key is used with ECDH-ES, an RSA
// key with RSA-OAEP.
func extractEncryptionKey(mode ValidationMode, reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any) (*encryptionKeyInfo, error) {
	jwk := findEncryptionJWK(reqObj, clientMetadata)
	selectionFinding := ""
	if jwk == nil && mode == ValidationModeDebug {
		// The verifier published no encryption-marked key. Debug mode encrypts
		// to a signing-marked key of a usable type and records a finding.
		if cand := firstSigningOnlyEncryptionJWK(encryptionJWKS(reqObj, clientMetadata)); cand != nil {
			jwk = cand
			selectionFinding = `verifier's key in client_metadata.jwks is marked "use":"sig" (signing only). OID4VP 1.0 needs an encryption key for a direct_post.jwt response, so it was used for encryption`
		}
	}
	if jwk == nil {
		return nil, fmt.Errorf("client_metadata.jwks carries no encryption key (OID4VP 1.0 requires one for an encrypted response)")
	}

	kid, _ := jwk["kid"].(string)
	alg, _ := jwk["alg"].(string)
	if alg == "" {
		return nil, fmt.Errorf("JWK missing required 'alg' parameter (OID4VP 1.0 requires alg in each JWK)")
	}

	switch kty, _ := jwk["kty"].(string); kty {
	case "RSA":
		rsaKey, err := rsaPublicKeyFromJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("constructing RSA key: %w", err)
		}
		return &encryptionKeyInfo{RSAKey: rsaKey, Kid: kid, Alg: alg, Finding: selectionFinding}, nil
	case "EC":
		x, _ := jwk["x"].(string)
		y, _ := jwk["y"].(string)
		if x == "" || y == "" {
			return nil, fmt.Errorf("missing x or y in JWK")
		}
		pubKey, finding, err := ecdsaPublicKeyFromJWK(mode, x, y)
		if err != nil {
			return nil, fmt.Errorf("constructing EC key: %w", err)
		}
		return &encryptionKeyInfo{Key: pubKey, Kid: kid, Alg: alg, Finding: joinFindings(selectionFinding, finding)}, nil
	default:
		return nil, fmt.Errorf("unsupported encryption key type %q in client_metadata.jwks", kty)
	}
}

func joinFindings(findings ...string) string {
	out := ""
	for _, f := range findings {
		if f == "" {
			continue
		}
		if out != "" {
			out += ". "
		}
		out += f
	}
	return out
}

func HasEncryptionKey(reqObj *oid4vc.RequestObjectJWT) bool {
	_, err := extractEncryptionKey(ValidationModeDebug, reqObj, nil)
	return err == nil
}

// The payload must include the top level members required by OID4VP 1.0 for success or
// error responses.
func (w *Wallet) encryptDirectPostJWTPayload(payload map[string]any, mdocNonce string, params PresentationParams) (string, []byte, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", nil, fmt.Errorf("marshaling response payload: %w", err)
	}

	keyInfo, err := extractEncryptionKey(w.Mode(), params.RequestObject, params.ClientMetadata)
	if err != nil {
		return "", nil, fmt.Errorf("extracting encryption key: %w", err)
	}
	if keyInfo.Finding != "" {
		w.AddLog("presentation", keyInfo.Finding, false)
	}

	enc := detectEncAlgorithm(params.RequestObject, params.ClientMetadata, "A128GCM")

	// RSA-OAEP wraps the key without key agreement, so the response has no ephemeral
	// key, apu or apv.
	if keyInfo.RSAKey != nil {
		return EncryptJWERSA(payloadJSON, keyInfo.RSAKey, keyInfo.Kid, keyInfo.Alg, enc)
	}

	// For ISO mode with mdoc_generated_nonce, set apu and apv per ISO 18013-7 Annex B.
	var apu, apv []byte
	if mdocNonce != "" {
		apu = []byte(mdocNonce)
		if params.Nonce != "" {
			apv = []byte(params.Nonce)
		}
	}

	return EncryptJWE(payloadJSON, keyInfo.Key, keyInfo.Kid, keyInfo.Alg, enc, apu, apv)
}

// EncryptResponse also returns the content encryption key (CEK) for debugging.
func (w *Wallet) EncryptResponse(vpToken any, idToken, state string, mdocNonce string, params PresentationParams) (string, []byte, error) {
	log.Printf("[VP] Encrypting response: response_mode=%s", params.ResponseMode)
	payload := map[string]any{}
	// OID4VP 1.0 Appendix A.2: "since the state parameter is not defined for the DC
	// API, the Verifier cannot expect it to be included in the response". Redirect
	// flows include state when the request supplies it.
	if state != "" && !isDCAPIResponseMode(params.ResponseMode) {
		payload["state"] = state
	}
	if vpToken != nil {
		payload["vp_token"] = vpToken
	}
	if idToken != "" {
		payload["id_token"] = idToken
	}
	return w.encryptDirectPostJWTPayload(payload, mdocNonce, params)
}

// EncryptErrorResponse encrypts an authorization error response. The payload
// carries error, optional error_description, and state as top-level members per
// OID4VP 1.0.
func (w *Wallet) EncryptErrorResponse(errorCode, errorDescription, state string, params PresentationParams) (string, []byte, error) {
	log.Printf("[VP] Encrypting error response: response_mode=%s error=%s", params.ResponseMode, errorCode)
	payload := map[string]any{
		"error": errorCode,
	}
	if errorDescription != "" {
		payload["error_description"] = oid4vc.ErrorDescription(errorDescription)
	}
	if state != "" && !isDCAPIResponseMode(params.ResponseMode) {
		payload["state"] = state
	}
	return w.encryptDirectPostJWTPayload(payload, "", params)
}

func detectEncAlgorithm(reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any, fallback string) string {
	clientMeta := clientMetadata
	if reqObj != nil && reqObj.Payload != nil {
		if reqClientMeta, ok := reqObj.Payload["client_metadata"].(map[string]any); ok {
			clientMeta = reqClientMeta
		}
	}
	if len(clientMeta) == 0 {
		return fallback
	}

	if arr, ok := clientMeta["encrypted_response_enc_values_supported"].([]any); ok && len(arr) > 0 {
		if v, ok := arr[0].(string); ok && v != "" {
			return v
		}
	}

	return fallback
}
