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
	"slices"

	"github.com/dominikschlosser/eudi-dev/v3/internal/jwe"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
)

// responseModeEncrypts reports whether a response mode sends the response as
// a JWE (OID4VP 1.0 §8.3.1 and Appendix A.4, OpenID4VCI 1.1 §6.2.1.1).
func responseModeEncrypts(mode string) bool {
	return mode == "direct_post.jwt" || mode == "dc_api.jwt" || mode == "ia_post.jwt"
}

// handoverJWKThumbprint is the jwkThumbprint of an mdoc handover. OID4VP 1.0
// Appendix B.2.6.1: "If the response is encrypted [...] the third element MUST
// be the JWK SHA-256 Thumbprint [...] of the Verifier's public key used to
// encrypt the response. Otherwise, the third element MUST be null." B.2.6.2
// says the same for dc_api.jwt and dc_api.
func (w *Wallet) handoverJWKThumbprint(params PresentationParams) []byte {
	if !responseModeEncrypts(params.ResponseMode) {
		return nil
	}
	jwk, _ := responseEncryptionJWK(w.Mode(), params.RequestObject, params.ClientMetadata)
	if jwk == nil {
		return nil
	}
	return computeJWKThumbprint(jwk)
}

// findEncryptionJWK returns the first encryption JWK in client_metadata.jwks
// that the wallet can encrypt to (OID4VP 1.0 §8.3).
func findEncryptionJWK(reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any) map[string]any {
	return firstJWK(encryptionJWKS(reqObj, clientMetadata))
}

// responseEncryptionJWK selects the key the response is encrypted to. The
// finding is set when debug mode falls back to a key marked for signing.
func responseEncryptionJWK(mode ValidationMode, reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any) (map[string]any, string) {
	if jwk := findEncryptionJWK(reqObj, clientMetadata); jwk != nil {
		return jwk, ""
	}
	if mode != ValidationModeDebug {
		return nil, ""
	}
	if jwk := firstSigningOnlyEncryptionJWK(encryptionJWKS(reqObj, clientMetadata)); jwk != nil {
		return jwk, `verifier's key in client_metadata.jwks is marked "use":"sig" (signing only). OID4VP 1.0 needs an encryption key for a direct_post.jwt response, so it was used for encryption`
	}
	return nil, ""
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
		if use, _ := jwk["use"].(string); use == "sig" && encryptableKeyMaterial(jwk) && walletImplementsKeyAlg(jwk) {
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
	return encryptableKeyMaterial(jwk) && walletImplementsKeyAlg(jwk)
}

// walletImplementsKeyAlg reports whether the wallet implements the key's alg.
// OID4VP 1.0 §8.3: "The alg parameter MUST be present in the JWKs. The JWE alg
// algorithm used MUST be equal to the alg value of the chosen jwk." The wallet
// does direct key agreement with EC keys and key wrapping with RSA keys.
func walletImplementsKeyAlg(jwk map[string]any) bool {
	alg, _ := jwk["alg"].(string)
	switch kty, _ := jwk["kty"].(string); kty {
	case "EC":
		return alg == "ECDH-ES"
	case "RSA":
		return alg == "RSA-OAEP" || alg == "RSA-OAEP-256"
	default:
		return false
	}
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
	jwk, selectionFinding := responseEncryptionJWK(mode, reqObj, clientMetadata)
	if jwk == nil {
		return nil, fmt.Errorf("client_metadata.jwks carries no encryption key with an alg this wallet implements (ECDH-ES on P-256, RSA-OAEP or RSA-OAEP-256). OID4VP 1.0 §8.3 requires one for an encrypted response")
	}

	kid, _ := jwk["kid"].(string)
	alg, _ := jwk["alg"].(string)

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

	enc, err := responseEncAlgorithm(params.RequestObject, params.ClientMetadata)
	if err != nil {
		return "", nil, err
	}

	// RSA-OAEP wraps the key without key agreement, so the response has no ephemeral
	// key, apu or apv.
	if keyInfo.RSAKey != nil {
		return jwe.EncryptRSAOAEP(payloadJSON, keyInfo.RSAKey, keyInfo.Kid, keyInfo.Alg, enc)
	}

	// For ISO mode with mdoc_generated_nonce, set apu and apv per ISO 18013-7 Annex B.
	var apu, apv []byte
	if mdocNonce != "" {
		apu = []byte(mdocNonce)
		if params.Nonce != "" {
			apv = []byte(params.Nonce)
		}
	}

	return jwe.EncryptECDHES(payloadJSON, keyInfo.Key, keyInfo.Kid, enc, "", apu, apv)
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

// responseEncAlgorithm picks the JWE enc of the response. OID4VP 1.0 §8.3
// takes it from encrypted_response_enc_values_supported, "allowing for the
// default value of A128GCM when not explicitly set". HAIP 1.0 §5: "If both are
// supported, the Wallet SHOULD use A256GCM for the JWE enc."
func responseEncAlgorithm(reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any) (string, error) {
	clientMeta := clientMetadata
	if reqObj != nil && reqObj.Payload != nil {
		if reqClientMeta, ok := reqObj.Payload["client_metadata"].(map[string]any); ok {
			clientMeta = reqClientMeta
		}
	}
	offered := stringValues(clientMeta["encrypted_response_enc_values_supported"])
	if len(offered) == 0 {
		return "A128GCM", nil
	}
	if slices.Contains(offered, "A256GCM") {
		return "A256GCM", nil
	}
	for _, enc := range offered {
		if _, err := jwe.EncKeyBitLen(enc); err == nil {
			return enc, nil
		}
	}
	return "", fmt.Errorf("client_metadata.encrypted_response_enc_values_supported lists %v, and this wallet implements none of them", offered)
}
