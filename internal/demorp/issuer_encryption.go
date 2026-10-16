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

// Encrypted credential requests and responses (OpenID4VCI 1.0 §10). The demo
// issuer offers both and requires neither, so wallets without encryption keep
// working. ETSI TS 119 472-3 V1.1.1 CRYPTO-5-01 requires a provider to
// support A128GCM and A256GCM.

package demorp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/jwe"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
)

const requestEncryptionKID = "demo-issuer-request-enc"

// credentialEncryptionMetadata is the credential_request_encryption and
// credential_response_encryption metadata of §12.2.4.
func (d *DemoRP) credentialEncryptionMetadata() (request, response map[string]any) {
	jwk, _ := keys.PublicJWK(&d.requestEncryptionKey.PublicKey)
	jwk["use"], jwk["alg"], jwk["kid"] = "enc", jwe.AlgECDHES, requestEncryptionKID
	request = map[string]any{
		"jwks":                 map[string]any{"keys": []map[string]any{jwk}},
		"enc_values_supported": responseEncValues,
		"encryption_required":  false,
	}
	response = map[string]any{
		"alg_values_supported": []string{jwe.AlgECDHES},
		"enc_values_supported": responseEncValues,
		"encryption_required":  false,
	}
	return request, response
}

// decodeCredentialRequest reads a plain or an encrypted request body of the
// Credential or Deferred Credential Endpoint. §10: an encrypted message is a
// JWT and its media type "MUST be set to application/jwt". encrypted reports
// which form arrived.
func (d *DemoRP) decodeCredentialRequest(r *http.Request, target any) (encrypted bool, errResp map[string]string) {
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType != "application/jwt" {
		if err := decodeJSONBody(r, target); err != nil {
			return false, oauthError("invalid_credential_request", err.Error())
		}
		return false, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return true, oauthError("invalid_credential_request", err.Error())
	}
	compact := strings.TrimSpace(string(body))
	header, err := jwe.ParseHeader(compact)
	if err != nil {
		return true, oauthError("invalid_encryption_parameters", err.Error())
	}
	if !slices.Contains(responseEncValues, header.Enc) {
		return true, oauthError("invalid_encryption_parameters", fmt.Sprintf("the credential request enc %q is not in enc_values_supported (%s)", header.Enc, strings.Join(responseEncValues, ", ")))
	}
	// §10: "If the selected public key contains a kid parameter, the JWE MUST
	// include the same value in the kid JWE Header Parameter".
	if kid, _ := header.Raw["kid"].(string); kid != requestEncryptionKID {
		return true, oauthError("invalid_encryption_parameters", fmt.Sprintf("the credential request kid is %q, want %q of credential_request_encryption", kid, requestEncryptionKID))
	}
	ecdhKey, err := d.requestEncryptionKey.ECDH()
	if err != nil {
		return true, oauthError("server_error", err.Error())
	}
	plaintext, err := jwe.Decrypt(compact, ecdhKey)
	if err != nil {
		return true, oauthError("invalid_encryption_parameters", "decrypting the credential request with the key of credential_request_encryption: "+err.Error())
	}
	if err := json.NewDecoder(bytes.NewReader(plaintext)).Decode(target); err != nil {
		return true, oauthError("invalid_credential_request", "the decrypted credential request is not a JSON object: "+err.Error())
	}
	return true, nil
}

// responseEncryption is the credential_response_encryption object of a
// request (§8.2).
type responseEncryption struct {
	key *ecdsa.PublicKey
	kid string
	enc string
}

// parseResponseEncryption reads the credential_response_encryption parameter.
// §8.2: "Credential Request encryption MUST be used if the
// credential_response_encryption parameter is included, to prevent it being
// substituted by an attacker." The error code is invalid_encryption_parameters
// of §8.3.1.2.
func parseResponseEncryption(raw json.RawMessage, encryptedRequest bool) (*responseEncryption, map[string]string) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	refuse := func(format string, args ...any) (*responseEncryption, map[string]string) {
		return nil, oauthError("invalid_encryption_parameters", fmt.Sprintf(format, args...))
	}
	if !encryptedRequest {
		return refuse("credential_response_encryption needs an encrypted credential request (OpenID4VCI 1.0 §8.2): encrypt it with the key of credential_request_encryption")
	}
	var params struct {
		JWK map[string]any `json:"jwk"`
		Enc string         `json:"enc"`
		Zip string         `json:"zip"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return refuse("credential_response_encryption is not an object: %v", err)
	}
	if !slices.Contains(responseEncValues, params.Enc) {
		return refuse("enc %q is not in enc_values_supported (%s)", params.Enc, strings.Join(responseEncValues, ", "))
	}
	if params.Zip != "" {
		return refuse("this issuer publishes no zip_values_supported, so it cannot compress with %q", params.Zip)
	}
	// §10: "The alg parameter MUST be present. The JWE alg algorithm used
	// MUST be equal to the alg value of the chosen JWK."
	if alg, _ := params.JWK["alg"].(string); alg != jwe.AlgECDHES {
		return refuse("the jwk alg is %q, want %s from alg_values_supported", alg, jwe.AlgECDHES)
	}
	key, err := holderKeyFromJWK(params.JWK)
	if err != nil {
		return refuse("credential_response_encryption jwk: %v", err)
	}
	if key.Curve != elliptic.P256() {
		return refuse("the jwk is a %s key, but this issuer encrypts only to P-256 keys", key.Curve.Params().Name)
	}
	kid, _ := params.JWK["kid"].(string)
	return &responseEncryption{key: key, kid: kid, enc: params.Enc}, nil
}

// writeCredentialResponse answers with a Credential Response or a Deferred
// Credential Response. §8.3: an issuer asked for encryption "MUST encode the
// information in the Credential Response as specified by Section 10 [...]
// regardless of the content". Error responses never go through here, since
// §8.3.1.2 says they "are never encrypted".
func writeCredentialResponse(w http.ResponseWriter, status int, doc any, encryption *responseEncryption) {
	if encryption == nil {
		writeJSON(w, status, doc)
		return
	}
	payload, err := json.Marshal(doc)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, oauthError("server_error", err.Error()))
		return
	}
	compact, _, err := jwe.EncryptECDHES(payload, encryption.key, encryption.kid, encryption.enc, "", nil, nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, oauthError("server_error", "encrypting the credential response: "+err.Error()))
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(compact)) //nolint:gosec // G705: a compact JWE holds only base64url characters and dots, served as application/jwt.
}
