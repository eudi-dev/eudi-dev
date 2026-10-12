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
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/jwe"
)

// The wallet advertises its encryption key even when encrypted Request Objects are
// optional.
func encryptionKeyCoords(w *Wallet) (x, y []byte, err error) {
	if w.RequestEncryptionKey == nil {
		return nil, nil, nil
	}
	return format.ECPublicCoords(&w.RequestEncryptionKey.PublicKey)
}

// BuildWalletMetadata advertises signing algorithms only when the client identifier prefix
// permits signed requests (OID4VP 1.0 §10).
func BuildWalletMetadata(w *Wallet, clientID string) map[string]any {
	meta := map[string]any{
		// Appendix B defines different algorithm fields for each format. SD-JWT fields
		// use JOSE names. The mso_mdoc fields use COSE identifiers, such as -7 for
		// ECDSA with SHA-256.
		"vp_formats_supported": map[string]any{
			"dc+sd-jwt": map[string]any{
				"sd-jwt_alg_values": []string{"ES256"},
				"kb-jwt_alg_values": []string{"ES256"},
			},
			"mso_mdoc": map[string]any{
				"issuerauth_alg_values": []int{-7},
				"deviceauth_alg_values": []int{-7},
			},
		},
		// OID4VP 1.0 §10.1 defaults to pre-registered when this field is absent.
		// Listing the prefixes allows x509_hash. The wallet cannot verify
		// verifier_attestation or decentralized_identifier requests, so it leaves
		// those out.
		"client_id_prefixes_supported": []string{
			"pre-registered",
			"redirect_uri",
			"x509_san_dns",
			"x509_hash",
		},
		// OID4VP 1.0 §10 uses RFC 8414 metadata, which requires
		// response_types_supported. OpenID4VP returns vp_token (§5.6).
		"response_types_supported": []string{"vp_token"},
		// RFC 8414 defaults to query and fragment, so the wallet lists its own
		// response modes.
		"response_modes_supported": []string{"direct_post", "direct_post.jwt", "dc_api", "dc_api.jwt"},
		// OID4VP 1.0 §10 advertises response encryption for direct_post.jwt and
		// dc_api.jwt. ECDH-ES with P-256 is the baseline. HAIP requires both A128GCM
		// and A256GCM.
		"authorization_encryption_alg_values_supported": []string{"ECDH-ES"},
		"authorization_encryption_enc_values_supported": []string{"A128GCM", "A256GCM"},
	}

	// OID4VP 1.0 §10 permits signing algorithms only for prefixes that support signed
	// Request Objects. The redirect_uri prefix forbids them (§5.9.1).
	if !strings.HasPrefix(clientID, "redirect_uri:") {
		meta["request_object_signing_alg_values_supported"] = []string{"ES256"}
	}

	if x, y, err := encryptionKeyCoords(w); err == nil && x != nil {
		meta["jwks"] = map[string]any{
			"keys": []any{
				map[string]any{
					"kty": "EC",
					"crv": "P-256",
					"x":   format.EncodeBase64URL(x),
					"y":   format.EncodeBase64URL(y),
					"use": "enc",
					"alg": "ECDH-ES",
				},
			},
		}
		// OID4VP 1.0 §5.10.5 puts request encryption keys in jwks. The
		// request_object_encryption_* fields follow OpenID Connect Discovery, with the
		// wallet acting as the server.
		meta["request_object_encryption_alg_values_supported"] = []string{"ECDH-ES"}
		meta["request_object_encryption_enc_values_supported"] = []string{"A128GCM", "A256GCM"}
	}

	return meta
}

// GenerateWalletNonce provides replay protection through wallet_nonce (OID4VP 1.0 §5.10).
func GenerateWalletNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating wallet nonce: %w", err)
	}
	return format.EncodeBase64URL(b), nil
}

// MakeFetchRequestURI includes wallet_metadata and wallet_nonce in POST requests. An empty
// method uses GET. Encrypted responses are decrypted when the wallet has an encryption
// key.
func MakeFetchRequestURI(w *Wallet, logFn func(string, ...any)) func(url, method, clientID string) (string, error) {
	return func(requestURI, method, clientID string) (string, error) {
		if method == "post" {
			return fetchRequestURIPOST(w, requestURI, clientID, logFn)
		}
		return fetchRequestURIGET(w, requestURI)
	}
}

func fetchRequestURIGET(w *Wallet, requestURI string) (string, error) {
	logRequestObjectFetchRequest(w, "GET", requestURI, nil)
	resp, err := w.HTTPClient().Get(requestURI)
	if err != nil {
		logRequestObjectFetchResponse(w, "GET", requestURI, nil, err)
		return "", fmt.Errorf("fetching %s: %w", requestURI, err)
	}
	defer resp.Body.Close()

	body, readErr := format.ReadRemoteBody(resp.Body, "request object")
	details := map[string]any{
		"content_type": resp.Header.Get("Content-Type"),
	}
	if readErr == nil {
		addStringDetail(details, "response_body", strings.TrimSpace(string(body)))
	}
	logRequestObjectFetchResponse(w, "GET", requestURI, responseLogResult(resp.StatusCode, details), readErr)
	if readErr != nil {
		return "", fmt.Errorf("reading response from %s: %w", requestURI, readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching %s: HTTP %d", requestURI, resp.StatusCode)
	}
	if err := w.judgeRequestURIMediaType(resp.Header.Get("Content-Type")); err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// Strict mode rejects an incorrect media type. Debug mode warns and reads the Request
// Object.
func (w *Wallet) judgeRequestURIMediaType(contentType string) error {
	err := validateRequestURIResponse(contentType)
	if err == nil {
		return nil
	}
	if w != nil && w.Mode() == ValidationModeStrict {
		return err
	}
	if w != nil {
		w.AddWarning("presentation", err.Error(), nil)
	}
	return nil
}

func fetchRequestURIPOST(w *Wallet, requestURI, clientID string, logFn func(string, ...any)) (string, error) {
	walletMeta := BuildWalletMetadata(w, clientID)
	walletMetaJSON, err := json.Marshal(walletMeta)
	if err != nil {
		return "", fmt.Errorf("marshaling wallet_metadata: %w", err)
	}

	walletNonce, err := GenerateWalletNonce()
	if err != nil {
		return "", err
	}

	if logFn != nil {
		logFn("  request_uri_method: post")
		logFn("  wallet_nonce:       %s", walletNonce)
		if w.RequireEncryptedRequest {
			logFn("  wallet_metadata:    sends encryption keys (encrypted request object required)")
		} else {
			logFn("  wallet_metadata:    sends encryption keys")
		}
	}

	form := url.Values{}
	form.Set("wallet_metadata", string(walletMetaJSON))
	form.Set("wallet_nonce", walletNonce)

	logRequestObjectFetchRequest(w, "POST", requestURI, map[string]any{
		"wallet_metadata": walletMeta,
		"wallet_nonce":    walletNonce,
	}, &LogPayload{Label: "Request", Body: form.Encode()})

	req, err := http.NewRequest("POST", requestURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/oauth-authz-req+jwt")

	resp, err := w.HTTPClient().Do(req)
	if err != nil {
		logRequestObjectFetchResponse(w, "POST", requestURI, nil, err)
		return "", fmt.Errorf("POSTing to request_uri: %w", err)
	}
	defer resp.Body.Close()

	body, err := format.ReadRemoteBody(resp.Body, "request object")
	if err != nil {
		logRequestObjectFetchResponse(w, "POST", requestURI, responseLogResult(resp.StatusCode, map[string]any{
			"content_type": resp.Header.Get("Content-Type"),
		}), err)
		return "", fmt.Errorf("reading request_uri response: %w", err)
	}
	result := strings.TrimSpace(string(body))
	logRequestObjectFetchResponse(w, "POST", requestURI, responseLogResult(resp.StatusCode, map[string]any{
		"content_type":  resp.Header.Get("Content-Type"),
		"response_body": result,
	}), nil)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("POST to request_uri returned HTTP %d", resp.StatusCode)
	}
	if err := w.judgeRequestURIMediaType(resp.Header.Get("Content-Type")); err != nil {
		return "", err
	}

	if !isJWT(result) && !isJWE(result) {
		return "", fmt.Errorf("request_uri response must be a compact JWT or JWE")
	}
	if w.RequireEncryptedRequest && !isJWE(result) {
		return "", fmt.Errorf("request_uri response must be a compact JWE when encrypted request objects are required")
	}

	if isJWE(result) {
		if w.RequestEncryptionKey == nil {
			return "", fmt.Errorf("received encrypted request object (JWE) but wallet has no decryption key")
		}
		if logFn != nil {
			logFn("  Request object is encrypted (JWE), decrypting...")
		}
		decrypted, err := DecryptRequestObjectJWE(result, w.RequestEncryptionKey)
		if err != nil {
			return "", fmt.Errorf("decrypting request object JWE: %w", err)
		}
		result = decrypted
	}
	if !isJWT(result) {
		return "", fmt.Errorf("request_uri response did not resolve to a compact JWT")
	}

	// wallet_nonce is optional in the returned request object. If the verifier
	// echoes it back, it must match the value sent in the POST body. The
	// returned request object may be signed or unsecured.
	if header, payload, _, err := format.ParseJWTParts(result); err == nil {
		if returnedNonce, ok := payload["wallet_nonce"].(string); ok {
			if returnedNonce != walletNonce {
				return "", fmt.Errorf("wallet_nonce mismatch in request object: expected %s, got %s", walletNonce, returnedNonce)
			}
			if logFn != nil {
				logFn("  wallet_nonce validated in request object")
			}
		} else if logFn != nil {
			if alg, _ := header["alg"].(string); alg != "" {
				logFn("  request object alg:      %s", alg)
			}
			logFn("  request object did not include wallet_nonce")
		}
	}

	return result, nil
}

func logRequestObjectFetchRequest(w *Wallet, method, requestURI string, details map[string]any, payloads ...*LogPayload) {
	if w == nil {
		return
	}
	if details == nil {
		details = map[string]any{}
	}
	details["direction"] = "outbound"
	details["method"] = method
	details["url"] = requestURI
	w.addProtocolLog("presentation", "request_object_fetch_request", fmt.Sprintf("Fetch request object %s %s", method, requestURI), true, details, firstLogPayload(payloads))
}

func logRequestObjectFetchResponse(w *Wallet, method, requestURI string, result map[string]any, err error) {
	if w == nil {
		return
	}
	details := map[string]any{
		"direction": "inbound",
		"method":    method,
		"url":       requestURI,
	}
	for key, value := range result {
		details[key] = value
	}
	if err != nil {
		details["error"] = err.Error()
	}
	success := err == nil
	if statusCode, ok := details["status_code"].(int); ok && (statusCode < 200 || statusCode >= 300) {
		success = false
	}
	var payload *LogPayload
	if body, ok := details["response_body"].(string); ok {
		payload = &LogPayload{Label: "Response", Body: body}
		if isJWE(body) {
			payload.Encrypted, payload.Wire, payload.Body = true, body, nil
			if plain, decryptErr := DecryptRequestObjectJWE(body, w.RequestEncryptionKey); decryptErr == nil {
				payload.Body = plain
			}
		}
	}
	w.addProtocolLog("presentation", "request_object_fetch_response", fmt.Sprintf("Request object fetch response %s %s", method, requestURI), success, details, payload)
}

func responseLogResult(statusCode int, details map[string]any) map[string]any {
	if details == nil {
		details = map[string]any{}
	}
	details["status_code"] = statusCode
	return details
}

// validateRequestURIResponse checks the media type required by OID4VP 1.0 §5.10.1.
func validateRequestURIResponse(contentType string) error {
	if contentType == "" {
		return fmt.Errorf("OID4VP 1.0 §5.10.1: the request_uri response is missing the Content-Type application/oauth-authz-req+jwt")
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return fmt.Errorf("OID4VP 1.0 §5.10.1: the request_uri response Content-Type does not parse: %w", err)
	}
	if mediaType != "application/oauth-authz-req+jwt" {
		return fmt.Errorf("OID4VP 1.0 §5.10.1: the request_uri response Content-Type must be application/oauth-authz-req+jwt, got %q", contentType)
	}
	return nil
}

func isJWT(s string) bool {
	parts := strings.SplitN(s, ".", 4)
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0
}

func isJWE(s string) bool {
	parts := strings.Split(s, ".")
	return len(parts) == 5 && len(parts[0]) > 0
}

func DecryptCompactJWE(compact string, key *ecdsa.PrivateKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("decryption requires a private key")
	}
	ecdhKey, err := key.ECDH()
	if err != nil {
		return "", fmt.Errorf("converting private key to ECDH: %w", err)
	}
	plaintext, err := jwe.Decrypt(compact, ecdhKey)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(plaintext)), nil
}

func DecryptRequestObjectJWE(jwe string, key *ecdsa.PrivateKey) (string, error) {
	return DecryptCompactJWE(jwe, key)
}
