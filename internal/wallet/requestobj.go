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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jwe"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

// BuildWalletMetadata advertises signing algorithms only when the client identifier prefix
// permits signed requests (OID4VP 1.0 §5.10).
func BuildWalletMetadata(w *Wallet, clientID string) map[string]any {
	meta := map[string]any{
		// Appendix B defines different algorithm fields for each format. SD-JWT fields
		// use JOSE names. The mso_mdoc fields use COSE identifiers, such as -7 for
		// ECDSA with SHA-256.
		"vp_formats_supported": map[string]any{
			credtype.FormatSDJWT: map[string]any{
				"sd-jwt_alg_values": []string{jws.AlgES256},
				"kb-jwt_alg_values": []string{jws.AlgES256},
			},
			credtype.FormatMDOC: map[string]any{
				"issuerauth_alg_values": []int{-7},
				"deviceauth_alg_values": []int{-7},
			},
		},
		// OID4VP 1.0 §10.1 defaults to pre-registered when this field is absent.
		// Listing the prefixes allows x509_hash.
		"client_id_prefixes_supported": oid4vp.AdvertisedClientIDPrefixes(),
		// OID4VP 1.0 §10 uses RFC 8414 metadata. RFC 8414 requires
		// response_types_supported. OpenID4VP returns vp_token (§5.6).
		"response_types_supported": []string{"vp_token"},
		// RFC 8414 defaults to query and fragment, so the wallet lists every
		// response mode it answers.
		"response_modes_supported": []string{"direct_post", "direct_post.jwt", "dc_api", "dc_api.jwt", "fragment"},
		// OID4VP 1.0 §5.10 advertises response encryption for direct_post.jwt and
		// dc_api.jwt. ECDH-ES with P-256 is the baseline. HAIP requires both A128GCM
		// and A256GCM.
		"authorization_encryption_alg_values_supported": []string{jwe.AlgECDHES},
		"authorization_encryption_enc_values_supported": []string{jwe.EncA128GCM, jwe.EncA256GCM},
	}

	// OID4VP 1.0 §5.10: "the Wallet MUST NOT include this parameter if the Client
	// Identifier Prefix precludes signed Request Objects". The redirect_uri prefix
	// does (§5.9.3).
	if !oid4vp.PrecludesSignedRequestObject(clientID) {
		meta["request_object_signing_alg_values_supported"] = []string{jws.AlgES256}
	}

	// The wallet advertises its encryption key even when encrypted Request
	// Objects are optional.
	if w.RequestEncryptionKey == nil {
		return meta
	}
	jwk, err := keys.PublicJWK(&w.RequestEncryptionKey.PublicKey)
	if err != nil {
		return meta
	}
	jwk["use"] = "enc"
	jwk["alg"] = jwe.AlgECDHES
	// OID4VP 1.0 §5.10 puts request encryption keys in jwks. The
	// request_object_encryption_* fields follow OpenID Connect Discovery, with the
	// wallet acting as the server.
	meta["jwks"] = map[string]any{"keys": []any{jwk}}
	meta["request_object_encryption_alg_values_supported"] = []string{jwe.AlgECDHES}
	meta["request_object_encryption_enc_values_supported"] = []string{jwe.EncA128GCM, jwe.EncA256GCM}
	return meta
}

// MakeFetchRequestURI includes wallet_metadata and wallet_nonce in POST requests. An empty
// method uses GET. Encrypted responses are decrypted when the wallet has an encryption
// key.
func MakeFetchRequestURI(w *Wallet, logFn func(string, ...any)) func(url, method, clientID string) (string, error) {
	return func(requestURI, method, clientID string) (string, error) {
		var fetched *fetchedRequestObject
		var err error
		if method == "post" {
			fetched, err = fetchRequestURIPOST(w, requestURI, clientID, logFn)
		} else {
			fetched, err = fetchRequestURIGET(w, requestURI)
		}
		if err != nil {
			return "", err
		}
		return w.resolveFetchedRequestObject(fetched, logFn)
	}
}

// fetchedRequestObject is a request_uri response before the wallet checks it.
// walletNonce is the wallet_nonce sent by the wallet, empty for GET.
type fetchedRequestObject struct {
	method      string
	contentType string
	body        string
	walletNonce string
}

func fetchRequestURIGET(w *Wallet, requestURI string) (*fetchedRequestObject, error) {
	logRequestObjectFetchRequest(w, "GET", requestURI, nil)
	resp, err := w.HTTPClient().Get(requestURI)
	if err != nil {
		logRequestObjectFetchResponse(w, "GET", requestURI, nil, err)
		return nil, fmt.Errorf("fetching %s: %w", requestURI, err)
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
		return nil, fmt.Errorf("reading response from %s: %w", requestURI, readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: HTTP %d", requestURI, resp.StatusCode)
	}
	return &fetchedRequestObject{method: "get", contentType: resp.Header.Get("Content-Type"), body: strings.TrimSpace(string(body))}, nil
}

func fetchRequestURIPOST(w *Wallet, requestURI, clientID string, logFn func(string, ...any)) (*fetchedRequestObject, error) {
	walletMeta := BuildWalletMetadata(w, clientID)
	walletMetaJSON, err := json.Marshal(walletMeta)
	if err != nil {
		return nil, fmt.Errorf("marshaling wallet_metadata: %w", err)
	}

	walletNonce, err := oid4vp.GenerateWalletNonce()
	if err != nil {
		return nil, err
	}

	if logFn != nil {
		logFn("  request_uri_method: post")
		logFn("  wallet_nonce:       %s", walletNonce)
		if w.Conformance().RequireEncryptedRequest {
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
	}, &LogPayload{Label: "Request", Body: map[string]any{
		"wallet_metadata": walletMeta,
		"wallet_nonce":    walletNonce,
	}, Wire: form.Encode()})

	req, err := http.NewRequest("POST", requestURI, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", format.MediaTypeRequestObject)

	resp, err := w.HTTPClient().Do(req)
	if err != nil {
		logRequestObjectFetchResponse(w, "POST", requestURI, nil, err)
		return nil, fmt.Errorf("POSTing to request_uri: %w", err)
	}
	defer resp.Body.Close()

	body, err := format.ReadRemoteBody(resp.Body, "request object")
	if err != nil {
		logRequestObjectFetchResponse(w, "POST", requestURI, responseLogResult(resp.StatusCode, map[string]any{
			"content_type": resp.Header.Get("Content-Type"),
		}), err)
		return nil, fmt.Errorf("reading request_uri response: %w", err)
	}
	result := strings.TrimSpace(string(body))
	logRequestObjectFetchResponse(w, "POST", requestURI, responseLogResult(resp.StatusCode, map[string]any{
		"content_type":  resp.Header.Get("Content-Type"),
		"response_body": result,
	}), nil)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST to request_uri returned HTTP %d", resp.StatusCode)
	}
	return &fetchedRequestObject{method: "post", contentType: resp.Header.Get("Content-Type"), body: result, walletNonce: walletNonce}, nil
}

// resolveFetchedRequestObject checks a request_uri response the same way for
// both methods and returns the compact Request Object JWT.
func (w *Wallet) resolveFetchedRequestObject(fetched *fetchedRequestObject, logFn func(string, ...any)) (string, error) {
	if err := w.judgeRequestURIMediaType(fetched.method, fetched.contentType); err != nil {
		return "", err
	}

	result := fetched.body
	if !format.IsJWT(result) && !format.IsJWE(result) {
		return "", fmt.Errorf("request_uri response must be a compact JWT or JWE")
	}
	if w.Conformance().RequireEncryptedRequest && !format.IsJWE(result) {
		return "", fmt.Errorf("request_uri response must be a compact JWE when encrypted request objects are required")
	}

	if format.IsJWE(result) {
		if w.RequestEncryptionKey == nil {
			return "", fmt.Errorf("received encrypted request object (JWE) but wallet has no decryption key")
		}
		if logFn != nil {
			logFn("  Request object is encrypted (JWE), decrypting...")
		}
		decrypted, err := oid4vp.DecryptRequestObjectJWE(result, w.RequestEncryptionKey)
		if err != nil {
			return "", fmt.Errorf("decrypting request object JWE: %w", err)
		}
		result = decrypted
	}
	if !format.IsJWT(result) {
		return "", fmt.Errorf("request_uri response did not resolve to a compact JWT")
	}

	if fetched.walletNonce != "" {
		if err := w.checkWalletNonce(result, fetched.walletNonce); err != nil {
			return "", err
		}
	}
	return result, nil
}

// judgeRequestURIMediaType refuses a POST response of another media type in
// strict mode, because OID4VP 1.0 §5.10.1 requires one. RFC 9101 only advises
// the check for GET (§10.4.1), so a GET response gets a warning.
func (w *Wallet) judgeRequestURIMediaType(method, contentType string) error {
	err := oid4vp.ValidateRequestURIResponse(method, contentType)
	if err == nil {
		return nil
	}
	if method != "post" {
		w.AddWarning("presentation", err.Error(), nil)
		return nil
	}
	return w.reportDeviation(deviation{action: "presentation", event: "request_uri_media_type", detail: err.Error(), refusal: err})
}

// checkWalletNonce applies OID4VP 1.0 §5.10.1: "if the Wallet passed a
// wallet_nonce in the POST request, the Wallet MUST validate whether the
// request object contains the respective nonce value in a wallet_nonce claim.
// If it does not, the Wallet MUST terminate request processing."
func (w *Wallet) checkWalletNonce(requestObject, sent string) error {
	_, payload, _, err := format.ParseJWTParts(requestObject)
	if err != nil {
		return fmt.Errorf("parsing the request object: %w", err)
	}
	returned, present := payload["wallet_nonce"].(string)
	if present && returned == sent {
		return nil
	}
	detail := fmt.Sprintf("OID4VP 1.0 §5.10.1: the request object does not contain the wallet_nonce %s sent by the wallet", sent)
	if present {
		detail = fmt.Sprintf("OID4VP 1.0 §5.10.1: wallet_nonce mismatch in request object: expected %s, got %s", sent, returned)
	}
	return w.reportDeviation(deviation{
		action: "presentation", event: "wallet_nonce_mismatch", detail: detail,
		details: map[string]any{"wallet_nonce": sent, "returned_wallet_nonce": returned},
	})
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
		if format.IsJWE(body) {
			payload.Encrypted, payload.Wire, payload.Body = true, body, nil
			if plain, decryptErr := oid4vp.DecryptRequestObjectJWE(body, w.RequestEncryptionKey); decryptErr == nil {
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
