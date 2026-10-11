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

package proxy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/web"
)

func Classify(entry *TrafficEntry) {
	entry.Class = classifyEntry(entry)
	entry.ClassLabel = entry.Class.Label()
	entry.Decoded = decodeEntry(entry)
	entry.Credentials, entry.CredentialLabels = extractCredentials(entry)
}

// StatefulClassifier learns advertised protocol endpoints from earlier traffic.
// It classifies later requests to dynamic paths with them.
type StatefulClassifier struct {
	mu        sync.Mutex
	endpoints map[string]TrafficClass
}

func NewStatefulClassifier() *StatefulClassifier {
	return &StatefulClassifier{
		endpoints: make(map[string]TrafficClass),
	}
}

func (c *StatefulClassifier) Classify(entry *TrafficEntry) {
	class := classifyEntry(entry)
	if class == ClassUnknown {
		c.mu.Lock()
		learned, ok := c.endpoints[endpointKeyFromRawURL(entry.URL)]
		c.mu.Unlock()
		if ok {
			class = learned
		}
	}

	entry.Class = class
	entry.ClassLabel = entry.Class.Label()
	entry.Decoded = decodeEntry(entry)
	entry.Credentials, entry.CredentialLabels = extractCredentials(entry)

	c.mu.Lock()
	c.learn(entry)
	c.mu.Unlock()
}

func classifyEntry(e *TrafficEntry) TrafficClass {
	u, _ := url.Parse(e.URL)
	path := ""
	query := url.Values{}
	if u != nil {
		path = u.Path
		query = oid4vc.URIQueryValues(u)
	}

	if strings.Contains(path, ".well-known/openid-credential-issuer") {
		return ClassVCIMetadata
	}

	if strings.Contains(path, ".well-known/openid-configuration") {
		return ClassOIDCMetadata
	}

	if query.Has("credential_offer") || query.Has("credential_offer_uri") {
		return ClassVCICredentialOffer
	}

	if isVPAuthRequest(query) {
		return ClassVPAuthRequest
	}

	if isOIDCAuthRequest(query) {
		return ClassOIDCAuthRequest
	}

	if isOIDCCallback(e.Method, query, e.RequestBody) {
		return ClassOIDCCallback
	}

	if e.Method == "GET" && isJWTBody(e.ResponseBody) {
		return ClassVPRequestObject
	}
	// With request_uri_method=post (OID4VP 1.0 §5.10) the wallet sends
	// wallet_metadata or wallet_nonce. The verifier answers with a JWT or JWE.
	if e.Method == "POST" && (hasBodyField(e.RequestBody, "wallet_metadata") || hasBodyField(e.RequestBody, "wallet_nonce")) {
		return ClassVPRequestObject
	}

	if e.Method == "POST" {
		if isVCINonceRequest(path, e.ResponseBody) {
			return ClassVCINonceRequest
		}

		if hasBodyField(e.RequestBody, "vp_token") ||
			hasBodyField(e.RequestBody, "presentation_submission") ||
			hasBodyField(e.RequestBody, "id_token") ||
			hasBodyField(e.RequestBody, "response") {
			return ClassVPAuthResponse
		}

		// OIDC token endpoints take precedence over the generic /token match.
		if isOIDCTokenRequest(path, e.RequestBody, e.ResponseBody) {
			return ClassOIDCTokenRequest
		}

		if strings.HasSuffix(path, "/token") {
			return ClassVCITokenRequest
		}

		if strings.HasSuffix(path, "/credential") || strings.HasSuffix(path, "/credentials") {
			return ClassVCICredentialRequest
		}
	}

	return ClassUnknown
}

func decodeEntry(e *TrafficEntry) map[string]any {
	decoded := make(map[string]any)

	switch e.Class {
	case ClassVPAuthRequest:
		u, _ := url.Parse(e.URL)
		if u != nil {
			q := oid4vc.URIQueryValues(u)
			decoded["client_id"] = q.Get("client_id")
			decoded["response_type"] = q.Get("response_type")
			if v := q.Get("response_mode"); v != "" {
				decoded["response_mode"] = v
			}
			if v := q.Get("nonce"); v != "" {
				decoded["nonce"] = v
			}
			if v := q.Get("state"); v != "" {
				decoded["state"] = v
			}
			if v := q.Get("request_uri"); v != "" {
				decoded["request_uri"] = v
			}
			if v := q.Get("response_uri"); v != "" {
				decoded["response_uri"] = v
			}
			if v := q.Get("request_uri_method"); v != "" {
				decoded["request_uri_method"] = v
			}
			if v := q.Get("redirect_uri"); v != "" {
				decoded["redirect_uri"] = v
			}
			if v := q.Get("dcql_query"); v != "" {
				var m map[string]any
				if err := json.Unmarshal([]byte(v), &m); err == nil {
					decoded["dcql_query"] = m
				} else {
					decoded["dcql_query"] = v
				}
			}
			if v := q.Get("presentation_definition"); v != "" {
				var m map[string]any
				if err := json.Unmarshal([]byte(v), &m); err == nil {
					decoded["presentation_definition"] = m
				} else {
					decoded["presentation_definition"] = v
				}
			}
		}

	case ClassVPRequestObject:
		responseBody := strings.TrimSpace(e.ResponseBody)
		if isJWTBody(responseBody) {
			if header, payload, _, err := format.ParseJWTParts(responseBody); err == nil {
				decoded["header"] = header
				decoded["payload"] = payload
				if jwks, ok := payload["jwks"].(map[string]any); ok {
					decoded["encryption_jwks"] = jwks
				}
				if wn, ok := payload["wallet_nonce"].(string); ok {
					decoded["wallet_nonce_in_response"] = wn
				}
			}
		} else if isJWE(responseBody) {
			headerBytes, err := format.DecodeBase64URL(strings.SplitN(responseBody, ".", 2)[0])
			if err == nil {
				var header map[string]any
				if err := json.Unmarshal(headerBytes, &header); err == nil {
					decoded["header"] = header
					decoded["encrypted"] = true
					if alg, ok := header["alg"].(string); ok {
						decoded["encryption_alg"] = alg
					}
					if enc, ok := header["enc"].(string); ok {
						decoded["encryption_enc"] = enc
					}
				}
			}
		}
		if e.RequestBody != "" {
			fields := parseFormOrJSON(e.RequestBody)
			if wm, ok := fields["wallet_metadata"]; ok && wm != "" {
				var wmObj map[string]any
				if err := json.Unmarshal([]byte(wm), &wmObj); err == nil {
					decoded["wallet_metadata"] = wmObj
				} else {
					decoded["wallet_metadata"] = wm
				}
			}
			if wn, ok := fields["wallet_nonce"]; ok && wn != "" {
				decoded["wallet_nonce"] = wn
			}
		}

	case ClassVPAuthResponse:
		fields := parseFormOrJSON(e.RequestBody)

		// direct_post.jwt carries the encrypted or signed response in the "response" field.
		if jarm, ok := fields["response"]; ok && jarm != "" {
			decoded["response_preview"] = format.Truncate(jarm, 100)
			decodeJARMResponse(jarm, e.DebugJWEKey, e.DebugJWK, decoded)
		}

		if vpToken, ok := fields["vp_token"]; ok {
			decoded["vp_token_preview"] = format.Truncate(vpToken, 100)
			if cred, err := web.Decode(vpToken); err == nil {
				decoded["vp_token_decoded"] = cred
			}
		}
		if idToken, ok := fields["id_token"]; ok {
			decoded["id_token_preview"] = format.Truncate(idToken, 100)
			if header, payload, _, err := format.ParseJWTParts(idToken); err == nil {
				decoded["id_token_header"] = header
				decoded["id_token_payload"] = payload
			}
		}
		if v, ok := fields["state"]; ok {
			decoded["state"] = v
		}
		if v, ok := fields["presentation_submission"]; ok {
			var ps map[string]any
			if err := json.Unmarshal([]byte(v), &ps); err == nil {
				decoded["presentation_submission"] = ps
			}
		}

	case ClassVCICredentialOffer:
		u, _ := url.Parse(e.URL)
		if u != nil {
			if offer := oid4vc.URIQueryValues(u).Get("credential_offer"); offer != "" {
				var m map[string]any
				if err := json.Unmarshal([]byte(offer), &m); err == nil {
					decoded["credential_offer"] = m
				}
			}
			if uri := oid4vc.URIQueryValues(u).Get("credential_offer_uri"); uri != "" {
				decoded["credential_offer_uri"] = uri
			}
		}

	case ClassVCIMetadata:
		if e.ResponseBody != "" {
			var m map[string]any
			if err := json.Unmarshal([]byte(e.ResponseBody), &m); err == nil {
				decoded["metadata"] = m
			}
		}

	case ClassVCITokenRequest:
		fields := parseFormOrJSON(e.RequestBody)
		for k, v := range fields {
			decoded[k] = v
		}
		if e.ResponseBody != "" {
			var resp map[string]any
			if err := json.Unmarshal([]byte(e.ResponseBody), &resp); err == nil {
				decoded["response"] = resp
			}
		}

	case ClassVCINonceRequest:
		if e.ResponseBody != "" {
			var resp map[string]any
			if err := json.Unmarshal([]byte(e.ResponseBody), &resp); err == nil {
				decoded["response"] = resp
				if nonce, ok := resp["c_nonce"]; ok {
					decoded["c_nonce"] = nonce
				}
			}
		}

	case ClassVCICredentialRequest:
		if e.RequestBody != "" {
			var reqBody map[string]any
			if err := json.Unmarshal([]byte(e.RequestBody), &reqBody); err == nil {
				decoded["request"] = reqBody
			}
		}
		if e.ResponseBody != "" {
			var resp map[string]any
			if err := json.Unmarshal([]byte(e.ResponseBody), &resp); err == nil {
				decoded["response"] = resp
				if cred, ok := resp["credential"].(string); ok {
					if credDecoded, err := web.Decode(cred); err == nil {
						decoded["credential_decoded"] = credDecoded
					}
				}
			}
		}

	case ClassOIDCMetadata:
		if e.ResponseBody != "" {
			var m map[string]any
			if err := json.Unmarshal([]byte(e.ResponseBody), &m); err == nil {
				decoded["metadata"] = m
			}
		}

	case ClassOIDCAuthRequest:
		u, _ := url.Parse(e.URL)
		if u != nil {
			q := oid4vc.URIQueryValues(u)
			decoded["client_id"] = q.Get("client_id")
			decoded["response_type"] = q.Get("response_type")
			if v := q.Get("scope"); v != "" {
				decoded["scope"] = v
			}
			if v := q.Get("redirect_uri"); v != "" {
				decoded["redirect_uri"] = v
			}
			if v := q.Get("state"); v != "" {
				decoded["state"] = v
			}
			if v := q.Get("nonce"); v != "" {
				decoded["nonce"] = v
			}
		}

	case ClassOIDCTokenRequest:
		fields := parseFormOrJSON(e.RequestBody)
		for k, v := range fields {
			decoded[k] = v
		}
		if e.ResponseBody != "" {
			var resp map[string]any
			if err := json.Unmarshal([]byte(e.ResponseBody), &resp); err == nil {
				decoded["response"] = resp
			}
		}

	case ClassOIDCCallback:
		u, _ := url.Parse(e.URL)
		if u != nil {
			q := oid4vc.URIQueryValues(u)
			if v := q.Get("code"); v != "" {
				decoded["code"] = v
			}
			if v := q.Get("state"); v != "" {
				decoded["state"] = v
			}
			if v := q.Get("error"); v != "" {
				decoded["error"] = v
			}
		}
	}

	if len(decoded) == 0 {
		return nil
	}
	return decoded
}

func isJWTBody(body string) bool {
	body = strings.TrimSpace(body)
	parts := strings.SplitN(body, ".", 4)
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0 && !strings.ContainsAny(body, " \n\t{<")
}

func isJWE(s string) bool {
	return format.IsJWE(strings.TrimSpace(s))
}

// decodeJARMResponse decodes a JARM response (direct_post.jwt). For a JWE only the
// protected header is readable without a debug CEK or a private JWK. For a JWS the
// header and payload are readable.
func decodeJARMResponse(raw string, cekB64 string, jwkJSON string, decoded map[string]any) {
	raw = strings.TrimSpace(raw)

	if isJWE(raw) {
		headerBytes, err := format.DecodeBase64URL(strings.SplitN(raw, ".", 2)[0])
		if err != nil {
			return
		}
		var header map[string]any
		if err := json.Unmarshal(headerBytes, &header); err != nil {
			return
		}
		decoded["response_header"] = header

		if alg, ok := header["alg"].(string); ok {
			decoded["encryption_alg"] = alg
		}
		if enc, ok := header["enc"].(string); ok {
			decoded["encryption_enc"] = enc
		}
		if kid, ok := header["kid"].(string); ok {
			decoded["encryption_kid"] = kid
		}
		if epk, ok := header["epk"].(map[string]any); ok {
			decoded["encryption_epk"] = epk
		}
		if apu, ok := header["apu"].(string); ok {
			decoded["encryption_apu"] = apu
		}
		if apv, ok := header["apv"].(string); ok {
			decoded["encryption_apv"] = apv
		}

		if cekB64 != "" {
			cek, err := format.DecodeBase64URL(cekB64)
			if err == nil {
				if plaintext, err := DecryptJWEWithCEK(raw, cek); err == nil {
					var payload map[string]any
					if err := json.Unmarshal(plaintext, &payload); err == nil {
						decoded["response_type"] = "JWE (decrypted via debug key)"
						decoded["response_payload"] = payload
						return
					}
				}
			}
		}

		if jwkJSON != "" {
			if plaintext, err := DecryptJWEWithJWK(raw, jwkJSON); err == nil {
				var payload map[string]any
				if err := json.Unmarshal(plaintext, &payload); err == nil {
					decoded["response_type"] = "JWE (decrypted via scanned verifier key)"
					decoded["response_payload"] = payload
					return
				}
			}
		}

		decoded["response_type"] = "JWE (encrypted, payload not readable without the verifier's ephemeral private key)"
		return
	}

	if header, payload, _, err := format.ParseJWTParts(raw); err == nil {
		decoded["response_type"] = "JWS (signed)"
		decoded["response_header"] = header
		decoded["response_payload"] = payload
	}
}

func extractJARMCredentials(payload map[string]any) ([]string, []string) {
	var creds []string
	var labels []string

	// vp_token can be a string or a map from query_id to a string or a []string.
	if vpToken, ok := payload["vp_token"]; ok {
		switch vp := vpToken.(type) {
		case string:
			if vp != "" {
				creds = append(creds, vp)
				labels = append(labels, "vp_token (JARM)")
			}
		case map[string]any:
			for queryID, val := range vp {
				switch v := val.(type) {
				case string:
					if v != "" {
						creds = append(creds, v)
						labels = append(labels, fmt.Sprintf("vp_token.%s (JARM)", queryID))
					}
				case []any:
					for i, item := range v {
						if s, ok := item.(string); ok && s != "" {
							creds = append(creds, s)
							labels = append(labels, fmt.Sprintf("vp_token.%s[%d] (JARM)", queryID, i))
						}
					}
				}
			}
		}
	}

	if idToken, ok := payload["id_token"].(string); ok && idToken != "" {
		creds = append(creds, idToken)
		labels = append(labels, "id_token (JARM)")
	}

	return creds, labels
}

func containsResponseType(responseType string, targets ...string) bool {
	for _, part := range strings.Fields(responseType) {
		for _, t := range targets {
			if part == t {
				return true
			}
		}
	}
	return false
}

func containsScope(scope string, target string) bool {
	for _, part := range strings.Fields(scope) {
		if part == target {
			return true
		}
	}
	return false
}

func isVPAuthRequest(query url.Values) bool {
	if query.Get("client_id") == "" {
		return false
	}
	responseType := query.Get("response_type")
	if containsResponseType(responseType, "vp_token") {
		return true
	}
	if !containsResponseType(responseType, "id_token") {
		return false
	}
	return query.Get("response_uri") != "" ||
		query.Get("request_uri") != "" ||
		query.Get("request_uri_method") != "" ||
		query.Get("presentation_definition") != "" ||
		query.Get("dcql_query") != "" ||
		query.Get("client_metadata") != "" ||
		query.Get("client_metadata_uri") != ""
}

func isOIDCAuthRequest(query url.Values) bool {
	if query.Get("client_id") == "" || query.Get("redirect_uri") == "" {
		return false
	}
	responseType := query.Get("response_type")
	if !containsResponseType(responseType, "code", "token", "id_token") {
		return false
	}
	return containsScope(query.Get("scope"), "openid") || strings.Contains(query.Get("response_mode"), "form_post")
}

func isOIDCCallback(method string, query url.Values, body string) bool {
	if method == "GET" {
		return query.Get("code") != "" || query.Get("error") != ""
	}
	if method == "POST" {
		return (hasBodyField(body, "code") || hasBodyField(body, "error")) &&
			!hasBodyField(body, "grant_type")
	}
	return false
}

func isVCINonceRequest(path, responseBody string) bool {
	if !strings.HasSuffix(path, "/nonce") && !strings.Contains(path, "/protocol/oid4vc/nonce") {
		return false
	}
	return hasBodyField(responseBody, "c_nonce")
}

func isOIDCTokenRequest(path, requestBody, responseBody string) bool {
	if strings.Contains(path, "/protocol/openid-connect/token") {
		return true
	}
	if hasBodyField(responseBody, "id_token") {
		return true
	}
	fields := parseFormOrJSON(requestBody)
	return fields["grant_type"] == "authorization_code" && fields["redirect_uri"] != ""
}

func endpointKeyFromRawURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u == nil {
		return rawURL
	}
	return endpointKey(u)
}

func endpointKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + u.Path
}

func hasBodyField(body, field string) bool {
	if values, err := url.ParseQuery(body); err == nil && values.Has(field) {
		return true
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err == nil {
		if _, ok := m[field]; ok {
			return true
		}
	}
	return false
}

func parseFormOrJSON(body string) map[string]string {
	result := make(map[string]string)
	trimmed := strings.TrimSpace(body)

	// url.ParseQuery reads arbitrary JSON text as a single query key.
	if strings.HasPrefix(trimmed, "{") {
		var m map[string]any
		if err := json.Unmarshal([]byte(trimmed), &m); err == nil {
			for k, v := range m {
				switch val := v.(type) {
				case string:
					result[k] = val
				default:
					if b, err := json.Marshal(v); err == nil {
						result[k] = string(b)
					}
				}
			}
			return result
		}
	}

	values, err := url.ParseQuery(body)
	if err == nil && len(values) > 0 {
		for k := range values {
			result[k] = values.Get(k)
		}
		return result
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err == nil {
		for k, v := range m {
			switch val := v.(type) {
			case string:
				result[k] = val
			default:
				if b, err := json.Marshal(v); err == nil {
					result[k] = string(b)
				}
			}
		}
	}

	return result
}

func ExtractCorrelationKeys(entry *TrafficEntry) []string {
	u, _ := url.Parse(entry.URL)
	var keys []string

	switch entry.Class {
	case ClassVPAuthRequest:
		if u != nil {
			if v := oid4vc.URIQueryValues(u).Get("state"); v != "" {
				keys = append(keys, "vp:state:"+v)
			}
			if v := oid4vc.URIQueryValues(u).Get("nonce"); v != "" {
				keys = append(keys, "vp:nonce:"+v)
			}
			if v := oid4vc.URIQueryValues(u).Get("request_uri"); v != "" {
				keys = append(keys, "vp:request_uri:"+v)
			}
		}

	case ClassVPRequestObject:
		if u != nil && u.String() != "" {
			keys = append(keys, "vp:request_uri:"+u.String())
		}
		if entry.Decoded != nil {
			if payload, ok := entry.Decoded["payload"].(map[string]any); ok {
				if v, ok := payload["state"].(string); ok && v != "" {
					keys = append(keys, "vp:state:"+v)
				}
				if v, ok := payload["nonce"].(string); ok && v != "" {
					keys = append(keys, "vp:nonce:"+v)
				}
				if v, ok := payload["response_uri"].(string); ok && v != "" {
					keys = append(keys, "vp:response_uri:"+v)
				}
			}
		}

	case ClassVPAuthResponse:
		fields := parseFormOrJSON(entry.RequestBody)
		if v, ok := fields["state"]; ok && v != "" {
			keys = append(keys, "vp:state:"+v)
		}
		if entry.Decoded != nil {
			if payload, ok := entry.Decoded["response_payload"].(map[string]any); ok {
				if v, ok := payload["state"].(string); ok && v != "" {
					keys = append(keys, "vp:state:"+v)
				}
			}
		}
		if u != nil && u.String() != "" {
			keys = append(keys, "vp:response_uri:"+u.String())
		}

	case ClassVCITokenRequest:
		fields := parseFormOrJSON(entry.RequestBody)
		if v, ok := fields["pre-authorized_code"]; ok && v != "" {
			keys = append(keys, "vci:pre-authorized_code:"+v)
		}
		if v, ok := fields["code"]; ok && v != "" {
			keys = append(keys, "oauth:code:"+v)
		}
		if v, ok := fields["issuer_state"]; ok && v != "" {
			keys = append(keys, "vci:issuer_state:"+v)
		}
		if entry.Decoded != nil {
			appendVCITokenResponseKeys(&keys, entry.Decoded["response"])
		}

	case ClassVCINonceRequest:
		appendAuthorizationKey(&keys, entry.RequestHeaders.Get("Authorization"))

	case ClassVCICredentialRequest:
		appendAuthorizationKey(&keys, entry.RequestHeaders.Get("Authorization"))
		if entry.Decoded != nil {
			appendVCICredentialKeys(&keys, entry.Decoded["request"])
			appendVCICredentialKeys(&keys, entry.Decoded["response"])
		}

	case ClassOIDCAuthRequest:
		if u != nil {
			if v := oid4vc.URIQueryValues(u).Get("state"); v != "" {
				keys = append(keys, "oidc:state:"+v)
			}
			if v := oid4vc.URIQueryValues(u).Get("nonce"); v != "" {
				keys = append(keys, "oidc:nonce:"+v)
			}
			if v := oid4vc.URIQueryValues(u).Get("issuer_state"); v != "" {
				keys = append(keys, "vci:issuer_state:"+v)
			}
		}

	case ClassOIDCTokenRequest:
		fields := parseFormOrJSON(entry.RequestBody)
		if v, ok := fields["code"]; ok && v != "" {
			keys = append(keys, "oauth:code:"+v)
		}
		if v, ok := fields["issuer_state"]; ok && v != "" {
			keys = append(keys, "vci:issuer_state:"+v)
		}
		if entry.Decoded != nil {
			appendVCITokenResponseKeys(&keys, entry.Decoded["response"])
		}

	case ClassOIDCCallback:
		if u != nil {
			if v := oid4vc.URIQueryValues(u).Get("state"); v != "" {
				keys = append(keys, "oidc:state:"+v)
			}
			if v := oid4vc.URIQueryValues(u).Get("code"); v != "" {
				keys = append(keys, "oauth:code:"+v)
			}
		}

	case ClassVCICredentialOffer:
		if u != nil {
			if offer := oid4vc.URIQueryValues(u).Get("credential_offer"); offer != "" {
				appendVCIOfferKeys(&keys, offer)
			}
			if offerURI := oid4vc.URIQueryValues(u).Get("credential_offer_uri"); offerURI != "" {
				keys = append(keys, "vci:credential_offer_uri:"+offerURI)
			}
		}
	}

	return uniqueStrings(keys)
}

func appendAuthorizationKey(keys *[]string, auth string) {
	if auth == "" {
		return
	}
	token := normalizeAuthorizationToken(auth)
	if token == "" {
		return
	}
	*keys = append(*keys, "vci:access_token:"+token)
}

func appendVCIOfferKeys(keys *[]string, rawOffer string) {
	var m map[string]any
	if err := json.Unmarshal([]byte(rawOffer), &m); err != nil {
		return
	}
	if issuer, ok := m["credential_issuer"].(string); ok && issuer != "" {
		*keys = append(*keys, "vci:credential_issuer:"+issuer)
	}
	if grants, ok := m["grants"].(map[string]any); ok {
		if preAuth, ok := grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]any); ok {
			if code, ok := preAuth["pre-authorized_code"].(string); ok && code != "" {
				*keys = append(*keys, "vci:pre-authorized_code:"+code)
			}
			if issuerState, ok := preAuth["issuer_state"].(string); ok && issuerState != "" {
				*keys = append(*keys, "vci:issuer_state:"+issuerState)
			}
		}
		if authCode, ok := grants["authorization_code"].(map[string]any); ok {
			if issuerState, ok := authCode["issuer_state"].(string); ok && issuerState != "" {
				*keys = append(*keys, "vci:issuer_state:"+issuerState)
			}
		}
	}
}

func appendVCITokenResponseKeys(keys *[]string, raw any) {
	resp, ok := raw.(map[string]any)
	if !ok {
		return
	}
	if token, ok := resp["access_token"].(string); ok && token != "" {
		*keys = append(*keys, "vci:access_token:"+token)
	}
	appendVCICredentialKeys(keys, resp)
}

func appendVCICredentialKeys(keys *[]string, raw any) {
	body, ok := raw.(map[string]any)
	if !ok {
		return
	}
	if v, ok := body["credential_identifier"].(string); ok && v != "" {
		*keys = append(*keys, "vci:credential_identifier:"+v)
	}
	if v, ok := body["credential_configuration_id"].(string); ok && v != "" {
		*keys = append(*keys, "vci:credential_configuration_id:"+v)
	}
	if authDetails, ok := body["authorization_details"].([]any); ok {
		for _, item := range authDetails {
			obj, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if v, ok := obj["credential_configuration_id"].(string); ok && v != "" {
				*keys = append(*keys, "vci:credential_configuration_id:"+v)
			}
			if ids, ok := obj["credential_identifiers"].([]any); ok {
				for _, id := range ids {
					if s, ok := id.(string); ok && s != "" {
						*keys = append(*keys, "vci:credential_identifier:"+s)
					}
				}
			}
		}
	}
}

func normalizeAuthorizationToken(auth string) string {
	auth = strings.TrimSpace(auth)
	if auth == "" {
		return ""
	}
	parts := strings.Fields(auth)
	if len(parts) == 2 {
		return parts[1]
	}
	return auth
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// extractCredentials returns the raw credentials of the entry for the dashboard's
// "Open in decoder" links. It returns parallel slices of values and labels.
func extractCredentials(e *TrafficEntry) ([]string, []string) {
	var creds []string
	var labels []string

	switch e.Class {
	case ClassVPAuthResponse:
		fields := parseFormOrJSON(e.RequestBody)
		if vp, ok := fields["vp_token"]; ok && vp != "" {
			vpCreds, vpLabels := extractVPTokenCredentials(vp)
			creds = append(creds, vpCreds...)
			labels = append(labels, vpLabels...)
		}
		if id, ok := fields["id_token"]; ok && id != "" {
			creds = append(creds, id)
			labels = append(labels, "id_token")
		}
		if e.Decoded != nil {
			if payload, ok := e.Decoded["response_payload"].(map[string]any); ok {
				jarmCreds, jarmLabels := extractJARMCredentials(payload)
				creds = append(creds, jarmCreds...)
				labels = append(labels, jarmLabels...)
			}
		}

	case ClassVPRequestObject:
		body := strings.TrimSpace(e.ResponseBody)
		if isJWTBody(body) {
			creds = append(creds, body)
			labels = append(labels, "Request Object")
		}

	case ClassVCICredentialRequest:
		if e.ResponseBody != "" {
			var resp map[string]any
			if err := json.Unmarshal([]byte(e.ResponseBody), &resp); err == nil {
				if cred, ok := resp["credential"].(string); ok && cred != "" {
					creds = append(creds, cred)
					labels = append(labels, "credential")
				}
				if arr, ok := resp["credentials"].([]any); ok {
					for i, item := range arr {
						if obj, ok := item.(map[string]any); ok {
							if cred, ok := obj["credential"].(string); ok && cred != "" {
								creds = append(creds, cred)
								labels = append(labels, fmt.Sprintf("credential[%d]", i))
							}
						}
					}
				}
			}
		}

	case ClassVCITokenRequest:
		if e.ResponseBody != "" {
			var resp map[string]any
			if err := json.Unmarshal([]byte(e.ResponseBody), &resp); err == nil {
				for _, key := range []string{"access_token", "refresh_token", "id_token"} {
					if tok, ok := resp[key].(string); ok && tok != "" && isJWTBody(tok) {
						creds = append(creds, tok)
						labels = append(labels, key)
					}
				}
			}
		}

	case ClassOIDCTokenRequest:
		if e.ResponseBody != "" {
			var resp map[string]any
			if err := json.Unmarshal([]byte(e.ResponseBody), &resp); err == nil {
				for _, key := range []string{"id_token", "access_token", "refresh_token"} {
					if tok, ok := resp[key].(string); ok && tok != "" && isJWTBody(tok) {
						creds = append(creds, tok)
						labels = append(labels, key)
					}
				}
			}
		}
	}

	return creds, labels
}

// extractVPTokenCredentials reads vp_token values of direct_post responses.
// vp_token is a raw credential string or a JSON object keyed by query ID.
func extractVPTokenCredentials(vpToken string) ([]string, []string) {
	var payload any
	if err := json.Unmarshal([]byte(vpToken), &payload); err != nil {
		return []string{vpToken}, []string{"vp_token"}
	}

	// Some clients send vp_token as a JSON string that holds the DCQL query_id
	// to credential map.
	if s, ok := payload.(string); ok {
		trimmed := strings.TrimSpace(s)
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			return extractVPTokenCredentials(trimmed)
		}
	}

	var creds []string
	var labels []string

	switch v := payload.(type) {
	case string:
		if v != "" {
			creds = append(creds, v)
			labels = append(labels, "vp_token")
		}
	case map[string]any:
		for queryID, val := range v {
			switch item := val.(type) {
			case string:
				if item != "" {
					creds = append(creds, item)
					labels = append(labels, fmt.Sprintf("vp_token.%s", queryID))
				}
			case []any:
				for i, entry := range item {
					if s, ok := entry.(string); ok && s != "" {
						creds = append(creds, s)
						labels = append(labels, fmt.Sprintf("vp_token.%s[%d]", queryID, i))
					}
				}
			}
		}
	}

	if len(creds) == 0 {
		return []string{vpToken}, []string{"vp_token"}
	}

	return creds, labels
}

func (c *StatefulClassifier) learn(entry *TrafficEntry) {
	switch entry.Class {
	case ClassVPAuthRequest:
		if raw, ok := entry.Decoded["request_uri"].(string); ok && raw != "" {
			c.endpoints[endpointKeyFromRawURL(raw)] = ClassVPRequestObject
		}
		if raw, ok := entry.Decoded["response_uri"].(string); ok && raw != "" {
			c.endpoints[endpointKeyFromRawURL(raw)] = ClassVPAuthResponse
		}

	case ClassVPRequestObject:
		if payload, ok := entry.Decoded["payload"].(map[string]any); ok {
			if raw, ok := payload["response_uri"].(string); ok && raw != "" {
				c.endpoints[endpointKeyFromRawURL(raw)] = ClassVPAuthResponse
			}
		}

	case ClassVCIMetadata, ClassOIDCMetadata:
		metadata, ok := entry.Decoded["metadata"].(map[string]any)
		if !ok {
			return
		}

		learnEndpoint := func(field string, class TrafficClass) {
			raw, ok := metadata[field].(string)
			if !ok || raw == "" {
				return
			}
			c.endpoints[endpointKeyFromRawURL(raw)] = class
		}

		if entry.Class == ClassVCIMetadata {
			learnEndpoint("token_endpoint", ClassVCITokenRequest)
			learnEndpoint("credential_endpoint", ClassVCICredentialRequest)
			learnEndpoint("nonce_endpoint", ClassVCINonceRequest)
			return
		}

		learnEndpoint("authorization_endpoint", ClassOIDCAuthRequest)
		learnEndpoint("token_endpoint", ClassOIDCTokenRequest)

	case ClassOIDCAuthRequest:
		if raw, ok := entry.Decoded["redirect_uri"].(string); ok && raw != "" {
			c.endpoints[endpointKeyFromRawURL(raw)] = ClassOIDCCallback
		}
	}
}
