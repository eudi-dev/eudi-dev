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
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/jws"
	"github.com/eudi-dev/eudi-dev/v2/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
)

type PresentationParams struct {
	Nonce          string
	ClientID       string
	RequestOrigin  string
	ResponseURI    string
	RedirectURI    string // used for fragment response mode
	ResponseMode   string // e.g. "direct_post.jwt", "direct_post", "fragment"
	ClientMetadata map[string]any
	RequestObject  *oid4vc.RequestObjectJWT // optional, used to extract JWK thumbprint for mdoc
	// InteractiveAuthorizationEndpoint is the Authorization Challenge Endpoint
	// that the presentation is bound to (OpenID4VCI 1.1 §6.2.1.1). It is the
	// endpoint the wallet called. Other flows leave it empty.
	InteractiveAuthorizationEndpoint string
}

// isInteractiveAuthorizationResponseMode reports whether a response mode is
// one of the two defined in OpenID4VCI 1.1 §6.2.1.1. Both send the response to
// the Authorization Challenge Endpoint.
func isInteractiveAuthorizationResponseMode(mode string) bool {
	return mode == "ia_post" || mode == "ia_post.jwt"
}

type VPTokenResult struct {
	Token     string
	MDocNonce string // only set for ISO mode mdoc
}

func (w *Wallet) CreateVPToken(match CredentialMatch, params PresentationParams) (VPTokenResult, error) {
	return w.createVPToken(match, params, "")
}

// createVPToken builds one presentation. mdocNonce is the mdoc generated nonce
// shared by the whole response (ISO 18013-7). When it is empty, an mdoc
// presentation generates its own nonce.
func (w *Wallet) createVPToken(match CredentialMatch, params PresentationParams, mdocNonce string) (VPTokenResult, error) {
	cred, ok := w.GetCredential(match.CredentialID)
	if !ok {
		return VPTokenResult{}, fmt.Errorf("credential %s not found", match.CredentialID)
	}

	// Try renewal before presentation because headless CLI flows have no background
	// poller. If renewal fails, the stored credential may still be accepted.
	if cred.CanRenew() && CredentialNeedsRenewal(cred, time.Now()) {
		if renewed, err := w.RefreshCredential(cred.ID); err != nil {
			log.Printf("[VP] renewing %s before presenting it failed, sending the credential as it is: %v", cred.ID, err)
		} else {
			log.Printf("[VP] renewed %s before presenting it", cred.ID)
			cred = *renewed
		}
	}

	if err := w.checkPresentableKeyBinding(cred); err != nil {
		return VPTokenResult{}, err
	}

	// Use the batch copy's key when present, otherwise the wallet holder key.
	signingKey, err := w.batchSigningKey(cred)
	if err != nil {
		return VPTokenResult{}, err
	}

	typeLabel := cred.VCT
	if typeLabel == "" {
		typeLabel = cred.DocType
	}
	log.Printf("[VP] Creating VP token: format=%s type=%s claims=%v", cred.Format, typeLabel, match.SelectedKeys)

	// Group missing claims and empty disclosed arrays in one warning so the user can
	// see what the presentation omits.
	var undisclosed []string
	for _, claim := range match.EmptyArrayClaims {
		undisclosed = append(undisclosed, fmt.Sprintf("The request selects the array %s but none of its selectively disclosable elements, so it is disclosed as an empty array. The verifier selects the elements by ending the path with null (all) or an index (OpenID4VP 1.0 §7.1).", claim))
	}
	for _, claim := range match.MissingClaims {
		undisclosed = append(undisclosed, fmt.Sprintf("The request asks for %s, which the selected credential does not provide (a claim it does not carry, or an array index out of range), so it is not disclosed.", claim))
	}
	w.warnFindings("presentation", "The presentation does not disclose every requested claim as asked", undisclosed)

	switch cred.Format {
	case "dc+sd-jwt":
		audience := sdJWTAudience(params)
		token, err := w.createSDJWTPresentation(cred, match.SelectedKeys, params.Nonce, audience, signingKey)
		if err != nil {
			return VPTokenResult{}, err
		}
		log.Printf("[VP] SD-JWT presentation created: %d disclosures selected, aud=%s", len(match.SelectedKeys), audience)
		return VPTokenResult{Token: token}, nil
	case "jwt_vc_json":
		log.Printf("[VP] Plain JWT presentation (no selective disclosure)")
		return VPTokenResult{Token: cred.Raw}, nil
	case "mso_mdoc":
		result, err := w.createMDocPresentation(cred, match.SelectedKeys, params, mdocNonce, signingKey)
		if err != nil {
			return VPTokenResult{}, err
		}
		log.Printf("[VP] mdoc presentation created: docType=%s transcript=%s", cred.DocType, w.SessionTranscript)
		return result, nil
	default:
		return VPTokenResult{}, fmt.Errorf("unsupported credential format: %s", cred.Format)
	}
}

// checkPresentableKeyBinding reports a credential whose key binding the wallet
// cannot sign. RFC 9901 §4.3 requires the KB-JWT to be signed by the key in the
// credential's cnf. ISO 18013-5 §9.1.3 requires DeviceSigned to use the MSO's
// deviceKey. Strict mode stops before the nonce is used. Debug mode sends the
// presentation and the verifier's refusal is the finding ([ADR-0001]). A plain
// JWT VC has no key binding.
//
// [ADR-0001]: docs/adr/0001-debug-by-default-validation-with-opt-in-strict-mode.md
func (w *Wallet) checkPresentableKeyBinding(cred StoredCredential) error {
	if cred.Format != "dc+sd-jwt" && cred.Format != "mso_mdoc" {
		return nil
	}
	if !w.keyBindingNotHeld(&cred) {
		return nil
	}
	detail := fmt.Sprintf(
		"Credential %s is bound to a holder key this wallet does not hold, so the key binding signature of this presentation comes from the wrong key and the verifier refuses it.",
		credentialLabel(cred))
	details := map[string]any{
		"credential_id": cred.ID,
		"format":        cred.Format,
	}
	addStringDetail(details, "vct", cred.VCT)
	addStringDetail(details, "doctype", cred.DocType)
	if w.Mode() == ValidationModeStrict {
		w.addProtocolLog("presentation", "key_binding_cannot_be_signed", detail, false, details)
		return errors.New(detail)
	}
	w.addProtocolWarning("presentation", "key_binding_cannot_be_signed", detail, details)
	log.Printf("[VP] WARNING: %s", detail)
	return nil
}

func sdJWTAudience(params PresentationParams) string {
	if isInteractiveAuthorizationResponseMode(params.ResponseMode) && params.InteractiveAuthorizationEndpoint != "" {
		return interactiveAuthorizationAudience(params.InteractiveAuthorizationEndpoint)
	}
	if (params.ResponseMode == "dc_api" || params.ResponseMode == "dc_api.jwt") && params.RequestOrigin != "" {
		return "origin:" + params.RequestOrigin
	}
	return params.ClientID
}

// interactiveAuthorizationAudience binds a Key Binding JWT to the
// Authorization Challenge Endpoint (Appendix A.3.5).
//
// A.3.5 says "the derived Origin ... of the Authorization Challenge Endpoint".
// The wallet sends the endpoint itself. A.1.1.5, A.1.2.5 and A.2.5 bind the
// endpoint, and §6.2.1.5 describes "binding the Authorization Challenge Endpoint
// to the Verifiable Presentation". An origin cannot tell apart two endpoints on
// the same host. The example in A.3.5 also uses the endpoint.
func interactiveAuthorizationAudience(endpoint string) string {
	return "ia:" + endpoint
}

func (w *Wallet) createSDJWTPresentation(cred StoredCredential, selectedKeys []string, nonce, clientID string, signingKey *ecdsa.PrivateKey) (string, error) {
	parts := strings.Split(cred.Raw, "~")
	if len(parts) < 1 {
		return "", fmt.Errorf("invalid SD-JWT format")
	}
	issuerJWT := parts[0]

	payload, err := parseIssuerJWTPayload(issuerJWT)
	if err != nil {
		return "", fmt.Errorf("parsing issuer JWT payload: %w", err)
	}

	digestMap := make(map[string]*sdjwt.Disclosure, len(cred.Disclosures))
	for i := range cred.Disclosures {
		digestMap[cred.Disclosures[i].Digest] = &cred.Disclosures[i]
	}

	includedDigests := make(map[string]bool)

	for _, selector := range selectedKeys {
		path, ok := parseSDJWTSelector(selector)
		if !ok || len(path) == 0 {
			continue
		}
		// Resolve paths through plain objects as well as disclosures. A selectively
		// disclosed child may have an always-visible parent.
		collectPathDisclosureDigests(payload, path, digestMap, includedDigests)
	}

	var selectedDisclosures []string
	for _, d := range cred.Disclosures {
		if includedDigests[d.Digest] {
			selectedDisclosures = append(selectedDisclosures, d.Raw)
		}
	}

	withoutKB := issuerJWT + "~"
	if len(selectedDisclosures) > 0 {
		withoutKB += strings.Join(selectedDisclosures, "~") + "~"
	}

	// A credential without cnf has no holder key. RFC 9901 §3.3 makes key binding
	// optional, so it is presented without a KB-JWT as issuer_jwt~disc~.
	if !credentialHolderBinding(cred.Raw).Bound {
		return withoutKB, nil
	}

	// sd_hash covers the SD-JWT without the KB-JWT. RFC 9901 §4.3 hashes it with
	// the credential's own _sd_alg, which may be SHA-384 or SHA-512.
	sdHashB64, err := sdjwt.SDHash(withoutKB, sdjwt.SDAlgFromPayload(payload))
	if err != nil {
		return "", fmt.Errorf("computing sd_hash: %w", err)
	}

	kbJWT, err := w.createKBJWT(nonce, clientID, sdHashB64, signingKey)
	if err != nil {
		return "", fmt.Errorf("creating KB-JWT: %w", err)
	}

	return withoutKB + kbJWT, nil
}

func (w *Wallet) createKBJWT(nonce, audience, sdHash string, signingKey *ecdsa.PrivateKey) (string, error) {
	header := map[string]any{
		"alg": "ES256",
		"typ": "kb+jwt",
	}

	payload := map[string]any{
		"iat":     time.Now().Unix(),
		"aud":     audience,
		"nonce":   nonce,
		"sd_hash": sdHash,
	}

	return signJWT(header, payload, signingKey)
}

func signJWT(header, payload map[string]any, key *ecdsa.PrivateKey) (string, error) {
	return jws.Sign(header, payload, key)
}

type VPTokenMapResult struct {
	// Presentations per query id, in match order. Only a query that sets multiple
	// has more than one.
	TokenMap  map[string][]string
	MDocNonce string // set if any mdoc credential produced a nonce (ISO mode)
}

func (w *Wallet) CreateVPTokenMap(matches []CredentialMatch, params PresentationParams) (*VPTokenMapResult, error) {
	log.Printf("[VP] Creating VP token map: %d credentials, client=%s, response_mode=%s", len(matches), params.ClientID, params.ResponseMode)
	result := &VPTokenMapResult{
		TokenMap: make(map[string][]string),
	}

	// ISO 18013-7 Annex B uses one mdoc nonce per response in apu. Share it across
	// documents so every session transcript matches the encrypted response.
	var mdocNonce string
	if w.SessionTranscript == SessionTranscriptISO {
		var err error
		if mdocNonce, err = newMDocGeneratedNonce(); err != nil {
			return nil, err
		}
	}

	for _, match := range matches {
		tokenResult, err := w.createVPToken(match, params, mdocNonce)
		if err != nil {
			return nil, fmt.Errorf("creating VP token for %s: %w", match.QueryID, err)
		}
		result.TokenMap[match.QueryID] = append(result.TokenMap[match.QueryID], tokenResult.Token)
		if tokenResult.MDocNonce != "" {
			result.MDocNonce = tokenResult.MDocNonce
		}
		w.recordBatchPresentation(match.CredentialID)
	}

	log.Printf("[VP] VP token map created: queries=%v", mapKeys(result.TokenMap))
	return result, nil
}

// VPToken builds the vp_token JSON object. OpenID4VP 1.0 §8.1: "the value is an
// array of one or more Presentations that match the respective Credential Query".
func (r *VPTokenMapResult) VPToken() map[string][]string {
	vpToken := make(map[string][]string, len(r.TokenMap))
	for k, v := range r.TokenMap {
		vpToken[k] = slices.Clone(v)
	}
	return vpToken
}

func (r *VPTokenMapResult) PresentationCount() int {
	n := 0
	for _, v := range r.TokenMap {
		n += len(v)
	}
	return n
}

func (r *VPTokenMapResult) QueryIDs() []string {
	return mapKeys(r.TokenMap)
}

func buildPlainAuthorizationResponse(vpToken any, idToken, state string) map[string]any {
	payload := map[string]any{}
	if state != "" {
		payload["state"] = state
	}
	if vpToken != nil {
		payload["vp_token"] = vpToken
	}
	if idToken != "" {
		payload["id_token"] = idToken
	}
	return payload
}

func buildPlainAuthorizationErrorResponse(errorCode, errorDescription, state string) map[string]any {
	payload := map[string]any{
		"error": errorCode,
	}
	if errorDescription != "" {
		payload["error_description"] = errorDescription
	}
	if state != "" {
		payload["state"] = state
	}
	return payload
}

func (w *Wallet) BuildAuthorizationResponse(vpResult *VPTokenMapResult, idToken, state string, params PresentationParams) (*AuthorizationResponseEnvelope, error) {
	var vpToken any
	if vpResult != nil {
		vpToken = vpResult.VPToken()
	}
	var mdocNonce string
	if vpResult != nil {
		mdocNonce = vpResult.MDocNonce
	}

	responseMode := params.ResponseMode
	if responseMode == "" {
		responseMode = "direct_post"
	}

	plain := buildPlainAuthorizationResponse(vpToken, idToken, state)

	switch responseMode {
	case "direct_post.jwt", "dc_api.jwt", "ia_post.jwt":
		if !HasEncryptionKeyForParams(params.RequestObject, params.ClientMetadata) {
			return nil, fmt.Errorf("response_mode is %s but client_metadata.jwks carries no encryption key (OID4VP 1.0 requires one)", responseMode)
		}
		jwe, cek, err := w.EncryptResponse(vpToken, idToken, state, mdocNonce, params)
		if err != nil {
			return nil, fmt.Errorf("encrypting response: %w", err)
		}
		return &AuthorizationResponseEnvelope{
			ResponseMode: responseMode,
			ResponseJWT:  jwe,
			CEK:          cek,
			Plain:        authorizationResponsePlaintext(plain, responseMode),
		}, nil
	case "fragment":
		redirectURI := params.RedirectURI
		if redirectURI == "" {
			redirectURI = params.ResponseURI
		}
		redirectURL, err := BuildFragmentRedirect(redirectURI, state, vpToken, idToken)
		if err != nil {
			return nil, fmt.Errorf("building fragment redirect: %w", err)
		}
		log.Printf("[VP] Fragment response mode: redirect to %s", format.Truncate(redirectURL, 120))
		return &AuthorizationResponseEnvelope{
			ResponseMode: responseMode,
			RedirectURI:  redirectURL,
			Plain:        plain,
		}, nil
	case "direct_post", "dc_api", "ia_post":
		return &AuthorizationResponseEnvelope{
			ResponseMode: responseMode,
			Plain:        plain,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported response_mode %q", responseMode)
	}
}

func (w *Wallet) BuildAuthorizationErrorResponse(errorCode, errorDescription, state string, params PresentationParams) (*AuthorizationResponseEnvelope, error) {
	responseMode := params.ResponseMode
	if responseMode == "" {
		responseMode = "direct_post"
	}

	// A Digital Credentials API error is never encrypted, whatever the response
	// mode. Appendix A.4 returns it "as an object within the data property". The
	// caller would read a JWE there as a response.
	if isDCAPIResponseMode(responseMode) {
		return &AuthorizationResponseEnvelope{
			ResponseMode: responseMode,
			Plain:        map[string]any{"error": errorCode},
		}, nil
	}

	switch responseMode {
	case "direct_post.jwt", "ia_post.jwt":
		if !HasEncryptionKeyForParams(params.RequestObject, params.ClientMetadata) {
			return nil, fmt.Errorf("response_mode is %s but client_metadata.jwks carries no encryption key (OID4VP 1.0 requires one)", responseMode)
		}
		jwe, cek, err := w.EncryptErrorResponse(errorCode, errorDescription, state, params)
		if err != nil {
			return nil, fmt.Errorf("encrypting error response: %w", err)
		}
		return &AuthorizationResponseEnvelope{
			ResponseMode: responseMode,
			ResponseJWT:  jwe,
			CEK:          cek,
			Plain:        buildPlainAuthorizationErrorResponse(errorCode, errorDescription, state),
		}, nil
	case "fragment":
		redirectURI := params.RedirectURI
		if redirectURI == "" {
			redirectURI = params.ResponseURI
		}
		return &AuthorizationResponseEnvelope{
			ResponseMode: responseMode,
			RedirectURI:  BuildFragmentErrorRedirect(redirectURI, state, errorCode, errorDescription),
			Plain:        buildPlainAuthorizationErrorResponse(errorCode, errorDescription, state),
		}, nil
	case "direct_post", "dc_api", "ia_post":
		return &AuthorizationResponseEnvelope{
			ResponseMode: responseMode,
			Plain:        buildPlainAuthorizationErrorResponse(errorCode, errorDescription, state),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported response_mode %q", responseMode)
	}
}

func (w *Wallet) SubmitPresentation(vpResult *VPTokenMapResult, idToken, state, responseURI string, params PresentationParams, observe ...func(*AuthorizationResponseEnvelope)) (*DirectPostResult, error) {
	response, err := w.BuildAuthorizationResponse(vpResult, idToken, state, params)
	for _, fn := range observe {
		fn(response)
	}
	if err != nil {
		return nil, err
	}
	submit := func(fn func() (*DirectPostResult, error)) (*DirectPostResult, error) {
		result, err := fn()
		if err == nil {
			w.warnUndefinedResponseMembers(result)
		}
		return result, err
	}
	switch response.ResponseMode {
	case "direct_post.jwt":
		return submit(func() (*DirectPostResult, error) {
			return SubmitDirectPostJWT(responseURI, response.ResponseJWT, response.CEK, w.HTTPClient())
		})
	case "fragment":
		return &DirectPostResult{
			StatusCode:  302,
			RedirectURI: response.RedirectURI,
		}, nil
	case "direct_post":
		return submit(func() (*DirectPostResult, error) {
			return SubmitDirectPostObject(responseURI, response.Plain, w.HTTPClient())
		})
	case "dc_api", "dc_api.jwt":
		return nil, fmt.Errorf("response_mode %q must be returned via Browser API, not direct submission", response.ResponseMode)
	case "ia_post", "ia_post.jwt":
		return nil, fmt.Errorf("response_mode %q goes back to the Authorization Challenge Endpoint, not to a response_uri", response.ResponseMode)
	default:
		return nil, fmt.Errorf("unsupported response_mode %q", response.ResponseMode)
	}
}

func (w *Wallet) SubmitAuthorizationError(errorCode, errorDescription, state, responseURI string, params PresentationParams, observe ...func(*AuthorizationResponseEnvelope)) (*DirectPostResult, error) {
	response, err := w.BuildAuthorizationErrorResponse(errorCode, errorDescription, state, params)
	for _, fn := range observe {
		fn(response)
	}
	if err != nil {
		return nil, err
	}
	switch response.ResponseMode {
	case "direct_post.jwt":
		return SubmitDirectPostJWT(responseURI, response.ResponseJWT, response.CEK, w.HTTPClient())
	case "fragment":
		return &DirectPostResult{
			StatusCode:  302,
			RedirectURI: response.RedirectURI,
		}, nil
	case "direct_post":
		return SubmitDirectPostObject(responseURI, response.Plain, w.HTTPClient())
	case "dc_api", "dc_api.jwt":
		return nil, fmt.Errorf("response_mode %q must be returned via Browser API, not direct submission", response.ResponseMode)
	case "ia_post", "ia_post.jwt":
		return nil, fmt.Errorf("response_mode %q goes back to the Authorization Challenge Endpoint, not to a response_uri", response.ResponseMode)
	default:
		return nil, fmt.Errorf("unsupported response_mode %q", response.ResponseMode)
	}
}

// A path ending at a selectively disclosed array reveals the array without its
// elements. Only a trailing null or index selects elements. Arrays with always-visible
// elements are unaffected.
func disclosesEmptyArray(cred StoredCredential, path []any) bool {
	if cred.Format != "dc+sd-jwt" || len(path) == 0 {
		return false
	}
	switch path[len(path)-1].(type) {
	case nil, float64, int:
		return false
	}
	parts := strings.Split(cred.Raw, "~")
	payload, err := parseIssuerJWTPayload(parts[0])
	if err != nil {
		return false
	}
	digestMap := make(map[string]*sdjwt.Disclosure, len(cred.Disclosures))
	for i := range cred.Disclosures {
		digestMap[cred.Disclosures[i].Digest] = &cred.Disclosures[i]
	}
	arr, ok := placeholderValueAtPath(payload, path, digestMap).([]any)
	if !ok || len(arr) == 0 {
		return false
	}
	for _, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			return false
		}
		if _, ok := obj["..."].(string); !ok {
			return false
		}
	}
	return true
}

// placeholderValueAtPath walks a claims path (string components only) to its
// value in the credential's placeholder form. A selectively disclosable member
// resolves to its disclosure value. For an array of disclosable elements that
// value is a list of {"...": digest} references.
func placeholderValueAtPath(value any, path []any, digestMap map[string]*sdjwt.Disclosure) any {
	if len(path) == 0 {
		return value
	}
	segment, ok := path[0].(string)
	if !ok {
		return nil
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	if next, ok := obj[segment]; ok {
		return placeholderValueAtPath(next, path[1:], digestMap)
	}
	sdArr, _ := obj["_sd"].([]any)
	for _, item := range sdArr {
		digest, ok := item.(string)
		if !ok {
			continue
		}
		disc := digestMap[digest]
		if disc == nil || disc.IsArrayEntry || disc.Name != segment {
			continue
		}
		return placeholderValueAtPath(disc.Value, path[1:], digestMap)
	}
	return nil
}

func parseIssuerJWTPayload(issuerJWT string) (map[string]any, error) {
	parts := strings.Split(issuerJWT, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid issuer JWT format")
	}

	rawPayload, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshaling payload: %w", err)
	}

	return payload, nil
}

func collectAllNestedDisclosureDigests(value any, digestMap map[string]*sdjwt.Disclosure, digests map[string]bool) {
	switch v := value.(type) {
	case map[string]any:
		if sdArr, ok := v["_sd"].([]any); ok {
			for _, item := range sdArr {
				digest, ok := item.(string)
				if !ok {
					continue
				}
				digests[digest] = true
				if disc := digestMap[digest]; disc != nil {
					collectAllNestedDisclosureDigests(disc.Value, digestMap, digests)
				}
			}
		}
		for k, item := range v {
			if k == "_sd" {
				continue
			}
			collectAllNestedDisclosureDigests(item, digestMap, digests)
		}
	case []any:
		for _, item := range v {
			if obj, ok := item.(map[string]any); ok {
				if _, ok := obj["..."].(string); ok {
					// OID4VP 1.0 §7.1 selects array elements with a null or an
					// index. §6.4 forbids sending a claim the path did not select.
					// An unselected disclosable element stays undisclosed. A path
					// that ends at the array discloses none of its elements.
					continue
				}
			}
			collectAllNestedDisclosureDigests(item, digestMap, digests)
		}
	}
}

func collectPathDisclosureDigests(value any, path []any, digestMap map[string]*sdjwt.Disclosure, digests map[string]bool) {
	if len(path) == 0 {
		collectAllNestedDisclosureDigests(value, digestMap, digests)
		return
	}

	switch segment := path[0].(type) {
	case string:
		obj, ok := value.(map[string]any)
		if !ok {
			return
		}
		if next, ok := obj[segment]; ok {
			collectPathDisclosureDigests(next, path[1:], digestMap, digests)
			return
		}
		if sdArr, ok := obj["_sd"].([]any); ok {
			for _, item := range sdArr {
				digest, ok := item.(string)
				if !ok {
					continue
				}
				disc := digestMap[digest]
				if disc == nil || disc.IsArrayEntry || disc.Name != segment {
					continue
				}
				digests[digest] = true
				collectPathDisclosureDigests(disc.Value, path[1:], digestMap, digests)
			}
		}
	case int:
		arr, ok := value.([]any)
		if !ok || segment < 0 || segment >= len(arr) {
			return
		}
		collectArrayItemDisclosureDigests(arr[segment], path[1:], digestMap, digests)
	case nil:
		arr, ok := value.([]any)
		if !ok {
			return
		}
		for _, item := range arr {
			collectArrayItemDisclosureDigests(item, path[1:], digestMap, digests)
		}
	}
}

func collectArrayItemDisclosureDigests(item any, path []any, digestMap map[string]*sdjwt.Disclosure, digests map[string]bool) {
	if ref, ok := item.(map[string]any); ok {
		if digest, ok := ref["..."].(string); ok {
			digests[digest] = true
			if disc := digestMap[digest]; disc != nil {
				collectPathDisclosureDigests(disc.Value, path, digestMap, digests)
			}
			return
		}
	}
	collectPathDisclosureDigests(item, path, digestMap, digests)
}
