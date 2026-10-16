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

// Package oid4vp holds the wallet side of OpenID4VP 1.0: the checks of an
// authorization request, its client identifier, client metadata and
// verifier_info, the HAIP checks of a presentation request and the delivery
// of the response.
package oid4vp

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

func ParseAuthorizationRequestWithOptions(raw string, opts oid4vc.ParseOptions) (*oid4vc.AuthorizationRequest, error) {
	raw = strings.TrimSpace(raw)

	reqType, result, err := oid4vc.ParseWithOptions(raw, opts)
	if err != nil {
		return nil, fmt.Errorf("parsing authorization request: %w", err)
	}

	if reqType != oid4vc.TypeVP {
		return nil, fmt.Errorf("expected VP authorization request, got VCI")
	}

	authReq, ok := result.(*oid4vc.AuthorizationRequest)
	if !ok {
		return nil, fmt.Errorf("unexpected result type")
	}

	return authReq, nil
}

func ResponseTypeContains(responseType, target string) bool {
	for _, rt := range strings.Fields(responseType) {
		if rt == target {
			return true
		}
	}
	return false
}

// ResponseTypeRequiresVP reports whether a request requires a vp_token response.
// An empty response_type defaults to vp_token.
func ResponseTypeRequiresVP(responseType string) bool {
	return responseType == "" || ResponseTypeContains(responseType, "vp_token")
}

// ResponseModeEncrypts reports whether a response mode sends the response as
// a JWE (OID4VP 1.0 §8.3.1 and Appendix A.4, OpenID4VCI 1.1 §6.2.1.1).
func ResponseModeEncrypts(mode string) bool {
	return mode == "direct_post.jwt" || mode == "dc_api.jwt" || mode == "ia_post.jwt"
}

// IsInteractiveAuthorizationResponseMode reports whether a response mode is
// one of the two defined in OpenID4VCI 1.1 §6.2.1.1. Both send the response to
// the Authorization Challenge Endpoint.
func IsInteractiveAuthorizationResponseMode(mode string) bool {
	return mode == "ia_post" || mode == "ia_post.jwt"
}

func requestPayload(reqObj *oid4vc.RequestObjectJWT, fallback map[string]any) map[string]any {
	if reqObj != nil && reqObj.Payload != nil {
		return reqObj.Payload
	}
	return fallback
}

type SessionTranscriptMode string

const (
	// SessionTranscriptISO uses the ISO 18013-7 Annex B.4.4 handover: the
	// SHA-256 of CBOR([client_id, mdocGeneratedNonce]), the SHA-256 of
	// CBOR([response_uri, mdocGeneratedNonce]), and the nonce.
	SessionTranscriptISO SessionTranscriptMode = "iso"

	// SessionTranscriptOID4VP uses the OID4VP 1.0 Appendix B.2.6 handover: the
	// SHA-256 of CBOR([client_id, nonce, jwkThumbprint, response_uri]). This is
	// the default.
	SessionTranscriptOID4VP SessionTranscriptMode = "oid4vp"
)

// ResponseDestination is where a redirect-based response goes.
func (r *Request) ResponseDestination() string {
	if r.ResponseURI != "" {
		return r.ResponseURI
	}
	return r.RedirectURI
}

// Request is an authorization request on its way through the wallet: the
// parsed parameters and where the request came from.
type Request struct {
	oid4vc.AuthorizationRequest
	// Findings are the checks that failed in debug mode. The consent dialog
	// and the API response list them.
	Findings []string
	// AutoAccept and SessionTranscript override the wallet's settings for
	// this request (POST /api/presentations).
	AutoAccept        bool
	SessionTranscript SessionTranscriptMode
	RequestOrigin     string
	// Session identifies the browser that owns the consent request. Empty for requests
	// without a browser session.
	Session string
	// RequestPayload is the payload of the request object, or else the JSON
	// of a request sent as JSON.
	RequestPayload map[string]any
	Source         string
	// Unsigned DC API requests use the platform's origin to identify the caller and
	// omit client_id (OpenID4VP 1.0 Appendix A.2 and A.3.1).
	UnsignedDCAPI bool
	// InteractiveAuthorizationEndpoint is the Authorization Challenge Endpoint
	// of a presentation during issuance (OpenID4VCI 1.1 §6.2.1.1).
	InteractiveAuthorizationEndpoint string
	// Browser navigations redirect to the verifier after submission. API calls receive
	// JSON.
	BrowserRedirect bool
	// StatusClient fetches the status lists of registration certificates
	// (Wallet.RegistrationStatusClient).
	StatusClient *http.Client
	// RelyingPartyCAs, RegistrarCAs and RegistrationStatusCAs anchor the --arf
	// checks of access certificates, registration certificates and their status
	// lists.
	RelyingPartyCAs       []*x509.Certificate
	RegistrarCAs          []*x509.Certificate
	RegistrationStatusCAs []*x509.Certificate
}

// CanDeliverError reports whether the wallet can send an error response to
// the verifier. DC API responses return through the API call (Appendix A.4).
// Other responses need response_uri or redirect_uri.
func CanDeliverError(authReq *Request) bool {
	if authReq == nil || IsDCAPIResponseMode(authReq.ResponseMode) {
		return false
	}
	return authReq.ResponseURI != "" || authReq.RedirectURI != ""
}

// ParseRequest reads the parameters of an /authorize request. The shared
// validation checks them, as it does for every entry point.
func ParseRequest(values map[string][]string, opts oid4vc.ParseOptions) (*Request, error) {
	parsed, err := oid4vc.ParseAuthorizationParams(values, opts)
	switch {
	case err != nil && len(values["request_uri"]) > 0:
		return nil, fmt.Errorf("parsing request_uri %q: %w", values["request_uri"][0], err)
	case err != nil:
		return nil, fmt.Errorf("parsing request JWT: %w", err)
	}
	return RequestFrom(parsed), nil
}

// RequestFrom carries a parsed authorization request into the
// wallet's flow. Callers add where the request came from.
func RequestFrom(parsed *oid4vc.AuthorizationRequest) *Request {
	return &Request{
		AuthorizationRequest: *parsed,
		RequestPayload:       requestPayload(parsed.RequestObject, parsed.FullJSON),
	}
}
