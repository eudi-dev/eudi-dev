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

// Package oid4vc parses OID4VCI credential offers and OID4VP authorization requests.
package oid4vc

import (
	"fmt"
	"net/http"
	"strings"
)

type RequestType int

const (
	TypeVCI RequestType = iota
	TypeVP
)

type CredentialOffer struct {
	CredentialIssuer           string
	CredentialConfigurationIDs []string
	Grants                     OfferGrants
	FullJSON                   map[string]any
}

type OfferGrants struct {
	PreAuthorizedCode string
	// TxCode is the tx_code object of the pre-authorized grant: input_mode,
	// length and description. It is non-nil whenever the offer carries one.
	TxCode            map[string]any
	AuthorizationCode string
	IssuerState       string
}

// RequiresTxCode reports whether the offer asks for a Transaction Code.
// OID4VCI 1.0 §4.1.1: the tx_code object indicates "that a Transaction Code is
// required if present, even if empty".
func (g OfferGrants) RequiresTxCode() bool {
	return g.TxCode != nil
}

// TxCodeHint describes the expected Transaction Code for the End-User. The
// issuer's description wins. Otherwise it states the length and input mode.
func (g OfferGrants) TxCodeHint() string {
	if description, _ := g.TxCode["description"].(string); strings.TrimSpace(description) != "" {
		return strings.TrimSpace(description)
	}
	mode, _ := g.TxCode["input_mode"].(string)
	length := 0
	switch n := g.TxCode["length"].(type) {
	case float64:
		length = int(n)
	case int:
		length = n
	}
	switch {
	case length > 0 && mode != "":
		return fmt.Sprintf("%d %s characters", length, mode)
	case length > 0:
		return fmt.Sprintf("%d characters", length)
	default:
		return mode
	}
}

type AuthorizationRequest struct {
	ClientID         string
	ResponseType     string
	ResponseMode     string
	Nonce            string
	State            string
	RedirectURI      string
	ResponseURI      string
	Scope            string
	RequestURIMethod string // "get" (default) or "post" per OID4VP 1.0 §5.10
	// RequestURI is the request_uri used to fetch the request object. It is
	// empty for inline parameters or an inline object. HAIP 1.0 §5.1 requires
	// delivery by request_uri.
	RequestURI     string
	ClientMetadata map[string]any
	DCQLQuery      map[string]any
	RequestObject  *RequestObjectJWT
	FullParams     map[string]string
	FullJSON       map[string]any
}

type RequestObjectJWT struct {
	Raw     string
	Header  map[string]any
	Payload map[string]any
}

type ParseOptions struct {
	HTTPClient *http.Client
	// FetchRequestURI retrieves the request object from request_uri. method is
	// "get" or "post". When nil, format.FetchURL sends a GET for either method.
	FetchRequestURI func(url string, method string, clientID string) (string, error)
}
