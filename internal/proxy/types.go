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

// Package proxy provides a debugging reverse proxy that intercepts and classifies OID4VP/VCI traffic.
package proxy

import (
	"net/http"
	"time"
)

// TrafficClass categorizes intercepted HTTP traffic by OID4VP/VCI protocol step.
type TrafficClass int

const (
	ClassUnknown              TrafficClass = iota
	ClassVPAuthRequest                     // GET with client_id, response_type=vp_token
	ClassVPRequestObject                   // GET request_uri → JWT response
	ClassVPAuthResponse                    // POST with vp_token to response_uri
	ClassVCICredentialOffer                // credential_offer / credential_offer_uri
	ClassVCIMetadata                       // .well-known/openid-credential-issuer
	ClassVCITokenRequest                   // POST to token endpoint
	ClassVCINonceRequest                   // POST to nonce endpoint
	ClassVCICredentialRequest              // POST to credential endpoint
	ClassOIDCMetadata                      // .well-known/openid-configuration
	ClassOIDCAuthRequest                   // OIDC authorization request
	ClassOIDCTokenRequest                  // OIDC token request
	ClassOIDCCallback                      // Redirect/callback back to the client
)

//nolint:gosec // G101: these are traffic-class display labels, not credentials.
var classLabels = map[TrafficClass]string{
	ClassUnknown:              "Unknown",
	ClassVPAuthRequest:        "VP auth request",
	ClassVPRequestObject:      "VP request object",
	ClassVPAuthResponse:       "VP auth response",
	ClassVCICredentialOffer:   "VCI credential offer",
	ClassVCIMetadata:          "VCI metadata",
	ClassVCITokenRequest:      "VCI token request",
	ClassVCINonceRequest:      "VCI nonce request",
	ClassVCICredentialRequest: "VCI credential request",
	ClassOIDCMetadata:         "OIDC metadata",
	ClassOIDCAuthRequest:      "OIDC auth request",
	ClassOIDCTokenRequest:     "OIDC token request",
	ClassOIDCCallback:         "OIDC callback",
}

func (c TrafficClass) Label() string {
	if l, ok := classLabels[c]; ok {
		return l
	}
	return "Unknown"
}

type TrafficEntry struct {
	ID             int64       `json:"id"`
	Timestamp      time.Time   `json:"timestamp"`
	Method         string      `json:"method"`
	URL            string      `json:"url"`
	RequestHeaders http.Header `json:"requestHeaders"`
	RequestBody    string      `json:"requestBody,omitempty"`
	// RequestTruncated and ResponseTruncated mark a body the proxy kept only
	// the start of.
	RequestTruncated  bool           `json:"requestTruncated,omitempty"`
	StatusCode        int            `json:"statusCode"`
	ResponseHeaders   http.Header    `json:"responseHeaders"`
	ResponseBody      string         `json:"responseBody,omitempty"`
	ResponseTruncated bool           `json:"responseTruncated,omitempty"`
	Class             TrafficClass   `json:"class"`
	ClassLabel        string         `json:"classLabel"`
	Decoded           map[string]any `json:"decoded,omitempty"`
	Credentials       []string       `json:"credentials,omitempty"`      // raw credential strings found in this entry
	CredentialLabels  []string       `json:"credentialLabels,omitempty"` // human-readable label per credential (parallel to Credentials)
	Duration          time.Duration  `json:"duration"`
	DurationMS        int64          `json:"durationMs"`
	FlowID            string         `json:"flowId,omitempty"`
	DebugJWEKey       string         `json:"-"` // CEK from X-Debug-JWE-CEK header (internal, not serialized)
	DebugJWK          string         `json:"-"` // JWK private key from scanner (internal, not serialized)
}

// EntryWriter is called for each intercepted traffic entry.
type EntryWriter interface {
	WriteEntry(entry *TrafficEntry)
}
