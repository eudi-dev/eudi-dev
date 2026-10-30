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

package oid4vp

import (
	"fmt"
	"slices"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
)

// Protocols lists the protocol of each request in the call, in order.
func (e BrowserAPIRequestEnvelope) Protocols() []string {
	protocols := make([]string, 0, len(e.Digital.Requests))
	for _, req := range e.Digital.Requests {
		protocols = append(protocols, req.Protocol)
	}
	return protocols
}

// IsBrowserAPIProtocol reports whether the wallet answers requests with the
// protocol (OID4VP 1.0 Appendix A.1).
func IsBrowserAPIProtocol(protocol string) bool {
	switch protocol {
	case browserAPIProtocolUnsigned, browserAPIProtocolSigned, browserAPIProtocolMultiSigned:
		return true
	}
	return false
}

// IgnoredBrowserAPIRequest is an unanswered request of a call, with the
// reason.
type IgnoredBrowserAPIRequest struct {
	Protocol string `json:"protocol"`
	Reason   string `json:"reason"`
}

// IgnoredBrowserAPIRequests explains each unanswered request. The wallet
// answers only the first request with a supported protocol.
func IgnoredBrowserAPIRequests(e BrowserAPIRequestEnvelope) []IgnoredBrowserAPIRequest {
	answered := slices.IndexFunc(e.Digital.Requests, func(req browserAPICredentialRequest) bool {
		return IsBrowserAPIProtocol(req.Protocol)
	})
	var ignored []IgnoredBrowserAPIRequest
	for i, req := range e.Digital.Requests {
		switch {
		case i == answered:
		case IsBrowserAPIProtocol(req.Protocol):
			ignored = append(ignored, IgnoredBrowserAPIRequest{req.Protocol, "The wallet answers the first request with a supported protocol"})
		default:
			ignored = append(ignored, IgnoredBrowserAPIRequest{req.Protocol, BrowserAPIProtocolHint(req.Protocol)})
		}
	}
	return ignored
}

// BrowserAPIProtocolHint explains why the wallet ignores requests with this
// protocol.
func BrowserAPIProtocolHint(protocol string) string {
	switch {
	case protocol == "":
		return "The request has no protocol"
	case protocol == "org-iso-mdoc":
		return "org-iso-mdoc is the protocol of ISO/IEC 18013-7 Annex C. This wallet answers only OpenID4VP"
	case strings.HasPrefix(protocol, "openid4vp"):
		return fmt.Sprintf("%s is not an OpenID4VP 1.0 protocol. Appendix A.1 defines %s, %s and %s",
			protocol, browserAPIProtocolUnsigned, browserAPIProtocolSigned, browserAPIProtocolMultiSigned)
	}
	return fmt.Sprintf("This wallet doesn't answer the protocol %s", protocol)
}

// dcAPIUnlistedParameters are OID4VP 1.0 request parameters missing from the
// Digital Credentials API list in Appendix A.2.
var dcAPIUnlistedParameters = []string{"redirect_uri", "request_uri", "request_uri_method", "response_uri", "scope", "state", "wallet_nonce"}

// dcAPIParameterWarnings reports parameters unused by the Digital
// Credentials API. They are warnings and never refuse a request.
func dcAPIParameterWarnings(protocol string, data any, params *Request) findings.List {
	keys := map[string]bool{}
	outer, _ := data.(map[string]any)
	if protocol == browserAPIProtocolUnsigned {
		for key := range outer {
			keys[key] = true
		}
	} else {
		if params.RequestObject != nil {
			for key := range params.RequestObject.Payload {
				keys[key] = true
			}
		}
		if protocol == browserAPIProtocolSigned {
			if _, ok := outer["request_uri"]; ok {
				keys["request_uri"] = true
			}
		}
	}

	var warnings findings.List
	for _, name := range dcAPIUnlistedParameters {
		if !keys[name] {
			continue
		}
		switch name {
		case "state":
			warnings = append(warnings, findings.OID4VP.Protocol("Appendix A.2").New("state is not defined for the Digital Credentials API, so a verifier can't expect it in the response"))
		case "request_uri":
			warnings = append(warnings, findings.OID4VP.Protocol("Appendix A.2").New("request_uri is not listed for the Digital Credentials API. This wallet fetches it, but other wallets may not"))
		default:
			warnings = append(warnings, findings.OID4VP.Protocol("Appendix A.2").Newf("%s is not listed for the Digital Credentials API. Other wallets may ignore it", name))
		}
	}
	if protocol == browserAPIProtocolUnsigned {
		if keys["client_id"] {
			warnings = append(warnings, findings.OID4VP.Protocol("Appendix A.2").New("client_id MUST be omitted in an unsigned request. The wallet ignores it"))
		}
		if keys["expected_origins"] {
			warnings = append(warnings, findings.OID4VP.Protocol("Appendix A.2").New("expected_origins is not for unsigned requests. The wallet ignores it"))
		}
	} else if keys["request"] {
		warnings = append(warnings, findings.OID4VP.Protocol("Appendix A.3.2").New("a signed request object can contain every parameter of Appendix A.2 except request"))
	}
	return warnings
}
