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

// Package scheme lists the URI schemes of presentation requests and credential
// offers. It imports nothing, so internal/format can classify input with it.
package scheme

import "strings"

var (
	// Presentation schemes start an OpenID4VP request. ETSI TS 119 472-2 V1.3.1
	// OIDFVP-HAIP-REDIRECTS-03: "The EUDI Wallet shall support at least a custom
	// URL scheme "eu-eaap://" for its authorization_endpoint."
	Presentation = []string{"openid4vp", "eudi-openid4vp", "haip-vp", "eu-eaap"}
	// Issuance schemes carry an OpenID4VCI credential offer.
	Issuance = []string{"openid-credential-offer", "haip-vci", "eu-eaa-offer"}
)

// IsPresentation reports whether uri uses a presentation scheme.
func IsPresentation(uri string) bool { return hasScheme(uri, Presentation) }

// IsIssuance reports whether uri uses an issuance scheme.
func IsIssuance(uri string) bool { return hasScheme(uri, Issuance) }

// hasScheme compares without case. RFC 3986 §3.1: "schemes are
// case-insensitive".
func hasScheme(uri string, schemes []string) bool {
	name, _, found := strings.Cut(strings.TrimSpace(uri), "://")
	if !found {
		return false
	}
	for _, s := range schemes {
		if strings.EqualFold(name, s) {
			return true
		}
	}
	return false
}
