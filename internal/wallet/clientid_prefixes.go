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
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
)

// clientIDPrefix is what the wallet does with one Client Identifier Prefix of
// OID4VP 1.0 §5.9.3.
type clientIDPrefix struct {
	// verify checks the rest of the client_id against the request. It returns
	// a finding, or "" when they match.
	verify func(clientID string, reqObj *oid4vc.RequestObjectJWT, responseURI, requestOrigin string) string
	// signed prefixes require a signed Request Object. unsigned prefixes
	// forbid one.
	signed, unsigned bool
	// x5c prefixes carry the signing certificate in the x5c header.
	x5c bool
	// unverified explains why the wallet cannot verify a signature under this
	// prefix. Nil when it can. See
	// docs/adr/0013-only-the-eudi-stack-is-supported.md.
	unverified func(value string) string
	// advertised prefixes go into client_id_prefixes_supported.
	advertised bool
}

var clientIDPrefixes = map[string]clientIDPrefix{
	"x509_san_dns": {
		verify: verifyX509SANDNS,
		signed: true, x5c: true, advertised: true,
	},
	"x509_hash": {
		verify: func(clientID string, reqObj *oid4vc.RequestObjectJWT, _, _ string) string {
			return verifyX509Hash(clientID, reqObj)
		},
		signed: true, x5c: true, advertised: true,
	},
	"redirect_uri": {
		verify: func(clientID string, reqObj *oid4vc.RequestObjectJWT, responseURI, _ string) string {
			return verifyRedirectURI(clientID, reqObj, responseURI)
		},
		unsigned: true, advertised: true,
	},
	"verifier_attestation": {
		verify: func(clientID string, reqObj *oid4vc.RequestObjectJWT, _, _ string) string {
			return verifyVerifierAttestation(clientID, reqObj)
		},
		signed: true,
		unverified: func(string) string {
			return "Request Object signature was not verified: verifier_attestation: carries its key in the cnf claim of the Verifier Attestation JWT, which this wallet does not read"
		},
	},
	"decentralized_identifier": {
		verify: func(clientID string, reqObj *oid4vc.RequestObjectJWT, _, _ string) string {
			return verifyDecentralizedIdentifier(clientID, reqObj)
		},
		signed: true,
		unverified: func(did string) string {
			return fmt.Sprintf("Request Object signature was not verified: decentralized_identifier: resolves its key through the DID %s, which this wallet does not resolve", did)
		},
	},
	// §5.9.3 defers to OpenID Federation for this prefix. This wallet does not
	// resolve federation trust chains.
	"openid_federation": {
		verify: func(string, *oid4vc.RequestObjectJWT, string, string) string {
			return "openid_federation: client_id is not supported by this wallet"
		},
		unverified: func(string) string {
			return "Request Object signature was not verified: openid_federation: resolves its key through an OpenID Federation trust chain, which this wallet does not resolve"
		},
	},
	// §5.9.3: "The Wallet MUST NOT accept this Client Identifier Prefix in
	// requests." The prefix marks the audience of a Digital Credentials API
	// presentation, which the wallet derives from the platform's origin.
	"origin": {
		verify: func(string, *oid4vc.RequestObjectJWT, string, string) string {
			return "OID4VP 1.0 §5.9.3: origin: is a reserved Client Identifier Prefix and MUST NOT be accepted in a request"
		},
	},
}

// lookupClientIDPrefix returns the prefix of a client_id and the value after
// it. §5.9.1: "The Client Identifier Prefix is defined as the string before
// the (first) : character."
func lookupClientIDPrefix(clientID string) (prefix clientIDPrefix, value string, known bool) {
	name, value, found := strings.Cut(clientID, ":")
	if !found {
		return clientIDPrefix{}, clientID, false
	}
	prefix, known = clientIDPrefixes[name]
	return prefix, value, known
}

// advertisedClientIDPrefixes lists the prefixes of client_id_prefixes_supported
// (OID4VP 1.0 §10.1). pre-registered is the behaviour without a prefix.
func advertisedClientIDPrefixes() []string {
	names := []string{"pre-registered"}
	for _, name := range slices.Sorted(maps.Keys(clientIDPrefixes)) {
		if clientIDPrefixes[name].advertised {
			names = append(names, name)
		}
	}
	return names
}
