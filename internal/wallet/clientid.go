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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/certchain"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jsonutil"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
)

// VerifyRequestObjectSignature verifies the Request Object JWS.
//
// The x509 prefixes (x509_san_dns:, x509_hash:) carry the signing certificate
// in the x5c header. The signature is checked against the leaf, and the chain
// is checked for consistency. verifier_attestation: and
// decentralized_identifier: take the key from the attestation or the resolved
// DID. This wallet resolves neither, so it reports the signature as unverified.
func VerifyRequestObjectSignature(clientID string, reqObj *oid4vc.RequestObjectJWT) string {
	if reqObj == nil {
		return ""
	}
	if reqObj.Raw == "" {
		return "Request Object signature cannot be verified because the raw JWT is unavailable"
	}
	if reqObj.Header == nil {
		return "Request Object has no header"
	}

	alg := jsonutil.GetString(reqObj.Header, "alg")
	if alg == "" {
		return fmt.Sprintf("Request Object has unsupported signing algorithm %q", alg)
	}
	if alg == "none" {
		return ""
	}

	if len(jsonutil.GetArray(reqObj.Header, "x5c")) == 0 {
		if clientIDVerifiesViaX5C(clientID) {
			return "OID4VP 1.0 §5.9.3: Request Object signature verification requires an x5c header"
		}
		return unverifiedSignatureFinding(clientID)
	}

	certs, warning := extractCertChain(reqObj)
	if warning != "" {
		return warning
	}
	if warning := verifySuppliedX5CChain(certs); warning != "" {
		return warning
	}

	if strings.Count(reqObj.Raw, ".") != 2 {
		return "Request Object is not a compact JWS"
	}
	if _, err := jws.Verify(reqObj.Raw, certs[0].PublicKey); err != nil {
		return fmt.Sprintf("OID4VP 1.0 §5.9.3: Request Object signature verification failed: %v", err)
	}

	return ""
}

// clientAuthState reports whether the request signature verified with the key
// material in the request. That does not establish trust in the signer.
// detail explains an unsigned or unverified request to the consent dialog.
func clientAuthState(params *AuthorizationRequestParams) (signed bool, detail string) {
	if params == nil || params.RequestObject == nil {
		return false, "The request was not a signed request object."
	}
	if jsonutil.GetString(params.RequestObject.Header, "alg") == "none" {
		return false, "The request object is unsigned (alg none)."
	}
	if finding := VerifyRequestObjectSignature(params.ClientID, params.RequestObject); finding != "" {
		return false, finding
	}
	return true, ""
}

// clientMetadataName returns client_name from the request object metadata, or
// else from the outer parameters. client_name is self-asserted display text.
func clientMetadataName(params *AuthorizationRequestParams) string {
	if params == nil {
		return ""
	}
	var reqPayload map[string]any
	if params.RequestObject != nil {
		reqPayload = params.RequestObject.Payload
	}
	if reqPayload == nil {
		reqPayload = params.RequestPayload
	}
	name, _ := ResolveClientMetadata(reqPayload, params.ClientMetadata)["client_name"].(string)
	return name
}

func (r *ConsentRequest) applyClientAuth(params *AuthorizationRequestParams) {
	r.ClientAuthSigned, r.ClientAuthDetail = clientAuthState(params)
	r.ClientName = clientMetadataName(params)
}

// unverifiedSignatureFinding explains why a signed request stays unverified
// when the wallet does not support the key resolution of its prefix. See
// docs/adr/0013-only-the-eudi-stack-is-supported.md.
func unverifiedSignatureFinding(clientID string) string {
	switch {
	case strings.HasPrefix(clientID, "decentralized_identifier:"):
		return fmt.Sprintf("Request Object signature was not verified: decentralized_identifier: resolves its key through the DID %s, which this wallet does not resolve",
			strings.TrimPrefix(clientID, "decentralized_identifier:"))
	case strings.HasPrefix(clientID, "verifier_attestation:"):
		return "Request Object signature was not verified: verifier_attestation: carries its key in the cnf claim of the Verifier Attestation JWT, which this wallet does not read"
	case strings.HasPrefix(clientID, "openid_federation:"):
		return "Request Object signature was not verified: openid_federation: resolves its key through an OpenID Federation trust chain, which this wallet does not resolve"
	case strings.HasPrefix(clientID, "redirect_uri:"):
		// VerifyClientID already reports a signed Request Object under this
		// prefix.
		return ""
	case clientID == "":
		// Other checks report a missing client_id.
		return ""
	default:
		return fmt.Sprintf("Request Object signature was not verified: client_id %q carries no Client Identifier Prefix, so its key would have been pre-registered with this wallet, and nothing is", clientID)
	}
}

// clientIDVerifiesViaX5C reports whether the prefix carries the signing
// certificate in x5c. Only the x509 prefixes do.
func clientIDVerifiesViaX5C(clientID string) bool {
	return strings.HasPrefix(clientID, "x509_san_dns:") || strings.HasPrefix(clientID, "x509_hash:")
}

// VerifyClientID checks the client_id prefix against the request object and
// the response URI (OID4VP 1.0 Client Identifier Prefixes). It returns a
// warning on a mismatch and "" otherwise.
func VerifyClientID(clientID string, reqObj *oid4vc.RequestObjectJWT, responseURI string, requestOrigin string) string {
	switch {
	case strings.HasPrefix(clientID, "x509_san_dns:"):
		return verifyX509SAN(clientID, "x509_san_dns:", "dns", reqObj, responseURI, requestOrigin)
	case strings.HasPrefix(clientID, "x509_hash:"):
		return verifyX509Hash(clientID, reqObj)
	case strings.HasPrefix(clientID, "origin:"):
		// OID4VP 1.0 §5.9.3: "The Wallet MUST NOT accept this Client Identifier
		// Prefix in requests." The prefix marks the audience of a Digital
		// Credentials API presentation. The wallet derives it from the origin
		// reported by the platform.
		return "OID4VP 1.0 §5.9.3: origin: is a reserved Client Identifier Prefix and MUST NOT be accepted in a request"
	case strings.HasPrefix(clientID, "openid_federation:"):
		// §5.9.3 defers to OpenID Federation for this prefix. This wallet does
		// not resolve federation trust chains.
		return "openid_federation: client_id is not supported by this wallet"
	case strings.HasPrefix(clientID, "redirect_uri:"):
		return verifyRedirectURI(clientID, reqObj, responseURI)
	case strings.HasPrefix(clientID, "verifier_attestation:"):
		return verifyVerifierAttestation(clientID, reqObj)
	case strings.HasPrefix(clientID, "decentralized_identifier:"):
		return verifyDecentralizedIdentifier(clientID, reqObj)
	default:
		return ""
	}
}

// verifyX509SAN checks that the leaf certificate SAN contains the expected DNS
// name. Outside the DC API it also checks that the FQDN of the response
// destination matches the client_id (OID4VP 1.0 §5.9.1).
func verifyX509SAN(clientID, prefix, scheme string, reqObj *oid4vc.RequestObjectJWT, responseURI, requestOrigin string) string {
	expected := strings.TrimPrefix(clientID, prefix)

	cert, warning := extractLeafCert(reqObj)
	if warning != "" {
		return warning
	}

	if scheme == "dns" {
		matched := false
		for _, name := range cert.DNSNames {
			if name == expected {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Sprintf("OID4VP 1.0 §5.9.3: client_id expects DNS SAN %q but the leaf certificate has DNSNames=%v", expected, cert.DNSNames)
		}
	}

	// §5.9.3: the FQDN of the response destination MUST match the client_id
	// unless a trusted client list waives it. The DC API is origin-bound, so
	// the rule does not apply there.
	if requestOrigin == "" && responseURI != "" {
		if parsed, err := url.Parse(responseURI); err != nil || !strings.EqualFold(parsed.Hostname(), expected) {
			return fmt.Sprintf("OID4VP 1.0 §5.9.3: the response goes to %q, whose host does not match the x509_san_dns client_id %q", responseURI, expected)
		}
	}

	return ""
}

func verifyX509Hash(clientID string, reqObj *oid4vc.RequestObjectJWT) string {
	expectedHash := strings.TrimPrefix(clientID, "x509_hash:")

	expectedBytes, err := format.DecodeBase64URL(expectedHash)
	if err != nil {
		return fmt.Sprintf("OID4VP 1.0 §5.9.3: the x509_hash client_id value is not valid base64url: %v", err)
	}

	cert, warning := extractLeafCert(reqObj)
	if warning != "" {
		return warning
	}

	actualHash := sha256.Sum256(cert.Raw)
	if string(expectedBytes) != string(actualHash[:]) {
		return "OID4VP 1.0 §5.9.3: the SHA-256 of the leaf certificate does not match the x509_hash client_id"
	}

	return ""
}

func verifyRedirectURI(clientID string, reqObj *oid4vc.RequestObjectJWT, responseURI string) string {
	expected := strings.TrimPrefix(clientID, "redirect_uri:")

	if reqObj != nil && reqObj.Header != nil && jsonutil.GetString(reqObj.Header, "alg") != "none" {
		return "OID4VP 1.0 §5.9.3: the redirect_uri: prefix MUST NOT be used with a signed request object"
	}

	if responseURI != "" && expected != responseURI {
		return fmt.Sprintf("OID4VP 1.0 §5.9.3: the redirect_uri: prefix value %q does not match response_uri %q", expected, responseURI)
	}

	return ""
}

// verifyVerifierAttestation checks the verifier_attestation: prefix (OID4VP
// 1.0 §5.9.3). The Request Object carries the Verifier Attestation JWT in its
// "jwt" header. The sub of that JWT matches the client_id after the prefix.
func verifyVerifierAttestation(clientID string, reqObj *oid4vc.RequestObjectJWT) string {
	if reqObj == nil || reqObj.Header == nil {
		return "OID4VP 1.0 §5.9.3: verifier_attestation: requires a signed Request Object"
	}

	jwtStr := jsonutil.GetString(reqObj.Header, "jwt")
	if jwtStr == "" {
		return "OID4VP 1.0 §5.9.3: verifier_attestation: the Request Object must carry a 'jwt' header with the Verifier Attestation JWT"
	}

	parts := strings.SplitN(jwtStr, ".", 4)
	if len(parts) != 3 || len(parts[0]) == 0 || len(parts[1]) == 0 {
		return "OID4VP 1.0 §5.9.3: verifier_attestation: the 'jwt' header value is not a valid JWT (expected 3 dot-separated parts)"
	}

	_, payload, _, err := format.ParseJWTParts(jwtStr)
	if err != nil {
		return fmt.Sprintf("OID4VP 1.0 §5.9.3: verifier_attestation: the Verifier Attestation JWT does not parse: %v", err)
	}

	expected := strings.TrimPrefix(clientID, "verifier_attestation:")
	sub, _ := payload["sub"].(string)
	if sub != "" && sub != expected {
		return fmt.Sprintf("OID4VP 1.0 §5.9.3: verifier_attestation: the Attestation JWT sub %q does not match the client_id value %q", sub, expected)
	}

	return ""
}

// verifyDecentralizedIdentifier checks the decentralized_identifier: prefix
// (OID4VP 1.0 §5.9.3). The value is a DID (did:method:identifier) and a signed
// Request Object is present. The DID is not resolved.
func verifyDecentralizedIdentifier(clientID string, reqObj *oid4vc.RequestObjectJWT) string {
	did := strings.TrimPrefix(clientID, "decentralized_identifier:")

	didParts := strings.SplitN(did, ":", 3)
	if len(didParts) < 3 || didParts[0] != "did" || didParts[1] == "" || didParts[2] == "" {
		return fmt.Sprintf("OID4VP 1.0 §5.9.3: decentralized_identifier: value %q is not a valid DID (expected did:method:identifier)", did)
	}

	if reqObj == nil || reqObj.Header == nil {
		return "OID4VP 1.0 §5.9.3: decentralized_identifier: requires a signed Request Object"
	}

	kid := jsonutil.GetString(reqObj.Header, "kid")
	if kid != "" && !strings.HasPrefix(kid, did) {
		return fmt.Sprintf("OID4VP 1.0 §5.9.3: decentralized_identifier: the Request Object kid %q does not reference the DID %q", kid, did)
	}

	return ""
}

func extractLeafCert(reqObj *oid4vc.RequestObjectJWT) (*x509.Certificate, string) {
	if reqObj == nil || reqObj.Header == nil {
		return nil, "OID4VP 1.0 §5.9.3: client_id uses an x509 prefix but the request object has no x5c header"
	}

	certs, err := certchain.FromX5C(reqObj.Header["x5c"])
	if err != nil {
		return nil, fmt.Sprintf("client_id uses x509 scheme but its x5c header is unreadable: %v", err)
	}
	if len(certs) == 0 {
		return nil, "OID4VP 1.0 §5.9.3: client_id uses an x509 prefix but the x5c header is empty or missing"
	}
	return certs[0], ""
}

func extractCertChain(reqObj *oid4vc.RequestObjectJWT) ([]*x509.Certificate, string) {
	if reqObj == nil || reqObj.Header == nil {
		return nil, "OID4VP 1.0 §5.9.3: Request Object signature verification requires an x5c header"
	}

	certs, err := certchain.FromX5C(reqObj.Header["x5c"])
	if err != nil {
		return nil, fmt.Sprintf("Request Object x5c header is unreadable: %v", err)
	}
	if len(certs) == 0 {
		return nil, "OID4VP 1.0 §5.9.3: Request Object signature verification requires an x5c header"
	}
	return certs, ""
}

// prefixRequiresSigning reports whether OID4VP 1.0 requires a signed Request
// Object for the client_id prefix.
func prefixRequiresSigning(clientID string) bool {
	prefixes := []string{"x509_san_dns:", "x509_hash:", "decentralized_identifier:", "verifier_attestation:"}
	for _, p := range prefixes {
		if strings.HasPrefix(clientID, p) {
			return true
		}
	}
	return false
}

// ValidateRequestObject checks that the typ header of the Request Object is
// "oauth-authz-req+jwt" (OID4VP 1.0, RFC 9101). It also warns when the
// client_id prefix requires signing and no Request Object is present.
func ValidateRequestObject(clientID string, reqObj *oid4vc.RequestObjectJWT) string {
	if reqObj == nil {
		if prefixRequiresSigning(clientID) {
			return "OID4VP 1.0 §5.9.3: the client_id prefix requires a signed Request Object but none was provided"
		}
		return ""
	}

	if reqObj.Header == nil {
		return "Request Object has no header"
	}

	alg := jsonutil.GetString(reqObj.Header, "alg")
	typ := jsonutil.GetString(reqObj.Header, "typ")

	// An unsigned ("alg": "none") Request Object fails every prefix that
	// OID4VP 1.0 requires to be signed. VerifyRequestObjectSignature has
	// nothing to verify for alg=none, so this check catches it.
	if alg == "none" && prefixRequiresSigning(clientID) {
		return "OID4VP 1.0 §5.9.3: the client_id prefix requires a signed Request Object but the Request Object is unsigned (alg \"none\")"
	}

	if typ == "" {
		if alg == "none" {
			return ""
		}
		return "OID4VP 1.0 §5: the Request Object is missing the required typ header 'oauth-authz-req+jwt'"
	}
	if typ != "oauth-authz-req+jwt" {
		return fmt.Sprintf("OID4VP 1.0 §5: the Request Object has typ %q, required is 'oauth-authz-req+jwt'", typ)
	}

	if warning := verifyAlgMatchesCert(reqObj); warning != "" {
		return warning
	}

	return ""
}

// verifyAlgMatchesCert checks that the JWT "alg" header fits the key type of
// the x5c leaf certificate. It returns a warning on a mismatch and "" when they
// match or x5c is absent.
func verifyAlgMatchesCert(reqObj *oid4vc.RequestObjectJWT) string {
	alg := jsonutil.GetString(reqObj.Header, "alg")
	if alg == "" {
		return ""
	}

	cert, warning := extractLeafCert(reqObj)
	if warning != "" {
		return ""
	}

	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !strings.HasPrefix(alg, "ES") {
			return fmt.Sprintf("Request Object alg %q is not compatible with EC key in x5c certificate", alg)
		}
	case *rsa.PublicKey:
		if !strings.HasPrefix(alg, "RS") && !strings.HasPrefix(alg, "PS") {
			return fmt.Sprintf("Request Object alg %q is not compatible with RSA key in x5c certificate", alg)
		}
	}

	return ""
}

func verifySuppliedX5CChain(certs []*x509.Certificate) string {
	if len(certs) < 2 {
		return ""
	}

	roots := x509.NewCertPool()
	roots.AddCert(certs[len(certs)-1])

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1 : len(certs)-1] {
		intermediates.AddCert(cert)
	}

	if _, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Sprintf("Request Object x5c chain is not internally consistent: %v", err)
	}

	return ""
}
