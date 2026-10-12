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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/certchain"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jsonutil"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
)

// verifyRequestObjectSignature verifies the Request Object JWS with the key
// that the Client Identifier Prefix names (OID4VP 1.0 §5.9.3).
//
// The x509 prefixes (x509_san_dns:, x509_hash:) carry the signing certificate
// in the x5c header. The signature is checked against the leaf, and the chain
// is checked for consistency. verifier_attestation: takes the key from the cnf
// claim of the Verifier Attestation JWT. Every other prefix takes it from a
// source this wallet does not resolve, so the signature stays unverified.
func verifyRequestObjectSignature(clientID string, reqObj *oid4vc.RequestObjectJWT) string {
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

	if strings.Count(reqObj.Raw, ".") != 2 {
		return "Request Object is not a compact JWS"
	}

	prefix, _, known := lookupClientIDPrefix(clientID)
	switch {
	case known && prefix.x5c:
		return verifyX5CSignature(reqObj)
	case known && prefix.attestation:
		return verifyAttestedSignature(reqObj)
	}
	return unverifiedSignatureFinding(clientID)
}

func verifyX5CSignature(reqObj *oid4vc.RequestObjectJWT) string {
	if len(jsonutil.GetArray(reqObj.Header, "x5c")) == 0 {
		return "OID4VP 1.0 §5.9.3: Request Object signature verification requires an x5c header"
	}
	certs, warning := extractCertChain(reqObj)
	if warning != "" {
		return warning
	}
	if warning := verifySuppliedX5CChain(certs); warning != "" {
		return warning
	}
	if _, err := jws.Verify(reqObj.Raw, certs[0].PublicKey); err != nil {
		return fmt.Sprintf("OID4VP 1.0 §5.9.3: Request Object signature verification failed: %v", err)
	}
	return ""
}

// verifyAttestedSignature checks the request against the cnf key of its
// Verifier Attestation JWT, and that JWT against the certificate in its x5c
// header. §5.9.3: "If the Wallet cannot establish trust, it MUST refuse the
// request." The wallet has no anchors for attestation issuers (ADR-0009), so
// a valid chain of signatures still ends in a finding.
func verifyAttestedSignature(reqObj *oid4vc.RequestObjectJWT) string {
	attestation := jsonutil.GetString(reqObj.Header, "jwt")
	header, payload, _, err := format.ParseJWTParts(attestation)
	if err != nil {
		return "Request Object signature was not verified: the jwt header carries no readable Verifier Attestation JWT"
	}
	cnfKey, err := attestationCNFKey(payload)
	if err != nil {
		return fmt.Sprintf("Request Object signature was not verified: %v", err)
	}
	if _, err := jws.Verify(reqObj.Raw, cnfKey); err != nil {
		return fmt.Sprintf("OID4VP 1.0 §5.9.3: the Request Object is not signed with the cnf key of the Verifier Attestation JWT: %v", err)
	}

	issuer, _ := payload["iss"].(string)
	certs, err := certchain.FromX5C(header["x5c"])
	if err != nil || len(certs) == 0 {
		return fmt.Sprintf("OID4VP 1.0 §5.9.3: the Verifier Attestation JWT signature was not verified: it carries no x5c header, and this wallet has no key for its issuer %q", issuer)
	}
	if _, err := jws.Verify(attestation, certs[0].PublicKey); err != nil {
		return fmt.Sprintf("OID4VP 1.0 §5.9.3: the Verifier Attestation JWT signature verification failed: %v", err)
	}
	return fmt.Sprintf("OID4VP 1.0 §5.9.3: the Verifier Attestation JWT issuer %q is not anchored to a trust anchor of this wallet, so the request signer is not verified", issuer)
}

// attestationCNFKey reads the key of OID4VP 1.0 §12: cnf "MUST contain a
// JSON Web Key [RFC7517] as defined in Section 3.2 of [RFC7800]."
func attestationCNFKey(payload map[string]any) (crypto.PublicKey, error) {
	cnf, _ := payload["cnf"].(map[string]any)
	jwk, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the Verifier Attestation JWT has no cnf.jwk")
	}
	raw, err := json.Marshal(jwk)
	if err != nil {
		return nil, err
	}
	key, err := keys.ParseJWK(raw)
	if err != nil {
		return nil, fmt.Errorf("the cnf.jwk of the Verifier Attestation JWT is unreadable: %w", err)
	}
	return key, nil
}

// ClientAuthState reports whether the request signature verified with the key
// material in the request. That does not establish trust in the signer.
// detail explains an unsigned or unverified request to the consent dialog.
func ClientAuthState(params *Request) (signed bool, detail string) {
	if params == nil || params.RequestObject == nil {
		return false, "The request was not a signed request object."
	}
	if jsonutil.GetString(params.RequestObject.Header, "alg") == "none" {
		return false, "The request object is unsigned (alg none)."
	}
	if finding := verifyRequestObjectSignature(params.ClientID, params.RequestObject); finding != "" {
		return false, finding
	}
	return true, ""
}

// ClientMetadataName returns client_name from the request object metadata, or
// else from the outer parameters. client_name is self-asserted display text.
func ClientMetadataName(params *Request) string {
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
	name, _ := resolveClientMetadata(reqPayload, params.ClientMetadata)["client_name"].(string)
	return name
}

// unverifiedSignatureFinding explains why a signed request under a prefix
// without a key source in this wallet stays unverified.
func unverifiedSignatureFinding(clientID string) string {
	prefix, value, known := lookupClientIDPrefix(clientID)
	switch {
	case clientID == "":
		// Other checks report a missing client_id.
		return ""
	case known && prefix.unverified != nil:
		return prefix.unverified(value)
	case known:
		// verifyClientID reports the prefix.
		return ""
	default:
		return fmt.Sprintf("Request Object signature was not verified: client_id %q has no known Client Identifier Prefix. OpenID4VP 1.0 §5.9.2 treats it as pre-registered, and this wallet has no pre-registered clients", clientID)
	}
}

// verifyClientID checks the client_id prefix against the request object and
// the response URI (OID4VP 1.0 §5.9.3). It returns a finding on a mismatch
// and "" otherwise.
func verifyClientID(clientID string, reqObj *oid4vc.RequestObjectJWT, responseURI string, requestOrigin string) string {
	if prefix, _, known := lookupClientIDPrefix(clientID); known {
		return prefix.verify(clientID, reqObj, responseURI, requestOrigin)
	}
	return ""
}

// verifyX509SANDNS checks that the leaf certificate SAN contains the expected
// DNS name. Outside the DC API it also checks that the FQDN of the response
// destination matches the client_id (OID4VP 1.0 §5.9.3).
func verifyX509SANDNS(clientID string, reqObj *oid4vc.RequestObjectJWT, responseURI, requestOrigin string) string {
	expected := strings.TrimPrefix(clientID, "x509_san_dns:")

	cert, warning := extractLeafCert(reqObj)
	if warning != "" {
		return warning
	}

	// RFC 5280 §4.2.1.6: "no significance is attached to the case" of a
	// domain name.
	if !slices.ContainsFunc(cert.DNSNames, func(name string) bool { return strings.EqualFold(name, expected) }) {
		return fmt.Sprintf("OID4VP 1.0 §5.9.3: client_id expects DNS SAN %q but the leaf certificate has DNSNames=%v", expected, cert.DNSNames)
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
		return "OID4VP 1.0 §5.9.3: a request under the redirect_uri: prefix cannot be signed, but this request object is signed"
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

	header, payload, _, err := format.ParseJWTParts(jwtStr)
	if err != nil {
		return fmt.Sprintf("OID4VP 1.0 §5.9.3: verifier_attestation: the Verifier Attestation JWT does not parse: %v", err)
	}

	// §12: "A Verifier Attestation JWT MUST set the typ JOSE header to
	// verifier-attestation+jwt."
	if typ := jsonutil.GetString(header, "typ"); !format.JOSETypeIs(typ, typeVerifierAttestation) {
		return fmt.Sprintf("OID4VP 1.0 §12: the Verifier Attestation JWT has typ %q, required is %q", typ, typeVerifierAttestation)
	}
	expected := strings.TrimPrefix(clientID, "verifier_attestation:")
	sub, _ := payload["sub"].(string)
	if sub == "" {
		return "OID4VP 1.0 §12: the Verifier Attestation JWT has no sub claim"
	}
	if sub != expected {
		return fmt.Sprintf("OID4VP 1.0 §5.9.3: verifier_attestation: the Attestation JWT sub %q does not match the client_id value %q", sub, expected)
	}
	exp, ok := payload["exp"].(float64)
	if !ok {
		return "OID4VP 1.0 §12: the Verifier Attestation JWT has no exp claim"
	}
	if time.Unix(int64(exp), 0).Add(clockSkew).Before(time.Now()) {
		return fmt.Sprintf("OID4VP 1.0 §12: the Verifier Attestation JWT expired at %s", time.Unix(int64(exp), 0).UTC().Format(time.RFC3339))
	}
	if _, err := attestationCNFKey(payload); err != nil {
		return "OID4VP 1.0 §12: " + err.Error()
	}
	return ""
}

const typeVerifierAttestation = "verifier-attestation+jwt"

// clockSkew is the allowance of OID4VP 1.0 §12 for exp: "subject to allowable
// clock skew between systems".
const clockSkew = time.Minute

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
	prefix, _, _ := lookupClientIDPrefix(clientID)
	return prefix.signed
}

// validateRequestObject checks that the typ header of the Request Object is
// "oauth-authz-req+jwt" (OID4VP 1.0, RFC 9101). It also warns when the
// client_id prefix requires signing and no Request Object is present.
func validateRequestObject(clientID string, reqObj *oid4vc.RequestObjectJWT) string {
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
	// OID4VP 1.0 requires to be signed. verifyRequestObjectSignature has
	// nothing to verify for alg=none, so this check catches it.
	if alg == "none" && prefixRequiresSigning(clientID) {
		return "OID4VP 1.0 §5.9.3: the client_id prefix requires a signed Request Object but the Request Object is unsigned (alg \"none\")"
	}

	if typ == "" {
		// unsignedRequestObjectAdvisory reports the missing typ of an
		// unsigned Request Object without refusing it.
		if alg == "none" {
			return ""
		}
		return "OID4VP 1.0 §5: the Request Object is missing the required typ header 'oauth-authz-req+jwt'"
	}
	if !format.JOSETypeIs(typ, format.TypeRequestObject) {
		return fmt.Sprintf("OID4VP 1.0 §5: the Request Object has typ %q, required is 'oauth-authz-req+jwt'", typ)
	}

	if warning := verifyAlgMatchesCert(reqObj); warning != "" {
		return warning
	}

	return ""
}

// unsignedRequestObjectAdvisory warns about an unsigned Request Object without
// typ. OID4VP 1.0 §5 says "Wallets MUST NOT process Request Objects where the
// typ Header Parameter is not present", yet the wallet processes such an
// object even in strict mode. The OIDF conformance suite (release-v5.3.2)
// sends its unsigned request_uri objects with only {"alg":"none"}, and an
// unsigned object carries no signature that typ could protect against
// cross-JWT confusion.
func unsignedRequestObjectAdvisory(reqObj *oid4vc.RequestObjectJWT) string {
	if reqObj == nil || jsonutil.GetString(reqObj.Header, "alg") != "none" || jsonutil.GetString(reqObj.Header, "typ") != "" {
		return ""
	}
	return "OID4VP 1.0 §5: the unsigned Request Object has no typ header 'oauth-authz-req+jwt'. The wallet processes it anyway"
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

// SignRequestObjectJWT signs an OpenID4VP authorization request object (JAR)
// with the signer's certificate chain in x5c. Its typ is
// oauth-authz-req+jwt, as validateRequestObject expects.
func SignRequestObjectJWT(claims map[string]any, signingKey *ecdsa.PrivateKey, signerCerts []*x509.Certificate) (string, error) {
	if signingKey == nil {
		return "", fmt.Errorf("signing key is required")
	}
	header := map[string]any{
		"alg": jws.AlgES256,
		"typ": format.TypeRequestObject,
	}
	if x5c := certchain.X5C(signerCerts); len(x5c) > 0 {
		header["x5c"] = x5c
	}
	return jws.Sign(header, claims, signingKey)
}

// X509HashClientID returns the `x509_hash:` client identifier for a leaf
// certificate. The value is the base64url-encoded SHA-256 of its DER encoding.
func X509HashClientID(leaf *x509.Certificate) string {
	if leaf == nil {
		return ""
	}
	sum := sha256.Sum256(leaf.Raw)
	return "x509_hash:" + format.EncodeBase64URL(sum[:])
}
