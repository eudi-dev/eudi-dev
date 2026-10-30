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

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

// verifyRequestObjectSignature verifies the Request Object JWS with the key
// given by the Client Identifier Prefix (OID4VP 1.0 §5.9.3).
//
// The x509 prefixes (x509_san_dns:, x509_hash:) carry the signing certificate
// in the x5c header. The signature is checked against the leaf, and the chain
// is checked for consistency. verifier_attestation: takes the key from the cnf
// claim of the Verifier Attestation JWT. This wallet does not resolve the key
// of any other prefix, so the signature stays unverified.
func verifyRequestObjectSignature(clientID string, reqObj *oid4vc.RequestObjectJWT) findings.Finding {
	if reqObj == nil {
		return findings.Finding{}
	}
	if reqObj.Raw == "" {
		return findings.Uncited("Request Object signature cannot be verified because the raw JWT is unavailable")
	}
	if reqObj.Header == nil {
		return findings.Uncited("Request Object has no header")
	}

	alg := jsonutil.GetString(reqObj.Header, "alg")
	if alg == "" {
		return findings.Uncited(fmt.Sprintf("Request Object has unsupported signing algorithm %q", alg))
	}
	if alg == "none" {
		return findings.Finding{}
	}

	if strings.Count(reqObj.Raw, ".") != 2 {
		return findings.Uncited("Request Object is not a compact JWS")
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

func verifyX5CSignature(reqObj *oid4vc.RequestObjectJWT) findings.Finding {
	if len(jsonutil.GetArray(reqObj.Header, "x5c")) == 0 {
		return findings.OID4VP.Protocol("§5.9.3").New("Request Object signature verification requires an x5c header")
	}
	certs, warning := extractCertChain(reqObj)
	if warning.Text != "" {
		return warning
	}
	if warning := verifySuppliedX5CChain(certs); warning.Text != "" {
		return warning
	}
	if _, err := jws.Verify(reqObj.Raw, certs[0].PublicKey); err != nil {
		return findings.OID4VP.Protocol("§5.9.3").Newf("Request Object signature verification failed: %v", err)
	}
	return findings.Finding{}
}

// verifyAttestedSignature checks the request against the cnf key of its
// Verifier Attestation JWT, and that JWT against the certificate in its x5c
// header. §5.9.3: "If the Wallet cannot establish trust, it MUST refuse the
// request." The wallet has no anchors for attestation issuers (ADR-0009), so
// a valid chain of signatures still ends in a finding.
func verifyAttestedSignature(reqObj *oid4vc.RequestObjectJWT) findings.Finding {
	attestation := jsonutil.GetString(reqObj.Header, "jwt")
	header, payload, _, err := format.ParseJWTParts(attestation)
	if err != nil {
		return findings.Uncited("Request Object signature was not verified: the jwt header carries no readable Verifier Attestation JWT")
	}
	cnfKey, err := attestationCNFKey(payload)
	if err != nil {
		return findings.Uncited(fmt.Sprintf("Request Object signature was not verified: %v", err))
	}
	if _, err := jws.Verify(reqObj.Raw, cnfKey); err != nil {
		return findings.OID4VP.Protocol("§5.9.3").Newf("the Request Object is not signed with the cnf key of the Verifier Attestation JWT: %v", err)
	}

	issuer, _ := payload["iss"].(string)
	certs, err := certchain.FromX5C(header["x5c"])
	if err != nil || len(certs) == 0 {
		return findings.OID4VP.Protocol("§5.9.3").Newf("the Verifier Attestation JWT signature was not verified: it carries no x5c header, and this wallet has no key for its issuer %q", issuer)
	}
	if _, err := jws.Verify(attestation, certs[0].PublicKey); err != nil {
		return findings.OID4VP.Protocol("§5.9.3").Newf("the Verifier Attestation JWT signature verification failed: %v", err)
	}
	return findings.OID4VP.Protocol("§5.9.3").Newf("the Verifier Attestation JWT issuer %q is not anchored to a trust anchor of this wallet, so the request signer is not verified", issuer)
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
	if finding := verifyRequestObjectSignature(params.ClientID, params.RequestObject); finding.Text != "" {
		return false, finding.String()
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
func unverifiedSignatureFinding(clientID string) findings.Finding {
	prefix, value, known := lookupClientIDPrefix(clientID)
	switch {
	case clientID == "":
		// Other checks report a missing client_id.
		return findings.Finding{}
	case known && prefix.unverified != nil:
		return prefix.unverified(value)
	case known:
		// verifyClientID reports the prefix.
		return findings.Finding{}
	default:
		return findings.OID4VP.Protocol("§5.9.2").Newf("Request Object signature was not verified: client_id %q has no known Client Identifier Prefix, so it counts as pre-registered, and this wallet has no pre-registered clients", clientID)
	}
}

// verifyClientID checks the client_id prefix against the request object and
// the response URI (OID4VP 1.0 §5.9.3). It returns a finding on a mismatch
// and the zero Finding otherwise.
func verifyClientID(clientID string, reqObj *oid4vc.RequestObjectJWT, responseURI string, requestOrigin string) findings.Finding {
	if prefix, _, known := lookupClientIDPrefix(clientID); known {
		return prefix.verify(clientID, reqObj, responseURI, requestOrigin)
	}
	return findings.Finding{}
}

// verifyX509SANDNS checks that the leaf certificate SAN contains the expected
// DNS name. Outside the DC API it also checks that the FQDN of the response
// destination matches the client_id (OID4VP 1.0 §5.9.3).
func verifyX509SANDNS(clientID string, reqObj *oid4vc.RequestObjectJWT, responseURI, requestOrigin string) findings.Finding {
	expected := strings.TrimPrefix(clientID, "x509_san_dns:")

	cert, warning := extractLeafCert(reqObj)
	if warning.Text != "" {
		return warning
	}

	// RFC 5280 §4.2.1.6: "no significance is attached to the case" of a
	// domain name.
	if !slices.ContainsFunc(cert.DNSNames, func(name string) bool { return strings.EqualFold(name, expected) }) {
		return findings.OID4VP.Protocol("§5.9.3").Newf("client_id expects DNS SAN %q but the leaf certificate has DNSNames=%v", expected, cert.DNSNames)
	}

	// §5.9.3: the FQDN of the response destination MUST match the client_id
	// unless a trusted client list waives it. The DC API is origin-bound, so
	// the rule does not apply there.
	if requestOrigin == "" && responseURI != "" {
		if parsed, err := url.Parse(responseURI); err != nil || !strings.EqualFold(parsed.Hostname(), expected) {
			return findings.OID4VP.Protocol("§5.9.3").Newf("the response goes to %q, whose host does not match the x509_san_dns client_id %q", responseURI, expected)
		}
	}

	return findings.Finding{}
}

func verifyX509Hash(clientID string, reqObj *oid4vc.RequestObjectJWT) findings.Finding {
	expectedHash := strings.TrimPrefix(clientID, "x509_hash:")

	expectedBytes, err := format.DecodeBase64URL(expectedHash)
	if err != nil {
		return findings.OID4VP.Protocol("§5.9.3").Newf("the x509_hash client_id value is not valid base64url: %v", err)
	}

	cert, warning := extractLeafCert(reqObj)
	if warning.Text != "" {
		return warning
	}

	actualHash := sha256.Sum256(cert.Raw)
	if string(expectedBytes) != string(actualHash[:]) {
		return findings.OID4VP.Protocol("§5.9.3").New("the SHA-256 of the leaf certificate does not match the x509_hash client_id")
	}

	return findings.Finding{}
}

func verifyRedirectURI(clientID string, reqObj *oid4vc.RequestObjectJWT, responseURI string) findings.Finding {
	expected := strings.TrimPrefix(clientID, "redirect_uri:")

	if reqObj != nil && reqObj.Header != nil && jsonutil.GetString(reqObj.Header, "alg") != "none" {
		return findings.OID4VP.Protocol("§5.9.3").New("a request under the redirect_uri: prefix cannot be signed, but this request object is signed")
	}

	if responseURI != "" && expected != responseURI {
		return findings.OID4VP.Protocol("§5.9.3").Newf("the redirect_uri: prefix value %q does not match response_uri %q", expected, responseURI)
	}

	return findings.Finding{}
}

// verifyVerifierAttestation checks the verifier_attestation: prefix (OID4VP
// 1.0 §5.9.3). The Request Object carries the Verifier Attestation JWT in its
// "jwt" header. The sub of that JWT matches the client_id after the prefix.
func verifyVerifierAttestation(clientID string, reqObj *oid4vc.RequestObjectJWT) findings.Finding {
	if reqObj == nil || reqObj.Header == nil {
		return findings.OID4VP.Protocol("§5.9.3").New("verifier_attestation: requires a signed Request Object")
	}

	jwtStr := jsonutil.GetString(reqObj.Header, "jwt")
	if jwtStr == "" {
		return findings.OID4VP.Protocol("§5.9.3").New("verifier_attestation: the Request Object must carry a 'jwt' header with the Verifier Attestation JWT")
	}

	parts := strings.SplitN(jwtStr, ".", 4)
	if len(parts) != 3 || len(parts[0]) == 0 || len(parts[1]) == 0 {
		return findings.OID4VP.Protocol("§5.9.3").New("verifier_attestation: the 'jwt' header value is not a valid JWT (expected 3 dot-separated parts)")
	}

	header, payload, _, err := format.ParseJWTParts(jwtStr)
	if err != nil {
		return findings.OID4VP.Protocol("§5.9.3").Newf("verifier_attestation: the Verifier Attestation JWT does not parse: %v", err)
	}

	// §12: "A Verifier Attestation JWT MUST set the typ JOSE header to
	// verifier-attestation+jwt."
	if typ := jsonutil.GetString(header, "typ"); !format.JOSETypeIs(typ, typeVerifierAttestation) {
		return findings.OID4VP.Protocol("§12").Newf("the Verifier Attestation JWT has typ %q, required is %q", typ, typeVerifierAttestation)
	}
	expected := strings.TrimPrefix(clientID, "verifier_attestation:")
	sub, _ := payload["sub"].(string)
	if sub == "" {
		return findings.OID4VP.Protocol("§12").New("the Verifier Attestation JWT has no sub claim")
	}
	if sub != expected {
		return findings.OID4VP.Protocol("§5.9.3").Newf("verifier_attestation: the Attestation JWT sub %q does not match the client_id value %q", sub, expected)
	}
	exp, ok := payload["exp"].(float64)
	if !ok {
		return findings.OID4VP.Protocol("§12").New("the Verifier Attestation JWT has no exp claim")
	}
	if time.Unix(int64(exp), 0).Add(clockSkew).Before(time.Now()) {
		return findings.OID4VP.Protocol("§12").Newf("the Verifier Attestation JWT expired at %s", time.Unix(int64(exp), 0).UTC().Format(time.RFC3339))
	}
	if _, err := attestationCNFKey(payload); err != nil {
		return findings.OID4VP.Protocol("§12").New(err.Error())
	}
	return findings.Finding{}
}

const typeVerifierAttestation = "verifier-attestation+jwt"

// clockSkew is the allowance of OID4VP 1.0 §12 for exp: "subject to allowable
// clock skew between systems".
const clockSkew = time.Minute

// verifyDecentralizedIdentifier checks the decentralized_identifier: prefix
// (OID4VP 1.0 §5.9.3). The value is a DID (did:method:identifier) and a signed
// Request Object is present. The DID is not resolved.
func verifyDecentralizedIdentifier(clientID string, reqObj *oid4vc.RequestObjectJWT) findings.Finding {
	did := strings.TrimPrefix(clientID, "decentralized_identifier:")

	didParts := strings.SplitN(did, ":", 3)
	if len(didParts) < 3 || didParts[0] != "did" || didParts[1] == "" || didParts[2] == "" {
		return findings.OID4VP.Protocol("§5.9.3").Newf("decentralized_identifier: value %q is not a valid DID (expected did:method:identifier)", did)
	}

	if reqObj == nil || reqObj.Header == nil {
		return findings.OID4VP.Protocol("§5.9.3").New("decentralized_identifier: requires a signed Request Object")
	}

	kid := jsonutil.GetString(reqObj.Header, "kid")
	if kid != "" && !strings.HasPrefix(kid, did) {
		return findings.OID4VP.Protocol("§5.9.3").Newf("decentralized_identifier: the Request Object kid %q does not reference the DID %q", kid, did)
	}

	return findings.Finding{}
}

func extractLeafCert(reqObj *oid4vc.RequestObjectJWT) (*x509.Certificate, findings.Finding) {
	if reqObj == nil || reqObj.Header == nil {
		return nil, findings.OID4VP.Protocol("§5.9.3").New("client_id uses an x509 prefix but the request object has no x5c header")
	}

	certs, err := certchain.FromX5C(reqObj.Header["x5c"])
	if err != nil {
		return nil, findings.Uncited(fmt.Sprintf("client_id uses x509 scheme but its x5c header is unreadable: %v", err))
	}
	if len(certs) == 0 {
		return nil, findings.OID4VP.Protocol("§5.9.3").New("client_id uses an x509 prefix but the x5c header is empty or missing")
	}
	return certs[0], findings.Finding{}
}

func extractCertChain(reqObj *oid4vc.RequestObjectJWT) ([]*x509.Certificate, findings.Finding) {
	if reqObj == nil || reqObj.Header == nil {
		return nil, findings.OID4VP.Protocol("§5.9.3").New("Request Object signature verification requires an x5c header")
	}

	certs, err := certchain.FromX5C(reqObj.Header["x5c"])
	if err != nil {
		return nil, findings.Uncited(fmt.Sprintf("Request Object x5c header is unreadable: %v", err))
	}
	if len(certs) == 0 {
		return nil, findings.OID4VP.Protocol("§5.9.3").New("Request Object signature verification requires an x5c header")
	}
	return certs, findings.Finding{}
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
func validateRequestObject(clientID string, reqObj *oid4vc.RequestObjectJWT) findings.Finding {
	if reqObj == nil {
		if prefixRequiresSigning(clientID) {
			return findings.OID4VP.Protocol("§5.9.3").New("the client_id prefix requires a signed Request Object but none was provided")
		}
		return findings.Finding{}
	}

	if reqObj.Header == nil {
		return findings.Uncited("Request Object has no header")
	}

	alg := jsonutil.GetString(reqObj.Header, "alg")
	typ := jsonutil.GetString(reqObj.Header, "typ")

	// An unsigned ("alg": "none") Request Object fails every prefix with a
	// signing requirement in OID4VP 1.0. verifyRequestObjectSignature has
	// nothing to verify for alg=none, so this check catches it.
	if alg == "none" && prefixRequiresSigning(clientID) {
		return findings.OID4VP.Protocol("§5.9.3").New("the client_id prefix requires a signed Request Object but the Request Object is unsigned (alg \"none\")")
	}

	if typ == "" {
		// unsignedRequestObjectAdvisory reports the missing typ of an
		// unsigned Request Object without refusing it.
		if alg == "none" {
			return findings.Finding{}
		}
		return findings.OID4VP.Protocol("§5").New("the Request Object is missing the required typ header 'oauth-authz-req+jwt'")
	}
	if !format.JOSETypeIs(typ, format.TypeRequestObject) {
		return findings.OID4VP.Protocol("§5").Newf("the Request Object has typ %q, required is 'oauth-authz-req+jwt'", typ)
	}

	if warning := verifyAlgMatchesCert(reqObj); warning.Text != "" {
		return warning
	}

	return findings.Finding{}
}

// unsignedRequestObjectAdvisory warns about an unsigned Request Object without
// typ. OID4VP 1.0 §5 says "Wallets MUST NOT process Request Objects where the
// typ Header Parameter is not present", yet the wallet processes such an
// object even in strict mode. The OIDF conformance suite (release-v5.3.2)
// sends its unsigned request_uri objects with only {"alg":"none"}. typ
// protects a signature against cross-JWT confusion, and an unsigned object
// has no signature.
func unsignedRequestObjectAdvisory(reqObj *oid4vc.RequestObjectJWT) findings.Finding {
	if reqObj == nil || jsonutil.GetString(reqObj.Header, "alg") != "none" || jsonutil.GetString(reqObj.Header, "typ") != "" {
		return findings.Finding{}
	}
	return findings.OID4VP.Protocol("§5").New("the unsigned Request Object has no typ header 'oauth-authz-req+jwt'. The wallet processes it anyway")
}

// verifyAlgMatchesCert checks that the JWT "alg" header fits the key type of
// the x5c leaf certificate. It returns a warning on a mismatch and the zero
// Finding when they match or x5c is absent.
func verifyAlgMatchesCert(reqObj *oid4vc.RequestObjectJWT) findings.Finding {
	alg := jsonutil.GetString(reqObj.Header, "alg")
	if alg == "" {
		return findings.Finding{}
	}

	cert, warning := extractLeafCert(reqObj)
	if warning.Text != "" {
		return findings.Finding{}
	}

	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !strings.HasPrefix(alg, "ES") {
			return findings.Uncited(fmt.Sprintf("Request Object alg %q is not compatible with EC key in x5c certificate", alg))
		}
	case *rsa.PublicKey:
		if !strings.HasPrefix(alg, "RS") && !strings.HasPrefix(alg, "PS") {
			return findings.Uncited(fmt.Sprintf("Request Object alg %q is not compatible with RSA key in x5c certificate", alg))
		}
	}

	return findings.Finding{}
}

// verifySuppliedX5CChain checks the validity period of every certificate in
// x5c (RFC 5280 §6.1.3 (a)(2)) and that each one certifies the one before it. A
// single certificate has no chain, so only its validity period applies.
func verifySuppliedX5CChain(certs []*x509.Certificate) findings.Finding {
	now := time.Now()
	for i, cert := range certs {
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return findings.RFC(5280).Protocol("§6.1.3 (a)(2)").Newf("the Request Object x5c certificate at position %d (subject %q) is valid from %s to %s, so it is not valid now",
				i+1, cert.Subject.String(), cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339))
		}
	}
	if len(certs) < 2 {
		return findings.Finding{}
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
		return findings.Uncited(fmt.Sprintf("Request Object x5c chain is not internally consistent: %v", err))
	}

	return findings.Finding{}
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
		// ETSI TS 119 472-2 V1.3.1 OIDFVP-HAIP-REDIRECTS_RO-03: "The JWS
		// Protected Header of the JWS signature on the RO shall incorporate
		// the iat header parameter."
		"iat": time.Now().Unix(),
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
