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

package validate

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v2/internal/keys"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v2/internal/trustlist"
)

func CanResolveJWTIssuerMetadata(token *sdjwt.Token) bool {
	if token == nil {
		return false
	}
	// SD-JWT VC §3 only defines this mechanism for an iss that is "a
	// case-sensitive URL using the HTTPS scheme that contains scheme, host
	// and, optionally, port number and path components, but no query or
	// fragment components".
	if _, err := JWTVCIssuerMetadataURL(jsonutil.GetString(token.Payload, "iss")); err != nil {
		return false
	}
	kid, _ := token.Header["kid"].(string)
	if strings.TrimSpace(kid) == "" {
		return false
	}
	alg, _ := token.Header["alg"].(string)
	if strings.EqualFold(strings.TrimSpace(alg), "none") {
		return false
	}
	return len(token.Signature) > 0
}

// ResolveJWTIssuerMetadataKey resolves a signing key from the issuer metadata
// endpoint referenced by the token's iss claim and kid header.
func ResolveJWTIssuerMetadataKey(token *sdjwt.Token, tlCerts []trustlist.CertInfo, clients ...*http.Client) (crypto.PublicKey, string, error) {
	if !CanResolveJWTIssuerMetadata(token) {
		return nil, "", nil
	}

	iss := strings.TrimSpace(jsonutil.GetString(token.Payload, "iss"))
	kid, _ := token.Header["kid"].(string)
	metadataURL, err := JWTVCIssuerMetadataURL(iss)
	if err != nil {
		return nil, "", err
	}

	doc, err := fetchIssuerMetadataDocument(metadataURL, clients...)
	if err != nil {
		return nil, "", fmt.Errorf("fetching issuer metadata: %w", err)
	}
	// SD-JWT VC §3.2 makes the issuer member REQUIRED, and §3.3 says "The
	// issuer value returned MUST be identical to the iss value of the
	// Issuer-signed JWT. If these values are not identical, the data
	// contained in the response MUST NOT be used." A trailing slash counts
	// as a difference.
	issuer, ok := doc["issuer"].(string)
	if !ok {
		return nil, "", fmt.Errorf("issuer metadata does not contain issuer")
	}
	if issuer != iss {
		return nil, "", fmt.Errorf("issuer metadata issuer mismatch: got %s want %s", issuer, iss)
	}

	jwk, err := findIssuerMetadataJWK(doc, kid, clients...)
	if err != nil {
		return nil, "", err
	}

	if len(tlCerts) > 0 {
		if key, err := extractAndValidateJWKX5C(jwk, tlCerts); err == nil && key != nil {
			return key, "issuer metadata (x5c chain verified)", nil
		}
	}

	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		return nil, "", fmt.Errorf("encoding issuer JWK: %w", err)
	}
	key, err := keys.ParsePublicKey(jwkJSON)
	if err != nil {
		return nil, "", fmt.Errorf("parsing issuer JWK: %w", err)
	}
	return key, "issuer metadata", nil
}

// SourceX5CLeaf marks a check against the embedded leaf. It proves integrity only.
// Issuer trust needs a trust list to validate the chain.
const SourceX5CLeaf = "x5c certificate, chain not validated"

// VerifyJWTSignature verifies the token signature. It tries in order x5c with
// the trust list, the given keys, the embedded x5c leaf (only without a trust
// list) and kid-based issuer metadata. The leaf step keeps validation offline
// for credentials that carry their issuer certificate.
func VerifyJWTSignature(token *sdjwt.Token, pubKeys []crypto.PublicKey, tlCerts []trustlist.CertInfo, clients ...*http.Client) (*sdjwt.VerifyResult, string, error) {
	return verifyJWTSignature(token, pubKeys, tlCerts, true, clients...)
}

// VerifyJWTSignatureOffline uses only supplied keys and certificates. This path must
// complete without network access.
func VerifyJWTSignatureOffline(token *sdjwt.Token, pubKeys []crypto.PublicKey, tlCerts []trustlist.CertInfo) (*sdjwt.VerifyResult, string, error) {
	return verifyJWTSignature(token, pubKeys, tlCerts, false)
}

func verifyJWTSignature(token *sdjwt.Token, pubKeys []crypto.PublicKey, tlCerts []trustlist.CertInfo, resolveIssuerMetadata bool, clients ...*http.Client) (*sdjwt.VerifyResult, string, error) {
	if token == nil {
		return nil, "", fmt.Errorf("token is nil")
	}

	if x5cKey, err := ExtractAndValidateX5C(token.Header, tlCerts); err == nil && x5cKey != nil {
		return sdjwt.Verify(token, x5cKey), "x5c chain", nil
	}

	var best *sdjwt.VerifyResult
	for _, key := range pubKeys {
		result := sdjwt.Verify(token, key)
		best = result
		if result.SignatureValid {
			return result, "provided key", nil
		}
	}

	// Without trust anchors the embedded leaf still proves the signature is intact.
	// A metadata lookup fails whenever the issuer is unreachable.
	if len(tlCerts) == 0 {
		if leafKey, err := ExtractX5CLeafKey(token.Header); err == nil && leafKey != nil {
			if result := sdjwt.Verify(token, leafKey); result.SignatureValid {
				return result, SourceX5CLeaf, nil
			}
		}
	}

	if best != nil {
		if resolveIssuerMetadata {
			if key, source, err := ResolveJWTIssuerMetadataKey(token, tlCerts, clients...); err == nil && key != nil {
				result := sdjwt.Verify(token, key)
				if result.SignatureValid {
					return result, source, nil
				}
			}
		}
		return best, "provided key", nil
	}

	if !resolveIssuerMetadata {
		return nil, "", nil
	}

	key, source, err := ResolveJWTIssuerMetadataKey(token, tlCerts, clients...)
	if err != nil {
		return nil, "", err
	}
	if key == nil {
		return nil, "", nil
	}
	return sdjwt.Verify(token, key), source, nil
}

func fetchIssuerMetadataDocument(metadataURL string, clients ...*http.Client) (map[string]any, error) {
	req, err := http.NewRequest("GET", metadataURL, nil)
	if err != nil {
		return nil, err
	}
	// Some issuers reject requests without an Accept header.
	req.Header.Set("Accept", "application/json")
	resp, err := format.HTTPClientForURL(metadataURL, clients...).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := format.ReadRemoteBody(resp.Body, "issuer metadata")
		return nil, fmt.Errorf("issuer metadata request failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("parsing issuer metadata: %w", err)
	}
	return doc, nil
}

// wellKnownJWTVCIssuer is the well-known string SD-JWT VC §3 defines for the
// JWT VC Issuer Metadata configuration.
const wellKnownJWTVCIssuer = "/.well-known/jwt-vc-issuer"

// JWTVCIssuerMetadataURL builds the location of an issuer's JWT VC Issuer
// Metadata configuration. SD-JWT VC §3 forms it "by inserting the well-known
// string /.well-known/jwt-vc-issuer between the host component and the path
// component (if any) of the iss claim value". So iss
// https://example.com/tenant/1234 is queried at
// https://example.com/.well-known/jwt-vc-issuer/tenant/1234.
func JWTVCIssuerMetadataURL(iss string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(iss))
	if err != nil {
		return "", fmt.Errorf("parsing iss %q: %w", iss, err)
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("iss %q does not use the https scheme", iss)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("iss %q has no host component", iss)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("iss %q carries a query or fragment component", iss)
	}

	path := strings.TrimRight(parsed.EscapedPath(), "/")
	return parsed.Scheme + "://" + parsed.Host + wellKnownJWTVCIssuer + path, nil
}

// issuerMetadataJWKSet returns the Issuer's JWK Set, by value or by reference.
// SD-JWT VC §3.2: metadata "MUST include either jwks_uri or jwks [...] but not
// both".
func issuerMetadataJWKSet(doc map[string]any, clients ...*http.Client) ([]any, error) {
	rawURI, hasURI := doc["jwks_uri"]
	rawJWKS, hasJWKS := doc["jwks"]

	switch {
	case hasURI && hasJWKS:
		return nil, fmt.Errorf("issuer metadata contains both jwks_uri and jwks")
	case hasURI:
		uri, ok := rawURI.(string)
		if !ok || strings.TrimSpace(uri) == "" {
			return nil, fmt.Errorf("issuer metadata jwks_uri is not a URL string")
		}
		set, err := fetchIssuerMetadataDocument(strings.TrimSpace(uri), clients...)
		if err != nil {
			return nil, fmt.Errorf("fetching jwks_uri: %w", err)
		}
		return jwkSetKeys(set)
	case hasJWKS:
		set, ok := rawJWKS.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("issuer metadata jwks is not a JSON object")
		}
		return jwkSetKeys(set)
	default:
		return nil, fmt.Errorf("issuer metadata contains neither jwks_uri nor jwks")
	}
}

func jwkSetKeys(set map[string]any) ([]any, error) {
	keysRaw, ok := set["keys"].([]any)
	if !ok || len(keysRaw) == 0 {
		return nil, fmt.Errorf("issuer JWK Set does not contain keys")
	}
	return keysRaw, nil
}

func findIssuerMetadataJWK(doc map[string]any, kid string, clients ...*http.Client) (map[string]any, error) {
	keysRaw, err := issuerMetadataJWKSet(doc, clients...)
	if err != nil {
		return nil, err
	}

	var first map[string]any
	for _, raw := range keysRaw {
		jwk, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if first == nil {
			first = jwk
		}
		if keyKid, _ := jwk["kid"].(string); strings.TrimSpace(keyKid) == strings.TrimSpace(kid) {
			return jwk, nil
		}
	}
	if strings.TrimSpace(kid) == "" && first != nil {
		return first, nil
	}
	return nil, fmt.Errorf("no issuer metadata JWK found for kid %s", kid)
}

func extractAndValidateJWKX5C(jwk map[string]any, tlCerts []trustlist.CertInfo) (crypto.PublicKey, error) {
	x5cRaw, ok := jwk["x5c"]
	if !ok || len(tlCerts) == 0 {
		return nil, nil
	}

	entries, err := normalizeX5CEntries(x5cRaw)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}

	certs := make([]*x509.Certificate, 0, len(entries))
	for _, b64 := range entries {
		der, err := format.DecodeBase64Std(b64)
		if err != nil {
			return nil, fmt.Errorf("decoding jwk x5c certificate: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing jwk x5c certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return ValidateCertChain(certs, tlCerts)
}

func normalizeX5CEntries(raw any) ([]string, error) {
	switch v := raw.(type) {
	case []string:
		return v, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, entry := range v {
			s, ok := entry.(string)
			if !ok {
				return nil, fmt.Errorf("x5c entry is not a string")
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("x5c is not an array")
	}
}
