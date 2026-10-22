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

// Package issuermetadata finds the signing keys of a JWT issuer in its JWT VC
// Issuer Metadata (SD-JWT VC §4) or its authorization server metadata.
package issuermetadata

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

// wellKnownPath is the well-known path of the JWT VC Issuer Metadata
// (SD-JWT VC §4).
const wellKnownPath = "/.well-known/jwt-vc-issuer"

// URL builds the location of an issuer's JWT VC Issuer Metadata
// configuration. SD-JWT VC §4 forms it "by inserting the well-known string
// /.well-known/jwt-vc-issuer between the host component and the path
// component (if any) of the iss claim value". So iss
// https://example.com/tenant/1234 is queried at
// https://example.com/.well-known/jwt-vc-issuer/tenant/1234.
func URL(iss string) (string, error) {
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
	return parsed.Scheme + "://" + parsed.Host + wellKnownPath + path, nil
}

// JWKs fetches the JWT VC Issuer Metadata of iss and returns the JWKs that
// match kid. Without a kid every key of the set is a candidate. SD-JWT VC
// §4.2: "It is RECOMMENDED that the Issuer-signed JWT contains a kid JWT
// header parameter that can be used to look up the public key in the JWK
// Set".
func JWKs(iss, kid string, clients ...*http.Client) ([]map[string]any, error) {
	iss = strings.TrimSpace(iss)
	metadataURL, err := URL(iss)
	if err != nil {
		return nil, err
	}

	doc, err := fetchDocument(metadataURL, clients...)
	if err != nil {
		return nil, fmt.Errorf("fetching issuer metadata: %w", err)
	}
	// SD-JWT VC §4.2 makes the issuer member REQUIRED, and §4.3 says "The
	// issuer value returned MUST be identical to the iss value of the
	// Issuer-signed JWT. If these values are not identical, the data
	// contained in the response MUST NOT be used." A trailing slash counts
	// as a difference.
	issuer, ok := doc["issuer"].(string)
	if !ok {
		return nil, fmt.Errorf("issuer metadata does not contain issuer")
	}
	if issuer != iss {
		return nil, fmt.Errorf("issuer metadata issuer mismatch: got %s want %s", issuer, iss)
	}
	return findJWKs(doc, kid, clients...)
}

func fetchDocument(metadataURL string, clients ...*http.Client) (map[string]any, error) {
	req, err := http.NewRequest("GET", metadataURL, nil)
	if err != nil {
		return nil, err
	}
	// Some issuers reject requests without an Accept header.
	req.Header.Set("Accept", "application/json")
	resp, err := format.HTTPClient(clients...).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := format.ReadRemoteBody(resp.Body, "issuer metadata")
		return nil, fmt.Errorf("issuer metadata request failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var doc map[string]any
	if _, err := format.DecodeRemoteJSON(resp.Body, "issuer metadata", &doc); err != nil {
		return nil, fmt.Errorf("parsing issuer metadata: %w", err)
	}
	return doc, nil
}

// jwkSet returns the Issuer's JWK Set, by value or by reference. SD-JWT VC
// §4.2: metadata "MUST include either jwks_uri or jwks [...] but not both".
func jwkSet(doc map[string]any, clients ...*http.Client) ([]any, error) {
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
		set, err := fetchDocument(strings.TrimSpace(uri), clients...)
		if err != nil {
			return nil, fmt.Errorf("fetching jwks_uri: %w", err)
		}
		return setKeys(set)
	case hasJWKS:
		set, ok := rawJWKS.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("issuer metadata jwks is not a JSON object")
		}
		return setKeys(set)
	default:
		return nil, fmt.Errorf("issuer metadata contains neither jwks_uri nor jwks")
	}
}

func setKeys(set map[string]any) ([]any, error) {
	keysRaw, ok := set["keys"].([]any)
	if !ok || len(keysRaw) == 0 {
		return nil, fmt.Errorf("issuer JWK Set does not contain keys")
	}
	return keysRaw, nil
}

// findJWKs returns the JWKs whose kid matches, or every JWK when kid is
// empty.
func findJWKs(doc map[string]any, kid string, clients ...*http.Client) ([]map[string]any, error) {
	keysRaw, err := jwkSet(doc, clients...)
	if err != nil {
		return nil, err
	}

	kid = strings.TrimSpace(kid)
	var found []map[string]any
	for _, raw := range keysRaw {
		jwk, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if keyKid, _ := jwk["kid"].(string); kid == "" || strings.TrimSpace(keyKid) == kid {
			found = append(found, jwk)
		}
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("no issuer metadata JWK found for kid %s", kid)
	}
	return found, nil
}
