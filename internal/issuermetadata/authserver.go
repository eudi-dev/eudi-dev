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

package issuermetadata

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// AuthorizationServerJWKs fetches the metadata of the authorization server
// iss and returns the JWKs of its jwks_uri that match kid. A JWT access token
// is signed with these keys (RFC 9068 §4). The lookup reads the OAuth 2.0
// Authorization Server Metadata (RFC 8414 §3) and then OpenID Connect
// Discovery (OpenID Connect Discovery 1.0 §4), which servers such as
// Keycloak publish below the issuer path.
func AuthorizationServerJWKs(iss, kid string, clients ...*http.Client) ([]map[string]any, error) {
	iss = strings.TrimSpace(iss)
	if _, err := URL(iss); err != nil {
		return nil, err
	}
	trimmed := strings.TrimSuffix(iss, "/")
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("parsing iss %q: %w", iss, err)
	}
	locations := []string{
		// RFC 8414 §3.1: remove a terminating "/" and insert the well-known
		// segment between host and path.
		parsed.Scheme + "://" + parsed.Host + "/.well-known/oauth-authorization-server" + parsed.EscapedPath(),
		// OpenID Connect Discovery 1.0 §4 appends the well-known segment to
		// the issuer.
		trimmed + "/.well-known/openid-configuration",
	}
	var errs []string
	for _, location := range locations {
		doc, err := fetchDocument(location, clients...)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", location, err))
			continue
		}
		// RFC 8414 §3.3 and OpenID Connect Discovery 1.0 §4.3: the issuer
		// value "MUST be identical" to the issuer the URL was built from.
		if issuer, _ := doc["issuer"].(string); issuer != iss {
			errs = append(errs, fmt.Sprintf("%s: issuer mismatch: got %s want %s", location, issuer, iss))
			continue
		}
		uri, _ := doc["jwks_uri"].(string)
		if strings.TrimSpace(uri) == "" {
			errs = append(errs, fmt.Sprintf("%s: no jwks_uri", location))
			continue
		}
		return findJWKs(map[string]any{"jwks_uri": uri}, kid, clients...)
	}
	return nil, fmt.Errorf("fetching authorization server metadata: %s", strings.Join(errs, "; "))
}
