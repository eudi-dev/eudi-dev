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
	"encoding/json"
	"fmt"
	"sort"

	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
)

// definedRequestParameters lists the Authorization Request parameters defined
// or reused by OID4VP 1.0 (§5.1, §5.2, §5.10, §8.2, Appendix A.2, RFC 6749,
// JAR).
var definedRequestParameters = map[string]bool{
	"client_id":          true,
	"response_type":      true,
	"response_mode":      true,
	"response_uri":       true,
	"redirect_uri":       true,
	"nonce":              true,
	"state":              true,
	"scope":              true,
	"request":            true,
	"request_uri":        true,
	"request_uri_method": true,
	"dcql_query":         true,
	"client_metadata":    true,
	"transaction_data":   true,
	"verifier_info":      true,
	"expected_origins":   true,
	"wallet_nonce":       true,
}

// definedRequestObjectMembers adds the members a signed request object may
// also carry: the RFC 7519 registered claims used by JAR.
var definedRequestObjectMembers = func() map[string]bool {
	merged := map[string]bool{}
	for _, name := range jws.RegisteredClaims {
		merged[name] = true
	}
	for name := range definedRequestParameters {
		merged[name] = true
	}
	return merged
}()

// UndefinedRequestParameterFindings names the request parameters that no
// specification defines. RFC 6749 §3.1 requires ignoring unrecognized
// parameters, so they are warnings even in strict mode.
func UndefinedRequestParameterFindings(params *Request) []string {
	if params == nil {
		return nil
	}
	undefined := map[string]bool{}
	if params.RequestObject != nil && params.RequestObject.Payload != nil {
		// Check outer parameters for diagnostics even though signed requests use only
		// Request Object members (OID4VP 1.0 §5.10.1).
		for name := range params.RequestObject.Payload {
			if !definedRequestObjectMembers[name] {
				undefined[name] = true
			}
		}
	} else if params.RequestPayload != nil {
		for name := range params.RequestPayload {
			if !definedRequestParameters[name] {
				undefined[name] = true
			}
		}
	}
	for name := range params.FullParams {
		if !definedRequestParameters[name] {
			undefined[name] = true
		}
	}

	names := make([]string, 0, len(undefined))
	for name := range undefined {
		names = append(names, name)
	}
	sort.Strings(names)

	findings := make([]string, 0, len(names))
	for _, name := range names {
		findings = append(findings, fmt.Sprintf("The request parameter %q is not defined in OID4VP 1.0 and is ignored", name))
	}
	return findings
}

// UndefinedResponseMembers names the members of a successful verifier
// response besides redirect_uri, the only one OID4VP 1.0 §8.2 defines.
// Non-2xx responses use OAuth error members instead.
func UndefinedResponseMembers(result *DirectPostResult) []string {
	if result == nil || result.StatusCode < 200 || result.StatusCode >= 300 {
		return nil
	}
	var respJSON map[string]any
	if json.Unmarshal([]byte(result.Body), &respJSON) != nil {
		return nil
	}
	var members []string
	for member := range respJSON {
		if member != "redirect_uri" {
			members = append(members, member)
		}
	}
	sort.Strings(members)
	return members
}
