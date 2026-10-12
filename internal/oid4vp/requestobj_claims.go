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
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
)

// SelfIssuedAudience is the Request Object aud of OID4VP 1.0 §5.8: "the aud
// claim MUST be "https://self-issued.me/v2", when Static Discovery metadata
// is used." The wallet publishes no metadata with an issuer, so a Verifier
// cannot discover it dynamically and this is the only audience it accepts.
const SelfIssuedAudience = "https://self-issued.me/v2"

// requestObjectClaimFindings checks the exp and aud claims of a Request
// Object (RFC 9101 §4, OID4VP 1.0 §5.8).
func requestObjectClaimFindings(params *Request) []string {
	reqObj := params.RequestObject
	if reqObj == nil || reqObj.Payload == nil {
		return nil
	}
	var findings []string
	if raw, present := reqObj.Payload["exp"]; present {
		// RFC 7519 §4.1.4: "The processing of the "exp" claim requires that
		// the current date/time MUST be before the expiration date/time".
		exp, ok := raw.(float64)
		switch {
		case !ok:
			findings = append(findings, fmt.Sprintf("RFC 7519 §4.1.4: the Request Object exp must be a NumericDate, got %v", raw))
		case time.Unix(int64(exp), 0).Add(clockSkew).Before(time.Now()):
			findings = append(findings, fmt.Sprintf("RFC 7519 §4.1.4: the Request Object expired at %s", time.Unix(int64(exp), 0).UTC().Format(time.RFC3339)))
		}
	}
	// OpenID4VCI 1.1 §6.2.1.1 sends the request to the wallet during issuance,
	// where §5.8 names no audience.
	if raw, present := reqObj.Payload["aud"]; present && !IsInteractiveAuthorizationResponseMode(params.ResponseMode) {
		if !slices.Contains(jsonutil.Strings(audienceValues(raw)), SelfIssuedAudience) {
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §5.8: the Request Object aud must be %q, got %v", SelfIssuedAudience, raw))
		}
	}
	return findings
}

// audienceValues reads aud as RFC 7519 §4.1.3 allows it: "an array of case-
// sensitive strings" or "a single case-sensitive string".
func audienceValues(raw any) any {
	if single, ok := raw.(string); ok {
		return []any{single}
	}
	return raw
}

// missingAudienceAdvisory warns about a signed Request Object without aud.
// RFC 9101 §4: a signed Request Object "SHOULD contain the Claims iss
// (issuer) and aud (audience)". §5.8 only constrains the value.
func missingAudienceAdvisory(params *Request) string {
	reqObj := params.RequestObject
	if reqObj == nil || reqObj.Payload == nil || IsInteractiveAuthorizationResponseMode(params.ResponseMode) {
		return ""
	}
	if alg := jsonutil.GetString(reqObj.Header, "alg"); alg == "" || alg == "none" {
		return ""
	}
	if _, present := reqObj.Payload["aud"]; present {
		return ""
	}
	return fmt.Sprintf("RFC 9101 §4: the signed Request Object has no aud claim. OID4VP 1.0 §5.8 expects %q", SelfIssuedAudience)
}
