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
	"net/url"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
)

// The /authorize parameters reach the flow like any other parsed request,
// values with spaces included.
func TestParseAuthParamsKeepsEveryParameter(t *testing.T) {
	values := url.Values{
		"client_id":     {"redirect_uri:https://verifier.example/cb"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"response_uri":  {"https://verifier.example/cb"},
		"nonce":         {"n"},
		"state":         {"a b+c"},
		"scope":         {"openid profile"},
		"dcql_query":    {`{"credentials":[{"id":"q","format":"dc+sd-jwt"}]}`},
	}
	params, err := parseAuthParams(values, oid4vc.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if params.Scope != "openid profile" || params.State != "a b+c" {
		t.Errorf("scope %q state %q", params.Scope, params.State)
	}
	if params.FullParams["scope"] != "openid profile" || params.DCQLQuery == nil {
		t.Errorf("full params %v, dcql %v", params.FullParams, params.DCQLQuery)
	}
	broken, err := parseAuthParams(url.Values{"client_id": {"x"}, "dcql_query": {"{"}}, oid4vc.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAuthorizationRequest(ConformanceSettings{ValidationMode: ValidationModeDebug}, broken); err == nil {
		t.Error("a broken dcql_query was accepted")
	}
}
