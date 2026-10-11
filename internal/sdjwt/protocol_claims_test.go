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

package sdjwt

import (
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
)

// The registered JWT claims and the never disclosed SD-JWT VC claims carry
// protocol data, and a subject claim does not.
func TestProtocolClaimsCoverTheRegisteredClaims(t *testing.T) {
	for _, list := range [][]string{jws.RegisteredClaims, credtype.NeverDisclosedClaims, {"_sd", "_sd_alg"}} {
		for _, name := range list {
			if !IsProtocolClaim(name) {
				t.Errorf("%s is not a protocol claim", name)
			}
		}
	}
	if IsProtocolClaim("given_name") {
		t.Error("given_name is a protocol claim")
	}
}
