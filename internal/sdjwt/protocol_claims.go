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
	"slices"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
)

// protocolClaims are the registered claims of RFC 7519 §4.1, the claims of
// SD-JWT VC §2.2.2.3 and the digest members of RFC 9901 §4.1.1 and §4.2.4.1.
var protocolClaims = func() map[string]bool {
	claims := map[string]bool{"_sd": true, "_sd_alg": true}
	for _, name := range append(slices.Clone(jws.RegisteredClaims), credtype.NeverDisclosedClaims...) {
		claims[name] = true
	}
	return claims
}()

// IsProtocolClaim reports whether a top-level claim of an SD-JWT VC carries
// protocol data instead of data about the subject. Claim counts, the claims a
// generated query asks for and the claims a verifier shows leave them out.
func IsProtocolClaim(name string) bool {
	return protocolClaims[name]
}
