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

package output

import "github.com/eudi-dev/eudi-dev/v3/internal/validate"

// BuildCredentialJSON is the JSON form of a validated credential, without its
// checks.
func BuildCredentialJSON(result *validate.Result) map[string]any {
	switch result.Format {
	case validate.FormatSDJWT:
		out := BuildSDJWTJSON(result.SDJWT)
		if result.Delegation != nil {
			out["delegation"] = BuildDelegationJSON(result.Delegation)
		}
		if result.Chain != nil {
			out["chain"] = BuildChainJSON(result.Chain)
		}
		return out
	case validate.FormatJWT:
		return BuildJWTJSON(result.SDJWT)
	case validate.FormatX509:
		return BuildCertificatesJSON(result.Certificates)
	}
	return BuildMDOCJSON(result.MDOC)
}
