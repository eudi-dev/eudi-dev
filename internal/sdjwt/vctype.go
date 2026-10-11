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
	"fmt"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
)

const (
	// TypeSDJWTVC is the typ header parameter of an SD-JWT VC.
	// draft-ietf-oauth-sd-jwt-vc-19 §2.2.1: "The Issuer MUST include the typ
	// header parameter in the SD-JWT. The typ value MUST use dc+sd-jwt."
	TypeSDJWTVC = "dc+sd-jwt"

	// TypeSDJWTVCLegacy is the typ value of earlier SD-JWT VC drafts. Reading
	// accepts it and reports a deviation. Issuance never uses it.
	TypeSDJWTVCLegacy = "vc+sd-jwt"

	// TypeKeyBinding is the typ of a Key Binding JWT (RFC 9901 §4.3).
	TypeKeyBinding = "kb+jwt"
)

func AcceptedVCTypes() []string {
	return []string{TypeSDJWTVC, TypeSDJWTVCLegacy}
}

// IsAcceptedVCType reports whether typ is an SD-JWT VC type.
func IsAcceptedVCType(typ string) bool {
	return format.JOSETypeIs(typ, TypeSDJWTVC) || format.JOSETypeIs(typ, TypeSDJWTVCLegacy)
}

// ValidateVCType checks the typ header parameter of an Issuer-signed JWT
// against the two accepted values. Without one of them a credential is no
// SD-JWT VC per draft-ietf-oauth-sd-jwt-vc-19 §2.2.1.
func ValidateVCType(header map[string]any) error {
	raw, present := header["typ"]
	if !present {
		return fmt.Errorf("no typ header parameter, want %s", TypeSDJWTVC)
	}
	typ, ok := raw.(string)
	if !ok {
		return fmt.Errorf("typ header parameter is not a string")
	}
	if !IsAcceptedVCType(typ) {
		return fmt.Errorf("typ header parameter is %q, want %s (or %s during the transition)", typ, TypeSDJWTVC, TypeSDJWTVCLegacy)
	}
	return nil
}
