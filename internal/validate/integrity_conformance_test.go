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
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
)

// draft-ietf-oauth-sd-jwt-vc-19 §2.2.1 requires dc+sd-jwt. A vc+sd-jwt token
// decodes but fails validation.
func TestCheckSDJWTType(t *testing.T) {
	tests := []struct {
		name   string
		header map[string]any
		want   string
	}{
		{name: "dc+sd-jwt", header: map[string]any{"typ": "dc+sd-jwt"}, want: "pass"},
		{name: "vc+sd-jwt", header: map[string]any{"typ": "vc+sd-jwt"}, want: "fail"},
		{name: "plain JWT", header: map[string]any{"typ": "JWT"}, want: "fail"},
		{name: "mixed case", header: map[string]any{"typ": "DC+SD-JWT"}, want: "pass"},
		{name: "full media type", header: map[string]any{"typ": "application/dc+sd-jwt"}, want: "pass"},
		{name: "legacy full media type", header: map[string]any{"typ": "application/vc+sd-jwt"}, want: "fail"},
		{name: "missing", header: map[string]any{"alg": "ES256"}, want: "fail"},
		{name: "not a string", header: map[string]any{"typ": 7}, want: "fail"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckSDJWTType(&sdjwt.Token{Header: tt.header})
			if got.Status != tt.want {
				t.Errorf("CheckSDJWTType(%v).Status = %q (%s), want %q", tt.header, got.Status, got.Detail, tt.want)
			}
		})
	}
}
