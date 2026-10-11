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

import "testing"

func TestValidateVCType(t *testing.T) {
	tests := []struct {
		name   string
		header map[string]any
		wantOK bool
	}{
		{"current type", map[string]any{"typ": "dc+sd-jwt"}, true},
		{"legacy type", map[string]any{"typ": "vc+sd-jwt"}, true},
		{"full media type", map[string]any{"typ": "application/dc+sd-jwt"}, true},
		{"upper case", map[string]any{"typ": "DC+SD-JWT"}, true},
		{"missing typ", map[string]any{"alg": "ES256"}, false},
		{"other typ", map[string]any{"typ": "JWT"}, false},
		{"non-string typ", map[string]any{"typ": 42}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateVCType(tt.header)
			if (err == nil) != tt.wantOK {
				t.Errorf("ValidateVCType(%v) error = %v, want ok = %v", tt.header, err, tt.wantOK)
			}
		})
	}
}
