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

package proxy

import "testing"

func TestTrafficClassLabel(t *testing.T) {
	tests := []struct {
		class TrafficClass
		want  string
	}{
		{ClassUnknown, "Unknown"},
		{ClassVPAuthRequest, "VP auth request"},
		{ClassVPRequestObject, "VP request object"},
		{ClassVPAuthResponse, "VP auth response"},
		{ClassVCICredentialOffer, "VCI credential offer"},
		{ClassVCIMetadata, "VCI metadata"},
		{ClassVCITokenRequest, "VCI token request"},
		{ClassVCINonceRequest, "VCI nonce request"},
		{ClassVCICredentialRequest, "VCI credential request"},
		{ClassOIDCMetadata, "OIDC metadata"},
		{ClassOIDCAuthRequest, "OIDC auth request"},
		{ClassOIDCTokenRequest, "OIDC token request"},
		{ClassOIDCCallback, "OIDC callback"},
	}

	for _, tt := range tests {
		if got := tt.class.Label(); got != tt.want {
			t.Errorf("TrafficClass(%d).Label() = %q, want %q", tt.class, got, tt.want)
		}
	}
}

func TestTrafficClassLabelUnmapped(t *testing.T) {
	unmapped := TrafficClass(999)
	if got := unmapped.Label(); got != "Unknown" {
		t.Errorf("unmapped TrafficClass.Label() = %q, want 'Unknown'", got)
	}
}
