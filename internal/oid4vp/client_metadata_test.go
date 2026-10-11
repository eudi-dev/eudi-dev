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
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
)

func TestValidateClientMetadata_RejectsInvalidVPFormatsSupportedValue(t *testing.T) {
	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"vp_formats_supported": []any{},
			},
		},
	}

	err := validateClientMetadata(reqObj.Payload["client_metadata"].(map[string]any))
	if err == nil {
		t.Fatal("expected error for non-object vp_formats_supported")
	}
	if !contains(err.Error(), "vp_formats_supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateClientMetadata_RejectsInvalidMDocAlgValuesSupported(t *testing.T) {
	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"vp_formats_supported": map[string]any{
					"mso_mdoc": map[string]any{
						"issuerauth_alg_values": []any{"ES256"},
					},
				},
			},
		},
	}

	err := validateClientMetadata(reqObj.Payload["client_metadata"].(map[string]any))
	if err == nil {
		t.Fatal("expected error for string mso_mdoc issuerauth_alg_values entry")
	}
	if !contains(err.Error(), "COSE algorithm number") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateClientMetadata_AcceptsNumericMDocAlgValuesSupported(t *testing.T) {
	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"vp_formats_supported": map[string]any{
					"mso_mdoc": map[string]any{
						"deviceauth_alg_values": []any{-7.0},
					},
					"dc+sd-jwt": map[string]any{
						"sd-jwt_alg_values": []any{"ES256"},
					},
				},
			},
		},
	}

	if err := validateClientMetadata(reqObj.Payload["client_metadata"].(map[string]any)); err != nil {
		t.Fatalf("expected valid client_metadata, got %v", err)
	}
}

// OID4VP 1.0 Appendix B.3.4 names the SD-JWT algorithm members of
// vp_formats_supported. §5.1: "Other metadata parameters MUST be ignored".
func TestValidateClientMetadataChecksTheOID4VPMemberNames(t *testing.T) {
	err := validateClientMetadata(map[string]any{
		"vp_formats_supported": map[string]any{"dc+sd-jwt": map[string]any{"kb-jwt_alg_values": []any{-7.0}}},
	})
	if err == nil || !contains(err.Error(), "kb-jwt_alg_values") {
		t.Errorf("a numeric kb-jwt_alg_values entry gave %v, want an error", err)
	}
	if err := validateClientMetadata(map[string]any{"authorization_encryption_alg_values_supported": "ECDH-ES"}); err != nil {
		t.Errorf("a wallet metadata member in client_metadata gave %v, want it ignored", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
