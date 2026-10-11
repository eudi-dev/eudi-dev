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

import "fmt"

func ResolveClientMetadata(reqPayload map[string]any, outer map[string]any) map[string]any {
	if reqPayload != nil {
		if clientMeta, ok := reqPayload["client_metadata"].(map[string]any); ok {
			return clientMeta
		}
	}
	return outer
}

func ValidateClientMetadata(clientMeta map[string]any) error {
	if len(clientMeta) == 0 {
		return nil
	}

	if err := validateVPFormatsSupported(clientMeta["vp_formats_supported"]); err != nil {
		return err
	}
	if err := validateStringArrayField(clientMeta, "encrypted_response_enc_values_supported"); err != nil {
		return err
	}
	if err := validateJWKSField(clientMeta["jwks"]); err != nil {
		return err
	}

	return nil
}

// vpFormatAlgMembers lists the members of each vp_formats_supported entry in
// OID4VP 1.0 Appendix B, and whether the array holds COSE algorithm numbers.
// §11.1: "The Wallet MUST ignore any unrecognized parameters."
var vpFormatAlgMembers = map[string]map[string]bool{
	"dc+sd-jwt":   {"sd-jwt_alg_values": false, "kb-jwt_alg_values": false},       // B.3.4
	"mso_mdoc":    {"issuerauth_alg_values": true, "deviceauth_alg_values": true}, // B.2.2
	"jwt_vc_json": {"alg_values": false},                                          // B.1.3.1.3
	"ldp_vc":      {"proof_type_values": false, "cryptosuite_values": false},      // B.1.3.2.3
}

func validateVPFormatsSupported(raw any) error {
	if raw == nil {
		return nil
	}

	formats, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("client_metadata.vp_formats_supported must be an object")
	}

	for formatName, rawFormatMeta := range formats {
		formatMeta, ok := rawFormatMeta.(map[string]any)
		if !ok {
			return fmt.Errorf("client_metadata.vp_formats_supported.%s must be an object", formatName)
		}
		for member, numeric := range vpFormatAlgMembers[formatName] {
			if err := validateFormatAlgValues(formatName, member, numeric, formatMeta[member]); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateFormatAlgValues(formatName, member string, numeric bool, raw any) error {
	if raw == nil {
		return nil
	}

	values, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("client_metadata.vp_formats_supported.%s.%s must be an array", formatName, member)
	}

	for i, value := range values {
		if numeric {
			if !isJSONNumber(value) {
				return fmt.Errorf("client_metadata.vp_formats_supported.%s.%s[%d] must be a COSE algorithm number", formatName, member, i)
			}
			continue
		}
		if _, ok := value.(string); !ok {
			return fmt.Errorf("client_metadata.vp_formats_supported.%s.%s[%d] must be a string", formatName, member, i)
		}
	}

	return nil
}

func validateStringArrayField(clientMeta map[string]any, field string) error {
	raw, ok := clientMeta[field]
	if !ok || raw == nil {
		return nil
	}
	values, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("client_metadata.%s must be an array", field)
	}
	for i, value := range values {
		if _, ok := value.(string); !ok {
			return fmt.Errorf("client_metadata.%s[%d] must be a string", field, i)
		}
	}
	return nil
}

func validateJWKSField(raw any) error {
	if raw == nil {
		return nil
	}
	jwks, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("client_metadata.jwks must be an object")
	}
	keys, ok := jwks["keys"]
	if !ok {
		return fmt.Errorf("client_metadata.jwks.keys must be present")
	}
	keyList, ok := keys.([]any)
	if !ok {
		return fmt.Errorf("client_metadata.jwks.keys must be an array")
	}
	for i, key := range keyList {
		if _, ok := key.(map[string]any); !ok {
			return fmt.Errorf("client_metadata.jwks.keys[%d] must be an object", i)
		}
	}
	return nil
}

func isJSONNumber(v any) bool {
	switch v.(type) {
	case float64, float32, int, int8, int16, int32, int64:
		return true
	default:
		return false
	}
}
