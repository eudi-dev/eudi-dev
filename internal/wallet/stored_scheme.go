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
	"encoding/json"
	"fmt"

	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
)

// storedSchemeV2 holds the trusted list fields of an issued attestation under
// the names that eudi-dev 2 wallets store.
type storedSchemeV2 struct {
	TrustListType string `json:"trust_list_type"`
	EntityName    string `json:"entity_name"`
}

// upgradeStoredScheme fills the trusted list type and entity name of spec from
// data, a stored issued attestation, when data carries the eudi-dev 2 names.
func upgradeStoredScheme(spec *provider.IssuedAttestationSpec, data []byte) {
	var v2 storedSchemeV2
	if json.Unmarshal(data, &v2) != nil {
		return
	}
	if spec.LoTEType == "" {
		spec.LoTEType = v2.TrustListType
	}
	if spec.EntityName == "" {
		spec.EntityName = v2.EntityName
	}
}

// upgradeStoredSchemes applies upgradeStoredScheme to the issued attestations
// in data, the content of wallet.json.
func upgradeStoredSchemes(specs []provider.IssuedAttestationSpec, data []byte) {
	var stored struct {
		IssuedAttestations []json.RawMessage `json:"issued_attestations"`
	}
	if json.Unmarshal(data, &stored) != nil || len(stored.IssuedAttestations) != len(specs) {
		return
	}
	for i := range specs {
		upgradeStoredScheme(&specs[i], stored.IssuedAttestations[i])
	}
}

// refuseRenamedTrustFields refuses a POST /api/issue body whose trust object
// uses the eudi-dev 2 field names.
func refuseRenamedTrustFields(body []byte) error {
	var req struct {
		Trust map[string]json.RawMessage `json:"trust"`
	}
	if json.Unmarshal(body, &req) != nil {
		return nil
	}
	for _, field := range [][2]string{{"trust_list_type", "trusted_list_type"}, {"entity_name", "trusted_entity_name"}} {
		if _, ok := req.Trust[field[0]]; ok {
			return fmt.Errorf("trust.%s is not a field. Use trust.%s", field[0], field[1])
		}
	}
	return nil
}
