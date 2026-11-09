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

package typemetadata

import "encoding/json"

// SCACategory is the category of an SCA Attestation (EUDI TS12 v1.0.1 §3).
const SCACategory = "urn:eu:europa:ec:eudi:sua:sca"

// TransactionDataType is an entry of transaction_data_types (EUDI TS12
// v1.0.1 §4.1). Each embedded member excludes its _uri counterpart.
type TransactionDataType struct {
	// Schema is a URN of a built-in type in the TS12 examples and an
	// embedded JSON Schema in the §4.1 text, so it keeps its JSON.
	Schema      json.RawMessage        `json:"schema,omitempty"`
	SchemaURI   string                 `json:"schema_uri,omitempty"`
	Claims      []TransactionDataClaim `json:"claims,omitempty"`
	ClaimsURI   string                 `json:"claims_uri,omitempty"`
	UILabels    map[string][]UILabel   `json:"ui_labels,omitempty"`
	UILabelsURI string                 `json:"ui_labels_uri,omitempty"`
}

// TransactionDataClaim is the metadata of a payload claim (EUDI TS12 v1.0.1
// §3.3.2).
type TransactionDataClaim struct {
	Path    []any                         `json:"path"`
	Display []TransactionDataClaimDisplay `json:"display,omitempty"`
	// Visualisation is 1 to 4. A wallet applies 3 when it is absent.
	Visualisation int `json:"visualisation,omitempty"`
}

// TransactionDataClaimDisplay is a claim label for one language. The TS12
// example calls the language member lang, and SD-JWT VC §5.6.2 calls it
// locale. A document carries both.
type TransactionDataClaimDisplay struct {
	Lang        string `json:"lang,omitempty"`
	Locale      string `json:"locale,omitempty"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
}

// UILabel is a localised UI element string (EUDI TS12 v1.0.1 §3.3.3).
type UILabel struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// IsSCA reports whether the metadata marks an SCA Attestation (EUDI TS12
// v1.0.1 §3).
func (m *Metadata) IsSCA() bool {
	return m != nil && m.Category == SCACategory
}
