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

// Package dcql generates Digital Credentials Query Language (DCQL) queries from
// existing credentials and matches credentials against a query.
package dcql

type Query struct {
	Credentials []CredentialQuery `json:"credentials"`
}

// CredentialQuery defines a single credential request. OID4VP 1.0 §6.1 makes
// id, format and meta REQUIRED, so meta is written even when empty ("If empty,
// no specific constraints are placed on the metadata"). claims is optional. When
// present it must be "a non-empty array", so an empty one is omitted.
type CredentialQuery struct {
	ID     string         `json:"id"`
	Format string         `json:"format"`
	Meta   CredentialMeta `json:"meta"`
	Claims []ClaimQuery   `json:"claims,omitempty"`
}

type CredentialMeta struct {
	VCTValues    []string `json:"vct_values,omitempty"`
	DoctypeValue string   `json:"doctype_value,omitempty"`
}

// ClaimQuery defines a single claim request. Path elements are strings for
// object keys or nil for an array wildcard.
type ClaimQuery struct {
	Path []any `json:"path"`
}
