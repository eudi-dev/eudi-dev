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

// Package lote parses and signs lists of trusted entities (LoTE, ETSI TS 119
// 602) and extracts the certificates of their services.
package lote

import "crypto"

// List is a parsed list of trusted entities (ETSI TS 119 602).
type List struct {
	Raw        string
	Header     map[string]any
	SchemeInfo *SchemeInfo
	Entities   []TrustedEntity
	// Findings list the entities, services and certificates that Parse could
	// not read. Parse leaves them out of the list.
	Findings []string
}

type SchemeInfo struct {
	LoTEType           string
	SchemeOperatorName string
	SchemeTerritory    string
	ListIssueDatetime  string
	NextUpdate         string
	// Pointers are the PointersToOtherLoTE of ETSI TS 119 602 V1.1.1
	// §6.3.13.
	Pointers []Pointer
}

// Pointer identifies another list of trusted entities: its location, its type,
// its operator and the certificates of its signer (ETSI TS 119 602 V1.1.1
// §6.3.13).
type Pointer struct {
	Location           string
	LoTEType           string
	SchemeOperatorName string
	SchemeTerritory    string
	Certificates       []CertInfo
}

type TrustedEntity struct {
	Name     string
	Services []TrustedService
}

type TrustedService struct {
	ServiceType string
	// ServiceStatus is empty when the list has no service status (ETSI TS
	// 119 602 V1.1.1 §6.6.0).
	ServiceStatus string
	Certificates  []CertInfo
}

type CertInfo struct {
	Subject   string
	Issuer    string
	NotBefore string
	NotAfter  string
	PublicKey crypto.PublicKey
	Raw       []byte
}
