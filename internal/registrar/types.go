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

// Package registrar implements the wallet's relying party registrar (ETSI TS 119 475,
// EC TS05) and its catalogue of attestations (EC TS11).
package registrar

import "encoding/json"

// Entitlements of ETSI TS 119 475 V1.2.1 Annex A.2.
const (
	ServiceProviderEntitlement = "https://uri.etsi.org/19475/Entitlement/Service_Provider"
	QEAAProviderEntitlement    = "https://uri.etsi.org/19475/Entitlement/QEAA_Provider"
	NonQEAAProviderEntitlement = "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"
	PubEAAProviderEntitlement  = "https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider"
	PIDProviderEntitlement     = "https://uri.etsi.org/19475/Entitlement/PID_Provider"
)

// IssuerInfoEntry is one element of issuer_info (ETSI TS 119 472-3) or
// verifier_info (ETSI TS 119 472-2).
type IssuerInfoEntry struct {
	Format string `json:"format"`
	Data   any    `json:"data"`
}

// Identifier is a TS05 identifier object.
type Identifier struct {
	Identifier string `json:"identifier"`
	Type       string `json:"type,omitempty"`
}

// MultiLangString is a localised string of TS05.
type MultiLangString struct {
	Lang    string `json:"lang"`
	Content string `json:"content"`
}

// ServiceDescription is the srvDescription of a TS05 v1.5 service: an array of
// arrays of MultiLangString (§2.4.1). Each inner array is one description in
// several languages. A flat array reads as one description.
type ServiceDescription [][]MultiLangString

func (d *ServiceDescription) UnmarshalJSON(data []byte) error {
	var nested [][]MultiLangString
	if err := json.Unmarshal(data, &nested); err == nil {
		*d = nested
		return nil
	}
	var flat []MultiLangString
	if err := json.Unmarshal(data, &flat); err != nil {
		return err
	}
	*d = nil
	if len(flat) > 0 {
		*d = ServiceDescription{flat}
	}
	return nil
}

// Strings lists every localised description.
func (d ServiceDescription) Strings() []MultiLangString {
	var out []MultiLangString
	for _, group := range d {
		out = append(out, group...)
	}
	return out
}

// SupervisoryAuthority is a supervisory authority record of TS05.
type SupervisoryAuthority struct {
	Name    string   `json:"name"`
	Country string   `json:"country"`
	Email   []string `json:"email,omitempty"`
	Phone   []string `json:"phone,omitempty"`
	FormURI []string `json:"formURI,omitempty"`
}

// ProvidedAttestation is an attestation type a provider issues (TS05 v1.5
// §2.4.8): its format and its vct or doctype.
type ProvidedAttestation struct {
	Format string `json:"format"`
	Type   string `json:"type"`
}

// certificateClaim is the provides_attestations entry of a registration
// certificate, which ETSI TS 119 475 V1.2.1 Table 8 shapes like a DCQL
// credential query.
func (a ProvidedAttestation) certificateClaim() map[string]any {
	if a.Format == "mso_mdoc" {
		return map[string]any{"format": a.Format, "meta": map[string]any{"doctype_value": a.Type}}
	}
	return map[string]any{"format": a.Format, "meta": map[string]any{"vct_values": []string{a.Type}}}
}

// RegistrarDataset is the registrar_dataset element of issuer_info. ETSI TS
// 119 472-3 V1.1.1 ISS-MDATA-REG_CERT-4.2.3-10 to -13 require these four
// members. The entitlements are in the registration certificate.
type RegistrarDataset struct {
	Identifier           []Identifier          `json:"identifier"`
	SrvDescription       []MultiLangString     `json:"srvDescription"`
	RegistryURI          string                `json:"registryURI"`
	ProvidesAttestations []ProvidedAttestation `json:"providesAttestations"`
}

// VerifierRegistrarDataset is the registrar_dataset element of verifier_info.
// ETSI TS 119 472-2 V1.2.1 §6.3.2.2 RO-06 to RO-11 require these members.
type VerifierRegistrarDataset struct {
	Identifier            []Identifier      `json:"identifier"`
	SrvDescription        []MultiLangString `json:"srvDescription"`
	RegistryURI           string            `json:"registryURI"`
	IntendedUseIdentifier string            `json:"intendedUseIdentifier"`
	Purpose               []MultiLangString `json:"purpose"`
	PolicyURI             string            `json:"policyURI"`
}

// registeredEntitlements are the entitlements of ETSI TS 119 475 V1.2.1 Annex
// A.2.
var registeredEntitlements = []string{
	ServiceProviderEntitlement,
	QEAAProviderEntitlement,
	NonQEAAProviderEntitlement,
	PubEAAProviderEntitlement,
	PIDProviderEntitlement,
	"https://uri.etsi.org/19475/Entitlement/QCert_for_ESeal_Provider",
	"https://uri.etsi.org/19475/Entitlement/QCert_for_ESig_Provider",
	"https://uri.etsi.org/19475/Entitlement/rQSealCDs_Provider",
	"https://uri.etsi.org/19475/Entitlement/rQSigCDs_Provider",
	"https://uri.etsi.org/19475/Entitlement/ESig_ESeal_Creation_Provider",
}

// providerEntitlements entitle a service to issue attestations, and its
// registration certificate lists them (ETSI TS 119 475 V1.2.1 GEN-5.2.4-05).
var providerEntitlements = []string{PIDProviderEntitlement, QEAAProviderEntitlement, PubEAAProviderEntitlement, NonQEAAProviderEntitlement}
