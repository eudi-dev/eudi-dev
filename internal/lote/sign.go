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

package lote

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/certchain"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
)

// The list types that ETSI TS 119 602 V1.1.1 defines in Annexes D to H.
const (
	PIDProvidersListType              = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList"
	WalletProvidersListType           = "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList"
	AccessCertProvidersListType       = "http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList"
	RegistrationCertProvidersListType = "http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList"
	PubEAAProvidersListType           = "http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList"
)

// PubEAANotifiedStatus is the status of every service on a PuB-EAA list
// (ETSI TS 119 602 V1.1.1 Table H.3).
const PubEAANotifiedStatus = "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified"

const (
	projectURL           = "https://github.com/dominikschlosser/eudi-dev"
	schemeInformationURI = projectURL + "/blob/main/docs/test-certificates.md"
)

// Profile describes the scheme of a list and the services of its entities.
// Category is the credential category whose providers the list names. It is
// empty for the other lists.
type Profile struct {
	Category                    string
	LoTEType                    string
	StatusDeterminationApproach string
	SchemeTypeCommunityRules    string
	SchemeTerritory             string
	IssuanceServiceType         string
	RevocationServiceType       string
	IssuanceServiceName         string
	RevocationServiceName       string
	EntityName                  string
}

// Options describe a list that Sign builds. Path is the path of the
// list under Issuer. The operator's own provider, ProviderName, comes first
// with the issuance and revocation certificates. Without issuance certificates
// it lists the signer's certificate for both services. Country is the country
// of the operator and of the listed providers.
type Options struct {
	OperatorName           string
	Issuer                 string
	Path                   string `json:"TrustListPath"`
	Profile                Profile
	Sequence               int
	IssuanceCertificates   []string
	RevocationCertificates []string
	// Entities are listed after the operator's own provider.
	Entities     []Entity
	ProviderName string `json:"-"`
	Country      string `json:"-"`
}

// Entity is a provider on a list with the base64 DER certificates of its
// issuance and revocation services.
type Entity struct {
	Name                 string
	Issuance, Revocation []string
}

// UpdateInterval is the time to the NextUpdate of a list Sign builds.
const UpdateInterval = 24 * time.Hour

// Sign builds a list of trusted entities and signs it with the key of
// signer. It is the inverse of Parse.
func Sign(signingKey *ecdsa.PrivateKey, signer *x509.Certificate, opts Options) (string, error) {
	signerB64 := base64.StdEncoding.EncodeToString(signer.Raw)
	if len(opts.IssuanceCertificates) == 0 {
		opts.IssuanceCertificates = []string{signerB64}
		if len(opts.RevocationCertificates) == 0 {
			opts.RevocationCertificates = []string{signerB64}
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	if opts.Sequence == 0 {
		opts.Sequence = 1
	}

	schemeInfo := map[string]any{
		"LoTEVersionIdentifier": 1,
		"LoTESequenceNumber":    opts.Sequence,
		"LoTEType":              opts.Profile.LoTEType,
		"SchemeOperatorName":    []map[string]string{{"lang": "en", "value": opts.OperatorName}},
		"ListIssueDateTime":     now.Format(time.RFC3339Nano),
		"NextUpdate":            now.Add(UpdateInterval).Format(time.RFC3339Nano),
	}
	// ETSI TS 119 602 V1.1.1 Annexes D to H ask for scheme explicit lists, and
	// Table 1 makes every scheme element mandatory for them.
	schemeInfo["SchemeName"] = []map[string]string{{"lang": "en", "value": opts.Profile.SchemeTerritory + ": EUDI Dev Test Providers"}}
	schemeInfo["PolicyOrLegalNotice"] = []map[string]string{{"LoTELegalNotice": "Test data of eudi-dev. The listed providers are fictional and carry no official trust."}}
	schemeInfo["SchemeOperatorAddress"] = map[string]any{
		"SchemeOperatorPostalAddress":     []map[string]string{{"lang": "en", "StreetAddress": "Test address", "Country": opts.Country}},
		"SchemeOperatorElectronicAddress": []map[string]string{{"lang": "en", "uriValue": projectURL}},
	}
	schemeInfo["StatusDeterminationApproach"] = opts.Profile.StatusDeterminationApproach
	schemeInfo["SchemeTypeCommunityRules"] = []map[string]string{{"lang": "en", "uriValue": opts.Profile.SchemeTypeCommunityRules}}
	if opts.Profile.SchemeTerritory != "" {
		schemeInfo["SchemeTerritory"] = opts.Profile.SchemeTerritory
	}
	schemeURIs := []map[string]string{{"lang": "en", "uriValue": schemeInformationURI}}
	if opts.Issuer != "" {
		schemeURIs = append(schemeURIs, map[string]string{"lang": "en", "uriValue": opts.Issuer + opts.Path + "/history"})
		schemeInfo["DistributionPoints"] = []string{opts.Issuer + opts.Path}
	}
	schemeInfo["SchemeInformationURI"] = schemeURIs
	// ETSI TS 119 602 V1.1.1 Tables D.1 to G.1 require a pointer to the list
	// itself. Table H.1 forbids pointers and fixes the history period.
	if opts.Profile.LoTEType == PubEAAProvidersListType {
		schemeInfo["HistoricalInformationPeriod"] = 65535
	} else if opts.Issuer != "" {
		schemeInfo["PointersToOtherLoTE"] = []map[string]any{PointerEntry(opts.Issuer+opts.Path, opts.Profile.LoTEType, opts.OperatorName, opts.Profile.SchemeTerritory, signerB64)}
	}

	entities := append([]Entity{{Name: opts.ProviderName, Issuance: opts.IssuanceCertificates, Revocation: opts.RevocationCertificates}}, opts.Entities...)
	trustedEntities := make([]map[string]any, 0, len(entities))
	for _, entity := range entities {
		trustedEntities = append(trustedEntities, map[string]any{
			"TrustedEntityInformation": trustedEntityInformation(opts, entity),
			"TrustedEntityServices":    services(opts.Profile, entity),
		})
	}
	return SignList(signingKey, signer, now, map[string]any{
		"ListAndSchemeInformation": schemeInfo,
		"TrustedEntitiesList":      trustedEntities,
	})
}

// SignList signs the LoTE content of a list with the signer's certificate in
// x5c and x5t#S256.
func SignList(signingKey *ecdsa.PrivateKey, signer *x509.Certificate, issuedAt time.Time, lote map[string]any) (string, error) {
	digest := sha256.Sum256(signer.Raw)
	header := map[string]any{
		"alg":      jws.AlgES256,
		"typ":      "JWT",
		"x5c":      []string{base64.StdEncoding.EncodeToString(signer.Raw)},
		"iat":      issuedAt.Unix(),
		"x5t#S256": base64.RawURLEncoding.EncodeToString(digest[:]),
	}
	return jws.Sign(header, map[string]any{"LoTE": lote}, signingKey)
}

// PointerEntry is an OtherLoTEPointer of ETSI TS 119 602 V1.1.1 §6.3.13. It
// names the list's location, the certificate of its signer and the qualifiers
// of §6.3.13 c).
func PointerEntry(location, loteType, operatorName, territory, signer string) map[string]any {
	return map[string]any{
		"LoTELocation":             location,
		"ServiceDigitalIdentities": []map[string]any{{"X509Certificates": []map[string]string{{"val": signer}}}},
		"LoTEQualifiers": []map[string]any{{
			"LoTEType":           loteType,
			"SchemeOperatorName": []map[string]string{{"lang": "en", "value": operatorName}},
			"SchemeTerritory":    territory,
			"MimeType":           "application/jwt",
		}},
	}
}

// The listed provider is test data. ETSI TS 119 602 V1.1.1 Tables D.2, E.2
// and H.2 ask for its registration identifier as trade name and for a contact
// email and phone. A PID or PuB-EAA provider also names its Member State with
// a URI, and a PuB-EAA provider the law it is established under.
//
// The trade name is the official registration identifier the entity's
// certificates carry, in the semantics of ETSI EN 319 412-1 LEG-5.1.4 (ETSI
// TS 119 602 V1.1.1 §6.5.2 and the TE trade name rows of Annexes D to H). An
// entity without one has none.
func trustedEntityInformation(opts Options, entity Entity) map[string]any {
	var tradeName []map[string]string
	if identifier := certificatesOrganizationIdentifier(append(entity.Issuance, entity.Revocation...)); identifier != "" {
		tradeName = append(tradeName, map[string]string{"lang": "en", "value": identifier})
	}
	contact := firstNonEmpty(opts.Issuer, projectURL)
	electronic := []map[string]string{
		{"lang": "en", "uriValue": contact},
		{"lang": "en", "uriValue": "mailto:provider@example.invalid"},
		{"lang": "en", "uriValue": "tel:+31000000000"},
	}
	informationURIs := []map[string]string{{"lang": "en", "uriValue": contact}}
	country := opts.Country
	switch opts.Profile.LoTEType {
	case PIDProvidersListType:
		informationURIs = append(informationURIs, map[string]string{"lang": "en", "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/" + country})
	case WalletProvidersListType:
		informationURIs = append(informationURIs, map[string]string{"lang": "en", "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/WalletProvider/" + country})
	case AccessCertProvidersListType:
		informationURIs = append(informationURIs, map[string]string{"lang": "en", "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/WRPACProvider/" + country})
	case RegistrationCertProvidersListType:
		informationURIs = append(informationURIs, map[string]string{"lang": "en", "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/WRPRCProvider/" + country})
	case PubEAAProvidersListType:
		tradeName = append(tradeName, map[string]string{"lang": "en", "value": "OJ:" + country + "-eudi-dev-test"})
		electronic = append(electronic, map[string]string{"lang": "en", "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PubEAAProvider/" + country})
	}
	information := map[string]any{
		"TEName": []map[string]string{{"lang": "en", "value": entity.Name}},
		"TEAddress": map[string]any{
			"TEPostalAddress":     []map[string]string{{"lang": "en", "StreetAddress": "Test address", "Locality": "Test city", "PostalCode": "0000", "Country": country}},
			"TEElectronicAddress": electronic,
		},
		"TEInformationURI": informationURIs,
	}
	if len(tradeName) > 0 {
		information["TETradeName"] = tradeName
	}
	return information
}

// services are the issuance and revocation services of an entity. A PuB-EAA
// list has one service per public key, and every service has a status (ETSI
// TS 119 602 V1.1.1 Table H.3).
func services(profile Profile, entity Entity) []map[string]any {
	var out []map[string]any
	if profile.LoTEType == PubEAAProvidersListType {
		for _, certificate := range entity.Issuance {
			out = append(out, service(profile.IssuanceServiceType, profile.IssuanceServiceName, []string{certificate}))
		}
		if len(entity.Revocation) > 0 {
			out = append(out, service(profile.RevocationServiceType, profile.RevocationServiceName, entity.Revocation))
		}
		for _, s := range out {
			s["ServiceInformation"].(map[string]any)["ServiceStatus"] = PubEAANotifiedStatus
		}
		return out
	}
	if len(entity.Issuance) > 0 {
		out = append(out, service(profile.IssuanceServiceType, profile.IssuanceServiceName, entity.Issuance))
	}
	if len(entity.Revocation) > 0 {
		out = append(out, service(profile.RevocationServiceType, profile.RevocationServiceName, entity.Revocation))
	}
	return out
}

func service(serviceType, name string, certificates []string) map[string]any {
	values := make([]map[string]string, len(certificates))
	for i, cert := range certificates {
		values[i] = map[string]string{"val": cert}
	}
	return map[string]any{
		"ServiceInformation": map[string]any{
			"ServiceTypeIdentifier":  serviceType,
			"ServiceName":            []map[string]string{{"lang": "en", "value": name}},
			"ServiceDigitalIdentity": map[string]any{"X509Certificates": values},
		},
	}
}

// certificatesOrganizationIdentifier returns the first organizationIdentifier
// of base64 DER certificates.
func certificatesOrganizationIdentifier(certificates []string) string {
	for _, encoded := range certificates {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		if identifier := certchain.OrganizationIdentifier(cert); identifier != "" {
			return identifier
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
