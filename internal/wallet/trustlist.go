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
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
)

type trustListOptions struct {
	OperatorName           string
	Issuer                 string
	TrustListPath          string
	Profile                trustListProfile
	Sequence               int
	IssuanceCertificates   []string
	RevocationCertificates []string
	// Entities are listed after the wallet's own provider.
	Entities []trustListEntity
}

// trustListEntity is a provider on a list with the base64 DER certificates of
// its issuance and revocation services.
type trustListEntity struct {
	Name                 string
	Issuance, Revocation []string
}

type TrustListGroup struct {
	ID      string
	Profile trustListProfile
	Specs   []IssuedAttestationSpec
}

type TrustListIndexEntry struct {
	ID                    string                  `json:"id"`
	Default               bool                    `json:"default"`
	Description           string                  `json:"description,omitempty"`
	Category              string                  `json:"category,omitempty"`
	Path                  string                  `json:"path"`
	LoTEType              string                  `json:"loTEType"`
	EntityName            string                  `json:"entityName"`
	IssuanceServiceType   string                  `json:"issuanceServiceType"`
	RevocationServiceType string                  `json:"revocationServiceType"`
	Attestations          []IssuedAttestationSpec `json:"attestations"`
	AdvertisedURL         string                  `json:"advertised_url,omitempty"`
	URL                   string                  `json:"url,omitempty"`
}

func GenerateTrustListJWTForWallet(w *Wallet, issuer string) (string, error) {
	if !w.hasCertificateAuthority() {
		return "", fmt.Errorf("wallet has no CA certificate chain")
	}
	group := DefaultTrustListGroupForWallet(w)
	return GenerateTrustListJWTForWalletGroup(w, issuer, group, "/api/trustlists/"+group.ID)
}

func GenerateTrustListJWTForWalletGroup(w *Wallet, issuer string, group TrustListGroup, path string) (string, error) {
	if !w.hasCertificateAuthority() {
		return "", fmt.Errorf("wallet has no CA certificate chain")
	}
	if path == "" {
		path = "/api/trustlist"
	}
	listKey, listChain, err := w.TrustListSigningMaterial("EUDI Dev Wallet", mock.DefaultCertificateCountry)
	if err != nil {
		return "", err
	}
	opts := trustListOptions{
		OperatorName:  "EUDI Dev Wallet",
		Issuer:        strings.TrimRight(strings.TrimSpace(issuer), "/"),
		TrustListPath: path,
		Profile:       group.Profile,
		Entities:      w.trustListEntities(group.ID),
	}
	switch group.ID {
	case accessCAListID:
		_, accessCA, err := w.RelyingPartyAccessCA()
		if err != nil {
			return "", err
		}
		opts.IssuanceCertificates = []string{base64.StdEncoding.EncodeToString(accessCA.Raw)}
		return w.signingStore().trustList(listKey, listChain[0], opts)
	case registrarListID:
		// The registrar key signs the registration certificates and their
		// status list.
		_, registrarCA, err := w.RegistrarCA()
		if err != nil {
			return "", err
		}
		opts.IssuanceCertificates = []string{base64.StdEncoding.EncodeToString(registrarCA.Raw)}
		opts.RevocationCertificates = opts.IssuanceCertificates
		return w.signingStore().trustList(listKey, listChain[0], opts)
	}
	var issuanceCertificates []string
	countries := []string{""}
	if group.Profile.Category == credtemplate.CategoryPID {
		countries = []string{"NL", "DE", "IT"}
	}
	for _, country := range countries {
		_, chain, err := w.signingMaterialForProfile(group.Profile, country)
		if err != nil {
			return "", err
		}
		issuanceCertificates = append(issuanceCertificates, base64.StdEncoding.EncodeToString(chain[0].Raw))
	}
	_, profileChain, err := w.signingMaterialForProfile(group.Profile, "")
	if err != nil {
		return "", err
	}
	certificates, err := w.signingStore().profileCertificates(profileChain[0], w.TrustAnchorCertificate())
	if err != nil {
		return "", err
	}
	seen := make(map[string]bool)
	for _, certificate := range issuanceCertificates {
		seen[certificate] = true
	}
	for _, certificate := range certificates {
		if !seen[certificate] {
			issuanceCertificates = append(issuanceCertificates, certificate)
			seen[certificate] = true
		}
	}
	_, statusChain, err := w.StatusListSigningMaterial()
	if err != nil {
		return "", err
	}
	opts.IssuanceCertificates = issuanceCertificates
	opts.RevocationCertificates = []string{base64.StdEncoding.EncodeToString(statusChain[0].Raw)}
	return w.signingStore().trustList(listKey, listChain[0], opts)
}

// TrustListGroupsForWallet lists one trusted list per credential category,
// the lists of credential types with their own trust profile, the wallet
// provider list, the access CA list and the registrar list. Unlisted credential
// types are on no list.
func TrustListGroupsForWallet(w *Wallet) []TrustListGroup {
	byID := make(map[string]*TrustListGroup)
	var groups []*TrustListGroup
	add := func(profile trustListProfile) *TrustListGroup {
		id := trustListGroupID(profile)
		if group := byID[id]; group != nil {
			return group
		}
		group := &TrustListGroup{ID: id, Profile: profile}
		byID[id] = group
		groups = append(groups, group)
		return group
	}
	for _, category := range credtemplate.Categories {
		add(categoryTrustListProfile(category))
	}
	add(walletProviderTrustListProfile())
	add(accessCATrustListProfile())
	add(registrarTrustListProfile())
	if w != nil {
		for _, spec := range w.issuedAttestationSpecs() {
			if spec.TrustListType == "" {
				continue
			}
			profile := trustListProfileFromSpec(spec)
			group := add(profile)
			group.Specs = append(group.Specs, spec)
		}
	}
	out := make([]TrustListGroup, 0, len(groups))
	for _, group := range groups {
		sort.Slice(group.Specs, func(i, j int) bool {
			if group.Specs[i].Format != group.Specs[j].Format {
				return group.Specs[i].Format < group.Specs[j].Format
			}
			if group.Specs[i].VCT != group.Specs[j].VCT {
				return group.Specs[i].VCT < group.Specs[j].VCT
			}
			return group.Specs[i].DocType < group.Specs[j].DocType
		})
		out = append(out, *group)
	}
	return out
}

// The wallet provider's CA anchors wallet and key attestations sent to issuers.
func walletProviderTrustListProfile() trustListProfile {
	return trustListProfile{
		LoTEType:                    walletProviderTrustListType,
		StatusDeterminationApproach: walletProviderStatusDetermination,
		SchemeTypeCommunityRules:    walletProviderSchemeCommunityRules,
		SchemeTerritory:             "EU",
		IssuanceServiceType:         walletProviderIssuanceServiceType,
		RevocationServiceType:       walletProviderRevocationServiceType,
		IssuanceServiceName:         "Wallet Attestation Issuance",
		RevocationServiceName:       "Wallet Attestation Revocation",
		EntityName:                  "EUDI Dev Wallet Provider",
	}
}

// DefaultTrustListGroupForWallet is the PID provider list.
func DefaultTrustListGroupForWallet(w *Wallet) TrustListGroup {
	return TrustListGroupsForWallet(w)[0]
}

func FindTrustListGroupForWallet(w *Wallet, id, vct, docType string) (TrustListGroup, bool) {
	groups := TrustListGroupsForWallet(w)
	if len(groups) == 0 {
		return TrustListGroup{}, false
	}
	id = strings.TrimSpace(id)
	vct = strings.TrimSpace(vct)
	docType = strings.TrimSpace(docType)

	if id != "" {
		for _, group := range groups {
			if group.ID == id {
				return group, true
			}
		}
		return TrustListGroup{}, false
	}
	if vct != "" || docType != "" {
		for _, group := range groups {
			for _, spec := range group.Specs {
				if (vct == "" || spec.VCT == vct) && (docType == "" || spec.DocType == docType) {
					return group, true
				}
			}
		}
		return TrustListGroup{}, false
	}
	return DefaultTrustListGroupForWallet(w), true
}

func BuildTrustListIndexEntries(w *Wallet, issuer string) []TrustListIndexEntry {
	groups := TrustListGroupsForWallet(w)
	defaultGroup := DefaultTrustListGroupForWallet(w)
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	entries := make([]TrustListIndexEntry, 0, len(groups))
	for _, group := range groups {
		path := "/api/trustlists/" + group.ID
		entry := TrustListIndexEntry{
			ID:                    group.ID,
			Default:               group.ID == defaultGroup.ID,
			Description:           trustListDescription(group),
			Category:              trustListCategory(group),
			Path:                  path,
			LoTEType:              group.Profile.LoTEType,
			EntityName:            group.Profile.EntityName,
			IssuanceServiceType:   group.Profile.IssuanceServiceType,
			RevocationServiceType: group.Profile.RevocationServiceType,
			Attestations:          append([]IssuedAttestationSpec(nil), group.Specs...),
		}
		if issuer != "" {
			entry.AdvertisedURL = issuer + path
			entry.URL = entry.AdvertisedURL
		}
		entries = append(entries, entry)
	}
	return entries
}

func trustListDescription(group TrustListGroup) string {
	switch group.Profile.LoTEType {
	case walletProviderTrustListType:
		return "Wallet and key attestations, for issuers"
	case accessCAListType:
		return "Access certificates of relying parties, for wallets"
	case registrarListType:
		return "Registration certificates and their status list, for wallets"
	}
	if group.ID != group.Profile.Category {
		return "Credentials with their own trusted list, for verifiers"
	}
	return registrar.CategoryOf(group.Profile.Category).Label + "s issued by this wallet, for verifiers"
}

func trustListCategory(group TrustListGroup) string {
	switch group.Profile.LoTEType {
	case walletProviderTrustListType:
		return "Wallet providers"
	case accessCAListType, registrarListType:
		return "Relying party certificates"
	}
	return "Credential providers"
}

func trustListProfileFromSpec(spec IssuedAttestationSpec) trustListProfile {
	return trustListProfile{
		Category:                    spec.Category,
		LoTEType:                    spec.TrustListType,
		StatusDeterminationApproach: spec.StatusDeterminationApproach,
		SchemeTypeCommunityRules:    spec.SchemeTypeCommunityRules,
		SchemeTerritory:             spec.SchemeTerritory,
		IssuanceServiceType:         spec.IssuanceServiceType,
		RevocationServiceType:       spec.RevocationServiceType,
		IssuanceServiceName:         spec.IssuanceServiceName,
		RevocationServiceName:       spec.RevocationServiceName,
		EntityName:                  spec.EntityName,
	}
}

func trustListProfileKey(profile trustListProfile) string {
	parts := []string{
		profile.Category,
		profile.LoTEType,
		profile.StatusDeterminationApproach,
		profile.SchemeTypeCommunityRules,
		profile.SchemeTerritory,
		profile.IssuanceServiceType,
		profile.RevocationServiceType,
		profile.IssuanceServiceName,
		profile.RevocationServiceName,
		profile.EntityName,
	}
	return strings.Join(parts, "|")
}

// trustListGroupID uses the category as the ID of a category list. A spec
// that changes the defaults of its category gets a list of its own.
func trustListGroupID(profile trustListProfile) string {
	switch profile.LoTEType {
	case walletProviderTrustListType:
		return walletProviderID
	case accessCAListType:
		return accessCAListID
	case registrarListType:
		return registrarListID
	}
	if profile.Category != "" && profile == categoryTrustListProfile(profile.Category) {
		return profile.Category
	}
	hash := sha256.Sum256([]byte(trustListProfileKey(profile)))
	return "tl-" + hex.EncodeToString(hash[:4])
}

// The listed provider is test data. ETSI TS 119 602 V1.1.1 Tables D.2, E.2
// and H.2 ask for its registration identifier as trade name and for a contact
// email and phone. A PID or PuB-EAA provider also names its Member State with
// a URI, and a PuB-EAA provider the law it is established under.
const (
	listedProviderName = "EUDI Dev Test Provider"
	// listedProviderEUID is the provider's registered EUID. Its certificates
	// carry it as NTRNL-NLTEST.00000000 (ETSI EN 319 412-1 V1.6.1
	// LEG-5.1.4-07 b).
	listedProviderEUID   = mock.DefaultCertificateCountry + "TEST.00000000"
	pubEAANotifiedStatus = "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified"
)

// trustedEntityInformation describes a listed entity. Its trade name is the
// official registration identifier its certificates carry, in the semantics
// of ETSI EN 319 412-1 LEG-5.1.4 (ETSI TS 119 602 V1.1.1 §6.5.2 and the
// TE trade name rows of Annexes D to H). An entity without one has none.
func trustedEntityInformation(opts trustListOptions, entity trustListEntity) map[string]any {
	var tradeName []map[string]string
	if identifier := certificatesOrganizationIdentifier(append(entity.Issuance, entity.Revocation...)); identifier != "" {
		tradeName = append(tradeName, map[string]string{"lang": "en", "value": identifier})
	}
	electronic := []map[string]string{
		{"lang": "en", "uriValue": firstNonEmpty(opts.Issuer, "https://github.com/dominikschlosser/eudi-dev")},
		{"lang": "en", "uriValue": "mailto:provider@example.invalid"},
		{"lang": "en", "uriValue": "tel:+31000000000"},
	}
	informationURIs := []map[string]string{{"lang": "en", "uriValue": firstNonEmpty(opts.Issuer, "https://github.com/dominikschlosser/eudi-dev")}}
	country := mock.DefaultCertificateCountry
	switch opts.Profile.LoTEType {
	case pidTrustListType:
		informationURIs = append(informationURIs, map[string]string{"lang": "en", "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/" + country})
	case walletProviderTrustListType:
		informationURIs = append(informationURIs, map[string]string{"lang": "en", "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/WalletProvider/" + country})
	case accessCAListType:
		informationURIs = append(informationURIs, map[string]string{"lang": "en", "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/WRPACProvider/" + country})
	case registrarListType:
		informationURIs = append(informationURIs, map[string]string{"lang": "en", "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/WRPRCProvider/" + country})
	case pubEAATrustListType:
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

func trustListService(serviceType, name string, certificates []string) map[string]any {
	return map[string]any{
		"ServiceInformation": map[string]any{
			"ServiceTypeIdentifier":  serviceType,
			"ServiceName":            []map[string]string{{"lang": "en", "value": name}},
			"ServiceDigitalIdentity": map[string]any{"X509Certificates": trustListCertificates(certificates)},
		},
	}
}

func generateTrustListJWTWithOptions(signingKey *ecdsa.PrivateKey, caCert *x509.Certificate, opts trustListOptions) (string, error) {
	certB64 := base64.StdEncoding.EncodeToString(caCert.Raw)
	certDigest := sha256.Sum256(caCert.Raw)
	if len(opts.IssuanceCertificates) == 0 {
		opts.IssuanceCertificates = []string{certB64}
		if len(opts.RevocationCertificates) == 0 {
			opts.RevocationCertificates = []string{certB64}
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	if opts.Sequence == 0 {
		opts.Sequence = 1
	}
	if strings.TrimSpace(opts.OperatorName) == "" {
		opts.OperatorName = "EUDI Dev Wallet"
	}
	if opts.Profile.LoTEType == "" {
		opts.Profile = eaaTrustListProfile()
	}

	if opts.Profile.SchemeTerritory == "" {
		opts.Profile.SchemeTerritory = "NL"
	}
	issueTime := now.Format(time.RFC3339Nano)
	nextUpdate := now.Add(24 * time.Hour).Format(time.RFC3339Nano)

	schemeInfo := map[string]any{
		"LoTEVersionIdentifier": 1,
		"LoTESequenceNumber":    opts.Sequence,
		"LoTEType":              opts.Profile.LoTEType,
		"SchemeOperatorName":    []map[string]string{{"lang": "en", "value": opts.OperatorName}},
		"ListIssueDateTime":     issueTime,
		"NextUpdate":            nextUpdate,
	}
	// ETSI TS 119 602 V1.1.1 Annexes D to H ask for scheme explicit lists, and
	// Table 1 makes every scheme element mandatory for them.
	schemeInfo["SchemeName"] = []map[string]string{{"lang": "en", "value": opts.Profile.SchemeTerritory + ": EUDI Dev Test Providers"}}
	schemeInfo["PolicyOrLegalNotice"] = []map[string]string{{"LoTELegalNotice": "Test data of eudi-dev. The listed providers are fictional and carry no official trust."}}
	schemeInfo["SchemeOperatorAddress"] = map[string]any{
		"SchemeOperatorPostalAddress":     []map[string]string{{"lang": "en", "StreetAddress": "Test address", "Country": "NL"}},
		"SchemeOperatorElectronicAddress": []map[string]string{{"lang": "en", "uriValue": "https://github.com/dominikschlosser/eudi-dev"}},
	}
	schemeInfo["StatusDeterminationApproach"] = firstNonEmpty(opts.Profile.StatusDeterminationApproach, eaaStatusDetermination)
	schemeInfo["SchemeTypeCommunityRules"] = []map[string]string{{"lang": "en", "uriValue": firstNonEmpty(opts.Profile.SchemeTypeCommunityRules, eaaSchemeCommunityRules)}}
	if opts.Profile.SchemeTerritory != "" {
		schemeInfo["SchemeTerritory"] = opts.Profile.SchemeTerritory
	}
	path := firstNonEmpty(opts.TrustListPath, "/api/trustlist")
	schemeURIs := []map[string]string{{"lang": "en", "uriValue": "https://github.com/dominikschlosser/eudi-dev/blob/main/docs/test-certificates.md"}}
	if opts.Issuer != "" {
		schemeURIs = append(schemeURIs, map[string]string{"lang": "en", "uriValue": opts.Issuer + path + "/history"})
		schemeInfo["DistributionPoints"] = []string{opts.Issuer + path}
	}
	schemeInfo["SchemeInformationURI"] = schemeURIs
	// ETSI TS 119 602 V1.1.1 Tables D.1 to G.1 require a pointer to the list
	// itself. Table H.1 forbids pointers and fixes the history period.
	if opts.Profile.LoTEType == pubEAATrustListType {
		schemeInfo["HistoricalInformationPeriod"] = 65535
	} else if opts.Issuer != "" {
		schemeInfo["PointersToOtherLoTE"] = []map[string]any{{
			"LoTELocation":             opts.Issuer + path,
			"ServiceDigitalIdentities": []map[string]any{{"X509Certificates": []map[string]string{{"val": certB64}}}},
			"LoTEQualifiers":           []map[string]any{{"LoTEType": opts.Profile.LoTEType, "SchemeOperatorName": schemeInfo["SchemeOperatorName"], "SchemeTerritory": schemeInfo["SchemeTerritory"], "MimeType": "application/jwt"}},
		}}
	}

	entities := append([]trustListEntity{{Name: listedProviderName, Issuance: opts.IssuanceCertificates, Revocation: opts.RevocationCertificates}}, opts.Entities...)
	trustedEntities := make([]map[string]any, 0, len(entities))
	for _, entity := range entities {
		trustedEntities = append(trustedEntities, map[string]any{
			"TrustedEntityInformation": trustedEntityInformation(opts, entity),
			"TrustedEntityServices":    trustListServices(opts.Profile, entity),
		})
	}
	payload := map[string]any{
		"LoTE": map[string]any{
			"ListAndSchemeInformation": schemeInfo,
			"TrustedEntitiesList":      trustedEntities,
		},
	}

	header := map[string]any{
		"alg":      "ES256",
		"typ":      "JWT",
		"x5c":      []string{certB64},
		"iat":      now.Unix(),
		"x5t#S256": base64.RawURLEncoding.EncodeToString(certDigest[:]),
	}

	return jws.Sign(header, payload, signingKey)
}

// trustListServices are the issuance and revocation services of an entity.
// A PuB-EAA list has one service per public key, and every service has a
// status (ETSI TS 119 602 V1.1.1 Table H.3).
func trustListServices(profile trustListProfile, entity trustListEntity) []map[string]any {
	var services []map[string]any
	if profile.LoTEType == pubEAATrustListType {
		for _, certificate := range entity.Issuance {
			services = append(services, trustListService(profile.IssuanceServiceType, profile.IssuanceServiceName, []string{certificate}))
		}
		if len(entity.Revocation) > 0 {
			services = append(services, trustListService(profile.RevocationServiceType, profile.RevocationServiceName, entity.Revocation))
		}
		for _, service := range services {
			service["ServiceInformation"].(map[string]any)["ServiceStatus"] = pubEAANotifiedStatus
		}
		return services
	}
	if len(entity.Issuance) > 0 {
		services = append(services, trustListService(profile.IssuanceServiceType, profile.IssuanceServiceName, entity.Issuance))
	}
	if len(entity.Revocation) > 0 {
		services = append(services, trustListService(profile.RevocationServiceType, profile.RevocationServiceName, entity.Revocation))
	}
	return services
}

func trustListCertificates(certificates []string) []map[string]string {
	values := make([]map[string]string, len(certificates))
	for i, cert := range certificates {
		values[i] = map[string]string{"val": cert}
	}
	return values
}

// certificatesOrganizationIdentifier returns the first organizationIdentifier
// (OID 2.5.4.97) of base64 DER certificates.
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
		if identifier := organizationIdentifier(cert); identifier != "" {
			return identifier
		}
	}
	return ""
}
