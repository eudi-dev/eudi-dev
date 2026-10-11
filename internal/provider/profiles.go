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

// Package provider holds the wallet's provider keys and certificates: the
// trusted list profile of each credential category, the signing key and CA
// of each profile, and the CAs of access and registration certificates.
package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/config"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/lote"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
)

const (
	// eudi-dev 2 wallets store these types for their EAA list.
	legacyTrustListType       = "http://uri.etsi.org/19602/LoTEType/local"
	legacyIssuanceServiceType = "http://uri.etsi.org/19602/SvcType/Issuance"
	legacyRevocationService   = "http://uri.etsi.org/19602/SvcType/Revocation"

	// An issuer that checks a wallet or key attestation looks for a Wallet
	// Provider list. The wallet publishes one next to its credential lists.
	// The URIs come from ETSI TS 119 602.
	walletProviderStatusDetermination   = "http://uri.etsi.org/19602/WalletProvidersList/StatusDetn/EU"
	walletProviderSchemeCommunityRules  = "http://uri.etsi.org/19602/WalletProvidersList/schemerules/EU"
	walletProviderIssuanceServiceType   = "http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance"
	walletProviderRevocationServiceType = "http://uri.etsi.org/19602/SvcType/WalletSolution/Revocation"
)

type IssuedAttestationSpec struct {
	Format  string `json:"format"`
	VCT     string `json:"vct,omitempty"`
	DocType string `json:"doctype,omitempty"`
	// Category is pid, qeaa, pub-eaa, eaa or unlisted. It decides which of the
	// wallet's trusted lists carries the type. An unlisted type is on none.
	Category                    string   `json:"category,omitempty"`
	Entitlements                []string `json:"entitlements,omitempty"`
	TrustListType               string   `json:"trust_list_type,omitempty"`
	StatusDeterminationApproach string   `json:"status_determination_approach,omitempty"`
	SchemeTypeCommunityRules    string   `json:"scheme_type_community_rules,omitempty"`
	SchemeTerritory             string   `json:"scheme_territory,omitempty"`
	EntityName                  string   `json:"entity_name,omitempty"`
	IssuanceServiceType         string   `json:"issuance_service_type,omitempty"`
	RevocationServiceType       string   `json:"revocation_service_type,omitempty"`
	IssuanceServiceName         string   `json:"issuance_service_name,omitempty"`
	RevocationServiceName       string   `json:"revocation_service_name,omitempty"`
}

// UnlistedCategory keeps a credential type off every trusted list. It tests
// how a verifier handles an issuer without a trust anchor. It is not a
// credential category of the catalogue.
const UnlistedCategory = "unlisted"

// NormalizeIssuedAttestationSpec trims the spec and resolves its category. A
// non-empty category replaces the one of the spec. A type without a category
// and without trusted list fields is an EAA.
func NormalizeIssuedAttestationSpec(spec IssuedAttestationSpec, category string) (IssuedAttestationSpec, error) {
	spec.Format = strings.TrimSpace(spec.Format)
	spec.VCT = strings.TrimSpace(spec.VCT)
	spec.DocType = strings.TrimSpace(spec.DocType)
	spec.Category = strings.TrimSpace(spec.Category)
	spec.TrustListType = strings.TrimSpace(spec.TrustListType)
	spec.StatusDeterminationApproach = strings.TrimSpace(spec.StatusDeterminationApproach)
	spec.SchemeTypeCommunityRules = strings.TrimSpace(spec.SchemeTypeCommunityRules)
	spec.SchemeTerritory = strings.TrimSpace(spec.SchemeTerritory)
	spec.EntityName = strings.TrimSpace(spec.EntityName)
	spec.IssuanceServiceType = strings.TrimSpace(spec.IssuanceServiceType)
	spec.RevocationServiceType = strings.TrimSpace(spec.RevocationServiceType)
	spec.IssuanceServiceName = strings.TrimSpace(spec.IssuanceServiceName)
	spec.RevocationServiceName = strings.TrimSpace(spec.RevocationServiceName)
	spec.Entitlements = dedupeStrings(spec.Entitlements)

	if category != "" {
		spec.Category = category
	}
	if spec.Category == UnlistedCategory {
		spec.TrustListType, spec.StatusDeterminationApproach, spec.SchemeTypeCommunityRules, spec.SchemeTerritory = "", "", "", ""
		spec.EntityName, spec.IssuanceServiceType, spec.RevocationServiceType, spec.IssuanceServiceName, spec.RevocationServiceName = "", "", "", "", ""
		return spec, nil
	}
	if err := credtemplate.CheckCategory(spec.Category); err != nil {
		return IssuedAttestationSpec{}, err
	}
	if spec.TrustListType == legacyTrustListType {
		spec.TrustListType = ""
		if spec.IssuanceServiceType == legacyIssuanceServiceType {
			spec.IssuanceServiceType = ""
		}
		if spec.RevocationServiceType == legacyRevocationService {
			spec.RevocationServiceType = ""
		}
		if spec.EntityName == config.WalletIssuerName {
			spec.EntityName = ""
		}
	}
	if spec.TrustListType == lote.WalletProvidersListType {
		return IssuedAttestationSpec{}, fmt.Errorf("the wallet provider list holds wallet and key attestations, not credentials")
	}
	if spec.Category == "" {
		if category, ok := registrar.CategoryOfListType(spec.TrustListType); ok {
			spec.Category = category
		} else if spec.TrustListType == "" {
			spec.Category = credtemplate.CategoryEAA
		}
	}
	if spec.Category != "" {
		spec = ApplyCategoryDefaults(spec)
		if len(spec.Entitlements) == 0 {
			spec.Entitlements = []string{registrar.CategoryOf(spec.Category).Entitlement}
		}
	}
	if spec.TrustListType != "" {
		spec.EntityName = firstNonEmpty(spec.EntityName, config.WalletIssuerName)
		spec.IssuanceServiceName = firstNonEmpty(spec.IssuanceServiceName, "Issuance Service")
		spec.RevocationServiceName = firstNonEmpty(spec.RevocationServiceName, "Revocation Service")
	}
	return spec, nil
}

// DedupeIssuedAttestations normalizes the specs and keeps the last spec of
// each credential type, sorted by format and type.
func DedupeIssuedAttestations(specs []IssuedAttestationSpec) []IssuedAttestationSpec {
	seen := make(map[string]int)
	out := make([]IssuedAttestationSpec, 0, len(specs))
	for _, spec := range specs {
		normalized, err := NormalizeIssuedAttestationSpec(spec, "")
		if err != nil {
			continue
		}
		key := normalized.Format + "|" + normalized.VCT + "|" + normalized.DocType
		if idx, ok := seen[key]; ok {
			out[idx] = normalized
			continue
		}
		seen[key] = len(out)
		out = append(out, normalized)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Format != out[j].Format {
			return out[i].Format < out[j].Format
		}
		if out[i].VCT != out[j].VCT {
			return out[i].VCT < out[j].VCT
		}
		return out[i].DocType < out[j].DocType
	})
	return out
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// CategoryProfile is the trusted list of a credential category. An
// empty or unknown category is an EAA.
func CategoryProfile(category string) lote.Profile {
	c := registrar.CategoryOf(category)
	return lote.Profile{
		Category:                    c.ID,
		LoTEType:                    c.TrustedList.Type,
		StatusDeterminationApproach: c.TrustedList.StatusDeterminationApproach,
		SchemeTypeCommunityRules:    c.TrustedList.SchemeTypeCommunityRules,
		SchemeTerritory:             c.TrustedList.SchemeTerritory,
		IssuanceServiceType:         c.TrustedList.IssuanceServiceType,
		RevocationServiceType:       c.TrustedList.RevocationServiceType,
		IssuanceServiceName:         c.Label + " Issuance Service",
		RevocationServiceName:       c.Label + " Revocation Service",
		EntityName:                  config.WalletName + " " + c.Label + " Provider",
	}
}

// ApplyCategoryDefaults fills the empty trusted list fields of the spec from
// the list of its category.
func ApplyCategoryDefaults(spec IssuedAttestationSpec) IssuedAttestationSpec {
	p := CategoryProfile(spec.Category)
	spec.TrustListType = firstNonEmpty(spec.TrustListType, p.LoTEType)
	spec.StatusDeterminationApproach = firstNonEmpty(spec.StatusDeterminationApproach, p.StatusDeterminationApproach)
	spec.SchemeTypeCommunityRules = firstNonEmpty(spec.SchemeTypeCommunityRules, p.SchemeTypeCommunityRules)
	spec.SchemeTerritory = firstNonEmpty(spec.SchemeTerritory, p.SchemeTerritory)
	spec.EntityName = firstNonEmpty(spec.EntityName, p.EntityName)
	spec.IssuanceServiceType = firstNonEmpty(spec.IssuanceServiceType, p.IssuanceServiceType)
	spec.RevocationServiceType = firstNonEmpty(spec.RevocationServiceType, p.RevocationServiceType)
	spec.IssuanceServiceName = firstNonEmpty(spec.IssuanceServiceName, p.IssuanceServiceName)
	spec.RevocationServiceName = firstNonEmpty(spec.RevocationServiceName, p.RevocationServiceName)
	return spec
}

// The wallet publishes the providers of access certificates and of
// registration certificates on lists of their own (ARF RPACANot_05 and
// RPACANot_05a). The URIs come from ETSI TS 119 602 V1.1.1 Annexes F and G.
// Annex G spells its status determination URI "WRPRCrovidersList", and the
// constant keeps that spelling.
const (
	accessCAStatusDetermination   = "http://uri.etsi.org/19602/WRPACProvidersList/StatusDetn/EU"
	accessCASchemeCommunityRules  = "http://uri.etsi.org/19602/WRPACProvidersList/schemerules/EU"
	accessCAIssuanceServiceType   = "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance"
	accessCARevocationServiceType = "http://uri.etsi.org/19602/SvcType/WRPAC/Revocation"

	registrarStatusDetermination   = "http://uri.etsi.org/19602/WRPRCrovidersList/StatusDetn/EU"
	registrarSchemeCommunityRules  = "http://uri.etsi.org/19602/WRPRCProvidersList/schemerules/EU"
	registrarIssuanceServiceType   = "http://uri.etsi.org/19602/SvcType/WRPRC/Issuance"
	registrarRevocationServiceType = "http://uri.etsi.org/19602/SvcType/WRPRC/Revocation"
)

// The IDs of the lists of the wallet provider, the access CA and the
// registrar. A credential category list has the category as its ID.
const (
	AccessCAListID       = "access-ca"
	RegistrarListID      = "registrar"
	WalletProviderListID = "wallet-provider"
)

// AccessCAProfile is the list of the CAs of access certificates.
func AccessCAProfile() lote.Profile {
	return lote.Profile{
		LoTEType:                    lote.AccessCertProvidersListType,
		StatusDeterminationApproach: accessCAStatusDetermination,
		SchemeTypeCommunityRules:    accessCASchemeCommunityRules,
		SchemeTerritory:             "EU",
		IssuanceServiceType:         accessCAIssuanceServiceType,
		RevocationServiceType:       accessCARevocationServiceType,
		IssuanceServiceName:         "Access Certificate Issuance",
		RevocationServiceName:       "Access Certificate Revocation",
		EntityName:                  config.ProductName + " Relying Party Access CA",
	}
}

// RegistrarProfile is the list of the registrars that sign registration
// certificates.
func RegistrarProfile() lote.Profile {
	return lote.Profile{
		LoTEType:                    lote.RegistrationCertProvidersListType,
		StatusDeterminationApproach: registrarStatusDetermination,
		SchemeTypeCommunityRules:    registrarSchemeCommunityRules,
		SchemeTerritory:             "EU",
		IssuanceServiceType:         registrarIssuanceServiceType,
		RevocationServiceType:       registrarRevocationServiceType,
		IssuanceServiceName:         "Registration Certificate Issuance",
		RevocationServiceName:       "Registration Certificate Revocation",
		EntityName:                  config.ProductName + " Registrar",
	}
}

// WalletProviderProfile is the list whose CA anchors the wallet and key
// attestations sent to issuers.
func WalletProviderProfile() lote.Profile {
	return lote.Profile{
		LoTEType:                    lote.WalletProvidersListType,
		StatusDeterminationApproach: walletProviderStatusDetermination,
		SchemeTypeCommunityRules:    walletProviderSchemeCommunityRules,
		SchemeTerritory:             "EU",
		IssuanceServiceType:         walletProviderIssuanceServiceType,
		RevocationServiceType:       walletProviderRevocationServiceType,
		IssuanceServiceName:         "Wallet Attestation Issuance",
		RevocationServiceName:       "Wallet Attestation Revocation",
		EntityName:                  config.WalletName + " Provider",
	}
}

// SpecProfile is the trusted list that carries the credential type of spec.
func SpecProfile(spec IssuedAttestationSpec) lote.Profile {
	return lote.Profile{
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

func profileKey(profile lote.Profile) string {
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

// ListID uses the category as the ID of a category list. A spec
// that changes the defaults of its category gets a list of its own.
func ListID(profile lote.Profile) string {
	switch profile.LoTEType {
	case lote.WalletProvidersListType:
		return WalletProviderListID
	case lote.AccessCertProvidersListType:
		return AccessCAListID
	case lote.RegistrationCertProvidersListType:
		return RegistrarListID
	}
	if profile.Category != "" && profile == CategoryProfile(profile.Category) {
		return profile.Category
	}
	hash := sha256.Sum256([]byte(profileKey(profile)))
	return "tl-" + hex.EncodeToString(hash[:4])
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
