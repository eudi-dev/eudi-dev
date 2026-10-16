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
// trusted list of each credential category, the signing key and CA of each
// list, and the CAs of access and registration certificates.
package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

const (
	// eudi-dev 2 wallets store these types for their EAA list.
	legacyTrustListType       = "http://uri.etsi.org/19602/LoTEType/local"
	legacyIssuanceServiceType = "http://uri.etsi.org/19602/SvcType/Issuance"
	legacyRevocationService   = "http://uri.etsi.org/19602/SvcType/Revocation"

	// Default service names for a custom list without its own names.
	defaultIssuanceServiceName   = "Issuance Service"
	defaultRevocationServiceName = "Revocation Service"

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
	Category     string   `json:"category,omitempty"`
	Entitlements []string `json:"entitlements,omitempty"`
	// Scheme is the scheme of the trusted list that carries the type.
	lote.Scheme
}

// List is the trusted list that carries the credential type.
func (spec IssuedAttestationSpec) List() List {
	return List{Category: spec.Category, Scheme: spec.Scheme}
}

// List is one of the wallet's own trusted lists. For a category list,
// Category is the credential category of its providers. It is empty for the
// other lists.
type List struct {
	Category string
	lote.Scheme
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
	spec.Scheme = spec.Scheme.Trimmed()
	spec.Entitlements = dedupeStrings(spec.Entitlements)

	if category != "" {
		spec.Category = category
	}
	if spec.Category == UnlistedCategory {
		spec.Scheme = lote.Scheme{}
		return spec, nil
	}
	if err := credtemplate.CheckCategory(spec.Category); err != nil {
		return IssuedAttestationSpec{}, err
	}
	if spec.LoTEType == legacyTrustListType {
		spec.LoTEType = ""
		if spec.IssuanceServiceType == legacyIssuanceServiceType {
			spec.IssuanceServiceType = ""
		}
		if spec.RevocationServiceType == legacyRevocationService {
			spec.RevocationServiceType = ""
		}
		if spec.EntityName == config.WalletIssuerName {
			spec.EntityName = ""
		}
		if spec.IssuanceServiceName == defaultIssuanceServiceName {
			spec.IssuanceServiceName = ""
		}
		if spec.RevocationServiceName == defaultRevocationServiceName {
			spec.RevocationServiceName = ""
		}
	}
	if spec.LoTEType == lote.WalletProvidersListType {
		return IssuedAttestationSpec{}, fmt.Errorf("the wallet provider list holds wallet and key attestations, not credentials")
	}
	if spec.Category == "" {
		if category, ok := registrar.CategoryOfListType(spec.LoTEType); ok {
			spec.Category = category
		} else if spec.LoTEType == "" {
			spec.Category = credtemplate.CategoryEAA
		}
	}
	if spec.Category != "" {
		spec.Scheme = spec.Scheme.Or(CategoryList(spec.Category).Scheme)
		if len(spec.Entitlements) == 0 {
			spec.Entitlements = []string{registrar.CategoryOf(spec.Category).Entitlement}
		}
	}
	if spec.LoTEType != "" {
		spec.EntityName = jsonutil.FirstNonEmpty(spec.EntityName, config.WalletIssuerName)
		spec.IssuanceServiceName = jsonutil.FirstNonEmpty(spec.IssuanceServiceName, defaultIssuanceServiceName)
		spec.RevocationServiceName = jsonutil.FirstNonEmpty(spec.RevocationServiceName, defaultRevocationServiceName)
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

// CategoryList is the trusted list of a credential category. An empty or
// unknown category is an EAA.
func CategoryList(category string) List {
	c := registrar.CategoryOf(category)
	scheme := c.Scheme
	scheme.IssuanceServiceName = c.Label + " Issuance Service"
	scheme.RevocationServiceName = c.Label + " Revocation Service"
	scheme.EntityName = config.WalletName + " " + c.Label + " Provider"
	return List{Category: c.ID, Scheme: scheme}
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

// TrustedListsPath is where the wallet serves its trusted lists.
const TrustedListsPath = "/api/trustlists"

// TrustedListPath is the path of one of the wallet's trusted lists.
func TrustedListPath(id string) string {
	return TrustedListsPath + "/" + id
}

// The IDs of the lists of the wallet provider, the access CA and the
// registrar. A credential category list has the category as its ID.
const (
	AccessCAListID       = "access-ca"
	RegistrarListID      = "registrar"
	WalletProviderListID = "wallet-provider"
)

// AccessCAList is the list of the CAs of access certificates.
func AccessCAList() List {
	return List{Scheme: lote.Scheme{
		LoTEType:                    lote.AccessCertProvidersListType,
		StatusDeterminationApproach: accessCAStatusDetermination,
		SchemeTypeCommunityRules:    accessCASchemeCommunityRules,
		SchemeTerritory:             "EU",
		IssuanceServiceType:         accessCAIssuanceServiceType,
		RevocationServiceType:       accessCARevocationServiceType,
		IssuanceServiceName:         "Access Certificate Issuance",
		RevocationServiceName:       "Access Certificate Revocation",
		EntityName:                  config.ProductName + " Relying Party Access CA",
	}}
}

// RegistrarList is the list of the registrars that sign registration
// certificates.
func RegistrarList() List {
	return List{Scheme: lote.Scheme{
		LoTEType:                    lote.RegistrationCertProvidersListType,
		StatusDeterminationApproach: registrarStatusDetermination,
		SchemeTypeCommunityRules:    registrarSchemeCommunityRules,
		SchemeTerritory:             "EU",
		IssuanceServiceType:         registrarIssuanceServiceType,
		RevocationServiceType:       registrarRevocationServiceType,
		IssuanceServiceName:         "Registration Certificate Issuance",
		RevocationServiceName:       "Registration Certificate Revocation",
		EntityName:                  config.ProductName + " Registrar",
	}}
}

// WalletProviderList is the list whose CA anchors the wallet and key
// attestations sent to issuers.
func WalletProviderList() List {
	return List{Scheme: lote.Scheme{
		LoTEType:                    lote.WalletProvidersListType,
		StatusDeterminationApproach: walletProviderStatusDetermination,
		SchemeTypeCommunityRules:    walletProviderSchemeCommunityRules,
		SchemeTerritory:             "EU",
		IssuanceServiceType:         walletProviderIssuanceServiceType,
		RevocationServiceType:       walletProviderRevocationServiceType,
		// ETSI TS 119 602 V1.1.1 Table E.3: "The value of the ServiceName
		// component shall be the name of a wallet solution". The wallet's
		// attestations name it in wallet_name.
		IssuanceServiceName:   config.WalletName,
		RevocationServiceName: config.WalletName,
		EntityName:            config.WalletName + " Provider",
	}}
}

// listKey joins the fields that derive the ID of a custom list. The ID also
// identifies the stored signing key of the list.
func listKey(list List) string {
	parts := []string{
		list.Category,
		list.LoTEType,
		list.StatusDeterminationApproach,
		list.SchemeTypeCommunityRules,
		list.SchemeTerritory,
		list.IssuanceServiceType,
		list.RevocationServiceType,
		list.IssuanceServiceName,
		list.RevocationServiceName,
		list.EntityName,
	}
	return strings.Join(parts, "|")
}

// ListID uses the category as the ID of a category list. A spec
// that changes the defaults of its category gets a list of its own.
func ListID(list List) string {
	switch list.LoTEType {
	case lote.WalletProvidersListType:
		return WalletProviderListID
	case lote.AccessCertProvidersListType:
		return AccessCAListID
	case lote.RegistrationCertProvidersListType:
		return RegistrarListID
	}
	if list.Category != "" && list == CategoryList(list.Category) {
		return list.Category
	}
	hash := sha256.Sum256([]byte(listKey(list)))
	return "tl-" + hex.EncodeToString(hash[:4])
}
