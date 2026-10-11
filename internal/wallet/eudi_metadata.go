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
	"maps"
	"sort"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
)

const (
	// ETSI TS 119 602 V1.1.1 registers no list type for QEAA or other EAA
	// providers. Annex C.1 has a scheme operator create its own URIs, and
	// §6.3.3 asks for one type per profile. The URIs name the profile, so
	// every deployment uses them whatever its base URL.
	qeaaTrustListType         = "https://eudi-test.dev/LoTEType/QEAAProvidersList"
	qeaaIssuanceServiceType   = "https://eudi-test.dev/SvcType/QEAA/Issuance"
	qeaaRevocationServiceType = "https://eudi-test.dev/SvcType/QEAA/Revocation"
	eaaTrustListType          = "https://eudi-test.dev/LoTEType/EAAProvidersList"
	eaaIssuanceServiceType    = "https://eudi-test.dev/SvcType/EAA/Issuance"
	eaaRevocationServiceType  = "https://eudi-test.dev/SvcType/EAA/Revocation"
	qeaaStatusDetermination   = "https://eudi-test.dev/QEAAProvidersList/StatusDetn"
	qeaaSchemeCommunityRules  = "https://eudi-test.dev/QEAAProvidersList/schemerules"
	eaaStatusDetermination    = "https://eudi-test.dev/EAAProvidersList/StatusDetn"
	eaaSchemeCommunityRules   = "https://eudi-test.dev/EAAProvidersList/schemerules"
	// eudi-dev 2 wallets store these types for their EAA list.
	legacyTrustListType       = "http://uri.etsi.org/19602/LoTEType/local"
	legacyIssuanceServiceType = "http://uri.etsi.org/19602/SvcType/Issuance"
	legacyRevocationService   = "http://uri.etsi.org/19602/SvcType/Revocation"

	pidTrustListType         = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList"
	pidStatusDetermination   = "http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU"
	pidSchemeCommunityRules  = "http://uri.etsi.org/19602/PIDProviders/schemerules/EU"
	pidIssuanceServiceType   = "http://uri.etsi.org/19602/SvcType/PID/Issuance"
	pidRevocationServiceType = "http://uri.etsi.org/19602/SvcType/PID/Revocation"

	// ETSI TS 119 602 V1.1.1 Annex H.
	pubEAATrustListType         = "http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList"
	pubEAAStatusDetermination   = "http://uri.etsi.org/19602/PubEAAProvidersList/StatusDetn/EU"
	pubEAASchemeCommunityRules  = "http://uri.etsi.org/19602/PubEAAProvidersList/schemerules/EU"
	pubEAAIssuanceServiceType   = "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance"
	pubEAARevocationServiceType = "http://uri.etsi.org/19602/SvcType/PubEAA/Revocation"

	// An issuer that checks a wallet or key attestation looks for a Wallet
	// Provider list. The wallet publishes one next to its credential lists.
	// The URIs come from ETSI TS 119 602.
	walletProviderTrustListType         = "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList"
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

type trustListProfile struct {
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

func (w *Wallet) issuedAttestationSpecs() []IssuedAttestationSpec {
	if w == nil {
		return nil
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if len(w.IssuedAttestations) > 0 {
		return dedupeIssuedAttestations(w.IssuedAttestations)
	}

	seen := make(map[string]bool)
	out := make([]IssuedAttestationSpec, 0)
	for _, cred := range w.Credentials {
		spec := IssuedAttestationSpec{Format: cred.Format, VCT: cred.VCT, DocType: cred.DocType}
		switch cred.Format {
		case "dc+sd-jwt":
			if strings.TrimSpace(spec.VCT) == "" {
				continue
			}
		case "mso_mdoc":
			if strings.TrimSpace(spec.DocType) == "" {
				continue
			}
		default:
			continue
		}
		key := spec.Format + "|" + spec.VCT + "|" + spec.DocType
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, spec)
	}
	return out
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
		if spec.EntityName == "EUDI Dev Wallet Issuer" {
			spec.EntityName = ""
		}
	}
	if spec.TrustListType == walletProviderTrustListType {
		return IssuedAttestationSpec{}, fmt.Errorf("the wallet provider list holds wallet and key attestations, not credentials")
	}
	switch {
	case spec.Category != "":
	case spec.TrustListType == pidTrustListType:
		spec.Category = credtemplate.CategoryPID
	case spec.TrustListType == pubEAATrustListType:
		spec.Category = credtemplate.CategoryPubEAA
	case spec.TrustListType == "":
		spec.Category = credtemplate.CategoryEAA
	}
	if spec.Category != "" {
		spec = applyCategoryDefaults(spec)
		if len(spec.Entitlements) == 0 {
			spec.Entitlements = []string{registrar.CategoryOf(spec.Category).Entitlement}
		}
	}
	if spec.TrustListType != "" {
		spec.EntityName = firstNonEmpty(spec.EntityName, "EUDI Dev Wallet Issuer")
		spec.IssuanceServiceName = firstNonEmpty(spec.IssuanceServiceName, "Issuance Service")
		spec.RevocationServiceName = firstNonEmpty(spec.RevocationServiceName, "Revocation Service")
	}
	return spec, nil
}

func dedupeIssuedAttestations(specs []IssuedAttestationSpec) []IssuedAttestationSpec {
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

// categoryTrustListProfile is the trusted list of a credential category. ETSI
// TS 119 602 V1.1.1 defines list types for PID providers (Annex D) and PuB-EAA
// providers (Annex H). QEAA providers are on TS 119 612 trusted lists, and
// other EAA providers have no list type, so both lists have types of their
// own.
func categoryTrustListProfile(category string) trustListProfile {
	switch category {
	case credtemplate.CategoryPID:
		return trustListProfile{
			Category:                    category,
			LoTEType:                    pidTrustListType,
			StatusDeterminationApproach: pidStatusDetermination,
			SchemeTypeCommunityRules:    pidSchemeCommunityRules,
			SchemeTerritory:             "EU",
			IssuanceServiceType:         pidIssuanceServiceType,
			RevocationServiceType:       pidRevocationServiceType,
			IssuanceServiceName:         "PID Issuance Service",
			RevocationServiceName:       "PID Revocation Service",
			EntityName:                  "EUDI Dev Wallet PID Provider",
		}
	case credtemplate.CategoryPubEAA:
		return trustListProfile{
			Category:                    category,
			LoTEType:                    pubEAATrustListType,
			StatusDeterminationApproach: pubEAAStatusDetermination,
			SchemeTypeCommunityRules:    pubEAASchemeCommunityRules,
			SchemeTerritory:             "EU",
			IssuanceServiceType:         pubEAAIssuanceServiceType,
			RevocationServiceType:       pubEAARevocationServiceType,
			IssuanceServiceName:         "PuB-EAA Issuance Service",
			RevocationServiceName:       "PuB-EAA Revocation Service",
			EntityName:                  "EUDI Dev Wallet PuB-EAA Provider",
		}
	case credtemplate.CategoryQEAA:
		return trustListProfile{
			Category:                    category,
			LoTEType:                    qeaaTrustListType,
			StatusDeterminationApproach: qeaaStatusDetermination,
			SchemeTypeCommunityRules:    qeaaSchemeCommunityRules,
			IssuanceServiceType:         qeaaIssuanceServiceType,
			RevocationServiceType:       qeaaRevocationServiceType,
			IssuanceServiceName:         "QEAA Issuance Service",
			RevocationServiceName:       "QEAA Revocation Service",
			EntityName:                  "EUDI Dev Wallet QEAA Provider",
		}
	default:
		return eaaTrustListProfile()
	}
}

func eaaTrustListProfile() trustListProfile {
	return trustListProfile{
		Category:                    credtemplate.CategoryEAA,
		LoTEType:                    eaaTrustListType,
		StatusDeterminationApproach: eaaStatusDetermination,
		SchemeTypeCommunityRules:    eaaSchemeCommunityRules,
		IssuanceServiceType:         eaaIssuanceServiceType,
		RevocationServiceType:       eaaRevocationServiceType,
		IssuanceServiceName:         "EAA Issuance Service",
		RevocationServiceName:       "EAA Revocation Service",
		EntityName:                  "EUDI Dev Wallet EAA Provider",
	}
}

// applyCategoryDefaults fills the empty trusted list fields of the spec from
// the list of its category.
func applyCategoryDefaults(spec IssuedAttestationSpec) IssuedAttestationSpec {
	p := categoryTrustListProfile(spec.Category)
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

// sanitizeMetadataID turns a credential type into a configuration id of at
// most 50 characters. A URN such as urn:eudi:pid:1 maps its ':' to '_'. Any
// other type could share that readable form with another type, so it gets a
// hash suffix and each type keeps its own configuration.
func sanitizeMetadataID(s string) string {
	readable := strings.NewReplacer(":", "_", ".", "_", "/", "_").Replace(s)
	trimmed := strings.TrimLeft(readable, "_")
	if trimmed != "" && trimmed == readable && !strings.ContainsAny(s, "_./") && len(trimmed) <= 50 {
		return trimmed
	}
	if trimmed == "" {
		trimmed = "credential"
	}
	sum := sha256.Sum256([]byte(s))
	return trimmed[:min(len(trimmed), 41)] + "_" + hex.EncodeToString(sum[:4])
}

func buildCredentialConfiguration(spec IssuedAttestationSpec) (string, map[string]any, bool) {
	switch spec.Format {
	case "dc+sd-jwt":
		if strings.TrimSpace(spec.VCT) == "" {
			return "", nil, false
		}
		id := "sdjwt_" + sanitizeMetadataID(spec.VCT)
		return id, map[string]any{
			"format": "dc+sd-jwt",
			"scope":  id,
			"vct":    spec.VCT,
			"cryptographic_binding_methods_supported": []string{"jwk"},
			"credential_signing_alg_values_supported": []string{"ES256"},
			"proof_types_supported": map[string]any{
				"jwt": map[string]any{
					"proof_signing_alg_values_supported": []string{"ES256"},
				},
			},
		}, true
	case "mso_mdoc":
		if strings.TrimSpace(spec.DocType) == "" {
			return "", nil, false
		}
		id := "mdoc_" + sanitizeMetadataID(spec.DocType)
		return id, map[string]any{
			"format":  "mso_mdoc",
			"scope":   id,
			"doctype": spec.DocType,
			"cryptographic_binding_methods_supported": []string{"cose_key"},
			"credential_signing_alg_values_supported": []int{-7},
			"proof_types_supported": map[string]any{
				"jwt": map[string]any{
					"proof_signing_alg_values_supported": []string{"ES256"},
				},
			},
		}, true
	default:
		return "", nil, false
	}
}

func buildOpenIDCredentialIssuerMetadata(w *Wallet, issuer string) (map[string]any, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	configs := make(map[string]any)
	for _, spec := range w.issuedAttestationSpecs() {
		id, cfg, ok := buildCredentialConfiguration(spec)
		if !ok {
			continue
		}
		configs[id] = cfg
	}

	metadata := map[string]any{
		"credential_issuer":                   issuer,
		"credential_endpoint":                 issuer + "/credential",
		"credential_configurations_supported": configs,
	}
	// Without a registration the metadata has no issuer_info, and a wallet
	// with --arf reports that (ETSI TS 119 472-3 §4.2.3).
	info, err := w.DemoIssuerInfo()
	if err != nil {
		return nil, err
	}
	if info != nil {
		metadata["issuer_info"] = info
	}
	return metadata, nil
}

func signJSONWebSignature(payload any, signingKey *ecdsa.PrivateKey, header map[string]any) (string, error) {
	if signingKey == nil {
		return "", fmt.Errorf("signing key is required")
	}
	return jws.Sign(header, payload, signingKey)
}

func buildJWSX5C(certs []*x509.Certificate) []string {
	chain := mock.WithoutSelfSignedTrustAnchor(certs)
	if len(chain) == 0 && len(certs) > 0 {
		chain = certs
	}
	x5c := make([]string, 0, len(chain))
	for _, cert := range chain {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))
	}
	return x5c
}

func signCredentialIssuerMetadataJWT(w *Wallet, issuer string, exp time.Time) (string, error) {
	metadata, err := buildOpenIDCredentialIssuerMetadata(w, issuer)
	if err != nil {
		return "", err
	}
	return SignCredentialIssuerMetadata(w, issuer, metadata, exp)
}

// SignCredentialIssuerMetadata signs the metadata with an access certificate,
// as TS 119 472-3 V1.1.1 §4.2.2 requires.
func SignCredentialIssuerMetadata(w *Wallet, issuer string, metadata map[string]any, exp time.Time) (string, error) {
	signingKey, signerCerts, err := w.AccessSigningMaterial()
	if err != nil {
		return "", err
	}
	payload := maps.Clone(metadata)
	payload["iss"] = issuer
	payload["sub"] = issuer
	payload["iat"] = time.Now().Unix()
	if !exp.IsZero() {
		payload["exp"] = exp.Unix()
	}
	header := map[string]any{
		"alg": "ES256",
		"typ": "openidvci-issuer-metadata+jwt",
	}
	if x5c := buildJWSX5C(signerCerts); len(x5c) > 0 {
		header["x5c"] = x5c
	}
	return signJSONWebSignature(payload, signingKey, header)
}

// SignRequestObjectJWT signs an OpenID4VP authorization request object (JAR)
// with the signer's certificate chain in x5c. Its typ is
// oauth-authz-req+jwt, as ValidateRequestObject expects.
func SignRequestObjectJWT(claims map[string]any, signingKey *ecdsa.PrivateKey, signerCerts []*x509.Certificate) (string, error) {
	if signingKey == nil {
		return "", fmt.Errorf("signing key is required")
	}
	header := map[string]any{
		"alg": "ES256",
		"typ": "oauth-authz-req+jwt",
	}
	if x5c := buildJWSX5C(signerCerts); len(x5c) > 0 {
		header["x5c"] = x5c
	}
	return signJSONWebSignature(claims, signingKey, header)
}

// X509HashClientID returns the `x509_hash:` client identifier for a leaf
// certificate. The value is the base64url-encoded SHA-256 of its DER encoding.
func X509HashClientID(leaf *x509.Certificate) string {
	if leaf == nil {
		return ""
	}
	sum := sha256.Sum256(leaf.Raw)
	return "x509_hash:" + format.EncodeBase64URL(sum[:])
}
