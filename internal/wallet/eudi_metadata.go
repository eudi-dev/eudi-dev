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
	"fmt"
	"maps"
	"sort"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/jws"
	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
)

const (
	serviceProviderEntitlement = "https://uri.etsi.org/19475/Entitlement/Service_Provider"
	nonQEAAProviderEntitlement = "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"
	pidProviderEntitlement     = "https://uri.etsi.org/19475/Entitlement/PID_Provider"
	localTrustListType         = "http://uri.etsi.org/19602/LoTEType/local"
	localIssuanceServiceType   = "http://uri.etsi.org/19602/SvcType/Issuance"
	localRevocationServiceType = "http://uri.etsi.org/19602/SvcType/Revocation"
	pidTrustListType           = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList"
	pidStatusDetermination     = "http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU"
	pidSchemeCommunityRules    = "http://uri.etsi.org/19602/PIDProviders/schemerules/EU"
	pidIssuanceServiceType     = "http://uri.etsi.org/19602/SvcType/PID/Issuance"
	pidRevocationServiceType   = "http://uri.etsi.org/19602/SvcType/PID/Revocation"

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
	Format                      string   `json:"format"`
	VCT                         string   `json:"vct,omitempty"`
	DocType                     string   `json:"doctype,omitempty"`
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

// IssuerInfoEntry matches ETSI TS 119 472-3 issuer_info elements.
type IssuerInfoEntry struct {
	Format string `json:"format"`
	Data   any    `json:"data"`
}

// Identifier is a minimal TS5-compatible identifier object.
type Identifier struct {
	Identifier string `json:"identifier"`
	Type       string `json:"type,omitempty"`
}

// MultiLangString is a localised string as defined in TS5.
type MultiLangString struct {
	Lang    string `json:"lang"`
	Content string `json:"content"`
}

// SupervisoryAuthority is a supervisory authority record as defined in TS5.
type SupervisoryAuthority struct {
	Name    string   `json:"name"`
	Country string   `json:"country"`
	Email   []string `json:"email,omitempty"`
	Phone   []string `json:"phone,omitempty"`
	FormURI []string `json:"formURI,omitempty"`
}

// ProvidedAttestation describes an issued attestation type in TS5 terms.
type ProvidedAttestation struct {
	Format string         `json:"format"`
	Meta   map[string]any `json:"meta"`
}

// RegistrarDataset is the minimal subset of registrar data needed for
// issuer-authorization checks.
type RegistrarDataset struct {
	Identifier           []Identifier          `json:"identifier"`
	TradeName            string                `json:"tradeName,omitempty"`
	SupportURI           []string              `json:"supportURI,omitempty"`
	SrvDescription       []MultiLangString     `json:"srvDescription"`
	IsPSB                bool                  `json:"isPSB"`
	Entitlements         []string              `json:"entitlements"`
	ProvidesAttestations []ProvidedAttestation `json:"providesAttestations"`
	SupervisoryAuthority SupervisoryAuthority  `json:"supervisoryAuthority"`
	RegistryURI          string                `json:"registryURI"`
	IsIntermediary       bool                  `json:"isIntermediary"`
}

type providerRegistrationProfile struct {
	Entitlements []string
	TradeName    string
	Description  string
}

type trustListProfile struct {
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
	if len(w.IssuedAttestations) > 0 {
		return dedupeIssuedAttestations(w.IssuedAttestations)
	}

	seen := make(map[string]bool)
	out := make([]IssuedAttestationSpec, 0)
	w.mu.RLock()
	defer w.mu.RUnlock()
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

func NormalizeIssuedAttestationSpec(spec IssuedAttestationSpec, trustProfileHint string) (IssuedAttestationSpec, error) {
	spec.Format = strings.TrimSpace(spec.Format)
	spec.VCT = strings.TrimSpace(spec.VCT)
	spec.DocType = strings.TrimSpace(spec.DocType)
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

	switch trustProfileHint {
	case "", "auto":
	case "pid":
		spec = applyPIDTrustProfileDefaults(spec)
	case "local":
		spec = applyLocalTrustProfileDefaults(spec)
	default:
		return IssuedAttestationSpec{}, fmt.Errorf("unsupported trust profile %q", trustProfileHint)
	}

	if len(spec.Entitlements) == 0 {
		if isPIDAttestation(spec) || spec.TrustListType == pidTrustListType {
			spec.Entitlements = []string{pidProviderEntitlement}
		} else if spec.VCT != "" || spec.DocType != "" {
			spec.Entitlements = []string{nonQEAAProviderEntitlement}
		} else {
			spec.Entitlements = []string{serviceProviderEntitlement}
		}
	}
	if spec.TrustListType == "" {
		if isPIDAttestation(spec) {
			spec = applyPIDTrustProfileDefaults(spec)
		} else {
			spec = applyLocalTrustProfileDefaults(spec)
		}
	}
	if spec.EntityName == "" {
		spec.EntityName = "EUDI Dev Wallet Issuer"
	}
	if spec.IssuanceServiceName == "" {
		spec.IssuanceServiceName = "Issuance Service"
	}
	if spec.RevocationServiceName == "" {
		spec.RevocationServiceName = "Revocation Service"
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

func applyPIDTrustProfileDefaults(spec IssuedAttestationSpec) IssuedAttestationSpec {
	if spec.TrustListType == "" {
		spec.TrustListType = pidTrustListType
	}
	if spec.StatusDeterminationApproach == "" {
		spec.StatusDeterminationApproach = pidStatusDetermination
	}
	if spec.SchemeTypeCommunityRules == "" {
		spec.SchemeTypeCommunityRules = pidSchemeCommunityRules
	}
	if spec.SchemeTerritory == "" {
		spec.SchemeTerritory = "EU"
	}
	if spec.EntityName == "" {
		spec.EntityName = "EUDI Dev Wallet PID Provider"
	}
	if spec.IssuanceServiceType == "" {
		spec.IssuanceServiceType = pidIssuanceServiceType
	}
	if spec.RevocationServiceType == "" {
		spec.RevocationServiceType = pidRevocationServiceType
	}
	if spec.IssuanceServiceName == "" {
		spec.IssuanceServiceName = "PID Issuance Service"
	}
	if spec.RevocationServiceName == "" {
		spec.RevocationServiceName = "PID Revocation Service"
	}
	return spec
}

func applyLocalTrustProfileDefaults(spec IssuedAttestationSpec) IssuedAttestationSpec {
	if spec.TrustListType == "" {
		spec.TrustListType = localTrustListType
	}
	if spec.EntityName == "" {
		spec.EntityName = "EUDI Dev Wallet Issuer"
	}
	if spec.IssuanceServiceType == "" {
		spec.IssuanceServiceType = localIssuanceServiceType
	}
	if spec.RevocationServiceType == "" {
		spec.RevocationServiceType = localRevocationServiceType
	}
	if spec.IssuanceServiceName == "" {
		spec.IssuanceServiceName = "Issuance Service"
	}
	if spec.RevocationServiceName == "" {
		spec.RevocationServiceName = "Revocation Service"
	}
	return spec
}

func isPIDAttestation(spec IssuedAttestationSpec) bool {
	vct := strings.TrimSpace(spec.VCT)
	docType := strings.TrimSpace(spec.DocType)
	switch {
	case strings.HasPrefix(vct, "urn:eudi:pid:"):
		return true
	case strings.HasPrefix(docType, "eu.europa.ec.eudi.pid."):
		return true
	default:
		return false
	}
}

func inferProviderRegistrationProfile(w *Wallet) providerRegistrationProfile {
	specs := w.issuedAttestationSpecs()
	entitlementSet := make([]string, 0)
	hasPID := false
	hasIssuer := false
	for _, spec := range specs {
		if isPIDAttestation(spec) {
			hasPID = true
		}
		if spec.VCT != "" || spec.DocType != "" {
			hasIssuer = true
		}
		entitlementSet = append(entitlementSet, spec.Entitlements...)
	}
	profile := providerRegistrationProfile{Entitlements: dedupeStrings(entitlementSet)}
	if len(profile.Entitlements) == 0 {
		profile.Entitlements = []string{serviceProviderEntitlement}
		profile.TradeName = "EUDI Dev Wallet Service Provider"
		profile.Description = "Local EUDI wallet service-provider dataset for testing"
		return profile
	}
	switch {
	case hasPID && hasIssuer && len(profile.Entitlements) > 1:
		profile.TradeName = "EUDI Dev Wallet Multi-Attestation Provider"
		profile.Description = "Local EUDI issuer dataset for mixed PID and non-PID attestation testing"
	case hasPID:
		profile.TradeName = "EUDI Dev Wallet PID Provider"
		profile.Description = "Local EUDI PID provider dataset for issuer-authorization testing"
	default:
		profile.TradeName = "EUDI Dev Wallet Non-PID Attestation Provider"
		profile.Description = "Local EUDI non-PID attestation provider dataset for issuer-authorization testing"
	}
	return profile
}

func inferWalletTrustListProfile(w *Wallet) trustListProfile {
	specs := w.issuedAttestationSpecs()
	if len(specs) > 0 {
		first := specs[0]
		sameProfile := true
		for _, spec := range specs[1:] {
			if spec.TrustListType != first.TrustListType ||
				spec.StatusDeterminationApproach != first.StatusDeterminationApproach ||
				spec.SchemeTypeCommunityRules != first.SchemeTypeCommunityRules ||
				spec.SchemeTerritory != first.SchemeTerritory ||
				spec.EntityName != first.EntityName ||
				spec.IssuanceServiceType != first.IssuanceServiceType ||
				spec.RevocationServiceType != first.RevocationServiceType ||
				spec.IssuanceServiceName != first.IssuanceServiceName ||
				spec.RevocationServiceName != first.RevocationServiceName {
				sameProfile = false
				break
			}
		}
		if sameProfile {
			return trustListProfile{
				LoTEType:                    first.TrustListType,
				StatusDeterminationApproach: first.StatusDeterminationApproach,
				SchemeTypeCommunityRules:    first.SchemeTypeCommunityRules,
				SchemeTerritory:             first.SchemeTerritory,
				IssuanceServiceType:         first.IssuanceServiceType,
				RevocationServiceType:       first.RevocationServiceType,
				IssuanceServiceName:         first.IssuanceServiceName,
				RevocationServiceName:       first.RevocationServiceName,
				EntityName:                  first.EntityName,
			}
		}
	}
	return trustListProfile{
		LoTEType:              localTrustListType,
		IssuanceServiceType:   localIssuanceServiceType,
		RevocationServiceType: localRevocationServiceType,
		IssuanceServiceName:   "Issuance Service",
		RevocationServiceName: "Revocation Service",
		EntityName:            "EUDI Dev Wallet Issuer",
	}
}

func sanitizeMetadataID(s string) string {
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.TrimLeft(s, "_")
	if len(s) > 50 {
		s = s[:50]
	}
	if s == "" {
		return "credential"
	}
	return s
}

func buildProvidedAttestation(spec IssuedAttestationSpec) (ProvidedAttestation, bool) {
	switch spec.Format {
	case "dc+sd-jwt":
		if strings.TrimSpace(spec.VCT) == "" {
			return ProvidedAttestation{}, false
		}
		return ProvidedAttestation{
			Format: spec.Format,
			Meta:   map[string]any{"vct_values": []string{spec.VCT}},
		}, true
	case "mso_mdoc":
		if strings.TrimSpace(spec.DocType) == "" {
			return ProvidedAttestation{}, false
		}
		return ProvidedAttestation{
			Format: spec.Format,
			Meta:   map[string]any{"doctype_value": spec.DocType},
		}, true
	default:
		return ProvidedAttestation{}, false
	}
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

func buildProviderIdentifier(issuer string) []Identifier {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return []Identifier{{Identifier: "urn:oid4vc-dev:wallet:issuer", Type: "uri"}}
	}
	return []Identifier{{Identifier: issuer, Type: "uri"}}
}

func buildRegistrarDataset(w *Wallet, issuer string) RegistrarDataset {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	registryURI := issuer + "/api/registrar/wrp"
	profile := inferProviderRegistrationProfile(w)
	provides := make([]ProvidedAttestation, 0)
	for _, spec := range w.issuedAttestationSpecs() {
		if att, ok := buildProvidedAttestation(spec); ok {
			provides = append(provides, att)
		}
	}
	if len(profile.Entitlements) == 1 && profile.Entitlements[0] == serviceProviderEntitlement {
		provides = nil
	}
	return RegistrarDataset{
		Identifier: buildProviderIdentifier(issuer),
		TradeName:  profile.TradeName,
		SupportURI: []string{issuer},
		SrvDescription: []MultiLangString{
			{Lang: "en", Content: profile.Description},
		},
		IsPSB:                false,
		Entitlements:         profile.Entitlements,
		ProvidesAttestations: provides,
		SupervisoryAuthority: SupervisoryAuthority{
			Name:    "Local Test Supervisory Authority",
			Country: "DE",
			Email:   []string{"dpa@example.invalid"},
		},
		RegistryURI:    registryURI,
		IsIntermediary: false,
	}
}

// IssuerInfo returns the issuer_info entries. They include the registration
// certificate that CIR (EU) 2026/1731 Annex XI requires.
func IssuerInfo(w *Wallet, issuer string, specs []IssuedAttestationSpec) ([]IssuerInfoEntry, error) {
	dataset := buildRegistrarDataset(&Wallet{IssuedAttestations: specs}, issuer)
	_, access, err := w.AccessSigningMaterial()
	if err != nil {
		return nil, err
	}
	key, chain, err := w.RegistrarSigningMaterial()
	if err != nil {
		return nil, err
	}
	identifier := access[0].Subject.CommonName
	for _, attribute := range access[0].Subject.Names {
		if attribute.Type.String() == "2.5.4.97" {
			identifier, _ = attribute.Value.(string)
			break
		}
	}
	now := time.Now()
	claims := map[string]any{
		"sub": identifier, "sub_ln": access[0].Subject.Organization[0],
		"country": access[0].Subject.Country[0], "name": dataset.TradeName,
		"registry_uri":    dataset.RegistryURI,
		"srv_description": []map[string]any{{"lang": "en", "value": dataset.SrvDescription[0].Content}},
		"entitlements":    dataset.Entitlements, "provides_attestations": dataset.ProvidesAttestations,
		"support_uri": issuer, "info_uri": issuer,
		"supervisory_authority": map[string]any{"email": dataset.SupervisoryAuthority.Email[0]},
		"policy_id":             []string{"0.4.0.19475.3.1"},
		"certificate_policy":    "https://github.com/eudi-dev/eudi-dev/blob/main/docs/test-certificates.md",
		"iat":                   now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}
	registration, err := SignRegistrationCertificateJWT(claims, key, chain)
	if err != nil {
		return nil, err
	}
	return []IssuerInfoEntry{
		{Format: "registrar_dataset", Data: dataset},
		{Format: "registration_cert", Data: registration},
	}, nil
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

	info, err := IssuerInfo(w, issuer, w.issuedAttestationSpecs())
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"credential_issuer":                   issuer,
		"credential_endpoint":                 issuer + "/credential",
		"credential_configurations_supported": configs,
		"issuer_info":                         info,
	}, nil
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
// with the signer's certificate chain in x5c. It sets the typ that
// ValidateRequestObject expects.
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

func signRegistrarResponseJWT(signingKey *ecdsa.PrivateKey, signerCerts []*x509.Certificate, payload any) (string, error) {
	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
	}
	if x5c := buildJWSX5C(signerCerts); len(x5c) > 0 {
		header["x5c"] = x5c
	}
	return signJSONWebSignature(payload, signingKey, header)
}
