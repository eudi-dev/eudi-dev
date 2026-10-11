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

package registrar

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dominikschlosser/eudi-dev/v3/internal/certchain"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jsonutil"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
)

// RegistrationCertificateRequest selects what to certify. A verifier gets one
// certificate per intended use (ARF RPRC_09). An attestation provider gets one
// per service (ARF RPRC_13), so the request sets the service and no intended
// use.
type RegistrationCertificateRequest struct {
	Identifier            string `json:"identifier"`
	ServiceIdentifier     string `json:"serviceIdentifier,omitempty"`
	IntendedUseIdentifier string `json:"intendedUseIdentifier,omitempty"`
	// Validity is a Go duration of at most 12 months (TS 119 475 GEN-5.2.4-08).
	Validity string `json:"validity,omitempty"`
}

// ServiceIdentifierClaim carries the relying party service in a registration
// certificate (ARF RPRC_07a, RPRC_04a). ETSI TS 119 475 V1.2.1 Table 7 has no
// claim for it, so the certificate uses the attribute name of EC TS5 v1.5
// §2.4.1.
const ServiceIdentifierClaim = "serviceIdentifier"

// RegistrationCertificateContent is what a registration certificate says about
// the relying party (ETSI TS 119 475 V1.2.1 §5.2.4).
type RegistrationCertificateContent struct {
	// Name is the trade name. The wallet shows it (ARF RPRC_06).
	Name string
	// ServiceIdentifier is the organizationalUnit of the service's access
	// certificate (ARF RPRC_07a).
	ServiceIdentifier string
	Purpose           []MultiLangString
	// Identifier is the registered legal entity identifier (ARF RPRC_07).
	Identifier string
	// Subject is its semantics identifier, the sub of the certificate. It is
	// the organizationIdentifier of the access certificate (ETSI TS 119 475
	// V1.2.1 GEN-5.1.3-03).
	Subject              string
	LegalName            string
	Country              string
	Description          ServiceDescription
	Entitlements         []string
	RegistryURI          string
	PrivacyPolicy        string
	SupportURI           string
	SupervisoryAuthority SupervisoryAuthority
	// IntendedUseIdentifier is the registered intended use (ETSI TS 119 475
	// V1.2.1 Table 9).
	IntendedUseIdentifier string
	// ProvidesAttestations are the attestation types a provider issues (ETSI TS
	// 119 475 V1.2.1 Table 8).
	ProvidesAttestations []ProvidedAttestation
	Validity             string
	// StatusIndex is the certificate's entry in the registrar's status list.
	StatusIndex int
	// StatusListURI defaults to the status list under base.
	StatusListURI string
}

// RegistrationCertificateResult holds the signed certificate, wrapped in
// verifier_info for a verifier (OpenID4VP 1.0 §5.1) or in issuer_info for an
// attestation provider (ETSI TS 119 472-3 V1.1.1 §4.2.3).
type RegistrationCertificateResult struct {
	RegistrationCertificate string `json:"registrationCertificate"`
	// VerifierInfo and IssuerInfo are JSON arrays as strings, ready for a request
	// parameter or the issuer metadata.
	VerifierInfo string `json:"verifierInfo,omitempty"`
	IssuerInfo   string `json:"issuerInfo,omitempty"`
}

// The certificate policy of ETSI TS 119 475 V1.2.1 OVR-6.1.3-01 and the
// document that describes the registrar's test certificates.
const (
	registrationCertificatePolicy    = "0.4.0.19475.3.1"
	registrationCertificatePolicyURI = "https://github.com/dominikschlosser/eudi-dev/blob/main/docs/test-certificates.md"
)

// errRegistrarSigning marks a failure of the wallet's own signer (HTTP 500).
var errRegistrarSigning = errors.New("registrar signer")

// The validity of a registration certificate.
const (
	DefaultRegistrationValidity = 6 * 30 * 24 * time.Hour
	MaxRegistrationValidity     = 365 * 24 * time.Hour
)

// Hours writes a validity as a Go duration in whole hours, such as 4320h.
func Hours(d time.Duration) string {
	return fmt.Sprintf("%dh", int64(d/time.Hour))
}

// IssueRegistrationCertificate signs a registration certificate for a
// registered intended use, or for a provider service without one, with the
// wallet's registrar key.
func (r *Registrar) IssueRegistrationCertificate(req RegistrationCertificateRequest) (*RegistrationCertificateResult, error) {
	rp, key, err := r.certificateSubject(req)
	if err != nil {
		return nil, err
	}
	var signed string
	if key.intendedUse == "" {
		service, _ := serviceByIdentifier(rp, key.service)
		signed, err = r.issueCertificate(rp, key, ProviderCertificateContent(rp, service), nil, req.Validity)
	} else {
		service, use, _ := findIntendedUse(rp, "", key.intendedUse)
		credentials := make([]map[string]any, 0, len(use.Credentials))
		for _, c := range use.Credentials {
			credentials = append(credentials, map[string]any{"format": c.Format, "meta": c.Meta, "claims": c.Claims})
		}
		signed, err = r.issueCertificate(rp, key, registrationContent(rp, service, use), credentials, req.Validity)
	}
	if err != nil {
		return nil, err
	}
	return certificateResult(rp, key, signed)
}

// CurrentRegistrationCertificate returns the newest certificate for the
// request that is not replaced and stays valid for at least another day. A
// revoked one stays current until it is activated or replaced, so the demo
// verifier can test a revoked registration. Without one it issues a
// certificate and reports that.
func (r *Registrar) CurrentRegistrationCertificate(req RegistrationCertificateRequest) (*RegistrationCertificateResult, bool, error) {
	rp, key, err := r.certificateSubject(req)
	if err != nil {
		return nil, false, err
	}
	identifier := rp.Identifier[0].Identifier
	soon := time.Now().Add(24 * time.Hour).Unix()
	r.mu.RLock()
	var current string
	for _, s := range r.state.RegistrationStatuses {
		if s.Identifier == identifier && key.matches(s) && !s.Superseded && s.Certificate != "" && s.Expires > soon {
			current = s.Certificate
		}
	}
	r.mu.RUnlock()
	if current == "" {
		result, err := r.IssueRegistrationCertificate(req)
		return result, err == nil, err
	}
	result, err := certificateResult(rp, key, current)
	return result, false, err
}

// CertificateRequests names every registration certificate of a relying
// party: one per attestation provider service (ARF RPRC_13) and one per
// intended use (ARF RPRC_09).
func CertificateRequests(rp WalletRelyingParty) []RegistrationCertificateRequest {
	id := rp.Identifier[0].Identifier
	var reqs []RegistrationCertificateRequest
	for _, service := range rp.Services {
		if isAttestationProvider(service) {
			reqs = append(reqs, RegistrationCertificateRequest{Identifier: id, ServiceIdentifier: service.ServiceIdentifier})
		}
		for _, use := range service.IntendedUses {
			reqs = append(reqs, RegistrationCertificateRequest{Identifier: id, IntendedUseIdentifier: use.IntendedUseIdentifier})
		}
	}
	return reqs
}

// certificateSubject finds the registration and what the certificate
// certifies.
func (r *Registrar) certificateSubject(req RegistrationCertificateRequest) (WalletRelyingParty, certificateKey, error) {
	rp, ok := r.RelyingParty(req.Identifier)
	if !ok {
		return rp, certificateKey{}, fmt.Errorf("%w: %s", errRelyingPartyNotFound, req.Identifier)
	}
	if req.IntendedUseIdentifier == "" {
		service, err := providerService(rp, req.ServiceIdentifier)
		return rp, certificateKey{service: service.ServiceIdentifier}, err
	}
	if _, _, ok := findIntendedUse(rp, req.ServiceIdentifier, req.IntendedUseIdentifier); !ok {
		return rp, certificateKey{}, fmt.Errorf("%w: no intended use %q", errRelyingPartyNotFound, req.IntendedUseIdentifier)
	}
	return rp, certificateKey{intendedUse: req.IntendedUseIdentifier}, nil
}

// certificateResult wraps a verifier's certificate in verifier_info and a
// provider's certificate in issuer_info (ARF RPRC_22).
func certificateResult(rp WalletRelyingParty, key certificateKey, signed string) (*RegistrationCertificateResult, error) {
	if key.intendedUse != "" {
		service, use, _ := findIntendedUse(rp, "", key.intendedUse)
		info, err := VerifierInfoValue(verifierRegistrarDataset(rp, service, use), signed)
		if err != nil {
			return nil, err
		}
		return &RegistrationCertificateResult{RegistrationCertificate: signed, VerifierInfo: info}, nil
	}
	service, _ := serviceByIdentifier(rp, key.service)
	info, err := IssuerInfoValue(RegistrarDatasetFor(rp, service), signed)
	if err != nil {
		return nil, err
	}
	return &RegistrationCertificateResult{RegistrationCertificate: signed, IssuerInfo: info}, nil
}

// providerService returns the provider service a certificate is for. Without a
// service identifier the relying party must have exactly one.
func providerService(rp WalletRelyingParty, serviceIdentifier string) (WalletRelyingPartyService, error) {
	if serviceIdentifier != "" {
		service, ok := serviceByIdentifier(rp, serviceIdentifier)
		if !ok {
			return service, fmt.Errorf("%w: no service %q", errRelyingPartyNotFound, serviceIdentifier)
		}
		if !isAttestationProvider(service) {
			return service, fmt.Errorf("%w as an attestation provider: service %q. Issue its certificates per intended use", errRelyingPartyNotFound, serviceIdentifier)
		}
		return service, nil
	}
	providers := slices.DeleteFunc(slices.Clone(rp.Services), func(s WalletRelyingPartyService) bool { return !isAttestationProvider(s) })
	if len(providers) == 0 {
		return WalletRelyingPartyService{}, fmt.Errorf("%w as an attestation provider: %s", errRelyingPartyNotFound, rp.Identifier[0].Identifier)
	}
	if len(providers) != 1 {
		return WalletRelyingPartyService{}, fmt.Errorf("%s has %d attestation provider services and no intended use was given, so name the service or the intended use", rp.Identifier[0].Identifier, len(providers))
	}
	return providers[0], nil
}

// issueCertificate reserves a status entry, signs the certificate and revokes
// the one it replaces.
func (r *Registrar) issueCertificate(rp WalletRelyingParty, key certificateKey, content RegistrationCertificateContent, credentials []map[string]any, validityValue string) (string, error) {
	content.Validity = validityValue
	validity, err := registrationValidity(validityValue)
	if err != nil {
		return "", err
	}
	now := time.Now()
	content.StatusListURI = r.RegistrationStatusListURL()
	content.StatusIndex, err = r.allocateRegistrationStatus(rp, key, now.Add(validity))
	if err != nil {
		return "", err
	}
	signed, err := r.signRegistrationCertificate(content, credentials, now)
	if err != nil {
		r.releaseRegistrationStatus(content.StatusIndex)
		return "", err
	}
	r.replaceRegistrationStatus(content.Identifier, key, content.StatusIndex, signed)
	return signed, nil
}

// ProviderCertificateContent returns the content of a provider certificate
// for the service. A provider certificate has no intended use (ARF RPRC_05).
// TS05 stores the purpose, the privacy policy and the credentials per intended
// use, so a provider certificate has none of them. ETSI TS 119 475 V1.2.1
// GEN-5.2.4-01 fills a certificate from the register.
func ProviderCertificateContent(rp WalletRelyingParty, service WalletRelyingPartyService) RegistrationCertificateContent {
	content := registrationContent(rp, service, IntendedUse{})
	content.Entitlements = service.Entitlements
	content.ProvidesAttestations = service.ProvidesAttestations
	return content
}

// RegistrarDatasetFor is the registrar_dataset entry of issuer_info (ETSI TS 119
// 472-3 V1.1.1 §4.2.3). It sits next to the registration certificate.
func RegistrarDatasetFor(rp WalletRelyingParty, service WalletRelyingPartyService) RegistrarDataset {
	return RegistrarDataset{
		Identifier:           rp.Identifier,
		SrvDescription:       service.SrvDescription.Strings(),
		RegistryURI:          rp.RegistryURI,
		ProvidesAttestations: service.ProvidesAttestations,
	}
}

// IssuerInfoValue builds the issuer_info array of ETSI TS 119 472-3 V1.1.1
// §4.2.3: the registrar dataset and the registration certificate, whose data
// "shall be the registration certificate" itself (ISS-MDATA-REG_CERT-4.2.3-06).
func IssuerInfoValue(dataset RegistrarDataset, registrationCertificate string) (string, error) {
	return infoValue("issuer_info", IssuerInfoEntry{Format: "registrar_dataset", Data: dataset}, IssuerInfoEntry{Format: "registration_cert", Data: registrationCertificate})
}

// verifierRegistrarDataset is the registrar_dataset entry of verifier_info
// (ETSI TS 119 472-2 V1.3.1 §6.3.2.2) for an intended use.
func verifierRegistrarDataset(rp WalletRelyingParty, service WalletRelyingPartyService, use IntendedUse) VerifierRegistrarDataset {
	return VerifierRegistrarDataset{
		Identifier:            rp.Identifier,
		SrvDescription:        service.SrvDescription.Strings(),
		RegistryURI:           rp.RegistryURI,
		IntendedUseIdentifier: use.IntendedUseIdentifier,
		Purpose:               use.Purpose,
		PolicyURI:             privacyPolicyURI(use),
	}
}

// VerifierInfoValue builds the verifier_info array of OpenID4VP 1.0 §5.1 as
// ETSI TS 119 472-2 V1.3.1 §6.3.2.2 profiles it: the registration certificate
// and the registrar dataset. RO-16 makes the data "the base64url encoding of
// the serialized RP registration certificate", which for a JWT is its compact
// serialization (RFC 7519 §1). Base64url omits the padding (RFC 7515 §2).
func VerifierInfoValue(dataset VerifierRegistrarDataset, registrationCertificate string) (string, error) {
	data := base64.RawURLEncoding.EncodeToString([]byte(registrationCertificate))
	return infoValue("verifier_info", IssuerInfoEntry{Format: "registration_cert", Data: data}, IssuerInfoEntry{Format: "registrar_dataset", Data: dataset})
}

func infoValue(name string, entries ...IssuerInfoEntry) (string, error) {
	encoded, err := json.Marshal(entries)
	if err != nil {
		return "", fmt.Errorf("encoding %s: %w", name, err)
	}
	return string(encoded), nil
}

// registrationContent returns what a certificate for the intended use contains,
// apart from the credentials.
func registrationContent(rp WalletRelyingParty, service WalletRelyingPartyService, use IntendedUse) RegistrationCertificateContent {
	return RegistrationCertificateContent{
		Name:              service.ServiceTradeName,
		ServiceIdentifier: service.ServiceIdentifier,
		Purpose:           use.Purpose,
		Identifier:        rp.Identifier[0].Identifier,
		Subject:           semanticIdentifier(rp),
		LegalName:         rp.LegalPerson.LegalName[0],
		Country:           rp.Country,
		Description:       service.SrvDescription,
		// ARF Reg_01a registers the data of EC TS6, which keeps the
		// entitlements per service (TS6 v1.2.2 row 12, TS05 v1.5 §2.4.1). ETSI
		// TS 119 475 V1.2.1 Annex B.2.1 keeps them per relying party.
		Entitlements:          service.Entitlements,
		RegistryURI:           rp.RegistryURI,
		PrivacyPolicy:         privacyPolicyURI(use),
		SupportURI:            service.SupportURI,
		SupervisoryAuthority:  rp.SupervisoryAuthority,
		IntendedUseIdentifier: use.IntendedUseIdentifier,
	}
}

// supervisoryAuthorityClaim carries the authority's contacts in the subfields
// of ETSI TS 119 475 V1.2.1 Table 7, and its name and country, which ARF
// RPRC_12 requires as well.
func supervisoryAuthorityClaim(a SupervisoryAuthority) map[string]any {
	claim := map[string]any{"name": a.Name, "country": a.Country}
	for field, values := range map[string][]string{"email": a.Email, "phone": a.Phone, "uri": a.FormURI} {
		if len(values) > 0 {
			claim[field] = values[0]
		}
	}
	return claim
}

func privacyPolicyURI(use IntendedUse) string {
	if len(use.PrivacyPolicy) == 0 {
		return ""
	}
	return use.PrivacyPolicy[0].PolicyURI
}

func (r *Registrar) signRegistrationCertificate(content RegistrationCertificateContent, credentials []map[string]any, now time.Time) (string, error) {
	claims, err := RegistrationCertificateClaimsFor(r.env.RegistrarBase(), content, credentials, now)
	if err != nil {
		return "", err
	}
	key, chain, err := r.env.RegistrarSigningMaterial()
	if err != nil {
		return "", fmt.Errorf("%w: loading the key: %w", errRegistrarSigning, err)
	}
	signed, err := SignRegistrationCertificateJWT(claims, key, chain)
	if err != nil {
		return "", fmt.Errorf("%w: signing the registration certificate: %w", errRegistrarSigning, err)
	}
	return signed, nil
}

// RegistrationCertificateClaimsFor builds the payload of ETSI TS 119 475 V1.2.1
// §5.2.4. base is the base URL of the default contact URLs.
func RegistrationCertificateClaimsFor(base string, req RegistrationCertificateContent, dcqlCredentials []map[string]any, now time.Time) (map[string]any, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("a registration certificate needs the relying party's name")
	}
	identifier, legalName, country := strings.TrimSpace(req.Subject), strings.TrimSpace(req.LegalName), strings.TrimSpace(req.Country)
	if identifier == "" {
		return nil, fmt.Errorf("a registration certificate needs the relying party's semantics identifier")
	}
	validity, err := registrationValidity(req.Validity)
	if err != nil {
		return nil, err
	}
	claims := map[string]any{
		"sub":          identifier,
		"sub_ln":       jsonutil.FirstNonEmpty(legalName, name),
		"name":         name,
		"country":      jsonutil.FirstNonEmpty(country, "EU"),
		"registry_uri": jsonutil.FirstNonEmpty(req.RegistryURI, base+"/api/registrar/wrp"),
		// TS05 v1.5 §2.4.1 and the example of ETSI TS 119 475 V1.2.1 Annex C
		// nest the descriptions in an array of arrays.
		"srv_description":       serviceDescriptionClaim(req.Description, name),
		"entitlements":          entitlementsOrDefault(req.Entitlements),
		"privacy_policy":        jsonutil.FirstNonEmpty(req.PrivacyPolicy, base+"/privacy-policy"),
		"support_uri":           jsonutil.FirstNonEmpty(req.SupportURI, base+"/support"),
		"supervisory_authority": supervisoryAuthorityClaim(req.SupervisoryAuthority),
		// ETSI TS 119 475 V1.2.1 GEN-6.2.6.1-03 asks for a unique identifier
		// of the certificate, which a JWT carries as jti (RFC 7519 §4.1.7).
		"jti": uuid.NewString(),
		"iat": now.Unix(),
		"exp": now.Add(validity).Unix(),
		// ETSI TS 119 475 V1.2.1 Table 7 lists the policy (OVR-6.1.3-01) and
		// status (GEN-6.2.6.1-04).
		"policy_id":          []string{registrationCertificatePolicy},
		"certificate_policy": registrationCertificatePolicyURI,
		"status":             registrationStatusClaim(jsonutil.FirstNonEmpty(req.StatusListURI, base+RegistrationStatusListPath), req.StatusIndex),
	}
	if dcqlCredentials != nil {
		claims["credentials"] = RegisteredCredentials(dcqlCredentials)
	} else {
		delete(claims, "privacy_policy")
	}
	if len(req.ProvidesAttestations) > 0 {
		provided := make([]map[string]any, 0, len(req.ProvidesAttestations))
		for _, a := range req.ProvidesAttestations {
			provided = append(provided, a.certificateClaim())
		}
		claims["provides_attestations"] = provided
	}
	if req.IntendedUseIdentifier != "" {
		claims["intended_use_id"] = req.IntendedUseIdentifier
	}
	if service := strings.TrimSpace(req.ServiceIdentifier); service != "" {
		claims[ServiceIdentifierClaim] = service
	}
	if purpose := multiLangClaim(req.Purpose, ""); len(purpose) > 0 {
		claims["purpose"] = purpose
	}
	return claims, nil
}

// serviceDescriptionClaim writes one inner array per description. Without a
// description it describes the service by its name.
func serviceDescriptionClaim(descriptions ServiceDescription, name string) []any {
	var out []any
	for _, description := range descriptions {
		if claim := multiLangClaim(description, ""); len(claim) > 0 {
			out = append(out, claim)
		}
	}
	if len(out) == 0 {
		out = append(out, multiLangClaim(nil, name))
	}
	return out
}

// multiLangClaim writes localised strings as ETSI TS 119 475 does, with lang
// and value. Without strings it uses fallback in English.
func multiLangClaim(values []MultiLangString, fallback string) []map[string]any {
	out := make([]map[string]any, 0, len(values))
	for _, v := range values {
		if strings.TrimSpace(v.Content) != "" {
			out = append(out, map[string]any{"lang": jsonutil.FirstNonEmpty(v.Lang, "en"), "value": v.Content})
		}
	}
	if len(out) == 0 && fallback != "" {
		out = append(out, map[string]any{"lang": "en", "value": fallback})
	}
	return out
}

func entitlementsOrDefault(entitlements []string) []string {
	if len(entitlements) == 0 {
		return []string{ServiceProviderEntitlement}
	}
	return entitlements
}

// RegisteredCredentials converts DCQL credential queries into the credentials
// claim of a registration certificate.
func RegisteredCredentials(dcqlCredentials []map[string]any) []map[string]any {
	registered := make([]map[string]any, 0, len(dcqlCredentials))
	for _, c := range dcqlCredentials {
		registered = append(registered, map[string]any{
			"format": c["format"],
			"meta":   c["meta"],
			"claim":  c["claims"],
		})
	}
	return registered
}

// AccessCertificateSubject reads the identifier that TS 119 475 V1.2.1 §5.1.1 uses
// to link registration and access certificates (organizationIdentifier, OID
// 2.5.4.97), falling back to the common name.
func AccessCertificateSubject(cert *x509.Certificate) (identifier, legalName, country string) {
	identifier = cert.Subject.CommonName
	for _, attribute := range cert.Subject.Names {
		if attribute.Type.String() == "2.5.4.97" {
			identifier, _ = attribute.Value.(string)
			break
		}
	}
	if len(cert.Subject.Organization) > 0 {
		legalName = cert.Subject.Organization[0]
	}
	if len(cert.Subject.Country) > 0 {
		country = cert.Subject.Country[0]
	}
	return identifier, legalName, country
}

// registrationValidity parses a validity, at most 12 months (ETSI TS 119 475
// GEN-5.2.4-08).
func registrationValidity(value string) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return DefaultRegistrationValidity, nil
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("validity %q is not a positive Go duration", value)
	}
	if parsed > MaxRegistrationValidity {
		return 0, fmt.Errorf("validity %s exceeds the 12 months of ETSI TS 119 475 GEN-5.2.4-08", value)
	}
	return parsed, nil
}

// RegistrationCertificateTyp is the JWT typ of a registration certificate
// (ETSI TS 119 475 V1.2.1 §5.2.2, Table 5).
const RegistrationCertificateTyp = "rc-wrp+jwt"

// SignRegistrationCertificateJWT includes the leaf in x5c so wallets can verify the
// registered purpose.
func SignRegistrationCertificateJWT(claims map[string]any, signingKey *ecdsa.PrivateKey, signerCerts []*x509.Certificate) (string, error) {
	header := map[string]any{
		"alg": jws.AlgES256,
		"typ": RegistrationCertificateTyp,
	}
	if x5c := x5cChain(signerCerts); len(x5c) > 0 {
		header["x5c"] = x5c
		digest := sha256.Sum256(signerCerts[0].Raw)
		header["x5t#S256"] = base64.RawURLEncoding.EncodeToString(digest[:])
	}
	// TS 119 475 V1.2.1 §5.2.1 requires JAdES B-B. TS 119 182-1 V1.2.1 §5.1.11 requires iat after July 2025.
	header["iat"] = time.Now().Unix()
	if iat, ok := claims["iat"]; ok {
		header["iat"] = iat
	}
	return jws.Sign(header, claims, signingKey)
}

// x5cChain leaves out a self-signed trust anchor, as RFC 7515 §4.1.6 allows.
func x5cChain(certs []*x509.Certificate) []string {
	chain := certchain.WithoutSelfSignedAnchor(certs)
	if len(chain) == 0 && len(certs) > 0 {
		chain = certs
	}
	x5c := make([]string, 0, len(chain))
	for _, cert := range chain {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))
	}
	return x5c
}
