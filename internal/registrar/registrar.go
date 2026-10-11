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
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

// State is what the registrar stores: the registrations, the status list
// entries of their certificates and the added catalogue entries. The wallet
// embeds it, so it is saved with the wallet.
type State struct {
	RelyingParties []WalletRelyingParty `json:"relying_parties,omitempty"`
	// RegistrationStatuses are the status list entries of the registration
	// certificates.
	RegistrationStatuses []RegistrationStatus `json:"registration_statuses,omitempty"`
	// Catalog holds the attestations added to the registrar's catalogue. The
	// templates add their own entries.
	Catalog []CatalogAttestation `json:"catalog,omitempty"`
}

// Env gives the registrar access to the wallet that hosts it.
type Env interface {
	// RegistrarBase is the base URL of the registrar's default contact URLs and
	// registry URIs.
	RegistrarBase() string
	RegistrarSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error)
	RelyingPartyAccessCA() (*ecdsa.PrivateKey, *x509.Certificate, error)
	TemplateLocation() credtemplate.Location
}

// Registrar changes a State while holding the lock of the wallet that stores
// it.
type Registrar struct {
	mu    *sync.RWMutex
	state *State
	env   Env
}

func New(mu *sync.RWMutex, state *State, env Env) *Registrar {
	return &Registrar{mu: mu, state: state, env: env}
}

// WalletRelyingParty is the relying party data model of TS05 v1.5 §2. A relying
// party offers services, and each service has intended uses that list the
// credentials and claims it may request. Field names follow the TS05 JSON
// schema.
type WalletRelyingParty struct {
	Identifier           []Identifier                `json:"identifier"`
	LegalPerson          LegalPerson                 `json:"legalPerson"`
	Country              string                      `json:"country"`
	TradeName            string                      `json:"tradeName,omitempty"`
	IsPSB                bool                        `json:"isPSB"`
	SupervisoryAuthority SupervisoryAuthority        `json:"supervisoryAuthority"`
	RegistryURI          string                      `json:"registryURI"`
	Services             []WalletRelyingPartyService `json:"services"`
}

type LegalPerson struct {
	LegalName []string `json:"legalName"`
}

// WalletRelyingPartyService is one service of a relying party (TS05 v1.5
// §2.4.1). Both certificates of the service carry its trade name.
type WalletRelyingPartyService struct {
	ServiceTradeName     string                `json:"serviceTradeName"`
	ServiceIdentifier    string                `json:"serviceIdentifier,omitempty"`
	SupportURI           string                `json:"supportURI,omitempty"`
	SrvDescription       ServiceDescription    `json:"srvDescription,omitempty"`
	Entitlements         []string              `json:"entitlements"`
	ProvidesAttestations []ProvidedAttestation `json:"providesAttestations,omitempty"`
	IsIntermediary       bool                  `json:"isIntermediary"`
	IntendedUses         []IntendedUse         `json:"intendedUses,omitempty"`
}

// IntendedUse is what a registration certificate certifies (TS05 v1.5 §2.4.4).
type IntendedUse struct {
	IntendedUseIdentifier string                 `json:"intendedUseIdentifier"`
	Purpose               []MultiLangString      `json:"purpose"`
	PrivacyPolicy         []Policy               `json:"privacyPolicy"`
	CreatedAt             string                 `json:"createdAt"`
	Credentials           []RegisteredCredential `json:"credentials"`
}

type Policy struct {
	PolicyURI string `json:"policyURI"`
	Type      string `json:"type"`
}

// privacyPolicyType is the policy type of a privacy policy (ETSI TS 119 475
// V1.2.1 Annex B.2.8).
const privacyPolicyType = "http://data.europa.eu/eudi/policy/privacy-policy"

// normalizeSupervisoryAuthority fills in a test authority with a contact when
// the registration names none. TS05 v1.5 §2.4.7 makes name and country
// mandatory and expects at least one contact.
func normalizeSupervisoryAuthority(a *SupervisoryAuthority, country, base string) error {
	if len(a.Email) == 0 && len(a.Phone) == 0 && len(a.FormURI) == 0 {
		a.Email = []string{testSupervisoryAuthorityEmail}
		a.FormURI = []string{base + "/supervisory-authority"}
	}
	a.Name = firstNonEmpty(a.Name, "Test Supervisory Authority")
	a.Country = strings.ToUpper(firstNonEmpty(a.Country, country))
	if !countryCodePattern.MatchString(a.Country) {
		return fmt.Errorf("supervisory authority country %q is not a two-letter country code", a.Country)
	}
	return nil
}

const testSupervisoryAuthorityEmail = "dpa@eudi-test.dev"

// RegisteredCredential has the DCQL shape: meta holds vct_values or
// doctype_value.
type RegisteredCredential struct {
	Format string            `json:"format"`
	Meta   map[string]any    `json:"meta"`
	Claims []RegisteredClaim `json:"claims"`
}

type RegisteredClaim struct {
	Path []any `json:"path"`
}

var (
	errRelyingPartyNotFound    = errors.New("relying party not registered")
	errUpdateWithoutIdentifier = errors.New("an update needs the identifier of the registered relying party")
	errRelyingPartyExists      = errors.New("relying party already registered")
	errRegistrarFull           = errors.New("the registrar holds the maximum number of relying parties")
	countryCodePattern         = regexp.MustCompile(`^[A-Z]{2}$`)
)

// RegisterRelyingParty stores a new relying party. If the request leaves them
// out, the registrar assigns the identifier and the intended use identifiers,
// and sets the contact URLs under base.
func (r *Registrar) RegisterRelyingParty(rp WalletRelyingParty) (WalletRelyingParty, error) {
	base := r.env.RegistrarBase()
	rp, err := cloneRelyingParty(rp)
	if err != nil {
		return WalletRelyingParty{}, err
	}
	if err := normalizeRelyingParty(&rp, base, nil, r.attestationCategories()); err != nil {
		return WalletRelyingParty{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.state.RelyingParties) >= MaxRelyingParties {
		return WalletRelyingParty{}, errRegistrarFull
	}
	if err := r.checkIdentifiersFreeLocked(rp, -1); err != nil {
		return WalletRelyingParty{}, err
	}
	r.state.RelyingParties = append(r.state.RelyingParties, rp)
	return cloneRelyingParty(rp)
}

// NormalizedRelyingParty returns rp with the registrar's defaults filled in.
// It doesn't store rp.
func (r *Registrar) NormalizedRelyingParty(rp WalletRelyingParty) (WalletRelyingParty, error) {
	rp, err := cloneRelyingParty(rp)
	if err != nil {
		return WalletRelyingParty{}, err
	}
	err = normalizeRelyingParty(&rp, r.env.RegistrarBase(), nil, r.attestationCategories())
	return rp, err
}

// UpdateRelyingParty replaces the registration with the same identifier. New
// intended uses get identifiers, and existing ones keep theirs.
func (r *Registrar) UpdateRelyingParty(rp WalletRelyingParty) (WalletRelyingParty, error) {
	base := r.env.RegistrarBase()
	rp, err := cloneRelyingParty(rp)
	if err != nil {
		return WalletRelyingParty{}, err
	}
	if len(rp.Identifier) == 0 || strings.TrimSpace(rp.Identifier[0].Identifier) == "" {
		return WalletRelyingParty{}, errUpdateWithoutIdentifier
	}
	categories := r.attestationCategories()
	r.mu.Lock()
	defer r.mu.Unlock()
	i := relyingPartyIndex(r.state.RelyingParties, rp.Identifier[0].Identifier)
	if i < 0 {
		return WalletRelyingParty{}, fmt.Errorf("%w: %s", errRelyingPartyNotFound, rp.Identifier[0].Identifier)
	}
	stored := r.state.RelyingParties[i].Identifier[0]
	if err := normalizeUpdate(&rp, r.state.RelyingParties[i], base, categories); err != nil {
		return WalletRelyingParty{}, err
	}
	if err := r.checkIdentifiersFreeLocked(rp, i); err != nil {
		return WalletRelyingParty{}, err
	}
	// A certificate certifies the content of its intended use. When an update
	// changes that content or drops the intended use, its certificates are
	// revoked for good.
	before := r.state.RelyingParties[i]
	r.supersedeRegistrationsLocked(func(s RegistrationStatus) string {
		if s.Identifier != stored.Identifier {
			return ""
		}
		return supersedeReason(before, rp, statusKey(s))
	})
	r.state.RelyingParties[i] = rp
	return cloneRelyingParty(rp)
}

// normalizeUpdate checks an update of the stored registration and fills in
// the values the registrar assigns. The first identifier never changes,
// because the issued certificates and their status entries contain it.
func normalizeUpdate(rp *WalletRelyingParty, stored WalletRelyingParty, base string, category func(format, typ string) string) error {
	rp.Identifier = append([]Identifier{stored.Identifier[0]}, rp.Identifier...)
	return normalizeRelyingParty(rp, base, &stored, category)
}

// EnsureRelyingParty registers rp, or updates the registration with its
// first identifier when the content differs. It reports whether the
// registration changed.
func (r *Registrar) EnsureRelyingParty(rp WalletRelyingParty) (WalletRelyingParty, bool, error) {
	base := r.env.RegistrarBase()
	if len(rp.Identifier) == 0 {
		return WalletRelyingParty{}, false, fmt.Errorf("the relying party needs an identifier")
	}
	stored, ok := r.RelyingParty(rp.Identifier[0].Identifier)
	if !ok {
		registered, err := r.RegisterRelyingParty(rp)
		return registered, err == nil, err
	}
	wanted, err := cloneRelyingParty(rp)
	if err != nil {
		return WalletRelyingParty{}, false, err
	}
	if err := normalizeRelyingParty(&wanted, base, &stored, r.attestationCategories()); err != nil {
		return WalletRelyingParty{}, false, err
	}
	if wanted, err = cloneRelyingParty(wanted); err != nil {
		return WalletRelyingParty{}, false, err
	}
	if reflect.DeepEqual(wanted, stored) {
		return stored, false, nil
	}
	updated, err := r.UpdateRelyingParty(rp)
	return updated, err == nil, err
}

// IsNotRegistered reports whether err says that a relying party or its
// intended use is not registered.
func IsNotRegistered(err error) bool {
	return errors.Is(err, errRelyingPartyNotFound)
}

func (r *Registrar) DeleteRelyingParty(identifier string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := relyingPartyIndex(r.state.RelyingParties, identifier)
	if i < 0 {
		return fmt.Errorf("%w: %s", errRelyingPartyNotFound, identifier)
	}
	deleted := r.state.RelyingParties[i].Identifier[0].Identifier
	r.supersedeRegistrationsLocked(func(s RegistrationStatus) string {
		if s.Identifier == deleted {
			return supersededDeleted
		}
		return ""
	})
	r.state.RelyingParties = slices.Delete(r.state.RelyingParties, i, i+1)
	return nil
}

func (r *Registrar) RelyingParty(identifier string) (WalletRelyingParty, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if i := relyingPartyIndex(r.state.RelyingParties, identifier); i >= 0 {
		rp, err := cloneRelyingParty(r.state.RelyingParties[i])
		return rp, err == nil
	}
	return WalletRelyingParty{}, false
}

func (r *Registrar) RegisteredRelyingParties() []WalletRelyingParty {
	r.mu.RLock()
	defer r.mu.RUnlock()
	parties := make([]WalletRelyingParty, 0, len(r.state.RelyingParties))
	for _, stored := range r.state.RelyingParties {
		if rp, err := cloneRelyingParty(stored); err == nil {
			parties = append(parties, rp)
		}
	}
	return parties
}

// cloneRelyingParty copies a registration through its JSON form. Callers then
// can't change the stored registration through shared slices or maps. Stored
// and updated values also get the same types as in an API request, so comparing
// them works.
func cloneRelyingParty(rp WalletRelyingParty) (WalletRelyingParty, error) {
	encoded, err := json.Marshal(rp)
	if err != nil {
		return WalletRelyingParty{}, fmt.Errorf("encoding the relying party: %w", err)
	}
	var clone WalletRelyingParty
	if err := json.Unmarshal(encoded, &clone); err != nil {
		return WalletRelyingParty{}, fmt.Errorf("decoding the relying party: %w", err)
	}
	return clone, nil
}

func relyingPartyIndex(parties []WalletRelyingParty, identifier string) int {
	return slices.IndexFunc(parties, func(rp WalletRelyingParty) bool { return HasIdentifier(rp, identifier) })
}

// checkIdentifiersFreeLocked refuses a registration whose identifiers name
// another party. Identifiers compare by their semantics identifier. skip is
// the index of the party itself on an update, or -1. Callers hold r.mu.
func (r *Registrar) checkIdentifiersFreeLocked(rp WalletRelyingParty, skip int) error {
	for _, key := range identifierKeys(rp) {
		for j, other := range r.state.RelyingParties {
			if j != skip && slices.Contains(identifierKeys(other), key) {
				return fmt.Errorf("%w: %s", errRelyingPartyExists, key)
			}
		}
	}
	return nil
}

// HasIdentifier matches a registered identifier and the semantics identifier
// of the relying party's certificates. Every identifier lookup goes through it.
func HasIdentifier(rp WalletRelyingParty, identifier string) bool {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return false
	}
	return slices.Contains(identifierKeys(rp), identifier) || slices.ContainsFunc(rp.Identifier, func(id Identifier) bool { return id.Identifier == identifier })
}

// attestationCategories returns the catalogue category of each attestation
// type. It reads the catalogue under r.mu, so call it before taking r.mu.
func (r *Registrar) attestationCategories() func(format, typ string) string {
	categories := map[string]string{}
	for _, entry := range r.CatalogAttestations() {
		for _, c := range entry.Credentials {
			categories[c.Format+" "+c.Type] = entry.Category
		}
	}
	return func(format, typ string) string { return categories[format+" "+typ] }
}

// normalizeRelyingParty checks a registration and fills in the values the
// registrar assigns. For an update, before is the stored registration.
// category returns the catalogue category of an attestation type.
func normalizeRelyingParty(rp *WalletRelyingParty, base string, before *WalletRelyingParty, category func(format, typ string) string) error {
	rp.TradeName = strings.TrimSpace(rp.TradeName)
	if rp.TradeName == "" && len(rp.Services) > 0 {
		rp.TradeName = strings.TrimSpace(rp.Services[0].ServiceTradeName)
	}
	if rp.TradeName == "" {
		return fmt.Errorf("a relying party needs a trade name")
	}
	rp.Country = strings.ToUpper(strings.TrimSpace(rp.Country))
	if rp.Country != "" && !countryCodePattern.MatchString(rp.Country) {
		return fmt.Errorf("country %q is not a two-letter country code", rp.Country)
	}
	if len(rp.Identifier) == 0 || strings.TrimSpace(rp.Identifier[0].Identifier) == "" {
		rp.Identifier = []Identifier{{Identifier: NewEUID(firstNonEmpty(rp.Country, mock.DefaultCertificateCountry)), Type: EUIDIdentifierType}}
	}
	for i, id := range rp.Identifier {
		id.Identifier, id.Type = strings.TrimSpace(id.Identifier), strings.TrimSpace(id.Type)
		if id.Type == "" {
			id = typedIdentifier(id.Identifier)
		}
		rp.Identifier[i] = id
	}
	semantic, err := SemanticIdentifier(rp.Identifier[0], rp.Country)
	if err != nil {
		return err
	}
	if rp.Country == "" {
		rp.Country = semantic[3:5]
	}
	// Every identifier maps to a semantics identifier, and one that names the
	// same party as an earlier one is dropped.
	seen := map[string]bool{}
	identifiers := rp.Identifier[:0]
	for _, id := range rp.Identifier {
		key, err := SemanticIdentifier(id, rp.Country)
		if err != nil {
			return err
		}
		if !seen[key] {
			seen[key] = true
			identifiers = append(identifiers, id)
		}
	}
	rp.Identifier = identifiers
	if len(rp.LegalPerson.LegalName) == 0 || strings.TrimSpace(rp.LegalPerson.LegalName[0]) == "" {
		rp.LegalPerson.LegalName = []string{rp.TradeName}
	}
	if err := normalizeSupervisoryAuthority(&rp.SupervisoryAuthority, rp.Country, base); err != nil {
		return err
	}
	rp.RegistryURI = base + "/api/registrar/wrp/" + rp.Identifier[0].Identifier
	if len(rp.Services) == 0 {
		rp.Services = []WalletRelyingPartyService{{}}
	}
	services := map[string]bool{}
	for i := range rp.Services {
		service := &rp.Services[i]
		if services[service.ServiceIdentifier] {
			if service.ServiceIdentifier == "" {
				return fmt.Errorf("each service needs its own serviceIdentifier")
			}
			return fmt.Errorf("service identifier %q is registered twice", service.ServiceIdentifier)
		}
		services[service.ServiceIdentifier] = true
		service.ServiceTradeName = firstNonEmpty(service.ServiceTradeName, rp.TradeName)
		service.SupportURI = firstNonEmpty(service.SupportURI, base+"/support")
		if address, err := mail.ParseAddress(service.SupportURI); err == nil && address.Address == service.SupportURI {
			service.SupportURI = "mailto:" + service.SupportURI
		}
		if _, _, err := supportContact(service.SupportURI); err != nil {
			return err
		}
		if len(service.SrvDescription) == 0 {
			service.SrvDescription = ServiceDescription{{{Lang: "en", Content: service.ServiceTradeName}}}
		}
		if err := normalizeEntitlements(service, category); err != nil {
			return err
		}
		for j := range service.IntendedUses {
			if err := normalizeIntendedUse(&service.IntendedUses[j], base, before); err != nil {
				return err
			}
		}
	}
	uses := map[string]bool{}
	for _, service := range rp.Services {
		for _, use := range service.IntendedUses {
			if uses[use.IntendedUseIdentifier] {
				return fmt.Errorf("intended use identifier %q is registered twice", use.IntendedUseIdentifier)
			}
			uses[use.IntendedUseIdentifier] = true
		}
	}
	return nil
}

// Size limits keep a public demo's registrar small between resets. They apply
// to registrations from the API. The wallet's own demo registrations list
// every type it issues.
const (
	MaxRelyingParties    = 500
	maxRegistrationItems = 20
	maxRegisteredClaims  = 100
)

func checkRegistrationSize(rp WalletRelyingParty) error {
	tooMany := func(what string, n, limit int) error {
		if n > limit {
			return fmt.Errorf("a registration may list at most %d %s", limit, what)
		}
		return nil
	}
	if err := tooMany("identifiers", len(rp.Identifier), maxRegistrationItems); err != nil {
		return err
	}
	if err := tooMany("services", len(rp.Services), maxRegistrationItems); err != nil {
		return err
	}
	for _, service := range rp.Services {
		if err := tooMany("provided attestations per service", len(service.ProvidesAttestations), maxRegistrationItems); err != nil {
			return err
		}
		if err := tooMany("intended uses per service", len(service.IntendedUses), maxRegistrationItems); err != nil {
			return err
		}
		for _, use := range service.IntendedUses {
			if err := tooMany("credentials per intended use", len(use.Credentials), maxRegistrationItems); err != nil {
				return err
			}
			for _, credential := range use.Credentials {
				if err := tooMany("claims per credential", len(credential.Claims), maxRegisteredClaims); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func normalizeIntendedUse(use *IntendedUse, base string, before *WalletRelyingParty) error {
	// TS05 v1.5 §2.4.4 and ETSI TS 119 475 V1.2.1 Annex B.2.7 make purpose
	// [1..*].
	if !slices.ContainsFunc(use.Purpose, func(p MultiLangString) bool { return strings.TrimSpace(p.Content) != "" }) {
		return fmt.Errorf("an intended use needs a purpose")
	}
	if len(use.Credentials) == 0 {
		return fmt.Errorf("an intended use needs at least one credential")
	}
	for _, credential := range use.Credentials {
		if credential.Format != "dc+sd-jwt" && credential.Format != "mso_mdoc" {
			return fmt.Errorf("credential format %q is not dc+sd-jwt or mso_mdoc", credential.Format)
		}
		if len(CredentialTypes(credential.Meta)) == 0 {
			return fmt.Errorf("a %s credential needs its type in meta (vct_values or doctype_value)", credential.Format)
		}
		// TS05 v1.5 §2.4.5: a credential always lists its requested attributes.
		if !slices.ContainsFunc(credential.Claims, func(c RegisteredClaim) bool { return len(c.Path) > 0 }) {
			return fmt.Errorf("the %s credential %s needs at least one claim", credential.Format, strings.Join(CredentialTypes(credential.Meta), ", "))
		}
	}
	use.CreatedAt = time.Now().UTC().Format(time.DateOnly)
	if before != nil {
		if _, kept, ok := findIntendedUse(*before, "", use.IntendedUseIdentifier); ok {
			use.CreatedAt = kept.CreatedAt
		}
	}
	if use.IntendedUseIdentifier == "" {
		use.IntendedUseIdentifier = newRegistrarID()
	}
	if len(use.PrivacyPolicy) == 0 {
		use.PrivacyPolicy = []Policy{{PolicyURI: base + "/privacy-policy"}}
	}
	for i := range use.PrivacyPolicy {
		use.PrivacyPolicy[i].Type = firstNonEmpty(use.PrivacyPolicy[i].Type, privacyPolicyType)
	}
	return nil
}

// normalizeEntitlements checks the entitlements of a service. ETSI TS 119 475
// V1.2.1 GEN-5.2.4-03 requires one from Annex A.2. Table 8 lists provided
// attestations only for attestation providers, and ARF RPRC_15 requires a
// provider to list them. A provider that also requests attributes is a service
// provider too (ARF RPRC_05 note). A service that lists attestation types
// without a provider entitlement gets the entitlements of their categories. A
// type outside the catalogue is a PID when its name says so (ARF PID_04 and
// PID_14). Otherwise it is an EAA.
func normalizeEntitlements(service *WalletRelyingPartyService, category func(format, typ string) string) error {
	service.Entitlements = dedupeStrings(service.Entitlements)
	// TS05 v1.5 §2.4.1: "A pure intermediary service SHALL NOT be registered
	// an entitlement."
	if service.IsIntermediary && len(service.IntendedUses) == 0 && len(service.ProvidesAttestations) == 0 {
		if len(service.Entitlements) > 0 {
			return fmt.Errorf("service %q only acts as an intermediary, so it has no entitlement (TS05 v1.5 §2.4.1)", service.ServiceTradeName)
		}
		return nil
	}
	if len(service.ProvidesAttestations) > 0 && !isAttestationProvider(*service) {
		for _, attestation := range service.ProvidesAttestations {
			id := category(attestation.Format, strings.TrimSpace(attestation.Type))
			if id == "" && credtype.IsPIDType(attestation.Type) {
				id = credtemplate.CategoryPID
			}
			service.Entitlements = append(service.Entitlements, CategoryOf(id).Entitlement)
		}
		service.Entitlements = dedupeStrings(service.Entitlements)
	}
	if len(service.Entitlements) == 0 && len(service.ProvidesAttestations) == 0 {
		service.Entitlements = []string{ServiceProviderEntitlement}
	}
	provider := isAttestationProvider(*service)
	switch {
	case provider && len(service.ProvidesAttestations) == 0:
		return fmt.Errorf("service %q is an attestation provider, so it has to list its attestation types (ARF RPRC_15)", service.ServiceTradeName)
	case !slices.ContainsFunc(service.Entitlements, func(e string) bool { return slices.Contains(registeredEntitlements, e) }):
		return fmt.Errorf("service %q needs an entitlement from ETSI TS 119 475 Annex A.2, such as %s", service.ServiceTradeName, ServiceProviderEntitlement)
	}
	for i := range service.ProvidesAttestations {
		attestation := &service.ProvidesAttestations[i]
		attestation.Type = strings.TrimSpace(attestation.Type)
		if attestation.Format != "dc+sd-jwt" && attestation.Format != "mso_mdoc" {
			return fmt.Errorf("attestation format %q is not dc+sd-jwt or mso_mdoc", attestation.Format)
		}
		if attestation.Type == "" {
			return fmt.Errorf("a %s attestation needs its type (vct or doctype)", attestation.Format)
		}
	}
	if len(service.IntendedUses) > 0 && !slices.Contains(service.Entitlements, ServiceProviderEntitlement) {
		service.Entitlements = append(service.Entitlements, ServiceProviderEntitlement)
	}
	return nil
}

// isAttestationProvider reports whether the service has an entitlement to
// issue attestations (ETSI TS 119 475 V1.2.1 Table 8).
func isAttestationProvider(service WalletRelyingPartyService) bool {
	return slices.ContainsFunc(service.Entitlements, func(e string) bool { return slices.Contains(providerEntitlements, e) })
}

// sameCertificateContent reports whether the certificate for key has the same
// content in before and after.
func sameCertificateContent(before, after WalletRelyingParty, key certificateKey) bool {
	if key.intendedUse == "" {
		afterService, ok := serviceByIdentifier(after, key.service)
		if !ok || !isAttestationProvider(afterService) {
			return false
		}
		beforeService, _ := serviceByIdentifier(before, key.service)
		return reflect.DeepEqual(ProviderCertificateContent(before, beforeService), ProviderCertificateContent(after, afterService))
	}
	afterService, afterUse, ok := findIntendedUse(after, "", key.intendedUse)
	if !ok {
		return false
	}
	beforeService, beforeUse, _ := findIntendedUse(before, "", key.intendedUse)
	return reflect.DeepEqual(registrationContent(before, beforeService, beforeUse), registrationContent(after, afterService, afterUse)) &&
		reflect.DeepEqual(beforeUse.Credentials, afterUse.Credentials)
}

// supersedeReason names what an update changed in the certificate for key, or
// returns "" when the certificate content stays the same. A certificate lists
// the entitlements of its service (TS6 v1.1 row 12), so a service that gains
// the other role changes the certificates of both roles.
func supersedeReason(before, after WalletRelyingParty, key certificateKey) string {
	if sameCertificateContent(before, after, key) {
		return ""
	}
	var beforeService, afterService WalletRelyingPartyService
	if key.intendedUse == "" {
		service, ok := serviceByIdentifier(after, key.service)
		if !ok || !isAttestationProvider(service) {
			return supersededRemoved
		}
		afterService = service
		beforeService, _ = serviceByIdentifier(before, key.service)
	} else {
		service, _, ok := findIntendedUse(after, "", key.intendedUse)
		if !ok {
			return supersededRemoved
		}
		afterService = service
		beforeService, _, _ = findIntendedUse(before, "", key.intendedUse)
	}
	switch {
	case !sameStrings(beforeService.Entitlements, afterService.Entitlements):
		return supersededEntitlements
	case key.intendedUse == "" && !reflect.DeepEqual(beforeService.ProvidesAttestations, afterService.ProvidesAttestations):
		return supersededAttestations
	}
	return supersededContent
}

func sameStrings(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// serviceByIdentifier finds the service with exactly this identifier. The only
// service of a relying party may have an empty one.
func serviceByIdentifier(rp WalletRelyingParty, identifier string) (WalletRelyingPartyService, bool) {
	i := slices.IndexFunc(rp.Services, func(s WalletRelyingPartyService) bool { return s.ServiceIdentifier == identifier })
	if i < 0 {
		return WalletRelyingPartyService{}, false
	}
	return rp.Services[i], true
}

// findIntendedUse returns the service and intended use. An empty service
// identifier searches every service.
func findIntendedUse(rp WalletRelyingParty, serviceIdentifier, intendedUseIdentifier string) (WalletRelyingPartyService, IntendedUse, bool) {
	for _, service := range rp.Services {
		if serviceIdentifier != "" && service.ServiceIdentifier != serviceIdentifier {
			continue
		}
		for _, use := range service.IntendedUses {
			if use.IntendedUseIdentifier == intendedUseIdentifier {
				return service, use, true
			}
		}
	}
	return WalletRelyingPartyService{}, IntendedUse{}, false
}

// findService returns the service with the identifier. An empty identifier
// names the party's only service.
func findService(rp WalletRelyingParty, serviceIdentifier string) (WalletRelyingPartyService, error) {
	if serviceIdentifier == "" {
		if len(rp.Services) != 1 {
			return WalletRelyingPartyService{}, fmt.Errorf("%s has %d services, so name the service", rp.Identifier[0].Identifier, len(rp.Services))
		}
		return rp.Services[0], nil
	}
	service, ok := serviceByIdentifier(rp, serviceIdentifier)
	if !ok {
		return service, fmt.Errorf("%w: no service %q", errRelyingPartyNotFound, serviceIdentifier)
	}
	return service, nil
}

func newRegistrarID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// matchesWRPQuery applies the search parameters of TS05 v1.5 §3.2.2 and its
// OpenAPI.
func matchesWRPQuery(rp WalletRelyingParty, q url.Values) bool {
	has := func(name string, match func(string) bool) bool {
		value := strings.TrimSpace(q.Get(name))
		return value == "" || match(value)
	}
	anyService := func(match func(WalletRelyingPartyService) bool) bool { return slices.ContainsFunc(rp.Services, match) }
	anyUse := func(match func(IntendedUse) bool) bool {
		return anyService(func(s WalletRelyingPartyService) bool { return slices.ContainsFunc(s.IntendedUses, match) })
	}
	anyCredential := func(match func(RegisteredCredential) bool) bool {
		return anyUse(func(u IntendedUse) bool { return slices.ContainsFunc(u.Credentials, match) })
	}
	contains := func(text, part string) bool { return strings.Contains(strings.ToLower(text), strings.ToLower(part)) }
	return has("identifier", func(v string) bool { return HasIdentifier(rp, v) }) &&
		has("serviceidentifier", func(v string) bool {
			return anyService(func(s WalletRelyingPartyService) bool { return s.ServiceIdentifier == v })
		}) &&
		has("legalname", func(v string) bool {
			return slices.ContainsFunc(rp.LegalPerson.LegalName, func(n string) bool { return contains(n, v) })
		}) &&
		has("tradename", func(v string) bool {
			return contains(rp.TradeName, v) || anyService(func(s WalletRelyingPartyService) bool { return contains(s.ServiceTradeName, v) })
		}) &&
		has("entitlement", func(v string) bool {
			return anyService(func(s WalletRelyingPartyService) bool { return slices.Contains(s.Entitlements, v) })
		}) &&
		has("providedattestation", func(v string) bool {
			return anyService(func(s WalletRelyingPartyService) bool {
				return slices.ContainsFunc(s.ProvidesAttestations, func(a ProvidedAttestation) bool { return a.Type == v })
			})
		}) &&
		has("intendeduseidentifier", func(v string) bool { return anyUse(func(u IntendedUse) bool { return u.IntendedUseIdentifier == v }) }) &&
		has("credentialformat", func(v string) bool { return anyCredential(func(c RegisteredCredential) bool { return c.Format == v }) }) &&
		has("credentialmeta", func(v string) bool {
			return anyCredential(func(c RegisteredCredential) bool { return slices.Contains(CredentialTypes(c.Meta), v) })
		}) &&
		has("claimpath", func(v string) bool {
			return anyCredential(func(c RegisteredCredential) bool {
				return slices.ContainsFunc(c.Claims, func(claim RegisteredClaim) bool { return pathString(claim.Path) == v })
			})
		}) &&
		has("policy", func(v string) bool {
			return anyUse(func(u IntendedUse) bool {
				return slices.ContainsFunc(u.PrivacyPolicy, func(p Policy) bool { return p.PolicyURI == v })
			})
		}) &&
		has("isintermediary", func(v string) bool {
			want, err := strconv.ParseBool(v)
			return err == nil && anyService(func(s WalletRelyingPartyService) bool { return s.IsIntermediary == want })
		}) &&
		// The registrar doesn't record intermediaries, so a usesintermediary
		// filter matches nothing.
		has("usesintermediary", func(string) bool { return false })
}

// registersIntendedUse reports whether one intended use of the relying party
// matches every given check-intended-use parameter (TS05 v1.5 §3.2.2).
// claimpath separates path components with dots.
func registersIntendedUse(rp WalletRelyingParty, q url.Values) bool {
	param := func(name string) string { return strings.TrimSpace(q.Get(name)) }
	service, useID, format, meta, claimPath, policy := param("serviceidentifier"), param("intendeduseidentifier"), param("credentialformat"), param("credentialmeta"), param("claimpath"), param("policyurl")
	credentialMatches := func(c RegisteredCredential) bool {
		return (format == "" || c.Format == format) && (meta == "" || slices.Contains(CredentialTypes(c.Meta), meta)) &&
			(claimPath == "" || slices.ContainsFunc(c.Claims, func(claim RegisteredClaim) bool { return pathString(claim.Path) == claimPath }))
	}
	for _, s := range rp.Services {
		if service != "" && s.ServiceIdentifier != service {
			continue
		}
		for _, use := range s.IntendedUses {
			if (useID == "" || use.IntendedUseIdentifier == useID) &&
				(policy == "" || slices.ContainsFunc(use.PrivacyPolicy, func(p Policy) bool { return p.PolicyURI == policy })) &&
				slices.ContainsFunc(use.Credentials, credentialMatches) {
				return true
			}
		}
	}
	return false
}

func pathString(path []any) string {
	parts := make([]string, 0, len(path))
	for _, p := range path {
		parts = append(parts, fmt.Sprint(p))
	}
	return strings.Join(parts, ".")
}
