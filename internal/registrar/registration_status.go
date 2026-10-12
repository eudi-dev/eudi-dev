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
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/statuslist"
)

const RegistrationStatusListPath = "/api/registrar/status-list"

// minRegistrationStatusListSize keeps random indices from colliding, even after
// a restart with memory storage has lost track of the used ones. The list
// compresses to a few hundred bytes.
const minRegistrationStatusListSize = 1 << 17

// maxCertificatesPerRelyingParty bounds the certificates of one relying party
// that the registrar has not replaced.
const maxCertificatesPerRelyingParty = 100

var (
	errPartyCertificatesFull = fmt.Errorf("the relying party already holds %d registration certificates. The registrar issues at most that many to one relying party. A certificate frees up when it expires or is replaced", maxCertificatesPerRelyingParty)
	errRegistrationChanged   = errors.New("the registration changed while the certificate was being issued. Try again")
)

// RegistrationStatus is the status list entry of one registration certificate
// (ETSI TS 119 475 V1.2.1 Table 7). A verifier's certificate covers an intended
// use. An attestation provider's certificate covers a service and has no
// intended use (ARF RPRC_13).
type RegistrationStatus struct {
	Index       int    `json:"index"`
	Identifier  string `json:"identifier"`
	IntendedUse string `json:"intendedUse"`
	Service     string `json:"service,omitempty"`
	Revoked     bool   `json:"revoked,omitempty"`
	// Superseded marks a certificate that expired, or whose relying party was
	// deleted or whose registered content was changed or removed. Its content
	// is out of date, so it stays revoked.
	Superseded bool `json:"superseded,omitempty"`
	// Reason says why the certificate was superseded: replaced, expired,
	// deleted, removed, entitlements, attestations or content.
	Reason string `json:"reason,omitempty"`
	// Expires is when the certificate expires (Unix time).
	Expires int64 `json:"expires,omitempty"`
	// Certificate is the signed registration certificate. A superseded entry
	// drops it, so a relying party that keeps issuing certificates doesn't grow
	// the stored state.
	Certificate string `json:"certificate,omitempty"`
}

// RegistrationScope selects registration certificates: those of an intended
// use, those of a service, or with both empty, all of a relying party.
type RegistrationScope struct {
	ServiceIdentifier     string `json:"serviceIdentifier,omitempty"`
	IntendedUseIdentifier string `json:"intendedUseIdentifier,omitempty"`
}

// certificateKey identifies what one certificate certifies: an intended use, or for
// an attestation provider, a service.
type certificateKey struct {
	service, intendedUse string
}

func (k certificateKey) matches(s RegistrationStatus) bool {
	if k.intendedUse != "" {
		return s.IntendedUse == k.intendedUse
	}
	return s.IntendedUse == "" && s.Service == k.service
}

func statusKey(s RegistrationStatus) certificateKey {
	if s.IntendedUse != "" {
		return certificateKey{intendedUse: s.IntendedUse}
	}
	return certificateKey{service: s.Service}
}

// registrationStatusListSize is the size of the status list with adding more
// entries in it. An index belongs to one certificate for good, even after
// it expires (ETSI TS 119 475 V1.2.1 GEN-6.2.6.1-05: "The value of idx shall
// be unique for each WRPRC issued by the same issuer"). The list doubles
// whenever it is half full, so a random index is found in a few tries. Token
// Status List §13.4: "The Status List Issuer may increase the size of a
// Status List if it requires indices for additional Referenced Tokens."
func registrationStatusListSize(statuses []RegistrationStatus, adding int) int {
	size := minRegistrationStatusListSize
	for size < 2*(len(statuses)+adding) {
		size *= 2
	}
	for _, s := range statuses {
		for s.Index >= size {
			size *= 2
		}
	}
	return size
}

// allocateRegistrationStatus reserves a status list entry for a new
// certificate. rp is the registration as it was read before signing. If it
// changed or was deleted since, the certificate would be out of date, so this
// fails.
func (r *Registrar) allocateRegistrationStatus(rp WalletRelyingParty, key certificateKey, expires time.Time) (int, error) {
	identifier := rp.Identifier[0].Identifier
	r.mu.Lock()
	defer r.mu.Unlock()
	i := relyingPartyIndex(r.state.RelyingParties, identifier)
	if i < 0 {
		return 0, fmt.Errorf("%w: %s", errRelyingPartyNotFound, identifier)
	}
	if !sameCertificateContent(rp, r.state.RelyingParties[i], key) {
		return 0, errRegistrationChanged
	}
	now := time.Now().Unix()
	r.supersedeRegistrationsLocked(func(s RegistrationStatus) string {
		if s.Expires > 0 && s.Expires < now {
			return supersededExpired
		}
		return ""
	})
	held := 0
	for _, s := range r.state.RegistrationStatuses {
		if s.Identifier == identifier && !s.Superseded {
			held++
		}
	}
	if held >= maxCertificatesPerRelyingParty {
		return 0, errPartyCertificatesFull
	}
	size := registrationStatusListSize(r.state.RegistrationStatuses, 1)
	for {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(size-1)))
		if err != nil {
			return 0, err
		}
		index := int(n.Int64()) + 1
		if !slices.ContainsFunc(r.state.RegistrationStatuses, func(s RegistrationStatus) bool { return s.Index == index }) {
			r.state.RegistrationStatuses = append(r.state.RegistrationStatuses, RegistrationStatus{Index: index, Identifier: identifier, IntendedUse: key.intendedUse, Service: key.service, Expires: expires.Unix()})
			return index, nil
		}
	}
}

// replaceRegistrationStatus permanently revokes the older certificates with
// the same key once the certificate at index is signed. An intended use or a
// provider service has one valid certificate at a time. Entries are appended in
// issue order, so when two certificates are issued at once, the later one stays
// valid.
func (r *Registrar) replaceRegistrationStatus(identifier string, key certificateKey, index int, certificate string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	newest := slices.IndexFunc(r.state.RegistrationStatuses, func(s RegistrationStatus) bool { return s.Index == index })
	if newest >= 0 {
		r.state.RegistrationStatuses[newest].Certificate = certificate
	}
	for i := range newest {
		s := &r.state.RegistrationStatuses[i]
		if s.Identifier == identifier && key.matches(*s) && !s.Superseded {
			s.Revoked, s.Superseded, s.Reason, s.Certificate = true, true, supersededReplaced, ""
		}
	}
}

func (r *Registrar) releaseRegistrationStatus(index int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state.RegistrationStatuses = slices.DeleteFunc(r.state.RegistrationStatuses, func(s RegistrationStatus) bool { return s.Index == index })
}

// Reasons a certificate was superseded.
const (
	supersededReplaced     = "replaced"
	supersededExpired      = "expired"
	supersededDeleted      = "deleted"
	supersededRemoved      = "removed"
	supersededEntitlements = "entitlements"
	supersededAttestations = "attestations"
	supersededContent      = "content"
)

// supersedeRegistrationsLocked permanently revokes every current certificate
// that reasonFor gives a reason. The caller holds r.mu.
func (r *Registrar) supersedeRegistrationsLocked(reasonFor func(RegistrationStatus) string) {
	for i := range r.state.RegistrationStatuses {
		s := &r.state.RegistrationStatuses[i]
		if s.Superseded {
			continue
		}
		if reason := reasonFor(*s); reason != "" {
			s.Revoked, s.Superseded, s.Reason, s.Certificate = true, true, reason, ""
		}
	}
}

// SetRegistrationCertificatesRevoked revokes or activates the registration
// certificates in scope. It returns how many changed. The registration stays.
func (r *Registrar) SetRegistrationCertificatesRevoked(identifier string, scope RegistrationScope, revoked bool) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := relyingPartyIndex(r.state.RelyingParties, identifier)
	if i < 0 {
		return 0, fmt.Errorf("%w: %s", errRelyingPartyNotFound, identifier)
	}
	rp := r.state.RelyingParties[i]
	inScope, err := scopeFilter(rp, scope)
	if err != nil {
		return 0, err
	}
	changed := 0
	for j := range r.state.RegistrationStatuses {
		s := &r.state.RegistrationStatuses[j]
		if s.Revoked != revoked && !s.Superseded && s.Identifier == rp.Identifier[0].Identifier && inScope(*s) {
			s.Revoked = revoked
			changed++
		}
	}
	return changed, nil
}

// RegistrationCertificateStatuses lists the status list entries of the
// registration certificates issued for a relying party, or for all of them
// when identifier is empty.
func (r *Registrar) RegistrationCertificateStatuses(identifier string) []RegistrationStatus {
	identifier = r.registeredIdentifier(identifier)
	r.mu.RLock()
	defer r.mu.RUnlock()
	statuses := []RegistrationStatus{}
	for _, s := range r.state.RegistrationStatuses {
		if identifier == "" || s.Identifier == identifier {
			statuses = append(statuses, s)
		}
	}
	return statuses
}

// RegistrationStatusView adds the ready-to-use value of a stored certificate:
// verifier_info for an intended use, issuer_info for a service.
type RegistrationStatusView struct {
	RegistrationStatus
	VerifierInfo string `json:"verifierInfo,omitempty"`
	IssuerInfo   string `json:"issuerInfo,omitempty"`
}

// RegistrationCertificateViews lists the status list entries like
// RegistrationCertificateStatuses, with the value of each stored certificate.
func (r *Registrar) RegistrationCertificateViews(identifier string) []RegistrationStatusView {
	statuses := r.RegistrationCertificateStatuses(identifier)
	views := make([]RegistrationStatusView, 0, len(statuses))
	for _, s := range statuses {
		view := RegistrationStatusView{RegistrationStatus: s}
		if s.Certificate != "" {
			if result, err := certificateResult(statusKey(s), s.Certificate); err == nil {
				view.VerifierInfo, view.IssuerInfo = result.VerifierInfo, result.IssuerInfo
			}
		}
		views = append(views, view)
	}
	return views
}

// RegistrationStatusList is the one-bit status list of the issued registration
// certificates. A set bit marks a revoked certificate.
func (r *Registrar) RegistrationStatusList() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	size := registrationStatusListSize(r.state.RegistrationStatuses, 0)
	bitstring := make([]byte, size/8)
	for _, s := range r.state.RegistrationStatuses {
		if s.Revoked && s.Index > 0 && s.Index < size {
			bitstring[s.Index/8] |= 1 << (s.Index % 8)
		}
	}
	return bitstring
}

// RegistrationStatusListToken is the registrar's status list as a Token Status
// List JWT signed by the registrar key (ETSI TS 119 475 V1.2.1 §6.2.6.1).
func (r *Registrar) RegistrationStatusListToken() (string, error) {
	key, chain, err := r.env.RegistrarSigningMaterial()
	if err != nil {
		return "", fmt.Errorf("loading registrar signer: %w", err)
	}
	return statuslist.GenerateStatusListJWT(r.RegistrationStatusList(), key, statuslist.StatusListConfig{
		URI:       r.RegistrationStatusListURL(),
		Issuer:    r.env.RegistrarBase(),
		Bits:      1,
		TTL:       300,
		CertChain: chain,
	})
}

func registrationStatusClaim(uri string, index int) map[string]any {
	return map[string]any{"status_list": map[string]any{"idx": index, "uri": uri}}
}

// RegistrationStatusListURL is where the registrar publishes its status list.
func (r *Registrar) RegistrationStatusListURL() string {
	return r.env.RegistrarBase() + RegistrationStatusListPath
}

// scopeFilter selects the status entries in scope. A service scope covers the
// service's provider certificate and the certificates of its intended uses.
func scopeFilter(rp WalletRelyingParty, scope RegistrationScope) (func(RegistrationStatus) bool, error) {
	if scope.IntendedUseIdentifier != "" {
		if _, _, ok := findIntendedUse(rp, scope.ServiceIdentifier, scope.IntendedUseIdentifier); !ok {
			return nil, fmt.Errorf("%w: no intended use %q", errRelyingPartyNotFound, scope.IntendedUseIdentifier)
		}
		return func(s RegistrationStatus) bool { return s.IntendedUse == scope.IntendedUseIdentifier }, nil
	}
	if scope.ServiceIdentifier == "" {
		return func(RegistrationStatus) bool { return true }, nil
	}
	service, err := findService(rp, scope.ServiceIdentifier)
	if err != nil {
		return nil, err
	}
	return func(s RegistrationStatus) bool {
		if s.IntendedUse == "" {
			return s.Service == service.ServiceIdentifier
		}
		return slices.ContainsFunc(service.IntendedUses, func(u IntendedUse) bool { return u.IntendedUseIdentifier == s.IntendedUse })
	}, nil
}

// registeredIdentifier resolves any identifier of a relying party to the one
// its status entries carry. An unknown identifier stays as it is.
func (r *Registrar) registeredIdentifier(identifier string) string {
	if rp, ok := r.RelyingParty(identifier); ok {
		return rp.Identifier[0].Identifier
	}
	return identifier
}
