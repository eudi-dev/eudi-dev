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
	"fmt"
	"slices"
	"strings"
)

// Enrolment registers a relying party, or changes its registration, and issues
// the certificates for it in one step. If a certificate fails, the
// registration stays as it was.
type Enrolment struct {
	RelyingParty WalletRelyingParty `json:"relyingParty"`
	// Access asks for an access certificate. The registrar fills in the
	// identifier.
	Access *AccessCertificateRequest `json:"access,omitempty"`
	// Registration asks for a registration certificate.
	Registration *EnrolmentRegistration `json:"registration,omitempty"`
}

// EnrolmentRegistration describes the registration certificate of an enrolment.
type EnrolmentRegistration struct {
	// Provider asks for the provider certificate of the service. Otherwise the
	// certificate covers the intended use added by the enrolment.
	Provider          bool   `json:"provider,omitempty"`
	ServiceIdentifier string `json:"serviceIdentifier,omitempty"`
	Validity          string `json:"validity,omitempty"`
}

type EnrolmentResult struct {
	RelyingParty WalletRelyingParty             `json:"relyingParty"`
	Access       *AccessCertificateResult       `json:"access,omitempty"`
	Registration *RegistrationCertificateResult `json:"registration,omitempty"`
}

// Enrol registers e.RelyingParty, or with update changes the registration with
// its first identifier, and issues the requested certificates. It checks the
// whole enrolment before it changes anything. If a certificate still fails,
// the registration and the status of its certificates are put back.
func (r *Registrar) Enrol(e Enrolment, update bool) (*EnrolmentResult, error) {
	candidate, before, err := r.enrolmentCandidate(e.RelyingParty, update)
	if err != nil {
		return nil, err
	}
	access, registration, err := enrolmentRequests(candidate, before, e)
	if err != nil {
		return nil, err
	}
	identifier := candidate.Identifier[0].Identifier
	statuses := r.RegistrationCertificateStatuses(identifier)
	var stored WalletRelyingParty
	if before != nil {
		stored, err = r.UpdateRelyingParty(candidate)
	} else {
		stored, err = r.RegisterRelyingParty(candidate)
	}
	if err != nil {
		return nil, err
	}
	result := &EnrolmentResult{RelyingParty: stored}
	if access != nil {
		result.Access, err = r.IssueAccessCertificate(*access)
	}
	if err == nil && registration != nil {
		result.Registration, err = r.IssueRegistrationCertificate(*registration)
	}
	if err != nil {
		r.undoEnrolment(identifier, before, statuses)
		return nil, err
	}
	return result, nil
}

// enrolmentCandidate returns the registration as the enrolment would store it,
// and for an update the stored one. It changes nothing.
func (r *Registrar) enrolmentCandidate(rp WalletRelyingParty, update bool) (WalletRelyingParty, *WalletRelyingParty, error) {
	if !update {
		candidate, err := r.NormalizedRelyingParty(rp)
		return candidate, nil, err
	}
	if len(rp.Identifier) == 0 || strings.TrimSpace(rp.Identifier[0].Identifier) == "" {
		return WalletRelyingParty{}, nil, errUpdateWithoutIdentifier
	}
	before, ok := r.RelyingParty(rp.Identifier[0].Identifier)
	if !ok {
		return WalletRelyingParty{}, nil, fmt.Errorf("%w: %s", errRelyingPartyNotFound, rp.Identifier[0].Identifier)
	}
	candidate, err := cloneRelyingParty(rp)
	if err != nil {
		return WalletRelyingParty{}, nil, err
	}
	err = normalizeUpdate(&candidate, before, r.env.RegistrarBase(), r.attestationCategories())
	return candidate, &before, err
}

// enrolmentRequests checks the requested certificates against the registration
// to be stored and returns the requests for them.
func enrolmentRequests(candidate WalletRelyingParty, before *WalletRelyingParty, e Enrolment) (*AccessCertificateRequest, *RegistrationCertificateRequest, error) {
	identifier := candidate.Identifier[0].Identifier
	var access *AccessCertificateRequest
	if e.Access != nil {
		req := *e.Access
		req.Identifier = identifier
		if _, _, err := req.parse(); err != nil {
			return nil, nil, err
		}
		if _, err := findService(candidate, req.ServiceIdentifier); err != nil {
			return nil, nil, err
		}
		if _, err := accessCertificateDNSNames(req.DNSNames); err != nil {
			return nil, nil, err
		}
		access = &req
	}
	if e.Registration == nil {
		return access, nil, nil
	}
	if _, err := registrationValidity(e.Registration.Validity); err != nil {
		return nil, nil, err
	}
	req := RegistrationCertificateRequest{Identifier: identifier, ServiceIdentifier: e.Registration.ServiceIdentifier, Validity: e.Registration.Validity}
	if e.Registration.Provider {
		if _, err := providerService(candidate, req.ServiceIdentifier); err != nil {
			return nil, nil, err
		}
		return access, &req, nil
	}
	added := addedIntendedUses(candidate, before)
	if len(added) != 1 {
		return nil, nil, fmt.Errorf("a registration certificate covers one intended use, and this step adds %d", len(added))
	}
	if _, _, ok := findIntendedUse(candidate, req.ServiceIdentifier, added[0]); !ok {
		return nil, nil, fmt.Errorf("%w: no intended use %q in service %q", errRelyingPartyNotFound, added[0], req.ServiceIdentifier)
	}
	req.IntendedUseIdentifier = added[0]
	return access, &req, nil
}

// undoEnrolment puts back the registration and the statuses of its
// certificates as they were before the enrolment. A new registration is
// removed.
func (r *Registrar) undoEnrolment(identifier string, before *WalletRelyingParty, statuses []RegistrationStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i := relyingPartyIndex(r.state.RelyingParties, identifier); i >= 0 {
		if before != nil {
			r.state.RelyingParties[i] = *before
		} else {
			r.state.RelyingParties = slices.Delete(r.state.RelyingParties, i, i+1)
		}
	}
	for _, kept := range statuses {
		j := slices.IndexFunc(r.state.RegistrationStatuses, func(s RegistrationStatus) bool {
			return s.Index == kept.Index && s.Identifier == kept.Identifier
		})
		if j >= 0 {
			r.state.RegistrationStatuses[j] = kept
		}
	}
}

// addedIntendedUses lists the intended uses of after that before doesn't have.
func addedIntendedUses(after WalletRelyingParty, before *WalletRelyingParty) []string {
	var known []string
	if before != nil {
		for _, service := range before.Services {
			for _, use := range service.IntendedUses {
				known = append(known, use.IntendedUseIdentifier)
			}
		}
	}
	var added []string
	for _, service := range after.Services {
		for _, use := range service.IntendedUses {
			if !slices.Contains(known, use.IntendedUseIdentifier) {
				added = append(added, use.IntendedUseIdentifier)
			}
		}
	}
	return added
}
