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

package trustedlists

import (
	"encoding/base64"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/config"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/lote"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/provider"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
)

// Group is one of the wallet's own lists: its ID, its profile and the
// credential types it carries.
type Group struct {
	ID      string
	Profile lote.Profile
	Specs   []provider.IssuedAttestationSpec
}

// ListsCredentialProviders reports whether the group lists the providers of
// credentials, as opposed to wallet providers, access CAs and registrars.
func (g Group) ListsCredentialProviders() bool {
	switch g.Profile.LoTEType {
	case lote.WalletProvidersListType, lote.AccessCertProvidersListType, lote.RegistrationCertProvidersListType:
		return false
	}
	return true
}

type IndexEntry struct {
	ID                    string                           `json:"id"`
	Default               bool                             `json:"default"`
	Description           string                           `json:"description,omitempty"`
	Category              string                           `json:"category,omitempty"`
	Path                  string                           `json:"path"`
	LoTEType              string                           `json:"loTEType"`
	EntityName            string                           `json:"entityName"`
	IssuanceServiceType   string                           `json:"issuanceServiceType"`
	RevocationServiceType string                           `json:"revocationServiceType"`
	Attestations          []provider.IssuedAttestationSpec `json:"attestations"`
	AdvertisedURL         string                           `json:"advertised_url,omitempty"`
	URL                   string                           `json:"url,omitempty"`
}

// SignedList returns the current PID list that the issuer publishes.
func (t *Set) SignedList(issuer string) (string, error) {
	group := t.DefaultGroup()
	return t.SignedGroupList(issuer, group, registrar.TrustListPath(group.ID))
}

// SignedGroupList returns the current list of the group that the issuer
// publishes at path.
func (t *Set) SignedGroupList(issuer string, group Group, path string) (string, error) {
	signer := t.env.Signer()
	if !signer.HasCA() {
		return "", fmt.Errorf("wallet has no CA certificate chain")
	}
	if path == "" {
		path = provider.DefaultTrustListPath
	}
	listKey, listChain, err := signer.TrustList(config.WalletName, mock.DefaultCertificateCountry)
	if err != nil {
		return "", err
	}
	opts := lote.Options{
		OperatorName: config.WalletName,
		Issuer:       strings.TrimRight(strings.TrimSpace(issuer), "/"),
		Path:         path,
		Profile:      group.Profile,
		Entities:     t.listEntities(group.ID),
		ProviderName: t.env.ListedProviderName(),
	}
	switch group.ID {
	case provider.AccessCAListID:
		_, accessCA, err := signer.RelyingPartyAccessCA()
		if err != nil {
			return "", err
		}
		opts.IssuanceCertificates = []string{base64.StdEncoding.EncodeToString(accessCA.Raw)}
		return signer.Keys().TrustList(listKey, listChain[0], opts)
	case provider.RegistrarListID:
		// The registrar key signs the registration certificates and their
		// status list.
		_, registrarCA, err := signer.RegistrarCA()
		if err != nil {
			return "", err
		}
		opts.IssuanceCertificates = []string{base64.StdEncoding.EncodeToString(registrarCA.Raw)}
		opts.RevocationCertificates = opts.IssuanceCertificates
		return signer.Keys().TrustList(listKey, listChain[0], opts)
	}
	var issuanceCertificates []string
	countries := []string{""}
	if group.Profile.Category == credtemplate.CategoryPID {
		countries = t.pidCountries()
	}
	for _, country := range countries {
		_, chain, err := signer.ForProfile(group.Profile, country)
		if err != nil {
			return "", err
		}
		issuanceCertificates = append(issuanceCertificates, base64.StdEncoding.EncodeToString(chain[0].Raw))
	}
	_, profileChain, err := signer.ForProfile(group.Profile, "")
	if err != nil {
		return "", err
	}
	certificates, err := signer.Keys().ProfileCertificates(profileChain[0], signer.TrustAnchor())
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
	_, statusChain, err := signer.StatusList()
	if err != nil {
		return "", err
	}
	opts.IssuanceCertificates = issuanceCertificates
	opts.RevocationCertificates = []string{base64.StdEncoding.EncodeToString(statusChain[0].Raw)}
	return signer.Keys().TrustList(listKey, listChain[0], opts)
}

// pidCountries lists the issuing countries of the PID templates and the
// default country. A PID is signed under a provider CA of its issuing
// country, so the PID list names the CA of each.
func (t *Set) pidCountries() []string {
	// List returns every readable template with its error.
	templates, _ := credtemplate.List(t.env.TemplateLocation())
	var others []string
	for _, tmpl := range templates {
		if country := provider.IssuingCountry(tmpl.Claims); tmpl.Category == credtemplate.CategoryPID && country != "" && country != mock.DefaultCertificateCountry {
			others = append(others, country)
		}
	}
	slices.Sort(others)
	return append([]string{mock.DefaultCertificateCountry}, slices.Compact(others)...)
}

// Groups lists one trusted list per credential category, the lists of
// credential types with their own trust profile, the wallet provider list,
// the access CA list and the registrar list. Unlisted credential types are on
// no list.
func (t *Set) Groups() []Group {
	byID := make(map[string]*Group)
	var groups []*Group
	add := func(profile lote.Profile) *Group {
		id := provider.ListID(profile)
		if group := byID[id]; group != nil {
			return group
		}
		group := &Group{ID: id, Profile: profile}
		byID[id] = group
		groups = append(groups, group)
		return group
	}
	for _, category := range credtemplate.Categories {
		add(provider.CategoryProfile(category))
	}
	add(provider.WalletProviderProfile())
	add(provider.AccessCAProfile())
	add(provider.RegistrarProfile())
	for _, spec := range t.env.IssuedAttestationSpecs() {
		if spec.TrustListType == "" {
			continue
		}
		group := add(provider.SpecProfile(spec))
		group.Specs = append(group.Specs, spec)
	}
	out := make([]Group, 0, len(groups))
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

// DefaultGroup is the PID provider list.
func (t *Set) DefaultGroup() Group {
	return t.Groups()[0]
}

// FindGroup returns the group with the ID, or else the first group that
// carries the credential type. Without either it returns the default group.
func (t *Set) FindGroup(id, vct, docType string) (Group, bool) {
	groups := t.Groups()
	if len(groups) == 0 {
		return Group{}, false
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
		return Group{}, false
	}
	if vct != "" || docType != "" {
		for _, group := range groups {
			for _, spec := range group.Specs {
				if (vct == "" || spec.VCT == vct) && (docType == "" || spec.DocType == docType) {
					return group, true
				}
			}
		}
		return Group{}, false
	}
	return t.DefaultGroup(), true
}

// IndexEntries describes the wallet's own lists as the issuer publishes them.
func (t *Set) IndexEntries(issuer string) []IndexEntry {
	groups := t.Groups()
	defaultGroup := t.DefaultGroup()
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	entries := make([]IndexEntry, 0, len(groups))
	for _, group := range groups {
		path := registrar.TrustListPath(group.ID)
		entry := IndexEntry{
			ID:                    group.ID,
			Default:               group.ID == defaultGroup.ID,
			Description:           groupDescription(group),
			Category:              groupCategory(group),
			Path:                  path,
			LoTEType:              group.Profile.LoTEType,
			EntityName:            group.Profile.EntityName,
			IssuanceServiceType:   group.Profile.IssuanceServiceType,
			RevocationServiceType: group.Profile.RevocationServiceType,
			Attestations:          append([]provider.IssuedAttestationSpec(nil), group.Specs...),
		}
		if issuer != "" {
			entry.AdvertisedURL = issuer + path
			entry.URL = entry.AdvertisedURL
		}
		entries = append(entries, entry)
	}
	return entries
}

func groupDescription(group Group) string {
	switch group.Profile.LoTEType {
	case lote.WalletProvidersListType:
		return "Wallet and key attestations, for issuers"
	case lote.AccessCertProvidersListType:
		return "Access certificates of relying parties, for wallets"
	case lote.RegistrationCertProvidersListType:
		return "Registration certificates and their status list, for wallets"
	}
	if group.ID != group.Profile.Category {
		return "Credentials with their own trusted list, for verifiers"
	}
	return registrar.CategoryOf(group.Profile.Category).Label + "s issued by this wallet, for verifiers"
}

func groupCategory(group Group) string {
	switch group.Profile.LoTEType {
	case lote.WalletProvidersListType:
		return "Wallet providers"
	case lote.AccessCertProvidersListType, lote.RegistrationCertProvidersListType:
		return "Relying party certificates"
	}
	return "Credential providers"
}
