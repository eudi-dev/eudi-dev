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
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

// Group is one of the wallet's own lists with its ID, its scheme and its
// credential types.
type Group struct {
	ID    string
	List  provider.List
	Specs []provider.IssuedAttestationSpec
}

// ListsCredentialProviders reports whether the group lists the providers of
// credentials, as opposed to wallet providers, access CAs and registrars.
func (g Group) ListsCredentialProviders() bool {
	switch g.List.LoTEType {
	case lote.WalletProvidersListType, lote.AccessCertProvidersListType, lote.RegistrationCertProvidersListType:
		return false
	}
	return true
}

type indexEntry struct {
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

// SignedGroupList returns the current list of the group, published by the
// issuer at path.
func (t *Set) SignedGroupList(issuer string, group Group, path string) (string, error) {
	signer := t.env.Signer()
	if !signer.HasCA() {
		return "", fmt.Errorf("wallet has no CA certificate chain")
	}
	if path == "" {
		path = provider.DefaultTrustListPath
	}
	listKey, listChain, err := signer.TrustList(config.WalletName, group.List.Territory())
	if err != nil {
		return "", err
	}
	opts := lote.Options{
		OperatorName: config.WalletName,
		Issuer:       strings.TrimRight(strings.TrimSpace(issuer), "/"),
		Path:         path,
		Scheme:       group.List.Scheme,
		Entities:     t.listEntities(group.ID),
		ProviderName: t.env.ListedProviderName(),
	}
	switch group.ID {
	case provider.WalletProviderListID:
		opts.WalletSolution = provider.WalletSolutionReference
	case provider.AccessCAListID:
		_, accessCA, err := signer.RelyingPartyAccessCA()
		if err != nil {
			return "", err
		}
		opts.ProviderName = caEntityName(accessCA, t.env.ListedProviderName())
		opts.IssuanceCertificates = []string{base64.StdEncoding.EncodeToString(accessCA.Raw)}
		return signer.Keys().TrustList(listKey, listChain[0], opts)
	case provider.RegistrarListID:
		// The registrar key signs the registration certificates and their
		// status list.
		_, registrarCA, err := signer.RegistrarCA()
		if err != nil {
			return "", err
		}
		opts.ProviderName = caEntityName(registrarCA, t.env.ListedProviderName())
		opts.IssuanceCertificates = []string{base64.StdEncoding.EncodeToString(registrarCA.Raw)}
		opts.RevocationCertificates = opts.IssuanceCertificates
		return signer.Keys().TrustList(listKey, listChain[0], opts)
	}
	var issuanceCertificates []string
	countries := []string{""}
	if group.List.Category == credtemplate.CategoryPID {
		countries = t.pidCountries()
	}
	for _, country := range countries {
		_, chain, err := signer.ForList(group.List, country)
		if err != nil {
			return "", err
		}
		issuanceCertificates = append(issuanceCertificates, base64.StdEncoding.EncodeToString(chain[0].Raw))
	}
	_, signingChain, err := signer.ForList(group.List, "")
	if err != nil {
		return "", err
	}
	certificates, err := signer.Keys().ListedCertificates(signingChain[0], signer.TrustAnchor())
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

// caEntityName is the TEName of the entity that lists a certificate, or
// fallback for a certificate without a name. ETSI TS 119 602 V1.1.1
// §6.6.3.0: the organizationName of a listed certificate "should strictly
// match the 'TE Name' value".
func caEntityName(cert *x509.Certificate, fallback string) string {
	if len(cert.Subject.Organization) > 0 {
		return jsonutil.FirstNonEmpty(cert.Subject.Organization[0], cert.Subject.CommonName, fallback)
	}
	return jsonutil.FirstNonEmpty(cert.Subject.CommonName, fallback)
}

// pidCountries lists the issuing countries of the PID templates and the
// default country. A PID is signed under a provider CA of its issuing
// country, so the PID list holds the CA of each country.
func (t *Set) pidCountries() []string {
	// List still returns the readable templates when it reports an error.
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
// credential types with their own scheme, the wallet provider list,
// the access CA list and the registrar list. Unlisted credential types are on
// no list.
func (t *Set) Groups() []Group {
	byID := make(map[string]*Group)
	var groups []*Group
	add := func(list provider.List) *Group {
		id := provider.ListID(list)
		if group := byID[id]; group != nil {
			return group
		}
		group := &Group{ID: id, List: list}
		byID[id] = group
		groups = append(groups, group)
		return group
	}
	for _, category := range credtemplate.Categories {
		add(provider.CategoryList(category))
	}
	add(provider.WalletProviderList())
	add(provider.AccessCAList())
	add(provider.RegistrarList())
	for _, spec := range t.env.IssuedAttestationSpecs() {
		if spec.LoTEType == "" {
			continue
		}
		group := add(spec.List())
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

// IndexEntries describes the wallet's own lists as published by the issuer.
func (t *Set) IndexEntries(issuer string) []indexEntry {
	groups := t.Groups()
	defaultGroup := t.DefaultGroup()
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	entries := make([]indexEntry, 0, len(groups))
	for _, group := range groups {
		path := provider.TrustedListPath(group.ID)
		entry := indexEntry{
			ID:                    group.ID,
			Default:               group.ID == defaultGroup.ID,
			Description:           groupDescription(group),
			Category:              groupCategory(group),
			Path:                  path,
			LoTEType:              group.List.LoTEType,
			EntityName:            group.List.EntityName,
			IssuanceServiceType:   group.List.IssuanceServiceType,
			RevocationServiceType: group.List.RevocationServiceType,
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
	switch group.List.LoTEType {
	case lote.WalletProvidersListType:
		return "Wallet and key attestations, for issuers"
	case lote.AccessCertProvidersListType:
		return "Access certificates of relying parties, for wallets"
	case lote.RegistrationCertProvidersListType:
		return "Registration certificates and their status list, for wallets"
	}
	if group.ID != group.List.Category {
		return "Credentials with their own trusted list, for verifiers"
	}
	return registrar.CategoryOf(group.List.Category).Label + "s issued by this wallet, for verifiers"
}

func groupCategory(group Group) string {
	switch group.List.LoTEType {
	case lote.WalletProvidersListType:
		return "Wallet providers"
	case lote.AccessCertProvidersListType, lote.RegistrationCertProvidersListType:
		return "Relying party certificates"
	}
	return "Credential providers"
}
