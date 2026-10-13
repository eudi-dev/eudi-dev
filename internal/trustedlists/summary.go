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
	"slices"

	"github.com/eudi-dev/eudi-dev/v3/internal/lote"

	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
)

// Summary is the answer to GET /api/trust: the providers added to the
// wallet's lists, and the external lists on its list of trusted lists.
type Summary struct {
	Entities []Entity `json:"entities"`
	// EntityLists are the lists that take entities.
	EntityLists []string `json:"entity_lists"`
	Lists       []Link   `json:"lists"`
	// ListsURL is the wallet's list of trusted lists.
	ListsURL string `json:"lists_url"`
	// RelyingPartyCAs and TrustedListCAs are the base64 DER certificates of
	// --relying-party-ca and --trusted-list-ca.
	RelyingPartyCAs []string `json:"relying_party_cas,omitempty"`
	TrustedListCAs  []string `json:"trusted_list_cas,omitempty"`
}

// Link is an external list. Configured comes from --trusted-list and can't
// be removed through the API. Error says why the wallet can't use the list.
// Via is the list of trusted lists that points to it. Type is its LoTEType
// (ETSI TS 119 602 V1.1.1 §6.3.3), and Direct reports whether the wallet uses
// a list of that type without a catalogue entry.
type Link struct {
	URL        string `json:"url"`
	Configured bool   `json:"configured,omitempty"`
	Via        string `json:"via,omitempty"`
	Error      string `json:"error,omitempty"`
	Type       string `json:"type,omitempty"`
	Direct     bool   `json:"direct,omitempty"`
}

// Summary describes the wallet's trusted lists for the API.
func (t *Set) Summary() Summary {
	settings := t.settings
	summary := Summary{
		Entities:        t.Entities(),
		EntityLists:     EntityLists(),
		ListsURL:        t.OwnListURL(ListOfListsID),
		RelyingPartyCAs: base64Certificates(settings.RelyingPartyCAPEM),
		TrustedListCAs:  base64Certificates(settings.ListCAPEM),
	}
	if summary.Entities == nil {
		summary.Entities = []Entity{}
	}
	summary.Lists = []Link{}
	external := t.externalLists()
	for _, tl := range t.Lists() {
		if tl.Via == "" && !slices.Contains(external, tl.URL) {
			continue
		}
		link := Link{URL: tl.URL, Configured: slices.Contains(settings.ConfiguredLists, tl.URL), Via: tl.Via}
		if tl.Err != nil {
			link.Error = tl.Err.Error()
		} else if tl.List != nil {
			link.Type = tl.List.SchemeInfo.LoTEType
			link.Direct = UsedDirectly(link.Type)
		}
		summary.Lists = append(summary.Lists, link)
	}
	return summary
}

func base64Certificates(bundle []byte) []string {
	certs, err := keys.ParseCertificatesPEM(bundle)
	if err != nil {
		return nil
	}
	out := make([]string, len(certs))
	for i, cert := range certs {
		out[i] = base64.StdEncoding.EncodeToString(cert.Raw)
	}
	return out
}

// UsedDirectly reports whether the wallet uses a list of this type without a
// catalogue entry. PID and PuB-EAA lists have a type of their own (ETSI TS
// 119 602 V1.1.1 Annexes D and H), so a credential of those categories
// anchors in them. The other lists anchor relying parties, wallets and
// lists. A list of another type anchors credentials only when a catalogue
// entry links it.
func UsedDirectly(listType string) bool {
	switch listType {
	case lote.PIDProvidersListType, lote.PubEAAProvidersListType,
		lote.WalletProvidersListType, lote.AccessCertProvidersListType, lote.RegistrationCertProvidersListType,
		ListOfListsType:
		return true
	}
	return false
}
