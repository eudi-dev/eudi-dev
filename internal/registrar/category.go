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
	"encoding/json"
	"fmt"

	"github.com/dominikschlosser/eudi-dev/v3/internal/defaults"
)

// Category describes a credential category for the wallet, the registrar and
// the UI. The categories are data in the defaults tree.
type Category struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
	// Entitlement registers a provider of the category (ETSI TS 119 475
	// V1.2.1 Annex A.2).
	Entitlement string `json:"entitlement"`
	// TrustRule is the ARF rule for validating a received credential with
	// the trusted list of its providers.
	TrustRule string `json:"trustRule"`
	// AttestationLoS is the default level of security of a catalogue entry
	// (TS11 v1.0 §4.3). A PID is issued at assurance level high, and the
	// test wallet treats QEAAs and PuB-EAAs the same way. The level of other
	// EAAs depends on their rulebook.
	AttestationLoS string `json:"attestationLoS"`
	// TrustedList describes the trusted list of the category's providers.
	TrustedList CategoryTrustedList `json:"trustedList"`
}

// CategoryTrustedList holds the scheme and service types of a category's
// trusted list (ETSI TS 119 602 V1.1.1). The standard defines list types for
// PID providers (Annex D) and PuB-EAA providers (Annex H). It registers none
// for QEAA or other EAA providers. Annex C.1 has a scheme operator create its
// own URIs, and §6.3.3 asks for one type per profile. Those URIs name the
// profile, so every deployment uses them whatever its base URL.
type CategoryTrustedList struct {
	// ETSIAnnex names the annex of ETSI TS 119 602 that defines the list
	// type. It is empty for a type of this test wallet.
	ETSIAnnex                   string `json:"etsiAnnex,omitempty"`
	Type                        string `json:"type"`
	StatusDeterminationApproach string `json:"statusDeterminationApproach"`
	SchemeTypeCommunityRules    string `json:"schemeTypeCommunityRules"`
	SchemeTerritory             string `json:"schemeTerritory,omitempty"`
	IssuanceServiceType         string `json:"issuanceServiceType"`
	RevocationServiceType       string `json:"revocationServiceType"`
}

var categories = loadCategories()

func loadCategories() []Category {
	data, err := defaults.ReadFile("categories.json")
	if err != nil {
		panic(fmt.Sprintf("reading the credential categories: %v", err))
	}
	var out []Category
	if err := json.Unmarshal(data, &out); err != nil {
		panic(fmt.Sprintf("parsing the credential categories: %v", err))
	}
	return out
}

// Categories lists the credential categories in the order of
// credtemplate.Categories.
func Categories() []Category {
	return append([]Category(nil), categories...)
}

// CategoryOf describes a category. An empty or unknown one is an EAA.
func CategoryOf(id string) Category {
	for _, c := range categories {
		if c.ID == id {
			return c
		}
	}
	return categories[len(categories)-1]
}

// CategoryOfEntitlement returns the category of a provider entitlement.
func CategoryOfEntitlement(entitlement string) (string, bool) {
	for _, c := range categories {
		if c.Entitlement == entitlement {
			return c.ID, true
		}
	}
	return "", false
}

// CategoryOfListType returns the category whose providers a trusted list of
// that type lists.
func CategoryOfListType(listType string) (string, bool) {
	for _, c := range categories {
		if c.TrustedList.Type == listType {
			return c.ID, true
		}
	}
	return "", false
}
