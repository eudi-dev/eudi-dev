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

package provider

import (
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
)

// A list type stored by an eudi-dev 2 wallet moves to the list of the spec's
// category.
func TestAnEudiDev2ListTypeMovesToTheListOfItsCategory(t *testing.T) {
	legacy := IssuedAttestationSpec{
		Format: "dc+sd-jwt",
		VCT:    "urn:test:1",
		Scheme: lote.Scheme{
			LoTEType:              legacyTrustListType,
			IssuanceServiceType:   legacyIssuanceServiceType,
			RevocationServiceType: legacyRevocationService,
			EntityName:            "EUDI Dev Wallet Issuer",
		},
	}
	for _, tc := range []struct {
		category string
		want     List
	}{
		{"", CategoryList(credtemplate.CategoryEAA)},
		{credtemplate.CategoryQEAA, CategoryList(credtemplate.CategoryQEAA)},
	} {
		spec := legacy
		spec.Category = tc.category
		got, err := NormalizeIssuedAttestationSpec(spec, "")
		if err != nil {
			t.Fatal(err)
		}
		if got.LoTEType != tc.want.LoTEType || got.IssuanceServiceType != tc.want.IssuanceServiceType || got.RevocationServiceType != tc.want.RevocationServiceType || got.EntityName != tc.want.EntityName {
			t.Errorf("category %q: got %+v, want the list of %s", tc.category, got, tc.want.Category)
		}
	}
}

// A spec that names the list type of a category belongs to that category and
// gets the defaults of its list.
func TestASpecWithACategoryListTypeGetsThatCategory(t *testing.T) {
	for _, category := range credtemplate.Categories {
		want := CategoryList(category)
		got, err := NormalizeIssuedAttestationSpec(IssuedAttestationSpec{Format: "dc+sd-jwt", VCT: "urn:test:1", Scheme: lote.Scheme{LoTEType: want.LoTEType}}, "")
		if err != nil {
			t.Fatal(err)
		}
		if got.Category != category || got.IssuanceServiceType != want.IssuanceServiceType || got.EntityName != want.EntityName {
			t.Errorf("list type %s: got category %q and %+v, want %s", want.LoTEType, got.Category, got, category)
		}
	}
}
