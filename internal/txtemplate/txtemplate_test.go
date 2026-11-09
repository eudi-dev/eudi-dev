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

package txtemplate

import (
	"errors"
	"slices"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
)

func TestPredefinedTemplatesCoverEveryTS12TypeAndMatchItsSchema(t *testing.T) {
	var types []string
	for _, tpl := range Predefined() {
		types = append(types, tpl.Type())
		if list := oid4vp.TS12Findings(tpl.TransactionData); len(list) > 0 {
			t.Errorf("%s: %v", tpl.Name, list.Texts())
		}
		if _, ok := tpl.TransactionData["credential_ids"]; ok {
			t.Errorf("%s sets credential_ids, which belong to the verifier's query", tpl.Name)
		}
	}
	slices.Sort(types)
	want := slices.Sorted(slices.Values(oid4vp.TS12TransactionDataTypes))
	if !slices.Equal(types, want) {
		t.Errorf("types = %v, want %v", types, want)
	}
}

func memoryLocation() Location {
	return Location{Store: storage.NewMemory(), Prefix: "transaction-templates"}
}

func TestSaveListLoadDelete(t *testing.T) {
	loc := memoryLocation()
	tpl := Template{
		Name:            "refund",
		Description:     "A refund",
		TransactionData: map[string]any{"type": "urn:example:refund", "amount": 3.0},
	}
	if err := Save(loc, tpl); err != nil {
		t.Fatal(err)
	}
	got, err := Load(loc, "refund")
	if err != nil {
		t.Fatal(err)
	}
	if got.Type() != "urn:example:refund" || got.Description != "A refund" || got.Predefined {
		t.Errorf("loaded %+v", got)
	}
	all, err := List(loc)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(Predefined())+1 {
		t.Errorf("List returned %d templates, want %d", len(all), len(Predefined())+1)
	}
	if err := Delete(loc, "refund"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(loc, "refund"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Load after Delete: %v, want ErrNotFound", err)
	}
}

func TestStoredTemplateReplacesThePredefinedOne(t *testing.T) {
	loc := memoryLocation()
	tpl, err := Load(loc, "payment")
	if err != nil || !tpl.Predefined {
		t.Fatalf("Load(payment) = %+v, %v", tpl, err)
	}
	tpl.Description = "Mine"
	if err := Save(loc, tpl); err != nil {
		t.Fatal(err)
	}
	if got, _ := Load(loc, "payment"); got.Description != "Mine" || got.Predefined {
		t.Errorf("Load after Save = %+v", got)
	}
	if err := Delete(loc, "payment"); err != nil {
		t.Fatal(err)
	}
	if got, _ := Load(loc, "payment"); !got.Predefined {
		t.Errorf("Delete did not restore the predefined template: %+v", got)
	}
	if err := Delete(loc, "payment"); err == nil {
		t.Error("deleting a predefined template succeeded")
	}
}

func TestSaveRefusesTemplatesWithoutNameOrType(t *testing.T) {
	loc := memoryLocation()
	for _, tpl := range []Template{
		{Name: "../x", TransactionData: map[string]any{"type": "t"}},
		{Name: "x"},
		{Name: "x", TransactionData: map[string]any{"amount": 1}},
	} {
		if err := Save(loc, tpl); err == nil {
			t.Errorf("Save(%+v) succeeded", tpl)
		}
	}
}
