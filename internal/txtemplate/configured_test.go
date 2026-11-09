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
	"strings"
	"testing"
)

func refund(amount float64) Template {
	return Template{Name: "refund", TransactionData: map[string]any{"type": "urn:example:refund", "amount": amount}}
}

// A configured template replaces a stored one of the same name and can't be
// saved or deleted through the location.
func TestAConfiguredTemplateReplacesTheStoredOneAndIsReadOnly(t *testing.T) {
	loc := memoryLocation()
	if err := Save(loc, refund(1)); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseConfigured([]ConfiguredFile{{Name: "refunds.yaml", Templates: []Template{refund(2)}}})
	if err != nil {
		t.Fatal(err)
	}
	loc.Configured = &Configured{}
	loc.Configured.Set(parsed)

	got, err := Load(loc, "refund")
	if err != nil || !got.Configured || got.TransactionData["amount"] != 2.0 {
		t.Fatalf("Load = %+v, %v, want the configured template", got, err)
	}
	list, err := List(loc)
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range list {
		if tpl.Name == "refund" && !tpl.Configured {
			t.Fatalf("List holds the stored refund %+v", tpl)
		}
	}
	if err := Save(loc, refund(3)); !errors.Is(err, ErrConfigured) || !strings.Contains(err.Error(), "refunds.yaml") {
		t.Fatalf("Save = %v, want ErrConfigured naming the file", err)
	}
	if err := Delete(loc, "refund"); !errors.Is(err, ErrConfigured) {
		t.Fatalf("Delete = %v, want ErrConfigured", err)
	}
}

func TestParseConfiguredRefusesBadTemplates(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []ConfiguredFile
		want  string
	}{
		{"empty file", []ConfiguredFile{{Name: "a.yaml"}}, "a.yaml holds no transaction template"},
		{"no type", []ConfiguredFile{{Name: "a.yaml", Templates: []Template{{Name: "x", TransactionData: map[string]any{}}}}}, "a.yaml, transaction template 1: transaction_data needs a type"},
		{"bad name", []ConfiguredFile{{Name: "a.yaml", Templates: []Template{{Name: "a/b", TransactionData: refund(1).TransactionData}}}}, "invalid transaction template name"},
		{"same name twice", []ConfiguredFile{{Name: "a.yaml", Templates: []Template{refund(1)}}, {Name: "b.yaml", Templates: []Template{refund(2)}}}, `"refund" appears in a.yaml and b.yaml`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseConfigured(tc.files); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}
