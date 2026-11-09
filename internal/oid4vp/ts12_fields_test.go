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

package oid4vp

import (
	"reflect"
	"testing"
)

// The payment schema of TS12 v1.0.1 §4.3.1 requires transaction_id, payee,
// currency and amount.
func TestTS12PayloadFieldsFollowTheSchema(t *testing.T) {
	fields, err := TS12PayloadFields("urn:eudi:sca:payment:1")
	if err != nil {
		t.Fatal(err)
	}
	var names, required []string
	for _, f := range fields {
		names = append(names, f.Name)
		if f.Required {
			required = append(required, f.Name)
		}
	}
	wantNames := []string{"transaction_id", "date_time", "payee", "pisp", "execution_date", "currency", "amount", "amount_estimated", "amount_earmarked", "sct_inst", "recurrence"}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("names = %v, want %v", names, wantNames)
	}
	if !reflect.DeepEqual(required, []string{"transaction_id", "payee", "currency", "amount"}) {
		t.Fatalf("required = %v", required)
	}
	if fields[2].Type != "object" || fields[6].Type != "number" {
		t.Fatalf("payee is %q and amount %q, want object and number", fields[2].Type, fields[6].Type)
	}
	for _, typ := range TS12TransactionDataTypes {
		if _, err := TS12PayloadFields(typ); err != nil {
			t.Errorf("%s: %v", typ, err)
		}
	}
	if _, err := TS12PayloadFields("urn:example:refund"); err == nil {
		t.Fatal("an unknown type has payload fields")
	}
}
