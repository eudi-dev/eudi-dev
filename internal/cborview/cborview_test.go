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

package cborview

import (
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func encode(t *testing.T, v any) []byte {
	t.Helper()
	data, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestStringKeysTurnsEveryKeyTypeIntoText(t *testing.T) {
	got := StringKeys(map[any]any{"text": "a", 42: "b", true: "c"})
	want := map[string]any{"text": "a", "42": "b", "true": "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("StringKeys = %v, want %v", got, want)
	}
}

func TestValue(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want any
	}{
		{"a string", "hello", "hello"},
		{"nil", nil, nil},
		{"an array", []any{"a", map[any]any{1: "one"}}, []any{"a", map[string]any{"1": "one"}}},
		{"a nested map", map[any]any{1: "one"}, map[string]any{"1": "one"}},
		{"a tdate", cbor.Tag{Number: 0, Content: "2026-01-02T03:04:05Z"}, "2026-01-02T03:04:05Z"},
		{"a full-date", cbor.Tag{Number: 1004, Content: "2026-01-02"}, "2026-01-02"},
		{"embedded CBOR", cbor.Tag{Number: 24, Content: encode(t, map[string]any{"k": "v"})}, map[string]any{"k": "v"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Value(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Value = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestDecodeReadsIntegersAsSigned(t *testing.T) {
	got, err := decode([]byte{0x18, 0x2a})
	if err != nil || got != int64(42) {
		t.Errorf("decode = %v (%T), %v, want int64 42", got, got, err)
	}
	if _, err := decode([]byte{0xff, 0xff}); err == nil {
		t.Error("decode accepted invalid CBOR")
	}
}

func TestMapUnwrapsTag24(t *testing.T) {
	inner := encode(t, map[any]any{"deviceKey": map[any]any{1: 2}})
	want := map[string]any{"deviceKey": map[string]any{"1": int64(2)}}
	for name, data := range map[string][]byte{
		"plain":  inner,
		"tag 24": encode(t, cbor.Tag{Number: 24, Content: inner}),
	} {
		if got := Map(data); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: Map = %#v, want %#v", name, got, want)
		}
	}
	if got := Map(encode(t, "text")); got != nil {
		t.Errorf("Map of a text string = %v, want nil", got)
	}
}

func TestSign1Headers(t *testing.T) {
	sign1 := []any{
		[]byte{0xa1, 0x01, 0x26}, // protected: {1: -7}
		map[any]any{33: []byte("certificate")},
		[]byte("payload"),
		make([]byte, 64),
	}
	untagged := encode(t, sign1)
	for name, data := range map[string][]byte{
		"tag 18":      encode(t, cbor.Tag{Number: 18, Content: sign1}),
		"untagged":    untagged,
		"byte string": encode(t, untagged),
	} {
		protected, unprotected := Sign1Headers(data)
		if !reflect.DeepEqual(protected, map[any]any{int64(1): int64(-7)}) {
			t.Errorf("%s: protected = %#v, want alg -7", name, protected)
		}
		if !reflect.DeepEqual(unprotected, map[any]any{int64(33): []byte("certificate")}) {
			t.Errorf("%s: unprotected = %#v, want the x5chain", name, unprotected)
		}
	}
	if protected, unprotected := Sign1Headers([]byte("no cbor")); protected != nil || unprotected != nil {
		t.Errorf("Sign1Headers of invalid input = %v, %v, want nil", protected, unprotected)
	}
}
