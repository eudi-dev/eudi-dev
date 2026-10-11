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

package jsonutil

import "testing"

func TestGetString(t *testing.T) {
	m := map[string]any{"name": "alice", "age": 30, "nil": nil}

	tests := []struct {
		key  string
		want string
	}{
		{"name", "alice"},
		{"age", ""},
		{"missing", ""},
		{"nil", ""},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := GetString(m, tt.key); got != tt.want {
				t.Errorf("GetString(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestGetMap(t *testing.T) {
	inner := map[string]any{"x": 1}
	m := map[string]any{"nested": inner, "flat": "hello"}

	if got := GetMap(m, "nested"); got == nil || got["x"] != 1 {
		t.Error("GetMap(nested) should return inner map")
	}
	if got := GetMap(m, "flat"); got != nil {
		t.Error("GetMap(flat) should return nil for non-map")
	}
	if got := GetMap(m, "missing"); got != nil {
		t.Error("GetMap(missing) should return nil")
	}
}

func TestGetArray(t *testing.T) {
	arr := []any{"a", "b"}
	m := map[string]any{"items": arr, "single": "x"}

	if got := GetArray(m, "items"); len(got) != 2 {
		t.Errorf("GetArray(items) = %v, want 2 elements", got)
	}
	if got := GetArray(m, "single"); got != nil {
		t.Error("GetArray(single) should return nil for non-array")
	}
	if got := GetArray(m, "missing"); got != nil {
		t.Error("GetArray(missing) should return nil")
	}
}

func TestGetFloat64(t *testing.T) {
	m := map[string]any{"score": 3.14, "name": "x"}

	if v, ok := GetFloat64(m, "score"); !ok || v != 3.14 {
		t.Errorf("GetFloat64(score) = (%v, %v), want (3.14, true)", v, ok)
	}
	if _, ok := GetFloat64(m, "name"); ok {
		t.Error("GetFloat64(name) should return false for non-float")
	}
	if _, ok := GetFloat64(m, "missing"); ok {
		t.Error("GetFloat64(missing) should return false")
	}
}
