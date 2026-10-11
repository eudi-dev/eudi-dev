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

import (
	"reflect"
	"testing"
)

func TestFirstNonEmptySkipsBlankValues(t *testing.T) {
	if got := FirstNonEmpty("", "  ", " b ", "c"); got != "b" {
		t.Errorf("FirstNonEmpty = %q, want b", got)
	}
	if got := FirstNonEmpty(" "); got != "" {
		t.Errorf("FirstNonEmpty of blanks = %q", got)
	}
}

func TestValueAccessors(t *testing.T) {
	if got := Text("  name "); got != "name" {
		t.Errorf("Text = %q", got)
	}
	if got := Text(42.0); got != "" {
		t.Errorf("Text of a number = %q", got)
	}
	if got := List([]string{"a"}); !reflect.DeepEqual(got, []any{"a"}) {
		t.Errorf("List of []string = %v", got)
	}
	if got := Maps([]any{map[string]any{"a": 1.0}, "b"}); len(got) != 1 || got[0]["a"] != 1.0 {
		t.Errorf("Maps = %v", got)
	}
	if got := Strings([]any{"a", "b"}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("Strings = %v", got)
	}
	if got := Strings([]any{"a", 1.0}); got != nil {
		t.Errorf("Strings with a number = %v, want nil", got)
	}
}
