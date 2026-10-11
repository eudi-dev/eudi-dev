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

import "strings"

// Text returns a string value without surrounding space. Any other value
// gives "".
func Text(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

// List returns an array value. It also takes []string, because in-memory
// records hold []string until a JSON round trip.
func List(v any) []any {
	if strs, ok := v.([]string); ok {
		list := make([]any, len(strs))
		for i, s := range strs {
			list[i] = s
		}
		return list
	}
	list, _ := v.([]any)
	return list
}

// Maps returns the objects of an array value and skips its other entries.
func Maps(v any) []map[string]any {
	list, _ := v.([]any)
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// Strings returns an array in which every entry is a string. Any other value
// gives nil.
func Strings(v any) []string {
	entries, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		text, ok := entry.(string)
		if !ok {
			return nil
		}
		out = append(out, text)
	}
	return out
}
