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

package dcql

// SelectClaims processes a claims path pointer against a JSON-based credential
// as OID4VP 1.0 §7.1.1 defines it. ok is false where processing aborts with an
// error, which includes an empty selection.
func SelectClaims(root map[string]any, path []any) (selected []any, ok bool) {
	if len(path) == 0 {
		return nil, false
	}
	selection := []any{root}
	for _, component := range path {
		var next []any
		switch c := component.(type) {
		// "If the component is a string, select the element in the respective
		// key in the currently selected element(s). If any of the currently
		// selected element(s) is not an object, abort processing and return an
		// error. If the key does not exist in any element currently selected,
		// remove that element from the selection."
		case string:
			for _, element := range selection {
				object, isObject := element.(map[string]any)
				if !isObject {
					return nil, false
				}
				if value, exists := object[c]; exists {
					next = append(next, value)
				}
			}
		// "If the component is null, select all elements of the currently
		// selected array(s). If any of the currently selected element(s) is not
		// an array, abort processing and return an error."
		case nil:
			for _, element := range selection {
				array, isArray := element.([]any)
				if !isArray {
					return nil, false
				}
				next = append(next, array...)
			}
		default:
			// "If the component is a non-negative integer, select the element
			// at the respective index in the currently selected array(s). [...]
			// If the index does not exist in a selected array, remove that array
			// from the selection." Anything else aborts processing.
			index, isIndex := PathIndex(c)
			if !isIndex {
				return nil, false
			}
			for _, element := range selection {
				array, isArray := element.([]any)
				if !isArray {
					return nil, false
				}
				if index < len(array) {
					next = append(next, array[index])
				}
			}
		}
		// "If the set of elements currently selected is empty, abort processing
		// and return an error."
		if len(next) == 0 {
			return nil, false
		}
		selection = next
	}
	return selection, true
}

// PathIndex reads an array index component. §7: "A claims path pointer MUST
// be a non-empty array of strings, nulls and non-negative integers". A JSON
// decoder returns those integers as float64.
func PathIndex(component any) (int, bool) {
	switch v := component.(type) {
	case float64:
		if v < 0 || v != float64(int(v)) {
			return 0, false
		}
		return int(v), true
	case int:
		return v, v >= 0
	default:
		return 0, false
	}
}
