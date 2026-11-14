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

// Package cborview decodes CBOR for reading and display. Map keys become
// strings and tagged values become their content.
package cborview

import (
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

// DecMode decodes unsigned integers as signed, so a CBOR integer key always
// has one Go type.
var DecMode = func() cbor.DecMode {
	mode, err := cbor.DecOptions{IntDec: cbor.IntDecConvertSigned}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("cborview: %v", err))
	}
	return mode
}()

// UnwrapTag24 returns the byte string inside a tag 24 item. Data without that
// tag comes back as it is.
func UnwrapTag24(data []byte) ([]byte, error) {
	var raw cbor.RawTag
	if err := DecMode.Unmarshal(data, &raw); err != nil {
		return data, nil
	}
	if raw.Number != 24 {
		return data, nil
	}

	var inner []byte
	if err := DecMode.Unmarshal(raw.Content, &inner); err != nil {
		return nil, fmt.Errorf("unwrapping tag 24 content: %w", err)
	}
	return inner, nil
}

func decode(data []byte) (any, error) {
	var result any
	if err := DecMode.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Map decodes a CBOR map into its display form. Tag 24 around the map is
// unwrapped. It returns nil for data that is not a map.
func Map(data []byte) map[string]any {
	inner, err := UnwrapTag24(data)
	if err != nil {
		return nil
	}
	var decoded map[any]any
	if err := DecMode.Unmarshal(inner, &decoded); err != nil {
		return nil
	}
	return StringKeys(decoded)
}

// StringKeys returns m in display form.
func StringKeys(m map[any]any) map[string]any {
	result := make(map[string]any)
	for k, v := range m {
		result[fmt.Sprintf("%v", k)] = Value(v)
	}
	return result
}

// Value returns a decoded CBOR value in display form.
func Value(v any) any {
	switch val := v.(type) {
	case time.Time:
		// The decoder turns a tdate (tag 0) into a time.Time. A full-date
		// (tag 1004) stays a string. Both display the same way.
		return val.UTC().Format(time.RFC3339)
	case map[any]any:
		return StringKeys(val)
	case []any:
		result := make([]any, len(val))
		for i, item := range val {
			result[i] = Value(item)
		}
		return result
	case cbor.Tag:
		if val.Number == 0 {
			if s, ok := val.Content.(string); ok {
				return s
			}
		}
		if val.Number == 24 {
			if b, ok := val.Content.([]byte); ok {
				decoded, err := decode(b)
				if err == nil {
					return Value(decoded)
				}
			}
		}
		return Value(val.Content)
	default:
		return v
	}
}

// Sign1Headers decodes the protected and the unprotected header of a
// COSE_Sign1 with or without tag 18 (RFC 9052 §4.2). A header that does not
// decode is nil.
func Sign1Headers(sign1 []byte) (protected, unprotected map[any]any) {
	untagged, err := format.StripCBORTag(sign1, 18)
	if err != nil {
		return nil, nil
	}
	// Some encoders wrap the array in a byte string.
	var wrapped []byte
	if err := DecMode.Unmarshal(untagged, &wrapped); err == nil {
		untagged = wrapped
	}
	var parts []cbor.RawMessage
	if err := DecMode.Unmarshal(untagged, &parts); err != nil || len(parts) != 4 {
		return nil, nil
	}
	var protectedBytes []byte
	if err := DecMode.Unmarshal(parts[0], &protectedBytes); err == nil && len(protectedBytes) > 0 {
		_ = DecMode.Unmarshal(protectedBytes, &protected)
	}
	_ = DecMode.Unmarshal(parts[1], &unprotected)
	return protected, unprotected
}
