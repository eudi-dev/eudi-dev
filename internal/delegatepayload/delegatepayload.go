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

// Package delegatepayload reads the members of a Delegate Payload
// (draft-ietf-oauth-delegate-sd-jwt-00 §5.1.4) for display.
package delegatepayload

import (
	"encoding/json"
	"maps"
	"slices"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
)

// MaxNumericDate is 9999-12-31T23:59:59Z. A time in RFC 3339 ends there.
const MaxNumericDate = 253402300799

// Limit is one member of a Delegate Payload as a label and a value.
type Limit struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	// JSON marks a Value that is the JSON text of an object or an array.
	JSON bool `json:"json,omitempty"`
}

// Limits lists the members of a Delegate Payload set by the requester, sorted
// by name. It leaves out cnf, the time claims and the digests of the payload.
// A number or a boolean is shown as JSON text.
func Limits(payload map[string]any) []Limit {
	var limits []Limit
	for _, name := range slices.Sorted(maps.Keys(payload)) {
		switch name {
		case "cnf", "exp", "nbf", "iat", "_sd", "_sd_alg":
			continue
		}
		if text, isText := payload[name].(string); isText {
			limits = append(limits, Limit{Name: name, Value: text})
			continue
		}
		encoded, err := json.Marshal(payload[name])
		if err != nil {
			continue
		}
		limit := Limit{Name: name, Value: string(encoded)}
		switch payload[name].(type) {
		case map[string]any, []any:
			limit.JSON = true
		}
		limits = append(limits, limit)
	}
	return limits
}

// KeyThumbprint is the JWK thumbprint (RFC 7638) of the cnf key of claims. It
// is empty for claims without a readable cnf key.
func KeyThumbprint(claims map[string]any) string {
	jwk := jsonutil.GetMap(jsonutil.GetMap(claims, "cnf"), "jwk")
	if jwk == nil {
		return ""
	}
	thumbprint, err := keys.Thumbprint(jwk)
	if err != nil {
		return ""
	}
	return format.EncodeBase64URL(thumbprint)
}

// Expiry is the exp of claims. ok is false when the claims have no numeric
// exp. Debug mode signs a payload whose exp is out of range, so the result is
// held to 0..MaxNumericDate.
func Expiry(claims map[string]any) (exp time.Time, ok bool) {
	seconds, ok := jsonutil.GetFloat64(claims, "exp")
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(min(max(seconds, 0), MaxNumericDate)), 0).UTC(), true
}
