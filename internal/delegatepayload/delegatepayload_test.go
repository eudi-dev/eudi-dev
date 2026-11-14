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

package delegatepayload

import (
	"reflect"
	"testing"
	"time"
)

var delegateJWK = map[string]any{
	"kty": "EC", "crv": "P-256",
	"x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
	"y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ",
}

func TestLimitsAndKeyThumbprint(t *testing.T) {
	payload := map[string]any{
		"cnf": map[string]any{"jwk": delegateJWK}, "exp": float64(1), "iat": float64(1), "nbf": float64(1),
		"_sd": []any{"digest"}, "_sd_alg": "sha-256",
		"purpose": "Order office supplies", "max_amount": float64(250), "audiences": []any{"https://verifier.example"},
		"budget": map[string]any{"currency": "EUR"},
	}
	want := []Limit{
		{Name: "audiences", Value: `["https://verifier.example"]`, JSON: true},
		{Name: "budget", Value: `{"currency":"EUR"}`, JSON: true},
		{Name: "max_amount", Value: "250"},
		{Name: "purpose", Value: "Order office supplies"},
	}
	if got := Limits(payload); !reflect.DeepEqual(got, want) {
		t.Errorf("Limits = %v, want %v", got, want)
	}
	// RFC 7638 thumbprint of delegateJWK.
	if got := KeyThumbprint(payload); got != "aISfTcr9M_Zd09AXGAAeFxnLbFY6lBa87UN515wm5d4" {
		t.Errorf("KeyThumbprint = %q", got)
	}
	if got := KeyThumbprint(map[string]any{"purpose": "x"}); got != "" {
		t.Errorf("KeyThumbprint without cnf = %q", got)
	}
}

func TestExpiry(t *testing.T) {
	if got, ok := Expiry(map[string]any{"exp": float64(4070908800)}); !ok || !got.Equal(time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("Expiry = %v, %v", got, ok)
	}
	if got, ok := Expiry(map[string]any{"exp": float64(1e15)}); !ok || got.Unix() != MaxNumericDate {
		t.Errorf("Expiry beyond the range = %v, %v", got, ok)
	}
	if _, ok := Expiry(map[string]any{"exp": "soon"}); ok {
		t.Error("Expiry accepted a string")
	}
}
