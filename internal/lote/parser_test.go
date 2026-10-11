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

package lote

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func buildListJWT(t *testing.T, payload map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "none"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON) + "."
}

func wrapLoTE(payload map[string]any) map[string]any {
	return map[string]any{"LoTE": payload}
}

func TestParse_BasicList(t *testing.T) {
	payload := wrapLoTE(map[string]any{
		"ListAndSchemeInformation": map[string]any{
			"LoTEType": "http://uri.etsi.org/19602/LoTEType/local",
			"SchemeOperatorName": []any{
				map[string]any{"lang": "en", "value": "Test Operator"},
			},
			"ListIssueDateTime": "2025-01-01T00:00:00Z",
			"NextUpdate":        "2025-01-02T00:00:00Z",
		},
		"TrustedEntitiesList": []any{
			map[string]any{
				"TrustedEntityInformation": map[string]any{
					"TEName": []any{
						map[string]any{"lang": "en", "value": "Test Entity"},
					},
				},
				"TrustedEntityServices": []any{
					map[string]any{
						"ServiceInformation": map[string]any{
							"ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/Issuance",
							"ServiceDigitalIdentity": map[string]any{
								"X509Certificates": []any{},
							},
						},
					},
				},
			},
		},
	})

	raw := buildListJWT(t, payload)
	tl, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if tl.SchemeInfo == nil {
		t.Fatal("expected SchemeInfo")
	}
	if tl.SchemeInfo.LoTEType != "http://uri.etsi.org/19602/LoTEType/local" {
		t.Errorf("LoTEType = %q", tl.SchemeInfo.LoTEType)
	}
	if tl.SchemeInfo.SchemeOperatorName != "Test Operator" {
		t.Errorf("SchemeOperatorName = %q", tl.SchemeInfo.SchemeOperatorName)
	}
	if tl.SchemeInfo.ListIssueDatetime != "2025-01-01T00:00:00Z" {
		t.Errorf("ListIssueDatetime = %q", tl.SchemeInfo.ListIssueDatetime)
	}
	if tl.SchemeInfo.NextUpdate != "2025-01-02T00:00:00Z" {
		t.Errorf("NextUpdate = %q", tl.SchemeInfo.NextUpdate)
	}

	if len(tl.Entities) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(tl.Entities))
	}
	if tl.Entities[0].Name != "Test Entity" {
		t.Errorf("entity name = %q", tl.Entities[0].Name)
	}
	if len(tl.Entities[0].Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(tl.Entities[0].Services))
	}
	if tl.Entities[0].Services[0].ServiceType != "http://uri.etsi.org/19602/SvcType/Issuance" {
		t.Errorf("service type = %q", tl.Entities[0].Services[0].ServiceType)
	}
}

func TestParse_LegacyListIssueDatetimeStillSupported(t *testing.T) {
	payload := wrapLoTE(map[string]any{
		"ListAndSchemeInformation": map[string]any{
			"ListIssueDatetime": "2025-01-01T00:00:00Z",
		},
	})

	raw := buildListJWT(t, payload)
	tl, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if tl.SchemeInfo == nil || tl.SchemeInfo.ListIssueDatetime != "2025-01-01T00:00:00Z" {
		t.Fatalf("expected legacy ListIssueDatetime to be parsed, got %+v", tl.SchemeInfo)
	}
}

func TestParse_NextUpdate(t *testing.T) {
	payload := wrapLoTE(map[string]any{
		"ListAndSchemeInformation": map[string]any{
			"ListIssueDateTime": "2025-01-01T00:00:00Z",
			"NextUpdate":        "2025-01-03T00:00:00Z",
		},
		"TrustedEntitiesList": []any{},
	})

	raw := buildListJWT(t, payload)
	tl, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if tl.SchemeInfo == nil || tl.SchemeInfo.NextUpdate != "2025-01-03T00:00:00Z" {
		t.Fatalf("expected NextUpdate to be parsed, got %+v", tl.SchemeInfo)
	}
}

func TestParse_InvalidJWT(t *testing.T) {
	_, err := Parse("not.a")
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

func TestParse_EmptyEntities(t *testing.T) {
	payload := wrapLoTE(map[string]any{
		"TrustedEntitiesList": []any{},
	})
	raw := buildListJWT(t, payload)
	tl, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(tl.Entities) != 0 {
		t.Errorf("expected 0 entities, got %d", len(tl.Entities))
	}
}

func TestParse_RejectsUnwrappedPayload(t *testing.T) {
	payload := map[string]any{
		"ListAndSchemeInformation": map[string]any{
			"LoTEType": "http://uri.etsi.org/19602/LoTEType/local",
		},
		"TrustedEntitiesList": []any{},
	}

	raw := buildListJWT(t, payload)
	_, err := Parse(raw)
	if err == nil {
		t.Fatal("expected unwrapped payload to be rejected")
	}
}
