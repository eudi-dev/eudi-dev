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
	"strings"
	"testing"
	"time"
)

func listWithNextUpdate(t *testing.T, nextUpdate any) *List {
	t.Helper()
	tl, err := Parse(listJWT(t, map[string]any{
		"LoTE": map[string]any{
			"ListAndSchemeInformation": map[string]any{"NextUpdate": nextUpdate},
			"TrustedEntitiesList": []any{
				map[string]any{"TrustedEntityServices": []any{serviceWith(map[string]any{"val": certB64(t, "Issuer CA")})}},
			},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	return tl
}

// A parsed list entry and a described certificate carry the same fields.
func TestCertInfosDescribeEveryField(t *testing.T) {
	tl := listWithNextUpdate(t, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	parsed := tl.Entities[0].Services[0].Certificates[0]
	certs, err := Certificates([]CertInfo{parsed})
	if err != nil {
		t.Fatal(err)
	}
	described := CertInfos(certs)[0]
	if described.Subject != parsed.Subject || described.Issuer != parsed.Issuer || described.NotBefore != parsed.NotBefore || described.NotAfter != parsed.NotAfter || described.PublicKey == nil || string(described.Raw) != string(parsed.Raw) {
		t.Errorf("described = %+v, want the fields of %+v", described, parsed)
	}
	if described.NotBefore == "" || described.NotAfter == "" {
		t.Error("the validity dates are missing")
	}
}

// A current list anchors with the certificates of its services.
func TestAnchorsOfACurrentList(t *testing.T) {
	now := time.Now()
	tl := listWithNextUpdate(t, now.Add(time.Hour).UTC().Format(time.RFC3339))
	anchors, err := Anchors(tl, IssuanceServices, now)
	if err != nil {
		t.Fatalf("Anchors: %v", err)
	}
	if len(anchors) != 1 || anchors[0].Subject.CommonName != "Issuer CA" {
		t.Errorf("anchors = %v, want the issuer CA", anchors)
	}
}

// ETSI TS 119 602 V1.1.1 §6.3.15: "LoTE with a Next update occurring in the
// past shall be discarded as expired". A null NextUpdate marks a closed list.
func TestAnchorsDiscardAnExpiredOrClosedList(t *testing.T) {
	now := time.Now()
	for name, next := range map[string]any{
		"expired": now.Add(-time.Hour).UTC().Format(time.RFC3339),
		"closed":  nil,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Anchors(listWithNextUpdate(t, next), IssuanceServices, now)
			if err == nil || !strings.Contains(err.Error(), "§6.3.15") {
				t.Errorf("Anchors = %v, want the §6.3.15 error", err)
			}
		})
	}
}
