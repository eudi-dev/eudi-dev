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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

func certB64(t *testing.T, commonName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// listJWT builds an unsigned ETSI TS 119 602 list. Parse only decodes
// the list. Signature verification is a separate step.
func listJWT(t *testing.T, payload map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(header) + "." + enc.EncodeToString(body) + ".c2ln"
}

func serviceWith(certVals ...any) map[string]any {
	return map[string]any{
		"ServiceInformation": map[string]any{
			"ServiceTypeIdentifier":  "http://uri.etsi.org/TrstSvc/Svctype/IssuerCert",
			"ServiceDigitalIdentity": map[string]any{"X509Certificates": certVals},
		},
	}
}

func TestParseReadsEntitiesServicesAndCertificates(t *testing.T) {
	pidCert := certB64(t, "PID Issuer CA")
	mdlCert := certB64(t, "mDL Issuer CA")

	raw := listJWT(t, map[string]any{
		"LoTE": map[string]any{
			"ListAndSchemeInformation": map[string]any{
				"LoTEType":           "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists",
				"SchemeOperatorName": []any{map[string]any{"value": "Test Operator"}},
				"ListIssueDateTime":  "2026-01-01T00:00:00Z",
				"NextUpdate":         "2026-07-01T00:00:00Z",
			},
			"TrustedEntitiesList": []any{
				map[string]any{
					"TrustedEntityInformation": map[string]any{
						"TEName": []any{map[string]any{"value": "Test Trust Provider"}},
					},
					"TrustedEntityServices": []any{
						serviceWith(map[string]any{"val": pidCert}, map[string]any{"val": mdlCert}),
					},
				},
			},
		},
	})

	tl, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if tl.SchemeInfo == nil {
		t.Fatal("scheme information was not parsed")
	}
	if tl.SchemeInfo.SchemeOperatorName != "Test Operator" {
		t.Errorf("SchemeOperatorName = %q", tl.SchemeInfo.SchemeOperatorName)
	}
	if tl.SchemeInfo.ListIssueDatetime != "2026-01-01T00:00:00Z" {
		t.Errorf("ListIssueDatetime = %q", tl.SchemeInfo.ListIssueDatetime)
	}
	if tl.SchemeInfo.NextUpdate != "2026-07-01T00:00:00Z" {
		t.Errorf("NextUpdate = %q", tl.SchemeInfo.NextUpdate)
	}

	if len(tl.Entities) != 1 {
		t.Fatalf("entities = %d, want 1", len(tl.Entities))
	}
	entity := tl.Entities[0]
	if entity.Name != "Test Trust Provider" {
		t.Errorf("entity name = %q", entity.Name)
	}
	if len(entity.Services) != 1 {
		t.Fatalf("services = %d, want 1", len(entity.Services))
	}
	if got := entity.Services[0].ServiceType; got != "http://uri.etsi.org/TrstSvc/Svctype/IssuerCert" {
		t.Errorf("ServiceType = %q", got)
	}

	certs := entity.Services[0].Certificates
	if len(certs) != 2 {
		t.Fatalf("certificates = %d, want 2", len(certs))
	}
	if certs[0].Subject != "CN=PID Issuer CA" {
		t.Errorf("subject = %q, want CN=PID Issuer CA", certs[0].Subject)
	}
	if certs[0].Issuer != "CN=PID Issuer CA" {
		t.Errorf("issuer = %q", certs[0].Issuer)
	}
	if certs[0].PublicKey == nil {
		t.Error("no public key was extracted, which is what a list is read for")
	}
	if len(certs[0].Raw) == 0 {
		t.Error("the certificate DER was not kept")
	}
	if certs[0].NotAfter == "" || certs[0].NotBefore == "" {
		t.Error("validity dates were not parsed")
	}
}

// An unreadable list entry leaves the valid trust anchors in place. Each
// unreadable entry gets its own finding.
func TestParseReportsUnreadableEntries(t *testing.T) {
	good := certB64(t, "Good CA")

	raw := listJWT(t, map[string]any{
		"LoTE": map[string]any{
			"TrustedEntitiesList": []any{
				"not an entity",
				map[string]any{
					"TrustedEntityInformation": map[string]any{
						"TEName": []any{map[string]any{"value": "Provider"}},
					},
					"TrustedEntityServices": []any{
						"not a service",
						map[string]any{"NoServiceInformation": true},
						serviceWith(
							"not a certificate map",
							map[string]any{"noval": "x"},
							map[string]any{"val": "!!! not base64 !!!"},
							map[string]any{"val": base64.StdEncoding.EncodeToString([]byte("not a certificate"))},
							map[string]any{"val": good},
						),
					},
				},
			},
		},
	})

	tl, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(tl.Entities) != 1 {
		t.Fatalf("entities = %d, want the readable one", len(tl.Entities))
	}
	certs := tl.Entities[0].Services[0].Certificates
	if len(certs) != 1 {
		t.Fatalf("certificates = %d, want only the readable one", len(certs))
	}
	if certs[0].Subject != "CN=Good CA" {
		t.Errorf("subject = %q, want CN=Good CA", certs[0].Subject)
	}
	// One entity, two services and four certificates are unreadable.
	if len(tl.Findings) != 7 {
		t.Errorf("findings = %q, want one for each of the 7 unreadable entries", tl.Findings)
	}
}

func TestParseRejectsMalformedLists(t *testing.T) {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"ES256"}`))

	tests := []struct {
		name string
		raw  string
	}{
		{"not a JWT", "only-one-part"},
		{"two parts", header + ".e30"},
		{"header not base64", "!!!.e30.c2ln"},
		{"payload not base64", header + ".!!!.c2ln"},
		{"header not json", enc.EncodeToString([]byte("nope")) + ".e30.c2ln"},
		{"payload not json", header + "." + enc.EncodeToString([]byte("nope")) + ".c2ln"},
		{"payload without LoTE", header + "." + enc.EncodeToString([]byte(`{"other":1}`)) + ".c2ln"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(tt.raw); err == nil {
				t.Error("expected an error")
			}
		})
	}
}
