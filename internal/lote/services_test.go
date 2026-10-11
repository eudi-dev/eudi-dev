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

import "testing"

// ETSI TS 119 602 V1.1.1 Table D.3: the issuance service anchors credentials,
// the revocation service their status lists. A withdrawn service anchors
// nothing.
func TestServiceCertificatesFollowTheServiceKind(t *testing.T) {
	cert := func(subject string) []CertInfo { return []CertInfo{{Subject: subject}} }
	typed := &List{Entities: []TrustedEntity{{Services: []TrustedService{
		{ServiceType: "http://uri.etsi.org/19602/SvcType/PID/Issuance", Certificates: cert("issuance")},
		{ServiceType: "http://uri.etsi.org/19602/SvcType/PID/Revocation", Certificates: cert("revocation")},
		{ServiceType: "http://uri.etsi.org/19602/SvcType/PID/Issuance", ServiceStatus: "http://example.com/withdrawn", Certificates: cert("withdrawn")},
	}}}}
	subjects := func(certs []CertInfo) []string {
		var out []string
		for _, c := range certs {
			out = append(out, c.Subject)
		}
		return out
	}
	if got := subjects(ServiceCertificates(typed, IssuanceServices)); len(got) != 1 || got[0] != "issuance" {
		t.Errorf("issuance = %v", got)
	}
	if got := subjects(ServiceCertificates(typed, RevocationServices)); len(got) != 1 || got[0] != "revocation" {
		t.Errorf("revocation = %v", got)
	}
	untyped := &List{Entities: []TrustedEntity{{Services: []TrustedService{
		{ServiceType: "http://uri.etsi.org/TrstSvc/Svctype/CA/QC", Certificates: cert("ca")},
		{ServiceType: "http://uri.etsi.org/TrstSvc/Svctype/CA/QC", ServiceStatus: "http://example.com/withdrawn", Certificates: cert("withdrawn")},
	}}}}
	for _, kind := range []string{IssuanceServices, RevocationServices} {
		if got := subjects(ServiceCertificates(untyped, kind)); len(got) != 1 || got[0] != "ca" {
			t.Errorf("untyped %s = %v", kind, got)
		}
	}
}
