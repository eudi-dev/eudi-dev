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

package wallet

import (
	"crypto/x509"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
)

// CIR (EU) 2024/2979 Annex II EAA-6.2.10.1-06.1, as amended by CIR (EU)
// 2026/1731: the certificate element of the MSO status_list "shall contain a
// certificate containing the public key that signed or sealed the top-level
// certificate in the x5chain element in the MSO revocation list structure".
func TestTheMdocStatusListNamesTheAnchorOfItsSigner(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example"
	res, err := w.IssueCredential(IssueOptions{
		Format: "mdoc", DocType: "eu.europa.ec.eudi.pid.1",
		Claims: map[string]any{"eu.europa.ec.eudi.pid.1": map[string]any{"given_name": "Alice"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := mdoc.Parse(res.Credential.Raw)
	if err != nil {
		t.Fatal(err)
	}
	statusList, _ := doc.StatusClaims()["status"].(map[string]any)["status_list"].(map[string]any)
	der, ok := statusList["certificate"].([]byte)
	if !ok {
		t.Fatalf("the status_list has no certificate: %v", statusList)
	}
	anchor, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	_, chain, err := w.Signer().StatusList()
	if err != nil {
		t.Fatal(err)
	}
	if err := chain[0].CheckSignatureFrom(anchor); err != nil {
		t.Errorf("the status list signer is not signed by the certificate of the MSO: %v", err)
	}
}
