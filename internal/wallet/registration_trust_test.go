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
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
)

// The decoder anchors a registration certificate and its status list in the
// wallet's registrar list, as a presentation does under --arf.
func TestDecoderAnchorsARegistrationCertificateInTheRegistrarList(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	cert := issueTestRegistrationCertificate(t, w, rp).RegistrationCertificate

	trust := validate.Trust{Catalogue: w, HTTPClient: w.RegistrationStatusClient()}
	result, err := validate.Credential(cert, trust, validate.Options{Status: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{validate.CheckSignature, validate.CheckTrust, validate.CheckStatus, validate.CheckStatusSignature} {
		check, ok := result.Find(name)
		if !ok || check.Status != validate.Pass {
			t.Errorf("%s: %+v, want pass", name, check)
		}
	}
	if check, _ := result.Find(validate.CheckTrust); !strings.HasSuffix(check.Detail, "trusted list registrar") {
		t.Errorf("trust detail = %q, want the registrar list", check.Detail)
	}

	// Another wallet's registrar doesn't anchor it. The check fails only in
	// strict mode with --arf.
	other := generateTestWallet(t)
	for _, refuses := range []bool{false, true} {
		other.ValidationMode = ValidationModeDebug
		other.RequireARF = refuses
		if refuses {
			other.ValidationMode = ValidationModeStrict
		}
		want := map[bool]string{false: validate.Warning, true: validate.Fail}[refuses]
		result, err = validate.Credential(cert, validate.Trust{Catalogue: other, HTTPClient: w.RegistrationStatusClient()}, validate.Options{Status: true})
		if err != nil {
			t.Fatal(err)
		}
		if check, _ := result.Find(validate.CheckTrust); check.Status != want || !strings.Contains(check.Detail, "does not chain to a trusted registrar") {
			t.Errorf("another wallet's registrar, refuses %v: %+v, want %s", refuses, check, want)
		}
	}
}
