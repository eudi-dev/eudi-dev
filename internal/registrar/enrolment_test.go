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

package registrar

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

func ageCheckUse(purpose string) IntendedUse {
	return IntendedUse{
		Purpose: []MultiLangString{{Lang: "en", Content: purpose}},
		Credentials: []RegisteredCredential{{
			Format: "dc+sd-jwt",
			Meta:   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
			Claims: []RegisteredClaim{{Path: []any{"given_name"}}},
		}},
	}
}

// A verifier enrols with its access certificate and the registration
// certificate of its intended use.
func TestEnrolRegistersAndIssuesBothCertificates(t *testing.T) {
	w := generateTestWallet(t)
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	result, err := w.Enrol(Enrolment{
		RelyingParty: WalletRelyingParty{TradeName: "Example Shop", Services: []WalletRelyingPartyService{{IntendedUses: []IntendedUse{ageCheckUse("Age check")}}}},
		Access:       &AccessCertificateRequest{CSR: testAccessCSR(t, key)},
		Registration: &EnrolmentRegistration{},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Access == nil || len(result.Access.ClientIDs) == 0 || result.Registration == nil || result.Registration.VerifierInfo == "" {
		t.Fatalf("result = %+v", result)
	}
	if _, ok := w.RelyingParty(result.RelyingParty.Identifier[0].Identifier); !ok {
		t.Error("the registration was not stored")
	}
}

// A failed step leaves the registrations as they were.
func TestEnrolKeepsTheRegistrationsOnFailure(t *testing.T) {
	w := generateTestWallet(t)
	shop := WalletRelyingParty{TradeName: "Example Shop", Services: []WalletRelyingPartyService{{IntendedUses: []IntendedUse{ageCheckUse("Age check")}}}}

	if _, err := w.Enrol(Enrolment{RelyingParty: shop, Access: &AccessCertificateRequest{CSR: "not a CSR"}}, false); err == nil {
		t.Fatal("a bad CSR was accepted")
	}
	// A verifier has no provider service, so its provider certificate fails
	// after the registration was stored.
	if _, err := w.Enrol(Enrolment{RelyingParty: shop, Registration: &EnrolmentRegistration{Provider: true}}, false); err == nil {
		t.Fatal("a provider certificate for a verifier was issued")
	}
	if got := w.RegisteredRelyingParties(); len(got) != 0 {
		t.Fatalf("failed enrolments left %d registrations", len(got))
	}

	stored, err := w.RegisterRelyingParty(shop)
	if err != nil {
		t.Fatal(err)
	}
	changed := stored
	changed.Services = []WalletRelyingPartyService{{IntendedUses: []IntendedUse{ageCheckUse("Other")}}}
	changed.Services[0].ServiceIdentifier = stored.Services[0].ServiceIdentifier
	if _, err := w.Enrol(Enrolment{RelyingParty: changed, Registration: &EnrolmentRegistration{Provider: true}}, true); err == nil {
		t.Fatal("a provider certificate for a verifier was issued")
	}
	after, _ := w.RelyingParty(stored.Identifier[0].Identifier)
	if !reflect.DeepEqual(after, stored) {
		t.Errorf("a failed update changed the registration:\n%+v\nwant\n%+v", after, stored)
	}
}

// An update that adds an intended use gets the certificate for that use.
func TestEnrolCertifiesTheAddedIntendedUse(t *testing.T) {
	w := generateTestWallet(t)
	stored := registerTestRelyingParty(t, w)
	updated := stored
	updated.Services = []WalletRelyingPartyService{stored.Services[0]}
	updated.Services[0].IntendedUses = append(slices.Clone(stored.Services[0].IntendedUses), ageCheckUse("Second check"))

	result, err := w.Enrol(Enrolment{RelyingParty: updated, Registration: &EnrolmentRegistration{}}, true)
	if err != nil {
		t.Fatal(err)
	}
	uses := result.RelyingParty.Services[0].IntendedUses
	if len(uses) != 2 {
		t.Fatalf("intended uses = %d, want 2", len(uses))
	}
	certificates := w.RegistrationCertificateStatuses(stored.Identifier[0].Identifier)
	if len(certificates) != 1 || certificates[0].IntendedUse != uses[1].IntendedUseIdentifier {
		t.Errorf("certificates = %+v, want one for %s", certificates, uses[1].IntendedUseIdentifier)
	}
}

// A failed update changes nothing: the certificates of an intended use it
// would change stay valid. A DNS name is checked before the update, and a
// signer that fails afterwards puts everything back.
func TestFailedEnrolmentKeepsTheCertificates(t *testing.T) {
	w := generateTestWallet(t)
	stored := registerTestRelyingParty(t, w)
	identifier := stored.Identifier[0].Identifier
	if _, err := w.IssueRegistrationCertificate(RegistrationCertificateRequest{Identifier: identifier, IntendedUseIdentifier: stored.Services[0].IntendedUses[0].IntendedUseIdentifier}); err != nil {
		t.Fatal(err)
	}
	certificates := w.RegistrationCertificateStatuses(identifier)
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	changed := stored
	changed.Services = []WalletRelyingPartyService{stored.Services[0]}
	changed.Services[0].IntendedUses = []IntendedUse{stored.Services[0].IntendedUses[0], ageCheckUse("Second check")}
	changed.Services[0].IntendedUses[0].Purpose = []MultiLangString{{Lang: "en", Content: "Changed purpose"}}

	for name, fail := range map[string]func(e *Enrolment){
		"bad DNS name": func(e *Enrolment) {
			e.Access = &AccessCertificateRequest{CSR: testAccessCSR(t, key), DNSNames: []string{"*.shop.example"}}
		},
		"signer failure": func(e *Enrolment) { w.env.signErr = errors.New("signer down") },
	} {
		e := Enrolment{RelyingParty: changed, Registration: &EnrolmentRegistration{}}
		fail(&e)
		if _, err := w.Enrol(e, true); err == nil {
			t.Fatalf("%s: the enrolment succeeded", name)
		}
		w.env.signErr = nil
		if after, _ := w.RelyingParty(identifier); !reflect.DeepEqual(after, stored) {
			t.Errorf("%s: the registration changed to %+v", name, after)
		}
		if after := w.RegistrationCertificateStatuses(identifier); !reflect.DeepEqual(after, certificates) {
			t.Errorf("%s: certificates %+v, want %+v", name, after, certificates)
		}
	}
}
