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
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

// ETSI TS 119 475 V1.2.1 GEN-6.2.6.1-05: "The value of idx shall be unique
// for each WRPRC issued by the same issuer".
func TestAnExpiredCertificateKeepsItsIndex(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	use := rp.Services[0].IntendedUses[0].IntendedUseIdentifier
	w.RegistrationStatuses = []RegistrationStatus{{Index: 5, Identifier: "NTRNL-1", Expires: time.Now().Add(-time.Hour).Unix(), Certificate: "expired"}}
	index, err := w.allocateRegistrationStatus(rp, certificateKey{intendedUse: use}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if index == 5 || len(w.RegistrationStatuses) != 2 {
		t.Fatalf("index %d, statuses %+v, want the expired entry kept and a new index", index, w.RegistrationStatuses)
	}
	if expired := w.RegistrationStatuses[0]; expired.Index != 5 || !expired.Superseded || expired.Reason != supersededExpired || expired.Certificate != "" {
		t.Errorf("expired entry %+v, want it kept for good without its certificate", expired)
	}
}

// Only the current certificate of an intended use is kept in the state.
func TestASupersededCertificateIsNotStored(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	issueTestRegistrationCertificate(t, w, rp)
	issueTestRegistrationCertificate(t, w, rp)
	if len(w.RegistrationStatuses) != 2 || w.RegistrationStatuses[0].Certificate != "" || w.RegistrationStatuses[1].Certificate == "" {
		t.Errorf("statuses %+v, want the certificate of the newer entry only", w.RegistrationStatuses)
	}
}

func TestAnUpdateRevokesCertificatesWhoseContentChanged(t *testing.T) {
	for name, change := range map[string]func(rp *WalletRelyingParty){
		"fewer claims": func(rp *WalletRelyingParty) {
			rp.Services[0].IntendedUses[0].Credentials[0].Claims = []RegisteredClaim{{Path: []any{"family_name"}}}
		},
		"another purpose": func(rp *WalletRelyingParty) {
			rp.Services[0].IntendedUses[0].Purpose = []MultiLangString{{Lang: "en", Content: "Marketing"}}
		},
		"another name": func(rp *WalletRelyingParty) { rp.Services[0].ServiceTradeName = "Other Shop" },
	} {
		t.Run(name, func(t *testing.T) {
			w := generateTestWallet(t)
			rp := registerTestRelyingParty(t, w)
			issueTestRegistrationCertificate(t, w, rp)
			change(&rp)
			if _, err := w.UpdateRelyingParty(rp); err != nil {
				t.Fatal(err)
			}
			if statuses := w.RegistrationCertificateStatuses(rp.Identifier[0].Identifier); len(statuses) != 1 || !statuses[0].Revoked {
				t.Errorf("statuses %+v, want the certificate revoked", statuses)
			}
		})
	}
}

func TestAnUnchangedUpdateKeepsCertificatesValid(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	issueTestRegistrationCertificate(t, w, rp)
	if _, err := w.UpdateRelyingParty(rp); err != nil {
		t.Fatal(err)
	}
	if statuses := w.RegistrationCertificateStatuses(rp.Identifier[0].Identifier); len(statuses) != 1 || statuses[0].Revoked {
		t.Errorf("statuses %+v, want the certificate valid", statuses)
	}
}

// A certificate lists the entitlements of its service (TS05 v1.5 §2.4.1). An
// intended use added to an issuer service gives that service the
// Service_Provider entitlement, so the service's provider certificate is out
// of date. The certificates of another service stay valid.
func TestANewRoleRevokesOnlyTheCertificatesOfItsService(t *testing.T) {
	w := generateTestWallet(t)
	rp, err := w.RegisterRelyingParty(WalletRelyingParty{TradeName: "Example University", Services: []WalletRelyingPartyService{
		{ServiceIdentifier: "checkout", IntendedUses: []IntendedUse{ageCheckUse("Age check")}},
		{ServiceIdentifier: "diplomas", ProvidesAttestations: []ProvidedAttestation{{Format: "dc+sd-jwt", Type: testDiplomaVCT}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	identifier := rp.Identifier[0].Identifier
	verifier := issueTestRegistrationCertificate(t, w, rp)
	if _, err := w.IssueRegistrationCertificate(RegistrationCertificateRequest{Identifier: identifier, ServiceIdentifier: "diplomas"}); err != nil {
		t.Fatal(err)
	}
	rp.Services[1].IntendedUses = []IntendedUse{ageCheckUse("Identity check")}
	if _, err := w.UpdateRelyingParty(rp); err != nil {
		t.Fatal(err)
	}
	for _, s := range w.RegistrationCertificateStatuses(identifier) {
		if provider := s.IntendedUse == ""; s.Superseded != provider {
			t.Errorf("status %+v: superseded %v, want %v", s, s.Superseded, provider)
		}
		if s.IntendedUse != "" && s.Certificate != verifier.RegistrationCertificate {
			t.Errorf("status %+v lost the verifier certificate", s)
		}
	}
}

func TestActivatingLeavesRemovedIntendedUsesRevoked(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	issueTestRegistrationCertificate(t, w, rp)
	rp.Services[0].IntendedUses[0].IntendedUseIdentifier = ""
	if _, err := w.UpdateRelyingParty(rp); err != nil {
		t.Fatal(err)
	}
	if n, err := w.SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, RegistrationScope{}, false); err != nil || n != 0 {
		t.Fatalf("activated %d (%v), want 0", n, err)
	}
}

func TestStatusesAreListedUnderEveryIdentifier(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	rp.Identifier = append(rp.Identifier, Identifier{Type: "http://data.europa.eu/eudi/id/EUID", Identifier: "DEHRB.12345"})
	if _, err := w.UpdateRelyingParty(rp); err != nil {
		t.Fatal(err)
	}
	issueTestRegistrationCertificate(t, w, rp)
	if got := w.RegistrationCertificateStatuses("DEHRB.12345"); len(got) != 1 {
		t.Errorf("statuses %+v, want the certificate", got)
	}
}

// When an intended use changes, its old certificate describes outdated
// content, so Activate leaves it revoked.
func TestActivatingLeavesChangedIntendedUsesRevoked(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	issueTestRegistrationCertificate(t, w, rp)
	rp.Services[0].IntendedUses[0].Purpose = []MultiLangString{{Lang: "en", Content: "Marketing"}}
	if _, err := w.UpdateRelyingParty(rp); err != nil {
		t.Fatal(err)
	}
	if n, err := w.SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, RegistrationScope{}, false); err != nil || n != 0 {
		t.Fatalf("activated %d (%v), want 0", n, err)
	}
}

func TestACertificateForChangedContentIsNotIssued(t *testing.T) {
	w := generateTestWallet(t)
	snapshot := registerTestRelyingParty(t, w)
	use := snapshot.Services[0].IntendedUses[0].IntendedUseIdentifier
	changed, _ := cloneRelyingParty(snapshot)
	changed.Services[0].IntendedUses[0].Purpose = []MultiLangString{{Lang: "en", Content: "Marketing"}}
	if _, err := w.UpdateRelyingParty(changed); err != nil {
		t.Fatal(err)
	}
	if _, err := w.allocateRegistrationStatus(snapshot, certificateKey{intendedUse: use}, time.Now().Add(time.Hour)); !errors.Is(err, errRegistrationChanged) {
		t.Errorf("error %v, want the changed registration refused", err)
	}
}

// One relying party holds at most 100 certificates that were not replaced, so
// visitors of a public demo can't fill the status list.
func TestTheRegistrarCapsTheCertificatesOfARelyingParty(t *testing.T) {
	reg := generateTestWallet(t)
	rp := registerTestRelyingParty(t, reg)
	for i := range maxCertificatesPerRelyingParty {
		reg.State.RegistrationStatuses = append(reg.State.RegistrationStatuses, RegistrationStatus{Index: i + 1, Identifier: rp.Identifier[0].Identifier, Revoked: i%2 == 0})
	}
	h := &Server{Registrar: func() *Registrar { return reg.Registrar }, Mutate: func(change func() bool) { change() }}
	request := RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier, IntendedUseIdentifier: rp.Services[0].IntendedUses[0].IntendedUseIdentifier}
	body, _ := json.Marshal(request)
	rec := httptest.NewRecorder()
	h.Routes()["POST /api/registrar/registration-certificates"](rec, httptest.NewRequest(http.MethodPost, "/api/registrar/registration-certificates", bytes.NewReader(body)))
	if rec.Code != http.StatusConflict {
		t.Errorf("%d %s, want the per-party cap", rec.Code, rec.Body)
	}
	// Direct callers get the same cap.
	if _, err := reg.Registrar.IssueRegistrationCertificate(request); err == nil {
		t.Error("a direct call issued past the cap")
	}
}

// A replaced certificate and those of a deleted relying party keep their
// entries, but they don't count against the cap of a relying party. Token
// Status List §13.4: "The Status List Issuer may increase the size of a Status
// List if it requires indices for additional Referenced Tokens."
func TestReplacedCertificatesGrowTheListOutsideThePartyCap(t *testing.T) {
	reg := generateTestWallet(t)
	rp := registerTestRelyingParty(t, reg)
	identifier := rp.Identifier[0].Identifier
	for i := range maxCertificatesPerRelyingParty {
		reg.State.RegistrationStatuses = append(reg.State.RegistrationStatuses, RegistrationStatus{Index: i + 1, Identifier: identifier, Revoked: true, Superseded: true, Expires: time.Now().Add(time.Hour).Unix()})
	}
	issueTestRegistrationCertificate(t, reg, rp)
	if len(reg.State.RegistrationStatuses) != maxCertificatesPerRelyingParty+1 {
		t.Errorf("%d entries, want the replaced ones kept", len(reg.State.RegistrationStatuses))
	}

	for i := len(reg.State.RegistrationStatuses); i < minRegistrationStatusListSize/2; i++ {
		reg.State.RegistrationStatuses = append(reg.State.RegistrationStatuses, RegistrationStatus{Index: i + 1, Identifier: "NLTEST.DELETED", Revoked: true, Superseded: true, Expires: time.Now().Add(time.Hour).Unix()})
	}
	issueTestRegistrationCertificate(t, reg, rp)
	if got, want := len(reg.RegistrationStatusList())*8, 2*minRegistrationStatusListSize; got != want {
		t.Errorf("status list of %d entries, want it doubled to %d", got, want)
	}
}

// The list shows the verifier_info of a stored certificate, so a relying party
// can copy it again later.
func TestTheStatusListShowsTheVerifierInfoOfAStoredCertificate(t *testing.T) {
	reg := generateTestWallet(t)
	rp := registerTestRelyingParty(t, reg)
	h := &Server{Registrar: func() *Registrar { return reg.Registrar }, Mutate: func(change func() bool) { change() }}
	body, _ := json.Marshal(RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier, IntendedUseIdentifier: rp.Services[0].IntendedUses[0].IntendedUseIdentifier})
	rec := httptest.NewRecorder()
	h.Routes()["POST /api/registrar/registration-certificates"](rec, httptest.NewRequest(http.MethodPost, "/api/registrar/registration-certificates", bytes.NewReader(body)))
	var issued RegistrationCertificateResult
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil || issued.VerifierInfo == "" {
		t.Fatalf("issue = %d %s", rec.Code, rec.Body)
	}

	rec = httptest.NewRecorder()
	h.Routes()["GET /api/registrar/registration-certificates"](rec, httptest.NewRequest(http.MethodGet, "/api/registrar/registration-certificates", nil))
	var listed []struct {
		VerifierInfo string `json:"verifierInfo"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || len(listed) != 1 {
		t.Fatalf("list = %s", rec.Body)
	}
	if listed[0].VerifierInfo != issued.VerifierInfo {
		t.Errorf("verifierInfo = %s, want %s", listed[0].VerifierInfo, issued.VerifierInfo)
	}
}

// A superseded certificate names what changed. A certificate lists the
// entitlements of its service (TS6 v1.1 row 12), so a service that gains the
// other role supersedes the certificates of the role it had.
func TestASupersededCertificateNamesWhatChanged(t *testing.T) {
	reg := generateTestWallet(t)
	verifier := registerTestRelyingParty(t, reg)
	issueTestRegistrationCertificate(t, reg, verifier)
	issueTestRegistrationCertificate(t, reg, verifier)

	issuer, err := reg.RegisterRelyingParty(WalletRelyingParty{
		TradeName: "Example University",
		Services:  []WalletRelyingPartyService{{ServiceIdentifier: "diplomas", ProvidesAttestations: []ProvidedAttestation{{Format: "dc+sd-jwt", Type: "urn:example:diploma:1"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	issueProvider := func() {
		t.Helper()
		if _, err := reg.IssueRegistrationCertificate(RegistrationCertificateRequest{Identifier: issuer.Identifier[0].Identifier, ServiceIdentifier: "diplomas"}); err != nil {
			t.Fatal(err)
		}
	}
	update := func(change func(rp *WalletRelyingParty)) {
		t.Helper()
		current, _ := reg.RelyingParty(issuer.Identifier[0].Identifier)
		change(&current)
		if _, err := reg.UpdateRelyingParty(current); err != nil {
			t.Fatal(err)
		}
	}
	issueProvider()
	update(func(rp *WalletRelyingParty) {
		rp.Services[0].ProvidesAttestations = append(rp.Services[0].ProvidesAttestations, ProvidedAttestation{Format: "dc+sd-jwt", Type: "urn:example:diploma:2"})
	})
	issueProvider()
	update(func(rp *WalletRelyingParty) { rp.Services[0].IntendedUses = verifier.Services[0].IntendedUses[:1] })

	var reasons []string
	for _, s := range reg.RegistrationStatuses {
		reasons = append(reasons, s.Reason)
	}
	if want := []string{supersededReplaced, "", supersededAttestations, supersededEntitlements}; !slices.Equal(reasons, want) {
		t.Errorf("reasons %q, want %q", reasons, want)
	}
}
