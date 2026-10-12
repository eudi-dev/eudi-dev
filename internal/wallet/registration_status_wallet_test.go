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
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/regcert"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

// registrarServer serves the registrar, so registration certificates point at a
// status list the test can fetch.
func registrarServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	srv := newTestServer(t, true)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	srv.wallet.IssuerURL = ts.URL
	return srv, ts
}

func issuedCertificate(t *testing.T, w *Wallet, rp registrar.WalletRelyingParty) map[string]any {
	t.Helper()
	certs, _ := verifiedRegistrationCertificates(map[string]any{"verifier_info": issueTestRegistrationCertificate(t, w, rp).VerifierInfo})
	return certs[0]
}

func TestARegistrationCertificateCarriesItsStatus(t *testing.T) {
	srv, ts := registrarServer(t)
	cert := issuedCertificate(t, srv.wallet, registerTestRelyingParty(t, srv.wallet))
	if got := regcert.ContentFindings(cert); len(got) != 0 {
		t.Errorf("content findings %v, want none", got)
	}
	if got := regcert.StatusFindings(cert, ts.Client(), srv.wallet.TrustedLists().RegistrationStatusCAs(), "ARF RPRC_17"); len(got) != 0 {
		t.Fatalf("status findings %v, want a valid status", got)
	}
}

func TestRevokingARegistrationCertificate(t *testing.T) {
	for name, revoke := range map[string]func(t *testing.T, w *Wallet, rp registrar.WalletRelyingParty){
		"revoke the intended use": func(t *testing.T, w *Wallet, rp registrar.WalletRelyingParty) {
			if n, err := w.Registrar().SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, registrar.RegistrationScope{IntendedUseIdentifier: rp.Services[0].IntendedUses[0].IntendedUseIdentifier}, true); err != nil || n != 1 {
				t.Fatalf("revoked %d (%v), want 1", n, err)
			}
		},
		"delete the relying party": func(t *testing.T, w *Wallet, rp registrar.WalletRelyingParty) {
			if err := w.Registrar().DeleteRelyingParty(rp.Identifier[0].Identifier); err != nil {
				t.Fatal(err)
			}
		},
		"update without the intended use": func(t *testing.T, w *Wallet, rp registrar.WalletRelyingParty) {
			rp.Services[0].IntendedUses[0].IntendedUseIdentifier = ""
			if _, err := w.Registrar().UpdateRelyingParty(rp); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv, ts := registrarServer(t)
			rp := registerTestRelyingParty(t, srv.wallet)
			cert := issuedCertificate(t, srv.wallet, rp)
			revoke(t, srv.wallet, rp)
			if got := regcert.StatusFindings(cert, ts.Client(), srv.wallet.TrustedLists().RegistrationStatusCAs(), "ARF RPRC_17"); len(got) != 1 || !strings.Contains(got[0], "revoked") {
				t.Fatalf("status findings %v, want the revocation", got)
			}
		})
	}
}

// An unreadable status list is a finding, because the wallet then cannot check
// whether the certificate is revoked.
func TestAnUnreachableStatusListIsAFinding(t *testing.T) {
	srv, ts := registrarServer(t)
	cert := issuedCertificate(t, srv.wallet, registerTestRelyingParty(t, srv.wallet))
	ts.Close()
	if got := regcert.StatusFindings(cert, ts.Client(), srv.wallet.TrustedLists().RegistrationStatusCAs(), "ARF RPRC_17"); len(got) != 1 || !strings.Contains(got[0], "cannot be checked") {
		t.Errorf("status findings %v, want one unknown status", got)
	}
}

func TestRegistrationStatusesAreStored(t *testing.T) {
	for name, open := range map[string]func(t *testing.T) *WalletStore{
		"file":   func(t *testing.T) *WalletStore { return NewWalletStore(t.TempDir()) },
		"entity": func(t *testing.T) *WalletStore { store, _ := entityStore(t); return store },
	} {
		t.Run(name, func(t *testing.T) {
			store := open(t)
			w, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			rp := registerTestRelyingParty(t, w)
			issueTestRegistrationCertificate(t, w, rp)
			if err := w.Registrar().DeleteRelyingParty(rp.Identifier[0].Identifier); err != nil {
				t.Fatal(err)
			}
			if err := store.Save(w); err != nil {
				t.Fatal(err)
			}
			reloaded, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			if len(reloaded.RegistrationStatuses) != 1 || !reloaded.RegistrationStatuses[0].Revoked {
				t.Fatalf("statuses %+v, want the revoked certificate", reloaded.RegistrationStatuses)
			}
		})
	}
}

func TestAReactivatedRegistrationCertificateIsValid(t *testing.T) {
	srv, ts := registrarServer(t)
	rp := registerTestRelyingParty(t, srv.wallet)
	cert := issuedCertificate(t, srv.wallet, rp)
	use := rp.Services[0].IntendedUses[0].IntendedUseIdentifier
	if _, err := srv.wallet.Registrar().SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, registrar.RegistrationScope{IntendedUseIdentifier: use}, true); err != nil {
		t.Fatal(err)
	}
	if n, err := srv.wallet.Registrar().SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, registrar.RegistrationScope{IntendedUseIdentifier: use}, false); err != nil || n != 1 {
		t.Fatalf("reactivated %d (%v), want 1", n, err)
	}
	if got := regcert.StatusFindings(cert, ts.Client(), srv.wallet.TrustedLists().RegistrationStatusCAs(), "ARF RPRC_17"); len(got) != 0 {
		t.Errorf("status findings %v, want a valid status", got)
	}
	if statuses := srv.wallet.Registrar().RegistrationCertificateStatuses(rp.Identifier[0].Identifier); len(statuses) != 1 || statuses[0].Revoked {
		t.Errorf("statuses %+v, want one active certificate", statuses)
	}
}

// Reloading wallet state saved by another process replaces the server's
// registrar state.
func TestAReloadTakesTheStoredRegistrar(t *testing.T) {
	srv := newTestServer(t, true)
	stored := generateTestWallet(t)
	rp := registerTestRelyingParty(t, stored)
	issueTestRegistrationCertificate(t, stored, rp)
	srv.applyPersistedWalletState(stored)
	if _, ok := srv.wallet.Registrar().RelyingParty(rp.Identifier[0].Identifier); !ok || len(srv.wallet.Registrar().RegistrationCertificateStatuses("")) != 1 {
		t.Errorf("after the reload the server holds %d parties and %d statuses, want the stored ones",
			len(srv.wallet.Registrar().RegisteredRelyingParties()), len(srv.wallet.Registrar().RegistrationCertificateStatuses("")))
	}
}

// The wallet reads its own registrar's status list without a network round
// trip, whatever form the URL takes.
func TestTheWalletReadsItsOwnStatusListInProcess(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://Wallet.Example:443"
	rp := registerTestRelyingParty(t, w)
	cert := issuedCertificate(t, w, rp)
	if got := regcert.StatusFindings(cert, w.RegistrationStatusClient(), w.TrustedLists().RegistrationStatusCAs(), "ARF RPRC_17"); len(got) != 0 {
		t.Fatalf("status findings %v, want the in-process list to answer", got)
	}
	for _, raw := range []string{"https://wallet.example/api/registrar/status-list", "HTTPS://WALLET.EXAMPLE:443/api/registrar/status-list/"} {
		u, _ := url.Parse(raw)
		if !format.SameURL(u, w.Registrar().RegistrationStatusListURL()) {
			t.Errorf("%s does not match %s", raw, w.Registrar().RegistrationStatusListURL())
		}
	}
}

// A new certificate replaces the old one, so an intended use has one valid
// certificate at a time. Activate doesn't bring a replaced one back.
func TestANewCertificateReplacesTheOldOne(t *testing.T) {
	srv, ts := registrarServer(t)
	w := srv.wallet
	rp := registerTestRelyingParty(t, w)
	id := rp.Identifier[0].Identifier
	old := issuedCertificate(t, w, rp)
	current := issuedCertificate(t, w, rp)
	if got := regcert.StatusFindings(old, ts.Client(), w.TrustedLists().RegistrationStatusCAs(), "ARF RPRC_17"); len(got) != 1 || !strings.Contains(got[0], "revoked") {
		t.Fatalf("status findings %v, want the replaced certificate revoked", got)
	}
	if got := regcert.StatusFindings(current, ts.Client(), w.TrustedLists().RegistrationStatusCAs(), "ARF RPRC_17"); len(got) != 0 {
		t.Fatalf("status findings %v, want the new certificate valid", got)
	}
	if _, err := w.Registrar().SetRegistrationCertificatesRevoked(id, registrar.RegistrationScope{}, true); err != nil {
		t.Fatal(err)
	}
	if n, err := w.Registrar().SetRegistrationCertificatesRevoked(id, registrar.RegistrationScope{}, false); err != nil || n != 1 {
		t.Fatalf("activated %d (%v), want only the current certificate", n, err)
	}
	if got := regcert.StatusFindings(old, ts.Client(), w.TrustedLists().RegistrationStatusCAs(), "ARF RPRC_17"); len(got) != 1 {
		t.Errorf("status findings %v, want the replaced certificate still revoked", got)
	}
}

func TestADemoResetClearsTheRegistrar(t *testing.T) {
	w := generateTestWallet(t)
	issueTestRegistrationCertificate(t, w, registerTestRelyingParty(t, w))
	w.ResetToBaseline()
	if len(w.Registrar().RegisteredRelyingParties()) != 0 || len(w.Registrar().RegistrationCertificateStatuses("")) != 0 {
		t.Errorf("after the reset %d parties and %d statuses remain", len(w.Registrar().RegisteredRelyingParties()), len(w.Registrar().RegistrationCertificateStatuses("")))
	}
}
