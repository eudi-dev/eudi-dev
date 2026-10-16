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
	"bytes"
	"encoding/base64"
	"errors"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"

	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
)

func pngDataURI(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 4, 4))); err != nil {
		t.Fatal(err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

// The public demo keeps an issuer's card images like any wallet. It stores
// them, so no card loads from the issuer.
func TestPublicDemoKeepsIssuerImages(t *testing.T) {
	srv := newDemoTestServer(t)
	srv.wallet.AdhocDisplayImages = true
	images := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(tinyPNG)
	}))
	defer images.Close()

	metadata := map[string]any{"credential_configurations_supported": map[string]any{
		"badge": map[string]any{"credential_metadata": map[string]any{"display": []any{map[string]any{
			"name":             "Badge",
			"logo":             map[string]any{"uri": images.URL + "/logo.png", "alt_text": "Badge"},
			"background_image": map[string]any{"uri": pngDataURI(t)},
		}}}},
	}}
	d := srv.wallet.resolveCredentialDisplay(nil, metadata, "badge")
	if d == nil || !strings.HasPrefix(d.LogoURI, "data:image/png;base64,") || !strings.HasPrefix(d.BackgroundURI, "data:image/png;base64,") {
		t.Fatalf("the issuer's card images were not stored: %+v", d)
	}
	if got := srv.wallet.embedDisplayImage(nil, images.URL+"/issuer.png", "issuer_logo"); !strings.HasPrefix(got, "data:image/png;base64,") {
		t.Errorf("the issuer logo for consent was not kept: %.40q", got)
	}
	if got := srv.wallet.cacheDisplayImage(nil, "https://issuer.example/logo.png", "logo"); got == "https://issuer.example/logo.png" {
		t.Error("the public demo linked an issuer image instead of storing it")
	}

	operatorLogo := pngDataURI(t)
	if _, err := credtemplate.Save(srv.wallet.Templates, credtemplate.Template{
		Name: "operator-badge", Format: "sdjwt", VCT: "urn:example:operator-badge:1", Claims: map[string]any{"a": "b"},
		Display: &credtemplate.TemplateDisplay{Name: "Operator Badge", Logo: operatorLogo},
	}); err != nil {
		t.Fatal(err)
	}
	issued, err := srv.management().Issue(IssueAPIRequest{Format: "sdjwt", Template: "operator-badge"})
	if err != nil {
		t.Fatalf("issuing from the operator's template: %v", err)
	}
	id, _ := issued["id"].(string)
	if c, ok := srv.wallet.GetCredential(id); !ok || c.Display == nil || c.Display.LogoURI != operatorLogo {
		t.Errorf("the operator's template art was not kept: %+v", c.Display)
	}
}

// Every visitor of the public demo sees the cards of the others. A visitor's
// linked image is fetched and stored like an image from issuer metadata, so no
// card loads it from elsewhere.
func TestPublicDemoStoresVisitorImages(t *testing.T) {
	srv := newDemoTestServer(t)
	images := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(tinyPNG)
	}))
	defer images.Close()

	uploaded := pngDataURI(t)
	issued, err := srv.management().Issue(IssueAPIRequest{Format: "sdjwt", VCT: "urn:test:art", Claims: map[string]any{"a": "b"}, Display: &IssueDisplay{Name: "Art", Logo: images.URL + "/logo.png", BackgroundImage: uploaded}})
	if err != nil {
		t.Fatalf("issuing with a linked logo: %v", err)
	}
	id, _ := issued["id"].(string)
	if c, ok := srv.wallet.GetCredential(id); !ok || c.Display == nil || !strings.HasPrefix(c.Display.LogoURI, "data:image/png;base64,") || c.Display.BackgroundURI != uploaded {
		t.Errorf("the linked logo and the uploaded background image were not stored: %+v", c.Display)
	}

	if _, err := srv.management().SaveTemplate(credtemplate.Template{
		Name: "visitor-art", Format: "sdjwt", VCT: "urn:test:visitor-art", Claims: map[string]any{"a": "b"},
		Display: &credtemplate.TemplateDisplay{Name: "Visitor Art", BackgroundImage: images.URL + "/card.png"},
	}, nil); err != nil {
		t.Fatalf("saving a template with a linked background image: %v", err)
	}
	if saved, err := srv.management().Template("visitor-art"); err != nil || !strings.HasPrefix(saved.Display.BackgroundImage, "data:image/png;base64,") {
		t.Errorf("the template keeps the link instead of the image: %v %+v", err, saved)
	}
	images.Close()
	// The stored image is used, so issuing needs the link no more.
	issued, err = srv.management().Issue(IssueAPIRequest{Format: "sdjwt", Template: "visitor-art"})
	if err != nil {
		t.Fatalf("issuing from the visitor's template: %v", err)
	}
	id, _ = issued["id"].(string)
	if c, ok := srv.wallet.GetCredential(id); !ok || c.Display == nil || !strings.HasPrefix(c.Display.BackgroundURI, "data:image/png;base64,") {
		t.Errorf("the template's linked background image was not stored: %+v", c.Display)
	}

	// A template image that the issue dialog keeps arrives as its bundled
	// reference.
	issued, err = srv.management().Issue(IssueAPIRequest{Format: "sdjwt", VCT: "urn:test:art", Claims: map[string]any{"a": "b"}, Display: &IssueDisplay{Name: "Art", Logo: "embedded:logo.svg"}})
	if err != nil {
		t.Fatalf("issuing with a bundled logo: %v", err)
	}
	id, _ = issued["id"].(string)
	if c, ok := srv.wallet.GetCredential(id); !ok || c.Display == nil || !strings.HasPrefix(c.Display.LogoURI, "data:image/svg+xml;base64,") {
		t.Errorf("the bundled logo was not stored: %+v", c.Display)
	}
}

// A wallet without visitors keeps any image the issuer sends.
func TestOwnWalletKeepsIssuerImages(t *testing.T) {
	w := generateTestWallet(t)
	if got := w.cacheDisplayImage(nil, pngDataURI(t), "logo"); got == "" {
		t.Error("the issuer's image was dropped")
	}
}

// The wallet publishes its issued credential types in metadata and trusted
// lists, so visitors can't add types without bound.
func TestIssuedAttestationTypesStopAtCapacity(t *testing.T) {
	w := generateTestWallet(t)
	w.SetCapacity(Capacity{IssuedAttestations: len(w.IssuedAttestations) + 1})
	first := provider.IssuedAttestationSpec{Format: "dc+sd-jwt", VCT: "urn:test:one"}
	if _, err := w.EnsureIssuedAttestation(first); err != nil {
		t.Fatalf("the first new type: %v", err)
	}
	var limit *VisitorLimitError
	if _, err := w.EnsureIssuedAttestation(provider.IssuedAttestationSpec{Format: "dc+sd-jwt", VCT: "urn:test:two"}); !errors.As(err, &limit) {
		t.Fatalf("a type past the capacity: %v", err)
	}
	if _, err := w.EnsureIssuedAttestation(first); err != nil {
		t.Fatalf("a known type at the capacity: %v", err)
	}
}

// A credential put back after a concurrent reload counts against the
// capacity like any other.
func TestPutCredentialMakesRoom(t *testing.T) {
	w := generateTestWallet(t)
	w.SetCapacity(Capacity{Credentials: 2})
	for _, id := range []string{"a", "b", "c"} {
		w.PutCredential(StoredCredential{ID: id, Format: "dc+sd-jwt"})
	}
	if n := len(w.GetCredentials()); n != 2 {
		t.Fatalf("the wallet holds %d credentials, want 2", n)
	}
}

// A slow image host must not block the reloads of every other request, so
// the issue form's images are fetched before the reload lock is taken.
func TestIssueFetchesDisplayImagesOutsideTheReloadLock(t *testing.T) {
	srv := newTestServer(t, true)
	var lockedDuringFetch bool
	images := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if srv.storeSyncMu.TryLock() {
			srv.storeSyncMu.Unlock()
		} else {
			lockedDuringFetch = true
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(tinyPNG)
	}))
	defer images.Close()

	if _, err := srv.management().Issue(IssueAPIRequest{Format: "sdjwt", VCT: "urn:test:art", Claims: map[string]any{"a": "b"}, Display: &IssueDisplay{Logo: images.URL + "/logo.png"}}); err != nil {
		t.Fatal(err)
	}
	if lockedDuringFetch {
		t.Fatal("the image was fetched while the server held its reload lock")
	}
}

// A shared wallet signs with its own keys only. The rule holds for every
// caller of Management, not only the HTTP API.
func TestVisitorRulesRefuseASigningKeyOverride(t *testing.T) {
	w := generateTestWallet(t)
	w.SetVisitorRules(VisitorRules{OwnSigningKeys: true})
	_, err := NewManagement(w, NewWalletStore(t.TempDir())).Issue(IssueAPIRequest{Format: "sdjwt", SigningKey: "key", SigningCert: "cert"})
	var limit *VisitorLimitError
	if !errors.As(err, &limit) {
		t.Fatalf("err %v, want a visitor limit", err)
	}
}

// The capacity bounds the registrar of a shared wallet.
func TestCapacityBoundsTheRegistrar(t *testing.T) {
	w := generateTestWallet(t)
	w.SetCapacity(Capacity{RelyingParties: 1})
	registerTestIssuer(t, w, registrar.NonQEAAProviderEntitlement)
	_, err := w.Registrar().RegisterRelyingParty(registrar.WalletRelyingParty{
		TradeName: "Second University",
		Services: []registrar.WalletRelyingPartyService{{
			ServiceIdentifier:    "diplomas",
			Entitlements:         []string{registrar.NonQEAAProviderEntitlement},
			ProvidesAttestations: []registrar.ProvidedAttestation{{Format: "dc+sd-jwt", Type: testDiplomaVCT}},
		}},
	})
	if err == nil {
		t.Error("a full registrar accepted another relying party")
	}
}

// Management changes the status of a credential and logs it, for the HTTP
// API and the local CLI alike.
func TestManagementSetsTheCredentialStatus(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "https://wallet.example"
	result, err := w.IssueCredential(IssueOptions{Format: "sdjwt", VCT: "urn:test:status", Claims: map[string]any{"a": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	m := NewManagement(w, NewWalletStore(t.TempDir()))
	entry, err := m.SetCredentialStatus(result.Credential.ID, 1)
	if err != nil || entry.Status != 1 {
		t.Fatalf("SetCredentialStatus = %+v, %v, want status 1", entry, err)
	}
	if _, err := m.SetCredentialStatus(result.Credential.ID, 256); !errors.Is(err, ErrInvalidStatus) {
		t.Errorf("status 256: %v, want ErrInvalidStatus", err)
	}
	if !strings.HasPrefix(w.GetLog()[len(w.GetLog())-1].Detail, "Revoked credential") {
		t.Error("the revocation is not in the activity log")
	}
}
