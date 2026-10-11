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
	"testing"
)

func pngDataURI(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 4, 4))); err != nil {
		t.Fatal(err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

// Every visitor of the public demo sees the cards of the others. A card
// keeps only the art bundled with the wallet. Images from issuer metadata are
// dropped, and an image a visitor chose is refused.
func TestPublicDemoKeepsOnlyBundledDisplayImages(t *testing.T) {
	srv := newDemoTestServer(t)
	bundled, err := staticFiles.ReadFile("static/logo.svg")
	if err != nil {
		t.Fatal(err)
	}
	bundledURI := "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(bundled)

	if got := srv.wallet.cacheDisplayImage(bundledURI, "logo"); got != bundledURI {
		t.Errorf("the bundled art was not kept: %.40q", got)
	}
	if got := srv.wallet.cacheDisplayImage(pngDataURI(t), "logo"); got != "" {
		t.Errorf("an issuer's own image was kept: %.40q", got)
	}
	if got := srv.wallet.embedDisplayImage(pngDataURI(t), "logo"); got != "" {
		t.Errorf("an issuer's own logo was kept for consent: %.40q", got)
	}

	// A visitor who uploads an image learns why the card has none.
	var limit *VisitorLimitError
	if _, err := srv.management().Issue(IssueAPIRequest{Format: "sdjwt", VCT: "urn:test:art", Claims: map[string]any{"a": "b"}, Display: &IssueDisplay{Name: "Art", Logo: pngDataURI(t)}}); !errors.As(err, &limit) {
		t.Errorf("issuing with an uploaded logo: %v, want a visitor limit", err)
	}
}

// A wallet without visitors keeps any image the issuer sends.
func TestOwnWalletKeepsIssuerImages(t *testing.T) {
	w := generateTestWallet(t)
	if got := w.cacheDisplayImage(pngDataURI(t), "logo"); got == "" {
		t.Error("the issuer's image was dropped")
	}
}

// The wallet publishes its issued credential types in metadata and trusted
// lists, so visitors can't add types without bound.
func TestIssuedAttestationTypesStopAtCapacity(t *testing.T) {
	w := generateTestWallet(t)
	w.SetCapacity(Capacity{IssuedAttestations: len(w.IssuedAttestations) + 1})
	first := IssuedAttestationSpec{Format: "dc+sd-jwt", VCT: "urn:test:one"}
	if _, err := w.EnsureIssuedAttestation(first); err != nil {
		t.Fatalf("the first new type: %v", err)
	}
	var limit *VisitorLimitError
	if _, err := w.EnsureIssuedAttestation(IssuedAttestationSpec{Format: "dc+sd-jwt", VCT: "urn:test:two"}); !errors.As(err, &limit) {
		t.Fatalf("a type past the capacity: %v", err)
	}
	if _, err := w.EnsureIssuedAttestation(first); err != nil {
		t.Fatalf("a known type at the capacity: %v", err)
	}
}

// A credential put back after a concurrent reload counts against the
// capacity like any other.
func TestRestoreCredentialMakesRoom(t *testing.T) {
	w := generateTestWallet(t)
	w.SetCapacity(Capacity{Credentials: 2})
	for _, id := range []string{"a", "b", "c"} {
		w.RestoreCredential(StoredCredential{ID: id, Format: "dc+sd-jwt"})
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
	oldClient := httpClient
	httpClient = images.Client()
	defer func() { httpClient = oldClient }()

	if _, err := srv.management().Issue(IssueAPIRequest{Format: "sdjwt", VCT: "urn:test:art", Claims: map[string]any{"a": "b"}, Display: &IssueDisplay{Logo: images.URL + "/logo.png"}}); err != nil {
		t.Fatal(err)
	}
	if lockedDuringFetch {
		t.Fatal("the image was fetched while the server held its reload lock")
	}
}
