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
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

const tinyPNGDataURI = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ/pLvAAAAAElFTkSuQmCC"

// Display images are stored as separate assets and wallet.json keeps only
// references. Embedded data URIs must stay readable.
func TestDisplayImagesStoredAsAssetsBesideWallet(t *testing.T) {
	srv := newTestServer(t, true)
	store := NewWalletStore(t.TempDir())
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatalf("initializing store: %v", err)
	}
	srv.SetStore(store)

	body := `{"format":"sdjwt","vct":"urn:example:asset","display":{"name":"Badge","logo":"` + tinyPNGDataURI + `"}}`
	resp := serverRequest(t, srv, http.MethodPost, "/api/issue", body)
	if resp.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", resp.Code, resp.Body.String())
	}
	id, _ := decodeJSON(t, resp)["id"].(string)

	// A newly issued image is served before it is saved as an asset.
	if before := serverRequest(t, srv, http.MethodGet, "/api/credentials/"+id+"/display/logo", ""); before.Code != http.StatusOK || before.Body.Len() == 0 {
		t.Fatalf("embedded image not served before save: %d len=%d", before.Code, before.Body.Len())
	}

	if err := store.Save(srv.wallet); err != nil {
		t.Fatalf("save: %v", err)
	}
	saved, err := store.storedCredentials()
	if err != nil || len(saved) != 1 || saved[0].Display == nil {
		t.Fatalf("stored credentials = %+v, %v", saved, err)
	}
	if !strings.HasPrefix(saved[0].Display.LogoURI, "asset:") {
		t.Errorf("the stored credential references %q, want an asset reference", saved[0].Display.LogoURI)
	}
	if entries, _ := store.Backend().List(store.key("assets")); len(entries) == 0 {
		t.Error("no asset file was written beside wallet.json")
	}

	reloaded, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	var stored *StoredCredential
	for i := range reloaded.Credentials {
		if reloaded.Credentials[i].ID == id {
			stored = &reloaded.Credentials[i]
		}
	}
	if stored == nil || stored.Display == nil || !strings.HasPrefix(stored.Display.LogoURI, "asset:") {
		t.Fatalf("reloaded display is not an asset reference: %+v", stored)
	}

	srv2 := NewServer(reloaded, 0, func() {})
	srv2.SetStore(store)
	img := serverRequest(t, srv2, http.MethodGet, "/api/credentials/"+id+"/display/logo", "")
	if img.Code != http.StatusOK || img.Body.Len() == 0 {
		t.Fatalf("asset not served after reload: %d len=%d", img.Code, img.Body.Len())
	}
	if ct := img.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
}

// The wallet serves display images from its own origin, so it serves image/*
// content only. A stored HTML page or unknown asset type is not served.
func TestDisplayImageEndpointServesOnlyImages(t *testing.T) {
	srv := newTestServer(t, true)
	store := NewWalletStore(t.TempDir())
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatalf("initializing store: %v", err)
	}
	srv.SetStore(store)
	if _, err := store.Backend().Write(store.assetKey("page.bin"), []byte("<script>alert(1)</script>"), 0o600); err != nil {
		t.Fatal(err)
	}
	html := "data:text/html;base64," + base64.StdEncoding.EncodeToString([]byte("<script>alert(1)</script>"))
	srv.wallet.PutCredential(StoredCredential{ID: "served", Display: &oid4vc.CredentialDisplay{LogoURI: tinyPNGDataURI, BackgroundURI: html}})
	srv.wallet.PutCredential(StoredCredential{ID: "asset", Display: &oid4vc.CredentialDisplay{LogoURI: "asset:page.bin"}})

	if got := serverRequest(t, srv, http.MethodGet, "/api/credentials/served/display/logo", ""); got.Code != http.StatusOK || got.Header().Get("Content-Type") != "image/png" {
		t.Errorf("image: %d %q, want 200 image/png", got.Code, got.Header().Get("Content-Type"))
	}
	for _, path := range []string{"/api/credentials/served/display/background", "/api/credentials/asset/display/logo"} {
		if got := serverRequest(t, srv, http.MethodGet, path, ""); got.Code != http.StatusNotFound {
			t.Errorf("%s: %d %q, want 404", path, got.Code, got.Header().Get("Content-Type"))
		}
	}
}

// Identical image content produces one stored asset and one reference.
func TestStoreDisplayAssetDedupes(t *testing.T) {
	store := NewWalletStore(t.TempDir())
	refA, okA, errA := store.storeDisplayAsset(tinyPNGDataURI)
	refB, okB, errB := store.storeDisplayAsset(tinyPNGDataURI)
	if errA != nil || errB != nil || !okA || !okB || refA != refB {
		t.Fatalf("expected one shared reference, got %q and %q", refA, refB)
	}
	entries, _ := store.Backend().List(store.key("assets"))
	if len(entries) != 1 {
		t.Fatalf("expected a single asset file, got %d", len(entries))
	}
	if ref, converted, err := store.storeDisplayAsset("https://issuer.example/logo.svg"); err != nil || converted || ref != "https://issuer.example/logo.svg" {
		t.Fatalf("an external URL should pass through unchanged, got %q converted=%v", ref, converted)
	}
}

// With --adhoc-display-images the browser loads HTTPS image URLs on demand.
// Data URIs stay embedded.
func TestAdhocDisplayImagesKeepsTheURL(t *testing.T) {
	w := generateTestWallet(t)
	w.AdhocDisplayImages = true

	url := "https://issuer.example/logo.png"
	if got := w.cacheDisplayImage(nil, url, "logo"); got != url {
		t.Fatalf("ad-hoc mode should keep the URL unfetched, got %q", got)
	}
	if entry := findLogEntry(w.GetLog(), "credential_display_image_rejected"); entry != nil {
		t.Error("keeping a URL for ad-hoc fetch should not log a rejection")
	}
	if ref := displayImageRef("some-id", "logo", url); ref != url {
		t.Fatalf("the kept URL should pass through to the client, got %q", ref)
	}
	if got := w.cacheDisplayImage(nil, tinyPNGDataURI, "logo"); !strings.HasPrefix(got, "data:") {
		t.Fatalf("a data URI image should still be embedded in ad-hoc mode, got %.20q", got)
	}
	// An http URL would be mixed content, so the wallet fetches it instead.
	// The fetch fails against this unreachable host and returns "".
	if got := w.cacheDisplayImage(nil, "http://issuer.example/logo.png", "logo"); got == "http://issuer.example/logo.png" {
		t.Fatal("an http image URL should not be kept ad-hoc")
	}
}

func TestPruneUnreferencedAssets(t *testing.T) {
	store := NewWalletStore(t.TempDir())
	usedRef, ok1, err1 := store.storeDisplayAsset(tinyPNGDataURI)
	orphanRef, ok2, err2 := store.storeDisplayAsset("data:image/png;base64," + base64.StdEncoding.EncodeToString(tinyPNG))
	if err1 != nil || err2 != nil || !ok1 || !ok2 || usedRef == orphanRef {
		t.Fatalf("expected two distinct assets, got %q and %q", usedRef, orphanRef)
	}
	if entries, _ := store.Backend().List(store.key("assets")); len(entries) != 2 {
		t.Fatalf("expected 2 asset files, got %d", len(entries))
	}

	w := generateTestWallet(t)
	w.Credentials = []StoredCredential{{ID: "a", Format: "dc+sd-jwt", Raw: "x~", Display: &oid4vc.CredentialDisplay{LogoURI: usedRef}}}
	if err := store.Save(w); err != nil {
		t.Fatalf("save: %v", err)
	}

	store.PruneUnreferencedAssets()

	if _, _, ok := store.ReadDisplayAsset(usedRef); !ok {
		t.Error("the referenced asset was pruned")
	}
	if _, _, ok := store.ReadDisplayAsset(orphanRef); ok {
		t.Error("the orphaned asset was not pruned")
	}
}
