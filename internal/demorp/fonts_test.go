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

package demorp

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	imprintpage "github.com/eudi-dev/eudi-dev/v2/internal/imprint"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
	"github.com/eudi-dev/eudi-dev/v2/internal/web"
	"github.com/eudi-dev/eudi-dev/v2/internal/webui/webuitest"
)

// Every page of `wallet serve --demo` loads the bundled fonts, at the root and
// below a path prefix.
func TestEveryWalletPageLoadsTheFonts(t *testing.T) {
	d, w, holderKey := newDemoRP(t)
	d.SetClientAuthMode(ClientAuthOptional)
	snippet := filepath.Join(t.TempDir(), "imprint.html")
	if err := os.WriteFile(snippet, []byte("<p>Example Org</p>"), 0o600); err != nil {
		t.Fatal(err)
	}
	imprint, err := imprintpage.Load(snippet)
	if err != nil {
		t.Fatal(err)
	}
	srv := wallet.NewServer(w, 0, nil)
	srv.SetImprint(imprint)
	srv.Mount("/decoder", web.NewMuxWithOptions(web.MuxOptions{ImprintHTML: imprint}))
	srv.Mount("/issuer", d.IssuerHandler())
	srv.Mount("/verifier", d.VerifierHandler())
	h := srv.Handler()
	for _, prefix := range []string{"", "/some/context"} {
		for _, page := range []string{"/", "/imprint", "/decoder/", "/decoder/imprint", "/issuer/", "/verifier/", signInPage(t, d, holderKey)} {
			t.Run(prefix+page, func(t *testing.T) {
				webuitest.CheckFonts(t, h, prefix, page)
			})
		}
	}
}

// signInPage pushes an authorization request and returns the path of the
// sign-in page for it.
func signInPage(t *testing.T, d *DemoRP, holderKey *ecdsa.PrivateKey) string {
	t.Helper()
	sum := sha256.Sum256([]byte("aVeryLongCodeVerifierThatIsAtLeastFortyThreeCharacters"))
	pushed := pushAuthorizationRequest(t, d.IssuerHandler(), "http://wallet.example", holderKey, format.EncodeBase64URL(sum[:]), nil)
	if pushed.Code != http.StatusCreated {
		t.Fatalf("pushing the authorization request: %d %s", pushed.Code, pushed.Body.String())
	}
	var doc struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(pushed.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	return "/issuer/authorize?request_uri=" + url.QueryEscape(doc.RequestURI)
}
