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
	"os"
	"path/filepath"
	"testing"

	imprintpage "github.com/eudi-dev/eudi-dev/v3/internal/imprint"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
	"github.com/eudi-dev/eudi-dev/v3/internal/web"
	"github.com/eudi-dev/eudi-dev/v3/internal/webui/webuitest"
)

// Every page of `wallet serve --demo` loads the bundled fonts, at the root and
// below a path prefix.
func TestEveryWalletPageLoadsTheFonts(t *testing.T) {
	d, w, _ := newDemoRP(t)
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
		for _, page := range []string{"/", "/imprint", "/privacy-policy", "/rulebook", "/decoder/", "/decoder/imprint", "/issuer/", "/verifier/"} {
			t.Run(prefix+page, func(t *testing.T) {
				webuitest.CheckFonts(t, h, prefix, page)
			})
		}
	}
}
