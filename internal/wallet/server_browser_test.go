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
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
)

// The browser sets Origin, so a web page can't claim another origin. The
// extension's own request carries the page origin in CallerOriginHeader.
func TestTheExtensionReportsThePageOrigin(t *testing.T) {
	cases := []struct {
		name, origin, caller, want string
		wantErr                    bool
	}{
		{name: "page", origin: "https://verifier.example", want: "https://verifier.example"},
		{name: "page cannot claim another origin", origin: "https://evil.example", caller: "https://verifier.example", want: "https://evil.example"},
		{name: "chrome extension", origin: "chrome-extension://abc", caller: "https://verifier.example", want: "https://verifier.example"},
		{name: "firefox extension", origin: "moz-extension://abc", caller: "http://localhost:8085", want: "http://localhost:8085"},
		{name: "client without origin", caller: "https://verifier.example", want: "https://verifier.example"},
		{name: "path is no origin", origin: "chrome-extension://abc", caller: "https://verifier.example/page", wantErr: true},
		{name: "other scheme", origin: "chrome-extension://abc", caller: "file:///tmp", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/api/dc-api", nil)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.caller != "" {
				r.Header.Set(CallerOriginHeader, tc.caller)
			}
			got, err := browserAPIOrigin(r)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Errorf("browserAPIOrigin = %q, %v, want %q (error %v)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

// The extension a wallet serves points to that wallet.
func TestTheServedExtensionPointsToThisWallet(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.BaseURL = "https://wallet.example"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/eudi-dev-dc-api-extension.zip", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("status %d, Content-Type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	archive, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	f, err := archive.Open("config.json")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(f)
	var config map[string]string
	if err := json.Unmarshal(data, &config); err != nil || config["wallet_url"] != "https://wallet.example" {
		t.Errorf("config.json = %s, want the wallet URL https://wallet.example", data)
	}
}

// When the caller stops waiting, for example because the user closed the
// extension window, the wallet cancels its consent request. The next request
// is then the only one the user sees.
func TestALeavingDCAPICallerCancelsItsConsent(t *testing.T) {
	srv := newTestServer(t, false)
	shown := make(chan *consent.Request, 1)
	srv.onConsentRequest = func(req *consent.Request) { shown <- req }
	body, _ := json.Marshal(map[string]any{"digital": map[string]any{"requests": []any{map[string]any{
		"protocol": "openid4vp-v1-unsigned",
		"data": map[string]any{
			"response_type": "vp_token",
			"response_mode": "dc_api",
			"nonce":         "browser-nonce",
			"dcql_query": map[string]any{"credentials": []any{map[string]any{
				"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
			}}},
		},
	}}}})
	ctx, leave := context.WithCancel(context.Background())
	r := httptest.NewRequestWithContext(ctx, "POST", "/api/dc-api", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://rp.example")
	done := make(chan struct{})
	go func() {
		srv.mux.ServeHTTP(httptest.NewRecorder(), r)
		close(done)
	}()

	var req *consent.Request
	select {
	case req = <-shown:
	case <-time.After(5 * time.Second):
		t.Fatal("the wallet did not ask for consent")
	}
	leave()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler kept waiting after the caller left")
	}
	if req.Status != consent.StatusCancelled {
		t.Errorf("status %q, want %q", req.Status, consent.StatusCancelled)
	}
	if pending := srv.wallet.Consents().Pending(); len(pending) != 0 {
		t.Errorf("%d consent requests still pending, want none", len(pending))
	}
}
