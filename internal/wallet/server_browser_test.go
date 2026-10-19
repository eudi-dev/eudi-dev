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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
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
