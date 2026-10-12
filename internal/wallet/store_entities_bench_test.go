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
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/storage"
)

func BenchmarkEntitySaveWithManyCredentials(b *testing.B) {
	quietLogs(b)
	store := NewWalletStoreOn(filepath.Join(b.TempDir(), "wallet"), storage.NewMemory())
	w, err := store.LoadOrCreate()
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 500; i++ {
		importTestCredential(b, w, "Held")
	}
	if err := store.Save(w); err != nil {
		b.Fatal(err)
	}
	// Create credentials before timing so the benchmark measures saving only.
	pool := New(w.HolderKey, w.IssuerKey, false)
	for i := 0; i < b.N; i++ {
		importTestCredential(b, pool, "New")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Log = append(w.Log, LogEntry{Time: time.Now(), Action: "step"})
		w.Credentials = append(w.Credentials, pool.Credentials[i])
		if err := store.Save(w); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEntityLoadOneAddedCredential(b *testing.B) {
	quietLogs(b)
	backend := storage.NewMemory()
	dir := filepath.Join(b.TempDir(), "wallet")
	store := NewWalletStoreOn(dir, backend)
	w, err := store.LoadOrCreate()
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 500; i++ {
		importTestCredential(b, w, "Held")
	}
	if err := store.Save(w); err != nil {
		b.Fatal(err)
	}
	other := NewWalletStoreOn(dir, backend)
	o, err := other.LoadOrCreate()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		importTestCredential(b, o, "New")
		if err := other.Save(o); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		changed, err := store.changedSections(w, false)
		if err != nil {
			b.Fatal(err)
		}
		if err := store.loadSections(w, changed); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServerIssueWithManyCredentials(b *testing.B) {
	quietLogs(b)
	srv := newTestServer(b, false)
	store := NewWalletStoreOn(filepath.Join(b.TempDir(), "wallet"), storage.NewMemory())
	srv.SetStore(store)
	srv.wallet.IssuerURL = "https://wallet.example:8086"
	for i := 0; i < 500; i++ {
		importTestCredential(b, srv.wallet, "Held")
	}
	if err := store.Save(srv.wallet); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := serverRequest(b, srv, "POST", "/api/issue", `{"format":"sdjwt","template":"pid-sdjwt"}`)
		if resp.Code != 201 {
			b.Fatalf("issue: %d %s", resp.Code, resp.Body.String())
		}
	}
}

func BenchmarkServerPresentWithManyCredentials(b *testing.B) {
	quietLogs(b)
	srv := newTestServer(b, true)
	store := NewWalletStoreOn(filepath.Join(b.TempDir(), "wallet"), storage.NewMemory())
	srv.SetStore(store)
	srv.wallet.IssuerURL = "https://wallet.example:8086"
	key, _ := mock.GenerateKey()
	for i := 0; i < 640; i++ {
		raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{Issuer: "https://test.example", VCT: "urn:eudi:pid:1", ExpiresIn: time.Hour, Claims: map[string]any{"given_name": "Held", "family_name": "Many"}, Key: key})
		if err != nil {
			b.Fatal(err)
		}
		if _, err := srv.wallet.ImportCredential(raw); err != nil {
			b.Fatal(err)
		}
	}
	if err := store.Save(srv.wallet); err != nil {
		b.Fatal(err)
	}
	received := make(chan struct{}, 1)
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("vp_token") != "" {
			received <- struct{}{}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	defer verifier.Close()
	query := url.Values{
		"client_id":     {"redirect_uri:" + verifier.URL},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"response_uri":  {verifier.URL},
		"nonce":         {"n"},
		"state":         {"s"},
		"dcql_query":    {`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["given_name"]}]}]}`},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := serverRequest(b, srv, "GET", "/authorize?"+query.Encode(), "")
		if resp.Code >= 400 {
			b.Fatalf("authorize: %d %s", resp.Code, resp.Body.String())
		}
		<-received
	}
}

func quietLogs(b *testing.B) {
	previous := log.Writer()
	log.SetOutput(io.Discard)
	b.Cleanup(func() { log.SetOutput(previous) })
}
