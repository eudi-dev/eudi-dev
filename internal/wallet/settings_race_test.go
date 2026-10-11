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
	"net/http"
	"net/http/httptest"
	"testing"
)

// changeSettingsWhile runs fn while another goroutine changes the runtime
// settings the way the config API does. go test -race reports an unlocked read.
func changeSettingsWhile(w *Wallet, fn func()) {
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			w.mu.Lock()
			w.PreferredFormat = []string{"mso_mdoc", "dc+sd-jwt"}[i%2]
			w.RequireEncryptedRequest = i%2 == 0
			w.mu.Unlock()
		}
	}()
	fn()
	close(stop)
	<-done
}

func TestDCQLEvaluationReadsThePreferredFormatUnderTheLock(t *testing.T) {
	w := pidBaselineWallet(t)
	changeSettingsWhile(w, func() {
		for i := 0; i < 50; i++ {
			evaluateDCQL(t, w, bothFormatDCQLQuery())
		}
	})
}

func TestRequestURIFetchReadsTheEncryptionSettingUnderTheLock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = rw.Write([]byte(makeTestJWT(map[string]any{"alg": "none"}, map[string]any{"client_id": "c"})))
	}))
	defer srv.Close()

	w := generateTestWallet(t)
	changeSettingsWhile(w, func() {
		for i := 0; i < 50; i++ {
			_, _ = MakeFetchRequestURI(w, nil)(srv.URL, "get", "")
		}
	})
}
