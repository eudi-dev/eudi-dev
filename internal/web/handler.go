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

package web

import (
	"encoding/json"
	"io/fs"
	"net/http"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/httpsec"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
	"github.com/eudi-dev/eudi-dev/v3/internal/webui"
)

const maxRequestBody = 1 << 20 // 1MB

type MuxOptions struct {
	Credential  string // pre-filled credential served via GET /api/prefill
	Version     string // release version reported by GET /api/meta
	ImprintHTML []byte // pre-rendered legal notice served at GET /imprint
	Demo        bool   // public demo deployment (the UI shows a data disclaimer)
	// CredentialByID resolves ?id= links, so the URL never holds the full
	// credential. A decoder without a wallet returns 404.
	CredentialByID func(id string) (string, bool)
	// WalletStore is a stored wallet. When it exists, its attestation
	// catalogue anchors credentials. The decoder never creates a wallet.
	WalletStore *wallet.WalletStore
	// Wallet is the running wallet. Its trusted lists include those from the
	// flags of wallet serve. The store doesn't keep them.
	Wallet *wallet.Wallet
}

func ListenAndServe(addr string, opts MuxOptions) error {
	srv := &http.Server{
		Addr:         addr,
		Handler:      NewMuxWithOptions(opts),
		ReadTimeout:  config.ServerReadTimeout,
		WriteTimeout: config.ServerWriteTimeout,
		IdleTimeout:  config.ServerIdleTimeout,
	}
	return srv.ListenAndServe()
}

func NewMux(credential string) http.Handler {
	return NewMuxWithOptions(MuxOptions{Credential: credential})
}

func NewMuxWithOptions(opts MuxOptions) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/validate", handleValidate(opts.WalletStore, opts.Wallet))
	mux.HandleFunc("GET /api/prefill", handlePrefill(opts.Credential))
	mux.HandleFunc("GET /api/credentials/{id}", handleCredentialByID(opts.CredentialByID))
	mux.HandleFunc("GET /api/meta", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"version": opts.Version,
			"imprint": len(opts.ImprintHTML) > 0,
			"demo":    opts.Demo,
			"wallet":  opts.CredentialByID != nil,
		})
	})
	mux.HandleFunc("GET /imprint", func(w http.ResponseWriter, r *http.Request) {
		if len(opts.ImprintHTML) == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(opts.ImprintHTML)
	})

	// Embedded files have no modification time for cache validation. Browsers must
	// revalidate, so they never mix assets from different releases.
	sub, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/", noStaleCache(webui.FileServer(sub)))

	// Decoder links can carry attacker-selected credentials. The guard sits inside the
	// handler, so mounted routes are checked after their prefix is stripped.
	return httpsec.Headers(httpsec.GuardAPI(mux))
}

func noStaleCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		h.ServeHTTP(w, r)
	})
}

func handlePrefill(credential string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"credential": credential})
	}
}

func handleCredentialByID(resolve func(string) (string, bool)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if resolve == nil {
			apierror.WriteStatus(w, http.StatusNotFound, "this decoder is not attached to a wallet, so it cannot resolve credential ids")
			return
		}
		credential, ok := resolve(r.PathValue("id"))
		if !ok {
			apierror.WriteStatus(w, http.StatusNotFound, "no credential with that id in this wallet")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"credential": credential})
	}
}

type validateRequest struct {
	Input        string `json:"input"`
	Key          string `json:"key"`
	TrustListURL string `json:"trustListURL"`
	TrustListRaw string `json:"trustListRaw"`
	CheckStatus  bool   `json:"checkStatus"`
	Offline      bool   `json:"offline"`
}

func handleValidate(store *wallet.WalletStore, live *wallet.Wallet) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

		var req validateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apierror.InvalidJSON(w, err)
			return
		}

		if req.Input == "" {
			apierror.WriteStatus(w, http.StatusBadRequest, "input is required")
			return
		}

		result, err := Validate(req.Input, ValidateOpts{
			Key:          req.Key,
			TrustListURL: req.TrustListURL,
			TrustListRaw: req.TrustListRaw,
			CheckStatus:  req.CheckStatus,
			Offline:      req.Offline,
			WalletStore:  store,
			Wallet:       live,
		})
		if err != nil {
			apierror.WriteStatusErr(w, http.StatusUnprocessableEntity, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.Encode(result)
	}
}
