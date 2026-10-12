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
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/httpsec"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

const maxRequestBody = 1 << 20 // 1MB

type MuxOptions struct {
	Credential  string // pre-filled credential served via GET /api/prefill
	Version     string // release version reported by GET /api/meta
	ImprintHTML []byte // pre-rendered legal notice served at GET /imprint
	Demo        bool   // public demo deployment, the UI shows a data disclaimer
	// CredentialByID resolves ?id= links, so the URL never holds the full
	// credential. A decoder without a wallet returns 404.
	CredentialByID func(id string) (string, bool)
	// WalletStore provides the CA and issuer key for local verification. Nil selects
	// the default wallet.
	WalletStore *wallet.WalletStore
	// HTTPClient returns the client for the outbound fetches of a validation. Nil
	// selects the shared developer client.
	HTTPClient func() *http.Client
}

func ListenAndServe(port int, opts MuxOptions) error {
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      NewMuxWithOptions(opts),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return srv.ListenAndServe()
}

func NewMux(credential string) http.Handler {
	return NewMuxWithOptions(MuxOptions{Credential: credential})
}

func NewMuxWithOptions(opts MuxOptions) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/decode", handleDecode(opts.HTTPClient))
	mux.HandleFunc("POST /api/validate", handleValidate(opts.WalletStore, opts.HTTPClient))
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
	mux.Handle("/", noStaleCache(http.FileServer(http.FS(sub))))

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
			writeError(w, http.StatusNotFound, "this decoder is not attached to a wallet, so it cannot resolve credential ids")
			return
		}
		credential, ok := resolve(r.PathValue("id"))
		if !ok {
			writeError(w, http.StatusNotFound, "no credential with that id in this wallet")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"credential": credential})
	}
}

type decodeRequest struct {
	Input string `json:"input"`
}

func handleDecode(httpClient func() *http.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

		var req decodeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if req.Input == "" {
			writeError(w, http.StatusBadRequest, "input is required")
			return
		}

		result, err := Validate(req.Input, ValidateOpts{HTTPClient: outboundClient(httpClient)})
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.Encode(result)
	}
}

func outboundClient(httpClient func() *http.Client) *http.Client {
	if httpClient == nil {
		return nil
	}
	return httpClient()
}

type validateRequest struct {
	Input        string `json:"input"`
	Key          string `json:"key"`
	TrustListURL string `json:"trustListURL"`
	TrustListRaw string `json:"trustListRaw"`
	CheckStatus  bool   `json:"checkStatus"`
	Offline      bool   `json:"offline"`
}

func handleValidate(store *wallet.WalletStore, httpClient func() *http.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

		var req validateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if req.Input == "" {
			writeError(w, http.StatusBadRequest, "input is required")
			return
		}

		result, err := Validate(req.Input, ValidateOpts{
			Key:          req.Key,
			TrustListURL: req.TrustListURL,
			TrustListRaw: req.TrustListRaw,
			CheckStatus:  req.CheckStatus,
			Offline:      req.Offline,
			WalletStore:  store,
			HTTPClient:   outboundClient(httpClient),
		})
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.Encode(result)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
