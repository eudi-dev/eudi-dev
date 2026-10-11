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

package proxy

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/config"
	"github.com/dominikschlosser/eudi-dev/v3/internal/httpsec"
	"github.com/dominikschlosser/eudi-dev/v3/internal/publicpath"
	"github.com/dominikschlosser/eudi-dev/v3/internal/web"
	"github.com/dominikschlosser/eudi-dev/v3/internal/webui"
)

// Tests shorten the keepalive interval.
var streamKeepaliveInterval = config.StreamKeepaliveInterval

// A client that stops reading must release its goroutine and subscription. The
// timeout leaves room for keepalives to reach active readers.
var streamWriteTimeout = config.SlowRequestTimeout

type Dashboard struct {
	store   *Store
	port    int
	baseURL string
}

func NewDashboard(store *Store, port int) *Dashboard {
	return &Dashboard{store: store, port: port}
}

// SetBaseURL sets the dashboard's public URL behind a reverse proxy, such as
// https://example.com/eudi-proxy.
func (d *Dashboard) SetBaseURL(raw string) error {
	first, err := publicpath.FirstSegment(raw)
	if err != nil {
		return err
	}
	if dashboardRoots()[first] {
		return fmt.Errorf("the dashboard base URL path cannot start with /%s because the dashboard uses that path itself", first)
	}
	d.baseURL = raw
	return nil
}

func dashboardRoots() map[string]bool {
	roots := map[string]bool{"api": true, "decode": true}
	for _, name := range webui.Names {
		roots[name] = true
	}
	if entries, err := fs.ReadDir(staticFiles, "static"); err == nil {
		for _, entry := range entries {
			roots[entry.Name()] = true
		}
	}
	return roots
}

func (d *Dashboard) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/entries", d.handleEntries)
	mux.HandleFunc("GET /api/har", d.handleHAR)
	mux.HandleFunc("GET /api/stream", d.handleStream)

	decodeMux := web.NewMux("")
	mux.Handle("/decode/", http.StripPrefix("/decode", decodeMux))

	sub, _ := fs.Sub(staticFiles, "static")
	index, _ := fs.ReadFile(sub, "index.html")
	mux.Handle("/", publicpath.ServeIndex(index, http.FileServer(http.FS(webui.Overlay(sub)))))

	// The dashboard shows captured traffic, which is untrusted input, so it
	// sends the security headers.
	return publicpath.Wrap(publicpath.Options{
		BaseURL: d.baseURL,
		OnMismatch: func(observed string) {
			log.Printf("Warning: a dashboard request came in with %s, but --dashboard-base-url is %s", observed, d.baseURL)
		},
	}, httpsec.Headers(mux))
}

func (d *Dashboard) ListenAndServe() error {
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", d.port),
		Handler:      d.Handler(),
		ReadTimeout:  config.ServerReadTimeout,
		WriteTimeout: config.ServerWriteTimeout,
		IdleTimeout:  config.ServerIdleTimeout,
	}
	return srv.ListenAndServe()
}

func (d *Dashboard) handleEntries(w http.ResponseWriter, r *http.Request) {
	entries := d.store.Entries()
	w.Header().Set("Content-Type", "application/json")
	// The page keeps no more entries than the store.
	w.Header().Set("X-Entries-Limit", strconv.Itoa(d.store.MaxSize()))
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(entries)
}

func (d *Dashboard) handleHAR(w http.ResponseWriter, r *http.Request) {
	entries := d.store.Entries()
	har := GenerateHAR(entries)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"eudi-dev.har\"")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(har)
}

func (d *Dashboard) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Each write gets a fresh deadline. A healthy stream stays open and a stalled
	// client releases its subscription.
	rc := http.NewResponseController(w)
	extendDeadline := func() {
		if err := rc.SetWriteDeadline(time.Now().Add(streamWriteTimeout)); err != nil {
			log.Printf("[Dashboard] stream write deadline not extended, the stream will end with the server's write timeout: %v", err)
		}
	}
	extendDeadline()

	// The subscription starts before the response head goes out. A client that
	// follows and then reads the entry list misses no entry.
	ch, unsub := d.store.Subscribe()
	defer unsub()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	keepalive := time.NewTicker(streamKeepaliveInterval)
	defer keepalive.Stop()

	for {
		select {
		case entry := <-ch:
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			extendDeadline()
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-keepalive.C:
			extendDeadline()
			// SSE comments keep intermediaries from closing idle streams.
			fmt.Fprint(w, ": keepalive\n\n") //nolint:errcheck // a dead connection ends the stream on the next write anyway
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
