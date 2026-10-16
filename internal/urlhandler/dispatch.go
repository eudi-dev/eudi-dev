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

package urlhandler

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc/scheme"
)

// DispatchLogPath is the log of the handler. A clicked link has no terminal.
// The log holds offer codes, so it stays in the user's own directory.
func DispatchLogPath() string {
	return filepath.Join(config.BaseDir(), "url-handler.log")
}

// serverLogPath is the log of a wallet started by the handler.
func serverLogPath() string {
	return filepath.Join(config.BaseDir(), "url-handler-server.log")
}

// Dispatcher hands a clicked offer or presentation link to the wallet. It
// submits the link to the running wallet, starts a local wallet when none
// answers, and falls back to 'wallet accept'.
type Dispatcher struct {
	Options
	// Binary is this executable. It starts the wallet and runs 'wallet accept'.
	Binary  string
	Version string
	// Remote is the wallet set by 'wallet use <url>'. It replaces the local
	// listener and is never started or restarted from here.
	Remote string
	// Open shows the wallet page in the browser.
	Open func(url string) bool
	// Log receives what the handler does. A clicked link has no terminal.
	Log io.Writer

	start  func(args []string) error
	run    func(args []string) error
	signal func(pid int) error
	poll   time.Duration
	client *http.Client
}

// NewDispatcher sets up the dispatch of links for a registration.
func NewDispatcher(opts Options, binary, version, remoteURL string, open func(string) bool, log io.Writer) *Dispatcher {
	d := &Dispatcher{Options: opts, Binary: binary, Version: version, Remote: strings.TrimRight(remoteURL, "/"), Open: open, Log: log}
	d.start = d.startServer
	d.run = d.runCommand
	d.signal = terminate
	d.poll = 250 * time.Millisecond
	d.client = &http.Client{}
	return d
}

func (d *Dispatcher) listener() string {
	if d.Remote != "" {
		return d.Remote
	}
	return fmt.Sprintf("http://localhost:%d", d.ListenerPort)
}

func (d *Dispatcher) logf(format string, args ...any) {
	fmt.Fprintf(d.Log, format+"\n", args...)
}

// Dispatch submits uri to the wallet. Without --auto-accept the wallet asks
// for consent, since a clicked link is a user interaction.
func (d *Dispatcher) Dispatch(uri string) error {
	// Any web page can open a link with these schemes, so nothing else is
	// handed on.
	if !scheme.IsPresentation(uri) && !scheme.IsIssuance(uri) {
		return fmt.Errorf("%q is not a presentation request or credential offer", uri)
	}
	if d.Remote != "" {
		d.logf("routing to active remote wallet %s", d.Remote)
	}
	path := "/api/presentations"
	if scheme.IsIssuance(uri) {
		path = "/api/offers"
	} else if d.AutoAccept {
		err := d.submit(path, uri, "")
		if err == nil {
			return nil
		}
		if d.Remote != "" {
			return err
		}
		d.logf("%v", err)
		return d.run([]string{"wallet", "accept", "--auto-accept", "--", uri})
	}
	if d.ensureListener() {
		owner := d.openRemoteUI()
		err := d.submit(path, uri, owner)
		if err == nil {
			return nil
		}
		// The remote already holds the request, so a local retry would process
		// it twice.
		if d.Remote != "" {
			return err
		}
		d.logf("%v", err)
	}
	return d.run([]string{"wallet", "accept", "--", uri})
}

// openRemoteUI opens the page of a remote wallet before the submit, which
// blocks until the user decides there. A remote wallet runs elsewhere, for
// example in a container, and can't open a browser on this desktop. The
// returned owner ties the submitted request to that page. A local wallet opens
// its own tab, so the owner stays empty.
func (d *Dispatcher) openRemoteUI() string {
	if d.Remote == "" || d.AutoAccept {
		return ""
	}
	owner := randomOwner()
	d.Open(d.Remote + "/?focus=overview&owner=" + owner)
	return owner
}

func randomOwner() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (d *Dispatcher) submit(path, uri, owner string) error {
	body, err := json.Marshal(map[string]any{"uri": uri, "interactive": !d.AutoAccept})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, d.listener()+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	d.identify(req)
	if owner != "" {
		req.Header.Set(config.OwnerHeader, owner)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("submitting to %s: %w", d.listener(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("submitting to %s: %s %s", d.listener(), resp.Status, strings.TrimSpace(string(detail)))
	}
	return nil
}

// identify names the handler and its release, so the wallet can tell its
// calls from those of other clients.
func (d *Dispatcher) identify(req *http.Request) {
	req.Header.Set(config.ClientHeader, "eudi-url-handler/"+d.Version)
}

func (d *Dispatcher) get(path string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, d.listener()+path, nil)
	if err != nil {
		return nil, err
	}
	d.identify(req)
	client := *d.client
	client.Timeout = 2 * time.Second
	return client.Do(req)
}

func (d *Dispatcher) listenerReady() bool {
	resp, err := d.get("/api/credentials")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 300
}

// ensureListener makes sure a wallet answers. A local wallet built from an
// older binary is restarted, and a missing one is started.
func (d *Dispatcher) ensureListener() bool {
	if d.Remote != "" {
		return d.listenerReady()
	}
	if d.listenerReady() {
		d.stopStaleListener()
		if d.listenerReady() {
			return true
		}
	}
	if err := d.start(append([]string{"wallet", "serve"}, d.ServeArgs...)); err != nil {
		d.logf("starting the wallet: %v", err)
		return false
	}
	return d.waitFor(40, true)
}

// waitFor polls up to n times until the listener's readiness is ready.
func (d *Dispatcher) waitFor(n int, ready bool) bool {
	for range n {
		if d.listenerReady() == ready {
			return true
		}
		time.Sleep(d.poll)
	}
	return false
}

// stopStaleListener stops a local wallet that runs an older build than the
// binary on disk. The wallet reports the SHA-256 of its executable as
// build_id on /api/version.
func (d *Dispatcher) stopStaleListener() {
	local, err := fileSHA256(d.Binary)
	if err != nil {
		return
	}
	resp, err := d.get("/api/version")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var version struct {
		BuildID string `json:"build_id"`
		PID     int    `json:"pid"`
	}
	if json.NewDecoder(resp.Body).Decode(&version) != nil || version.BuildID == local || version.PID == 0 {
		return
	}
	d.logf("wallet server is running an outdated build, restarting")
	if err := d.signal(version.PID); err != nil {
		d.logf("stopping pid %d: %v", version.PID, err)
		return
	}
	d.waitFor(20, false)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// startServer starts 'wallet serve' in its own session, so it keeps running
// after the handler exits.
func (d *Dispatcher) startServer(args []string) error {
	logFile, err := os.OpenFile(serverLogPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	cmd := exec.Command(d.Binary, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func (d *Dispatcher) runCommand(args []string) error {
	cmd := exec.Command(d.Binary, args...)
	cmd.Stdout = d.Log
	cmd.Stderr = d.Log
	return cmd.Run()
}
