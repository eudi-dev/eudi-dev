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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeWallet answers like a wallet server and records what the handler does.
type fakeWallet struct {
	t       *testing.T
	mu      sync.Mutex
	ready   bool
	buildID string
	pid     int
	refuse  bool
	submits []submission
	events  []string
}

type submission struct {
	path, client, owner string
	body                map[string]any
}

func (f *fakeWallet) event(e string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}

func (f *fakeWallet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	ready := f.ready
	f.mu.Unlock()
	if !ready {
		http.Error(w, "starting", http.StatusServiceUnavailable)
		return
	}
	switch r.URL.Path {
	case "/api/credentials":
		_, _ = w.Write([]byte("[]"))
	case "/api/version":
		_ = json.NewEncoder(w).Encode(map[string]any{"build_id": f.buildID, "pid": f.pid})
	case "/api/offers", "/api/presentations":
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			f.t.Errorf("the submitted body is not JSON: %v", err)
		}
		f.mu.Lock()
		f.submits = append(f.submits, submission{r.URL.Path, r.Header.Get("X-Eudi-Client"), r.Header.Get("X-Eudi-Owner"), body})
		f.events = append(f.events, "submit")
		refuse := f.refuse
		f.mu.Unlock()
		if refuse {
			http.Error(w, "no", http.StatusBadGateway)
		}
	default:
		http.NotFound(w, r)
	}
}

// newTestDispatcher points a dispatcher at a fake wallet. The binary is a
// file whose hash is the fake wallet's build_id unless a test changes it.
func newTestDispatcher(t *testing.T, opts Options, remote bool) (*Dispatcher, *fakeWallet) {
	t.Helper()
	wallet := &fakeWallet{t: t, ready: true}
	srv := httptest.NewServer(wallet)
	t.Cleanup(srv.Close)
	binary := filepath.Join(t.TempDir(), "eudi")
	if err := os.WriteFile(binary, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	wallet.buildID, _ = fileSHA256(binary)

	remoteURL := ""
	if remote {
		remoteURL = srv.URL
	} else {
		opts.ListenerPort, _ = strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	}
	d := NewDispatcher(opts, binary, "1.2.3", remoteURL, func(url string) bool {
		wallet.event("open " + strings.TrimPrefix(url, srv.URL))
		return true
	}, io.Discard)
	d.poll = time.Millisecond
	d.start = func(args []string) error {
		wallet.event("start " + strings.Join(args, " "))
		return nil
	}
	d.run = func(args []string) error {
		wallet.event("run " + strings.Join(args, " "))
		return nil
	}
	d.signal = func(pid int) error {
		wallet.event(fmt.Sprintf("signal %d", pid))
		return nil
	}
	return d, wallet
}

func TestAClickedOfferIsSubmittedToTheLocalWallet(t *testing.T) {
	d, wallet := newTestDispatcher(t, Options{}, false)
	uri := `OPENID-CREDENTIAL-OFFER://?credential_offer={"a":"b\c"}` + "\t"
	if err := d.Dispatch(uri); err != nil {
		t.Fatal(err)
	}
	want := []submission{{"/api/offers", "eudi-url-handler/1.2.3", "", map[string]any{"uri": uri, "interactive": true}}}
	if !reflect.DeepEqual(wallet.submits, want) {
		t.Errorf("submitted %+v, want %+v", wallet.submits, want)
	}
	if !reflect.DeepEqual(wallet.events, []string{"submit"}) {
		t.Errorf("events %v, want only the submit", wallet.events)
	}
}

func TestAutoAcceptSubmitsAPresentationWithoutConsent(t *testing.T) {
	d, wallet := newTestDispatcher(t, Options{AutoAccept: true}, false)
	if err := d.Dispatch("openid4vp://?request_uri=x"); err != nil {
		t.Fatal(err)
	}
	if len(wallet.submits) != 1 || wallet.submits[0].path != "/api/presentations" || wallet.submits[0].body["interactive"] != false {
		t.Errorf("submitted %+v, want one non-interactive presentation", wallet.submits)
	}
}

// Without a wallet that takes the link, 'wallet accept' handles it.
func TestARefusedSubmitFallsBackToWalletAccept(t *testing.T) {
	for _, tc := range []struct {
		autoAccept bool
		uri, want  string
	}{
		{false, "haip-vci://offer", "run wallet accept -- haip-vci://offer"},
		{false, "openid4vp://request", "run wallet accept -- openid4vp://request"},
		{true, "openid4vp://request", "run wallet accept --auto-accept -- openid4vp://request"},
	} {
		d, wallet := newTestDispatcher(t, Options{AutoAccept: tc.autoAccept}, false)
		wallet.refuse = true
		if err := d.Dispatch(tc.uri); err != nil {
			t.Fatal(err)
		}
		if got := wallet.events[len(wallet.events)-1]; got != tc.want {
			t.Errorf("auto-accept %t, %s: last event %q, want %q", tc.autoAccept, tc.uri, got, tc.want)
		}
	}
}

func TestAMissingWalletIsStartedWithTheRegisteredArguments(t *testing.T) {
	d, wallet := newTestDispatcher(t, Options{ServeArgs: []string{"--auto-accept", "--port", "9000"}}, false)
	wallet.ready = false
	d.start = func(args []string) error {
		wallet.event("start " + strings.Join(args, " "))
		wallet.mu.Lock()
		wallet.ready = true
		wallet.mu.Unlock()
		return nil
	}
	if err := d.Dispatch("openid-credential-offer://x"); err != nil {
		t.Fatal(err)
	}
	if want := []string{"start wallet serve --auto-accept --port 9000", "submit"}; !reflect.DeepEqual(wallet.events, want) {
		t.Errorf("events %v, want %v", wallet.events, want)
	}
}

// A wallet built from an older binary is stopped and started from the binary
// on disk.
func TestAnOutdatedWalletIsRestarted(t *testing.T) {
	d, wallet := newTestDispatcher(t, Options{}, false)
	wallet.buildID = "older"
	wallet.pid = 4711
	d.signal = func(pid int) error {
		wallet.event(fmt.Sprintf("signal %d", pid))
		wallet.mu.Lock()
		wallet.ready = false
		wallet.mu.Unlock()
		return nil
	}
	d.start = func(args []string) error {
		wallet.event("start")
		wallet.mu.Lock()
		wallet.ready = true
		wallet.mu.Unlock()
		return nil
	}
	if err := d.Dispatch("openid-credential-offer://x"); err != nil {
		t.Fatal(err)
	}
	if want := []string{"signal 4711", "start", "submit"}; !reflect.DeepEqual(wallet.events, want) {
		t.Errorf("events %v, want %v", wallet.events, want)
	}
}

// A remote wallet can't open a browser on this desktop. The handler opens its
// page first, because the submit waits for the decision there, and names that
// page on the submit.
func TestARemoteWalletGetsItsPageOpenedBeforeTheSubmit(t *testing.T) {
	d, wallet := newTestDispatcher(t, Options{}, true)
	if err := d.Dispatch("openid4vp://request"); err != nil {
		t.Fatal(err)
	}
	if len(wallet.events) != 2 || wallet.events[1] != "submit" {
		t.Fatalf("events %v, want the page opened and then the submit", wallet.events)
	}
	owner := wallet.submits[0].owner
	if owner == "" || wallet.events[0] != "open /?focus=overview&owner="+owner {
		t.Errorf("opened %q, submitted for owner %q", wallet.events[0], owner)
	}
}

// The remote already holds a refused request, so the handler doesn't process
// it again locally.
func TestARemoteRefusalIsNotRetriedLocally(t *testing.T) {
	d, wallet := newTestDispatcher(t, Options{}, true)
	wallet.refuse = true
	if err := d.Dispatch("openid4vp://request"); err == nil {
		t.Error("a refused remote submit reported success")
	}
	for _, e := range wallet.events {
		if strings.HasPrefix(e, "run") || strings.HasPrefix(e, "start") {
			t.Errorf("event %q after a remote refusal", e)
		}
	}
}

// Any web page can open these schemes. Other input is not handed on.
func TestOnlyOffersAndPresentationRequestsAreDispatched(t *testing.T) {
	d, wallet := newTestDispatcher(t, Options{}, false)
	for _, uri := range []string{"--remote=evil", "https://example.com", "file:///etc/passwd"} {
		if err := d.Dispatch(uri); err == nil {
			t.Errorf("%q was dispatched", uri)
		}
	}
	if len(wallet.events) != 0 {
		t.Errorf("events %v, want none", wallet.events)
	}
}
