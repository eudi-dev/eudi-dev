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
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
)

type caller struct {
	cookie string
	owner  string
}

func (c caller) apply(r *http.Request) {
	if c.cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: c.cookie})
	}
	if c.owner != "" {
		r.Header.Set(OwnerHeader, c.owner)
	}
}

func listRequestsAs(t *testing.T, srv *Server, who caller) []map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/requests", nil)
	who.apply(req)
	rec := httptest.NewRecorder()
	srv.handleListRequests(rec, req)
	var docs []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&docs); err != nil {
		t.Fatalf("decoding the request list: %v", err)
	}
	return docs
}

func pendingPresentation(owner string) *consent.Request {
	return &consent.Request{
		ID:       newConsentID(),
		Type:     "presentation",
		Owner:    owner,
		Status:   "pending",
		ClientID: "https://verifier.example",
	}
}

func TestPendingRequests_ReachTheBrowserThatStartedThem(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)
	w.Consents().Create(pendingPresentation("browser-a"))

	forA := listRequestsAs(t, srv, caller{cookie: "browser-a"})
	if len(forA) != 1 || forA[0]["mine"] != true {
		t.Fatalf("the starting browser sees %v, want the request as its own", forA)
	}
	if forB := listRequestsAs(t, srv, caller{cookie: "browser-b"}); len(forB) != 0 {
		t.Errorf("another visitor sees %d requests, want none", len(forB))
	}
}

func TestPendingRequests_ClientNamingTheBrowserItActsFor(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)
	w.Consents().Create(pendingPresentation("dispatch-nonce"))

	// The opened page has the client's browser ID as well as its own session cookie.
	page := listRequestsAs(t, srv, caller{cookie: "browser-a", owner: "dispatch-nonce"})
	if len(page) != 1 || page[0]["mine"] != true {
		t.Fatalf("the page the client opened sees %v, want the request as its own", page)
	}
	if other := listRequestsAs(t, srv, caller{cookie: "browser-b"}); len(other) != 0 {
		t.Errorf("another visitor sees %d requests, want none", len(other))
	}
}

// Older clients and API callers may omit a browser ID. Their requests stay
// visible to every caller.
func TestPendingRequests_UnownedStayVisible(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)
	w.Consents().Create(pendingPresentation(""))

	for _, who := range []struct {
		name string
		as   caller
	}{
		{"a caller with nothing at all, such as the CLI polling", caller{}},
		{"a browser that started nothing", caller{cookie: "browser-b"}},
		{"a page a client opened for something else", caller{cookie: "browser-b", owner: "other-nonce"}},
	} {
		docs := listRequestsAs(t, srv, who.as)
		if len(docs) != 1 {
			t.Errorf("%s sees %d requests, want the unowned one", who.name, len(docs))
		}
	}
}

func TestRequestOwner(t *testing.T) {
	for _, tc := range []struct {
		name string
		as   caller
		want string
	}{
		{"a page submitting its own URI", caller{cookie: "browser-a"}, "browser-a"},
		{"a client naming the browser it acts for", caller{owner: "dispatch-nonce"}, "dispatch-nonce"},
		{"a client naming a browser beats the cookie it does not hold", caller{cookie: "browser-a", owner: "dispatch-nonce"}, "dispatch-nonce"},
		{"a client that names nothing", caller{}, ""},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/presentations", nil)
		tc.as.apply(req)
		if got := requestOwner(req); got != tc.want {
			t.Errorf("%s: owner = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// EventSource cannot set custom headers, so the event stream accepts the browser ID in
// its URL.
func TestOwnerFromQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/requests/stream?owner=dispatch-nonce", nil)
	if got := presentedOwner(req); got != "dispatch-nonce" {
		t.Errorf("owner = %q, want the one in the query", got)
	}
}

func TestBrowserSession(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	id := newBrowserSession(rec, req, true)
	if id == "" {
		t.Fatal("expected a session id")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName || cookies[0].Value != id {
		t.Fatalf("cookies = %v, want the session that was minted", cookies)
	}
	got := cookies[0]
	if !got.HttpOnly {
		t.Error("the session is the wallet's own and no script needs to read it")
	}
	if got.SameSite != http.SameSiteLaxMode {
		t.Error("the session travels with a navigation to the wallet, which is how a verifier's link arrives")
	}
	if got.Path != "/" {
		t.Errorf("path = %q, want / so the API and the flow endpoints share it", got.Path)
	}
	if !got.Secure {
		t.Error("a wallet served over https marks its session Secure")
	}
	if got.MaxAge != 0 || !got.Expires.IsZero() {
		t.Error("a session cookie lives as long as the browser is open")
	}

	again := httptest.NewRecorder()
	kept := httptest.NewRequest(http.MethodGet, "/", nil)
	kept.AddCookie(&http.Cookie{Name: sessionCookieName, Value: id})
	if got := newBrowserSession(again, kept, true); got != id {
		t.Errorf("session = %q, want the one the browser already had", got)
	}
	if len(again.Result().Cookies()) != 0 {
		t.Error("a browser that already has a session is not given another")
	}
}

// Setting Secure on a cookie received over plain HTTP would prevent the browser from
// keeping it.
func TestBrowserSecure(t *testing.T) {
	w := generateTestWallet(t)
	// The public URL can use HTTPS while a local browser connects over HTTP.
	w.BaseURL = "https://eudi-test.dev"
	srv := NewServer(w, 0, nil)

	forwarded := httptest.NewRequest(http.MethodGet, "/", nil)
	forwarded.Header.Set("X-Forwarded-Proto", "https")
	if !srv.browserSecure(forwarded) {
		t.Error("a browser the proxy reached over https marks its session Secure")
	}

	chained := httptest.NewRequest(http.MethodGet, "/", nil)
	chained.Header.Set("X-Forwarded-Proto", "https, http")
	if !srv.browserSecure(chained) {
		t.Error("the first hop is the browser's own, and it was https")
	}

	if srv.browserSecure(httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Error("a browser on plain http would never send a Secure session back")
	}

	direct := httptest.NewRequest(http.MethodGet, "/", nil)
	direct.TLS = &tls.ConnectionState{}
	if !srv.browserSecure(direct) {
		t.Error("a browser that reached the wallet over TLS itself marks its session Secure")
	}
}

// The main page needs a session before it submits a request. Asset requests do not
// need to create sessions.
func TestPageRequestMintsTheSession(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)
	handler := srv.withBrowserSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	for _, tc := range []struct {
		method, path string
		wantCookie   bool
	}{
		{http.MethodGet, "/", true},
		{http.MethodGet, "/index.html", true},
		{http.MethodGet, "/app.js", false},
		{http.MethodGet, "/style.css", false},
		{http.MethodPost, "/", false},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		got := len(rec.Result().Cookies()) == 1
		if got != tc.wantCookie {
			t.Errorf("%s %s: session minted = %v, want %v", tc.method, tc.path, got, tc.wantCookie)
		}
	}
}

func TestClientName(t *testing.T) {
	for _, tc := range []struct {
		header, name string
	}{
		{"eudi-cli/1.25.2", "eudi-cli"},
		{"eudi-url-handler/dev", "eudi-url-handler"},
		{"eudi-ui", "eudi-ui"},
		{"", ""},
	} {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		if tc.header != "" {
			req.Header.Set(ClientHeader, tc.header)
		}
		if got := clientName(req); got != tc.name {
			t.Errorf("%q -> %q, want %q", tc.header, got, tc.name)
		}
	}
}

// Older handlers have no warning UI. The activity log lets the current wallet page
// display the upgrade notice.
func TestNoteStaleClient(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)

	named := httptest.NewRequest(http.MethodPost, "/api/presentations", nil)
	named.Header.Set(OwnerHeader, "a-page-it-opened")
	srv.noteStaleClient(named)
	if entry := findLogEntry(w.GetLog(), "client_names_no_page"); entry != nil {
		t.Fatalf("a client that names a page is not reported: %s", entry.Detail)
	}

	srv.noteStaleClient(httptest.NewRequest(http.MethodPost, "/api/presentations", nil))
	entry := findLogEntry(w.GetLog(), "client_names_no_page")
	if entry == nil {
		t.Fatal("expected the notice for a client that names nothing")
	}
	if entry.Severity != severityWarning {
		t.Errorf("severity = %q, want %q", entry.Severity, severityWarning)
	}

	// Report once per server to avoid repeating the warning in every flow.
	srv.noteStaleClient(httptest.NewRequest(http.MethodPost, "/api/presentations", nil))
	var notices int
	for _, e := range w.GetLog() {
		if e.Details != nil && e.Details["event"] == "client_names_no_page" {
			notices++
		}
	}
	if notices != 1 {
		t.Errorf("%d notices, want one per server", notices)
	}

	other := NewServer(w, 0, nil)
	other.noteStaleClient(httptest.NewRequest(http.MethodPost, "/api/presentations", nil))
	notices = 0
	for _, e := range w.GetLog() {
		if e.Details != nil && e.Details["event"] == "client_names_no_page" {
			notices++
		}
	}
	if notices != 2 {
		t.Errorf("%d notices, want one from each server", notices)
	}
}

// A presentation requested during issuance belongs to the offer's owner, or to the
// browser that approved an unowned offer.
func TestApprovingOwner(t *testing.T) {
	if got := approvingOwner("browser-a", "browser-b"); got != "browser-a" {
		t.Errorf("owner = %q, want the browser the offer belonged to", got)
	}
	if got := approvingOwner("", "browser-b"); got != "browser-b" {
		t.Errorf("owner = %q, want the browser that approved the offer", got)
	}
	if got := approvingOwner("", ""); got != "" {
		t.Errorf("owner = %q, want none when neither named a browser", got)
	}
}

// Older URL handlers and CLI clients omit the browser ID. Their requests must remain
// accessible to all callers.
func TestBackwardsCompatibility_ClientsThatNameNoBrowser(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)

	for _, client := range []struct {
		name    string
		prepare func(*http.Request)
	}{
		{"a URL handler installed before the wallet asked for a name", func(r *http.Request) {}},
		{"a CLI from an older release", func(r *http.Request) {}},
		{"a script driving the API directly", func(r *http.Request) {
			r.Header.Set("User-Agent", "curl/8.4.0")
		}},
	} {
		submission := httptest.NewRequest(http.MethodPost, "/api/presentations", nil)
		client.prepare(submission)
		if owner := requestOwner(submission); owner != "" {
			t.Errorf("%s: owner = %q, want none", client.name, owner)
		}
		w.Consents().Create(pendingPresentation(requestOwner(submission)))
	}

	for _, who := range []struct {
		name string
		as   caller
	}{
		{"the client polling for what it submitted", caller{}},
		{"the page it opened before the wallet ever set a session", caller{}},
		{"the page it opened once the wallet set one", caller{cookie: "browser-a"}},
	} {
		if got := len(listRequestsAs(t, srv, who.as)); got != 3 {
			t.Errorf("%s sees %d requests, want all 3", who.name, got)
		}
	}
}

// An upgrade warning must not prevent an older client from completing its flow.
func TestBackwardsCompatibility_OlderClientIsToldToUpgrade(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)

	srv.noteStaleClient(httptest.NewRequest(http.MethodPost, "/api/presentations", nil))
	entry := findLogEntry(w.GetLog(), "client_names_no_page")
	if entry == nil {
		t.Fatal("expected the notice")
	}
	if !strings.Contains(entry.Detail, "eudi wallet register") || !strings.Contains(entry.Detail, OwnerHeader) {
		t.Errorf("the notice does not say how to fix it: %s", entry.Detail)
	}

	w.Consents().Create(pendingPresentation(""))
	if got := len(listRequestsAs(t, srv, caller{})); got != 1 {
		t.Errorf("the submitted request is listed %d times, want 1", got)
	}
}

func TestBackwardsCompatibility_CurrentClientNamesThePageItOpened(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)

	submission := httptest.NewRequest(http.MethodPost, "/api/presentations", nil)
	submission.Header.Set(ClientHeader, "eudi-url-handler/1.25.2")
	submission.Header.Set(OwnerHeader, "dispatch-nonce")
	owner := requestOwner(submission)
	if owner != "dispatch-nonce" {
		t.Fatalf("owner = %q, want the page the client named", owner)
	}
	w.Consents().Create(pendingPresentation(owner))

	if got := listRequestsAs(t, srv, caller{cookie: "browser-a", owner: "dispatch-nonce"}); len(got) != 1 {
		t.Errorf("the page the client opened sees %d requests, want 1", len(got))
	}
	if got := listRequestsAs(t, srv, caller{cookie: "browser-b"}); len(got) != 0 {
		t.Errorf("another visitor sees %d requests, want none", len(got))
	}
	srv.noteStaleClient(submission)
	if entry := findLogEntry(w.GetLog(), "client_names_no_page"); entry != nil {
		t.Errorf("a client that names a page is reported: %s", entry.Detail)
	}
}

// Issuers and verifiers construct protocol URLs. Query parameters on these URLs must
// not select the browser that owns a consent request.
func TestProtocolURLCannotNameTheBrowser(t *testing.T) {
	navigation := httptest.NewRequest(http.MethodGet, "/authorize?client_id=x&owner=elsewhere", nil)
	navigation.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "browser-a"})
	if got := requestOwner(navigation); got != "browser-a" {
		t.Errorf("owner = %q, want the browser that navigated", got)
	}

	offer := httptest.NewRequest(http.MethodGet, "/credential-offer?credential_offer=x&owner=elsewhere", nil)
	if got := requestOwner(offer); got != "" {
		t.Errorf("owner = %q, want none: the link says nothing about whose browser this is", got)
	}

	// EventSource needs the query parameter because it cannot set custom headers.
	stream := httptest.NewRequest(http.MethodGet, "/api/requests/stream?owner=dispatch-nonce", nil)
	if got := callerOwners(stream); len(got) != 1 || got[0] != "dispatch-nonce" {
		t.Errorf("stream owners = %v, want the name the page holds", got)
	}
}

// Knowing an ID from an address bar does not establish ownership.
func TestAnswerBelongsToTheBrowserThatWasAsked(t *testing.T) {
	for _, action := range []string{"approve", "deny"} {
		w := generateTestWallet(t)
		srv := NewServer(w, 0, nil)
		req := pendingPresentation("browser-a")
		req.ResultCh = make(chan consent.Result, 1)
		req.SubmissionCh = make(chan consent.SubmissionResult, 1)
		w.Consents().Create(req)

		stranger := httptest.NewRequest(http.MethodPost, "/api/requests/"+req.ID+"/"+action, strings.NewReader("{}"))
		stranger.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "browser-b"})
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, stranger)

		if rec.Code != http.StatusNotFound {
			t.Errorf("%s by another browser: %d, want 404", action, rec.Code)
		}
		if got, _ := w.Consents().Get(req.ID); got != nil && got.Status != "pending" {
			t.Errorf("%s by another browser resolved the request as %q", action, got.Status)
		}
	}
}

func TestUnownedRequestStaysAnswerable(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)
	req := pendingPresentation("")
	req.ResultCh = make(chan consent.Result, 1)
	req.SubmissionCh = make(chan consent.SubmissionResult, 1)
	w.Consents().Create(req)

	deny := httptest.NewRequest(http.MethodPost, "/api/requests/"+req.ID+"/deny", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, deny)
	if rec.Code != http.StatusOK {
		t.Fatalf("deny by a caller with no browser: %d, want 200", rec.Code)
	}
	if result := <-req.ResultCh; result.Approved {
		t.Error("expected the denial to reach the flow")
	}
}

// A redirected browser may not send cookies, for example inside an iframe. The request
// ID in its redirect URL must still let it access that request.
func TestRedirectedBrowserReachesItsRequest(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)
	req := pendingPresentation("a-session-this-browser-never-kept")
	w.Consents().Create(req)

	if got := listRequestsAs(t, srv, caller{}); len(got) != 0 {
		t.Fatalf("a caller naming nothing sees %d requests, want none", len(got))
	}

	named := httptest.NewRequest(http.MethodGet, "/api/requests?request="+req.ID, nil)
	rec := httptest.NewRecorder()
	srv.handleListRequests(rec, named)
	var docs []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&docs); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(docs) != 1 || docs[0]["id"] != req.ID {
		t.Fatalf("naming the redirected id sees %v, want that request", docs)
	}

	other := pendingPresentation("another-browser")
	w.Consents().Create(other)
	guess := httptest.NewRequest(http.MethodGet, "/api/requests?request=not-an-id", nil)
	rec = httptest.NewRecorder()
	srv.handleListRequests(rec, guess)
	docs = nil
	if err := json.NewDecoder(rec.Body).Decode(&docs); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(docs) != 0 {
		t.Errorf("naming an id nobody holds sees %v, want nothing", docs)
	}
}

// The callback receives the request ID so the command can open or print the URL for
// that consent request.
func TestUIRequestNamesTheRequestItIsFor(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)
	var announced []string
	srv.SetOnUIRequest(func(requestID string) { announced = append(announced, requestID) })

	srv.triggerUIRequest("request-a")
	_, unsubscribe := w.Consents().Subscribe()
	defer unsubscribe()
	srv.triggerUIRequest("request-b")

	if len(announced) != 2 || announced[0] != "request-a" || announced[1] != "request-b" {
		t.Errorf("announced %v, want both requests named", announced)
	}
	if w.Consents().AttachedUIs() != 1 {
		t.Errorf("attached UIs = %d, want the watching tab counted", w.Consents().AttachedUIs())
	}
}

// Serializing the owner would let callers claim another browser's request.
func TestOwnerNeverLeavesTheServer(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)
	w.Consents().Create(pendingPresentation("browser-a"))

	docs := listRequestsAs(t, srv, caller{cookie: "browser-a"})
	if len(docs) != 1 {
		t.Fatalf("listed %d requests, want 1", len(docs))
	}
	encoded, err := json.Marshal(docs[0])
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if strings.Contains(string(encoded), "browser-a") {
		t.Errorf("the request document carries the browser it belongs to: %s", encoded)
	}
}

func TestLastErrorReachesTheFlowItBelongsTo(t *testing.T) {
	w := generateTestWallet(t)
	w.Consents().NotifyError(consent.Error{Message: "A's flow", Owner: "browser-a"})

	if got := w.Consents().PeekLastError([]string{"browser-a"}); got == nil || got.Message != "A's flow" {
		t.Errorf("the browser whose flow failed reads %v, want its own error", got)
	}
	if got := w.Consents().PeekLastError([]string{"browser-b"}); got != nil {
		t.Errorf("another browser reads %v, want nothing", got)
	}

	w.Consents().NotifyError(consent.Error{Message: "a client with no browser"})
	for _, owners := range [][]string{nil, {"browser-b"}} {
		if got := w.Consents().PeekLastError(owners); got == nil || got.Message != "a client with no browser" {
			t.Errorf("caller %v reads %v, want the unowned error", owners, got)
		}
	}

	// Clear every error the caller can read, including unowned errors. Otherwise
	// dismissed errors would return after reloading.
	w.Consents().ClearLastError([]string{"browser-b"})
	for _, owners := range [][]string{nil, {"browser-b"}} {
		if got := w.Consents().PeekLastError(owners); got != nil {
			t.Errorf("caller %v still reads %v after dismissing it", owners, got)
		}
	}
	if got := w.Consents().PeekLastError([]string{"browser-a"}); got == nil {
		t.Error("dismissing one browser's error dropped another's")
	}
}

func TestOwnerNameIsBounded(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/presentations", nil)
	req.Header.Set(OwnerHeader, strings.Repeat("x", maxOwnerLength+1))
	if got := requestOwner(req); got != "" {
		t.Errorf("owner = %q, want none for a name longer than a name", got)
	}
	req.Header.Set(OwnerHeader, strings.Repeat("x", maxOwnerLength))
	if got := requestOwner(req); got == "" {
		t.Error("a name of the greatest allowed length is still a name")
	}
}

// Distinguish timed out requests from requests answered in another tab. The message
// determines what the user should check.
func TestALateAnswerIsToldWhichHappened(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, nil)

	for _, tc := range []struct {
		name, resolveAs, want string
	}{
		{"expired", consent.StatusExpired, "This request timed out before it was answered"},
		{"answered", "denied", "This request was already answered"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := pendingPresentation("browser-a")
			req.ID = "late-" + tc.name
			w.Consents().Create(req)
			if _, ok := w.Consents().Resolve(req.ID, tc.resolveAs); !ok {
				t.Fatalf("resolving as %s", tc.resolveAs)
			}

			call := httptest.NewRequest(http.MethodPost, "/api/requests/"+req.ID+"/approve", nil)
			call.Header.Set(OwnerHeader, "browser-a")
			call.SetPathValue("id", req.ID)
			rec := httptest.NewRecorder()
			srv.handleApproveRequest(rec, call)

			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
			}
			var body map[string]string
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decoding: %v", err)
			}
			if body["error"] != "conflict" || body["error_description"] != tc.want {
				t.Errorf("body = %v, want conflict with %q", body, tc.want)
			}
		})
	}
}
