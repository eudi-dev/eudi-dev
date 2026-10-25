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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

// CallIDHeader carries the ID of a browser extension call. The extension
// needs it to cancel the call with a reason. Extensions before 3.5.0 don't
// send it.
const CallIDHeader = "X-Eudi-Call-Id"

// refusalInterval limits refusal log entries to one per page and reason, even
// when a page retries in a loop.
const refusalInterval = time.Minute

// dcAPICalls tracks open browser extension calls and recently logged
// refusals. The zero value is ready to use.
type dcAPICalls struct {
	mu      sync.Mutex
	open    map[string]dcAPICall
	refused map[string]time.Time
}

type dcAPICall struct {
	owner  string
	cancel context.CancelCauseFunc
}

// track returns the context of a call. A call without an id ends only with its
// HTTP request.
func (c *dcAPICalls) track(parent context.Context, id, owner string) (context.Context, func()) {
	if id == "" {
		return parent, func() {}
	}
	ctx, cancel := context.WithCancelCause(parent)
	c.mu.Lock()
	if c.open == nil {
		c.open = map[string]dcAPICall{}
	}
	c.open[id] = dcAPICall{owner: owner, cancel: cancel}
	c.mu.Unlock()
	return ctx, func() {
		c.mu.Lock()
		delete(c.open, id)
		c.mu.Unlock()
		cancel(nil)
	}
}

// cancel ends the open call with the reason. Only the calling browser can
// cancel it.
func (c *dcAPICalls) cancel(id, owner, reason string) bool {
	c.mu.Lock()
	call, ok := c.open[id]
	c.mu.Unlock()
	if !ok || call.owner != owner {
		return false
	}
	call.cancel(errors.New(reason))
	return true
}

// firstRefusal reports whether the refusal wasn't logged within the last
// refusalInterval.
func (c *dcAPICalls) firstRefusal(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refused == nil {
		c.refused = map[string]time.Time{}
	}
	for k, at := range c.refused {
		if now.Sub(at) >= refusalInterval {
			delete(c.refused, k)
		}
	}
	if _, seen := c.refused[key]; seen {
		return false
	}
	c.refused[key] = now
	return true
}

// cancelReason says why a call ended before the user answered.
func cancelReason(ctx context.Context) string {
	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
		return cause.Error()
	}
	return "The caller stopped waiting"
}

// logDCAPICall logs the argument of navigator.credentials.get(). The entry
// lists every request and explains each unanswered one.
func (s *Server) logDCAPICall(origin string, raw []byte, body oid4vp.BrowserAPIRequestEnvelope) {
	protocols := body.Protocols()
	details := map[string]any{"direction": "inbound", "source": "dc_api", "protocols": protocols}
	addStringDetail(details, "request_origin", origin)
	if ignored := oid4vp.IgnoredBrowserAPIRequests(body); len(ignored) > 0 {
		details["ignored_requests"] = ignored
	}
	var payload any
	_ = json.Unmarshal(raw, &payload)
	s.wallet.addProtocolLog("presentation", "dc_api_call", fmt.Sprintf("Received a Digital Credentials API call from %s", callerName(origin)), true, details,
		&LogPayload{Label: "Digital Credentials API call", Body: payload})
}

// logUnreadableDCAPICall logs an unreadable call with its raw body.
func (s *Server) logUnreadableDCAPICall(origin string, raw []byte, err error) {
	details := map[string]any{"direction": "inbound", "source": "dc_api", "error": err.Error()}
	addStringDetail(details, "request_origin", origin)
	body := string(raw)
	if len(body) > 4096 {
		body = body[:4096] + "…"
	}
	s.wallet.addProtocolLog("presentation", "dc_api_call", fmt.Sprintf("Failed to read the Digital Credentials API call from %s: %v", callerName(origin), err), false, details,
		&LogPayload{Label: "Digital Credentials API call", Body: body})
}

func callerName(origin string) string {
	if origin == "" {
		return "a page without an origin"
	}
	return origin
}

// handleDCAPIRefusal logs a call refused by the browser extension, for
// example a request without a supported protocol or a call without a user
// action.
func (s *Server) handleDCAPIRefusal(w http.ResponseWriter, r *http.Request) {
	// The endpoint is open cross-origin. Only the extension may report.
	if !extensionOrigin(r.Header.Get("Origin")) {
		apierror.Write(w, http.StatusForbidden, apierror.Forbidden, "only the browser extension reports refused calls")
		return
	}
	var body struct {
		Name    string `json:"name"`
		Message string `json:"message"`
		Request any    `json:"request"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.InvalidJSON(w, err)
		return
	}
	origin, err := browserAPIOrigin(r)
	if err != nil {
		apierror.WriteErr(w, http.StatusBadRequest, apierror.InvalidRequest, err)
		return
	}
	name := boundDisplayText(body.Name, 40)
	message := boundDisplayText(body.Message, 300)
	if message == "" {
		apierror.Write(w, http.StatusBadRequest, apierror.InvalidRequest, "message is required")
		return
	}
	if !s.dcapi.firstRefusal(origin+"\n"+name+"\n"+message, time.Now()) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	details := map[string]any{"direction": "inbound", "source": "dc_api", "error": name, "error_description": message}
	addStringDetail(details, "request_origin", origin)
	var envelope oid4vp.BrowserAPIRequestEnvelope
	if data, err := json.Marshal(body.Request); err == nil && json.Unmarshal(data, &envelope) == nil && len(envelope.Digital.Requests) > 0 {
		details["protocols"] = envelope.Protocols()
		if ignored := oid4vp.IgnoredBrowserAPIRequests(envelope); len(ignored) > 0 {
			details["ignored_requests"] = ignored
		}
	}
	var payload *LogPayload
	if body.Request != nil {
		payload = &LogPayload{Label: "Digital Credentials API call", Body: body.Request}
	}
	s.wallet.addProtocolLog("presentation", "dc_api_refused", fmt.Sprintf("The browser extension refused the Digital Credentials API call from %s: %s", callerName(origin), message), false, details, payload)
	w.WriteHeader(http.StatusNoContent)
}

// handleDCAPICancel ends an open extension call. The activity log shows the
// reason, for example a closed wallet window.
func (s *Server) handleDCAPICancel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.InvalidJSON(w, err)
		return
	}
	reason := boundDisplayText(body.Reason, 200)
	if reason == "" {
		reason = "The caller cancelled the request"
	}
	if !s.dcapi.cancel(body.ID, requestOwner(r), reason) {
		apierror.Write(w, http.StatusNotFound, apierror.InvalidRequest, "no open Digital Credentials API call with this id")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// addDCAPIResultDetails adds the origin of the presentation and the
// encryption key of the response. A verifier needs both to read the result.
func addDCAPIResultDetails(details map[string]any, authReq *oid4vp.Request, result *oid4vp.BrowserAPIResult) {
	addStringDetail(details, "request_origin", authReq.RequestOrigin)
	data, _ := result.Data.(map[string]any)
	jwe, _ := data["response"].(string)
	if header := joseHeader(jwe); header != nil {
		encryption := map[string]any{}
		for _, name := range []string{"alg", "enc", "kid"} {
			if value, ok := header[name]; ok {
				encryption[name] = value
			}
		}
		details["response_encryption"] = encryption
	}
}

// joseHeader decodes the protected header of a compact JWE or JWS.
func joseHeader(compact string) map[string]any {
	first, _, found := strings.Cut(compact, ".")
	if !found {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil {
		return nil
	}
	var header map[string]any
	if json.Unmarshal(raw, &header) != nil {
		return nil
	}
	return header
}
