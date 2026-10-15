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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var authReq *oid4vp.Request
	var err error
	var values map[string][]string

	if r.Method == "GET" {
		// RFC 3986 treats + as a literal character in a URI query. Form encoding
		// instead uses it for a space.
		values = oid4vc.URIQueryValues(r.URL)
	} else {
		if parseErr := r.ParseForm(); parseErr != nil {
			apierror.Write(w, http.StatusBadRequest, apierror.InvalidRequest, "invalid form data: "+parseErr.Error())
			return
		}
		values = r.Form
	}
	authReq, err = oid4vp.ParseRequest(values, s.parseOpts)

	if err != nil {
		s.refuseUnreadableRequest(w, requestOwner(r), err)
		return
	}

	authReq.BrowserRedirect = isBrowserNavigation(r)
	// This may be the browser's first request. Create its session before associating
	// the consent request with it.
	authReq.Session = requestOwner(r)
	if authReq.BrowserRedirect && authReq.Session == "" {
		authReq.Session = newBrowserSession(w, r, s.browserSecure(r))
	}
	s.handleAuthFlow(w, authReq)
}

// refuseUnreadableRequest answers a request the wallet cannot parse. The
// error goes to the caller and the user. The request's destination gets
// nothing (RFC 6749 §4.1.2.1, applied by OpenID4VP 1.0 §8.5).
func (s *Server) refuseUnreadableRequest(w http.ResponseWriter, owner string, err error) {
	s.log("  ERROR: %v", err)
	action, message := "presentation", "Failed to parse authorization request"
	if errors.Is(err, oid4vc.ErrUnrecognizedInput) {
		action, message = "input", "Not an OpenID4VCI offer or OpenID4VP request"
	}
	s.wallet.reportRefusal(action, "authorization_request_unreadable", owner, message, "", err)
	s.triggerUIRequest("")
	apierror.WriteErr(w, http.StatusBadRequest, oid4vp.ParseErrorCode(err), err)
}

func (s *Server) handlePresentationAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URI               string `json:"uri"`
		AutoAccept        bool   `json:"auto_accept,omitempty"`
		Interactive       bool   `json:"interactive,omitempty"`
		SessionTranscript string `json:"session_transcript,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.InvalidJSON(w, err)
		return
	}

	s.wallet.Consents().ClearLastError(callerOwners(r))

	s.log("Received authorization request")
	uriDisplay := format.Truncate(body.URI, 120)
	s.log("  URI: %s", uriDisplay)

	transcript := oid4vp.SessionTranscriptMode(body.SessionTranscript)
	switch transcript {
	case "", oid4vp.SessionTranscriptOID4VP, oid4vp.SessionTranscriptISO:
	default:
		apierror.Write(w, http.StatusBadRequest, apierror.InvalidRequest, fmt.Sprintf("invalid session transcript %q", body.SessionTranscript))
		return
	}
	parsed, err := oid4vp.ParseAuthorizationRequestWithOptions(body.URI, s.parseOpts)
	if err != nil {
		s.refuseUnreadableRequest(w, requestOwner(r), err)
		return
	}

	s.log("  Client ID:     %s", parsed.ClientID)
	s.log("  Response Mode: %s", parsed.ResponseMode)
	s.log("  Response URI:  %s", parsed.ResponseURI)
	if parsed.State != "" {
		s.log("  State:         %s", parsed.State)
	}
	if parsed.Nonce != "" {
		s.log("  Nonce:         %s", parsed.Nonce)
	}
	if parsed.RequestURIMethod != "" {
		s.log("  Request URI Method: %s", parsed.RequestURIMethod)
	}

	authReq := oid4vp.RequestFrom(parsed)
	authReq.Source = "api"
	authReq.Session = requestOwner(r)
	authReq.AutoAccept = body.AutoAccept
	authReq.SessionTranscript = transcript

	if body.Interactive {
		// Scheme dispatches still require interactive consent even though they use the
		// API.
		authReq.Source = "interactive"
		s.noteStaleClient(r)
	}

	s.handleAuthFlow(w, authReq)
}

func mapKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
