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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/config"
)

// dcAPIIssuanceProtocol is the issuance protocol of W3C Digital Credentials §5.
const dcAPIIssuanceProtocol = "openid4vci-v1"

type browserIssuanceEnvelope struct {
	Digital struct {
		Requests []struct {
			Protocol string          `json:"protocol"`
			Data     json.RawMessage `json:"data"`
		} `json:"requests"`
	} `json:"digital"`
}

// offer returns the first request with a supported protocol as a credential
// offer URI. W3C Digital Credentials §5 names OpenID4VCI 1.0 for the data, so it
// is a Credential Offer (OpenID4VCI 1.0 §4.1.1).
func (e browserIssuanceEnvelope) offer() (string, error) {
	for _, request := range e.Digital.Requests {
		if request.Protocol != dcAPIIssuanceProtocol {
			continue
		}
		var data map[string]json.RawMessage
		if err := json.Unmarshal(request.Data, &data); err != nil || data == nil {
			return "", errors.New("the data of an " + dcAPIIssuanceProtocol + " request must be a credential offer object")
		}
		// The offer parser reads a plus sign literally, so a space is %20.
		return "openid-credential-offer://?credential_offer=" + strings.ReplaceAll(url.QueryEscape(string(request.Data)), "+", "%20"), nil
	}
	return "", errors.New("no request uses the protocol " + dcAPIIssuanceProtocol)
}

// offerAnswer keeps the answer of the offer flow, because the page gets a
// different result than an API caller.
type offerAnswer struct {
	noopResponseWriter
	status int
	body   bytes.Buffer
}

func (a *offerAnswer) Write(b []byte) (int, error) { return a.body.Write(b) }

func (a *offerAnswer) WriteHeader(status int) { a.status = status }

// handleBrowserIssuanceAPI takes the argument of navigator.credentials.create()
// and runs the offer like any other. The answer only acknowledges the issuance.
func (s *Server) handleBrowserIssuanceAPI(w http.ResponseWriter, r *http.Request) {
	// The endpoint skips the API guard for the extension. A web page can post
	// to it without a preflight, and with auto-accept that would issue.
	if origin := r.Header.Get("Origin"); origin != "" && !extensionOrigin(origin) {
		apierror.Write(w, http.StatusForbidden, apierror.Forbidden, "only the browser extension calls this endpoint")
		return
	}
	origin, originErr := browserAPIOrigin(r)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		apierror.InvalidJSON(w, err)
		return
	}
	var body browserIssuanceEnvelope
	if err := json.Unmarshal(raw, &body); err != nil {
		s.logUnreadableDCAPICall("issuance", origin, raw, err)
		apierror.InvalidJSON(w, err)
		return
	}
	if originErr != nil {
		s.logUnreadableDCAPICall("issuance", "", raw, originErr)
		apierror.WriteErr(w, http.StatusBadRequest, apierror.InvalidRequest, originErr)
		return
	}
	s.logDCAPIIssuance(origin, raw, body)
	uri, err := body.offer()
	if err != nil {
		apierror.WriteErr(w, http.StatusBadRequest, apierror.InvalidRequest, err)
		return
	}

	s.allowSlowResponse(w, config.ConsentTimeout+interactiveAuthorizationConsentTimeout+config.AuthorizationCallbackWait)
	ctx, done := s.dcapi.track(r.Context(), r.Header.Get(CallIDHeader), requestOwner(r))
	defer done()
	answer := &offerAnswer{}
	s.processOfferURI(ctx, answer, uri, OfferOptions{Owner: requestOwner(r), Tab: requestTab(r), Caller: ctx}, false, false)
	s.writeBrowserIssuanceResult(ctx, w, origin, answer)
}

func (s *Server) logDCAPIIssuance(origin string, raw []byte, body browserIssuanceEnvelope) {
	protocols := make([]string, 0, len(body.Digital.Requests))
	for _, request := range body.Digital.Requests {
		protocols = append(protocols, request.Protocol)
	}
	s.addDCAPICallLog("issuance", origin, raw, map[string]any{"protocols": protocols})
}

func (s *Server) writeBrowserIssuanceResult(ctx context.Context, w http.ResponseWriter, origin string, answer *offerAnswer) {
	var outcome struct {
		Status  string `json:"status"`
		OfferID string `json:"offer_id"`
		Error   string `json:"error"`
	}
	_ = json.Unmarshal(answer.body.Bytes(), &outcome)
	switch {
	case answer.status >= http.StatusBadRequest:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(answer.status)
		_, _ = w.Write(answer.body.Bytes()) //nolint:gosec // G705: the wallet's own JSON answer.
		return
	case outcome.Status == "denied":
		apierror.Write(w, http.StatusForbidden, apierror.Forbidden, outcome.Error)
		return
	case outcome.Status == "authorization_required":
		// With auto-accept no wallet page is open to show the sign-in.
		if s.wallet.AutoAcceptSetting() {
			if pending := s.lookupPendingOffer(outcome.OfferID); pending != nil {
				pending.requestCancel()
			}
			apierror.Write(w, http.StatusBadRequest, apierror.InvalidRequest, "this offer needs a sign-in at the issuer. An auto-accepting wallet can't show it")
			return
		}
		if err := s.awaitSignIn(ctx, outcome.OfferID); err != nil {
			apierror.WriteErr(w, http.StatusBadRequest, apierror.InvalidRequest, err)
			return
		}
	}
	result := map[string]any{"protocol": dcAPIIssuanceProtocol, "data": map[string]any{}}
	details := map[string]any{"direction": "outbound", "source": "dc_api", "dc_api_result": result}
	addStringDetail(details, "request_origin", origin)
	s.wallet.addProtocolLog("issuance", "issuance_response", fmt.Sprintf("Returned the issuance result to %s through the Digital Credentials API", callerName(origin)), true, details)
	writeJSON(w, http.StatusOK, result)
}

// awaitSignIn keeps the call open during the sign-in, because the extension
// closes the wallet window when the call ends.
func (s *Server) awaitSignIn(ctx context.Context, offerID string) error {
	pending := s.lookupPendingOffer(offerID)
	if pending == nil {
		return errors.New("the sign-in at the issuer ended")
	}
	select {
	case <-pending.finished:
		_, err, _ := pending.outcome()
		return err
	case <-ctx.Done():
		pending.requestCancel()
		return errors.New(cancelReason(ctx))
	}
}
