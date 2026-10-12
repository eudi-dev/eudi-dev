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
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/config"
)

func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Vary", "Cookie, "+OwnerHeader)
	writeJSON(w, http.StatusOK, s.wallet.PendingRequestDocsFor(callerOwners(r), namedRequest(r)))
}

// Limit each stream write so disconnected readers release their goroutine and
// subscriptions. Allow enough time for the keepalive interval.
var streamWriteTimeout = 2 * time.Minute

// A variable lets tests shorten the keepalive interval.
var sseKeepaliveInterval = 25 * time.Second

func (s *Server) handleRequestStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// The server's normal write timeout would end the stream. Extend the deadline
	// before each write while retaining a timeout for clients that stop reading.
	rc := http.NewResponseController(w)
	extendDeadline := func() {
		if err := rc.SetWriteDeadline(time.Now().Add(streamWriteTimeout)); err != nil {
			s.log("  WARNING: event stream write deadline not extended, the stream ends with the server's write timeout: %v", err)
		}
	}
	extendDeadline()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Only the wallet UI should read these consent events. A wildcard CORS header
	// would let other sites subscribe to the requested claims.
	flusher.Flush()

	owners := callerOwners(r)

	reqCh, reqUnsub := s.wallet.Subscribe()
	defer reqUnsub()
	errCh, errUnsub := s.wallet.SubscribeErrors()
	defer errUnsub()
	stateCh, stateUnsub := s.wallet.SubscribeState()
	defer stateUnsub()
	authCh, authUnsub := s.wallet.SubscribeAuthorization()
	defer authUnsub()

	// Keepalives prevent proxies from dropping idle streams and causing repeated
	// reconnects.
	keepalive := time.NewTicker(sseKeepaliveInterval)
	defer keepalive.Stop()

	for {
		select {
		case <-keepalive.C:
			extendDeadline()
			if _, err := fmt.Fprintf(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case req := <-reqCh:
			if !ownsRequest(owners, req, "") {
				continue
			}
			data, err := json.Marshal(s.wallet.RequestDocFor(req, owners))
			if err != nil {
				continue
			}
			extendDeadline()
			if _, err := fmt.Fprintf(w, "event: consent\ndata: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		case walletErr := <-errCh:
			// Send failures to the flow's browser. Errors from unowned flows remain
			// visible to everyone.
			if walletErr.Owner != "" && !ownedBy(owners, walletErr.Owner) {
				continue
			}
			data, err := json.Marshal(walletErr)
			if err != nil {
				continue
			}
			extendDeadline()
			// Using the event name error would also trigger EventSource's connection
			// failure handler and close the stream.
			if _, err := fmt.Fprintf(w, "event: wallet-error\ndata: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		case <-stateCh:
			extendDeadline()
			if _, err := fmt.Fprintf(w, "event: state\ndata: {}\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case prompt := <-authCh:
			// Only the browser that owns the issuance should navigate to the sign-in
			// URL.
			if !ownedBy(owners, prompt.Owner) {
				continue
			}
			// The issuer redirects to /callback after sign-in, resuming the existing
			// flow.
			data, err := json.Marshal(map[string]string{"url": prompt.URL})
			if err != nil {
				continue
			}
			extendDeadline()
			if _, err := fmt.Fprintf(w, "event: authorize\ndata: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// Consent can outlast the normal write timeout. Extend it so URL handlers receive the
// result and do not retry an offer after a dropped connection.
func (s *Server) allowSlowResponse(w http.ResponseWriter, wait time.Duration) {
	err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(wait + config.SlowRequestTimeout))
	// Detached browser flows use a writer with no deadline.
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.log("  WARNING: write deadline not extended, a slow answer may not reach the caller: %v", err)
	}
}

// Distinguish timeout from an answer in another tab so the user knows what happened.
func refusalReason(status string) string {
	if status == statusExpired {
		return "This request timed out before it was answered"
	}
	return "This request was already answered"
}

func (s *Server) handleApproveRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var body struct {
		SelectedClaims map[string][]string `json:"selected_claims"`
		TxCode         string              `json:"tx_code"`
		// References the credential options selected in the dialog.
		Picks      map[string]consentPick `json:"picks"`
		SetChoices []int                  `json:"set_choices"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
			return
		}
	}
	var picks map[string][]string
	for qid, pick := range body.Picks {
		// null leaves the query to the wallet's default, like an omitted pick.
		if pick == nil {
			continue
		}
		if picks == nil {
			picks = make(map[string][]string, len(body.Picks))
		}
		picks[qid] = pick
	}

	// Validate selection before resolving consent so an invalid choice leaves the
	// dialog open.
	if pending, ok := s.wallet.GetRequest(id); ok {
		if !ownsRequest(callerOwners(r), pending, namedRequest(r)) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "request not found"})
			return
		}
		if err := ValidateConsentSelection(pending.CredentialOptions, picks, body.SetChoices); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}

	req, ok := s.wallet.ResolveRequest(id, "approved")
	if !ok {
		if req == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "request not found"})
		} else {
			writeJSON(w, http.StatusConflict, map[string]string{"error": refusalReason(req.Status)})
		}
		return
	}

	req.ResultCh <- ConsentResult{
		Approved:       true,
		Owner:          requestOwner(r),
		SelectedClaims: body.SelectedClaims,
		TxCode:         strings.TrimSpace(body.TxCode),
		Picks:          picks,
		SetChoices:     body.SetChoices,
	}

	s.allowSlowResponse(w, config.SlowRequestTimeout)
	select {
	case submission := <-req.SubmissionCh:
		out := map[string]any{
			"status":       "approved",
			"redirect_uri": submission.RedirectURI,
			"error":        submission.Error,
			"status_code":  submission.StatusCode,
		}
		if submission.Pending {
			// Report deferred issuance explicitly. Approval does not mean the
			// credential has arrived.
			out["status"] = "pending"
			out["pending"] = true
			out["transaction_id"] = submission.TransactionID
			out["retry_interval"] = submission.RetryInterval
		}
		writeJSON(w, http.StatusOK, out)
	case <-time.After(config.SlowRequestTimeout):
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "approved",
			"error":  "submission timeout",
		})
	}
}

func (s *Server) handleDenyRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if pending, ok := s.wallet.GetRequest(id); ok && !ownsRequest(callerOwners(r), pending, namedRequest(r)) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "request not found"})
		return
	}
	req, ok := s.wallet.ResolveRequest(id, "denied")
	if !ok {
		if req == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "request not found"})
		} else {
			writeJSON(w, http.StatusConflict, map[string]string{"error": refusalReason(req.Status)})
		}
		return
	}

	req.ResultCh <- ConsentResult{Approved: false}

	// OpenID4VP 1.0 §8.2: the verifier can answer the Authorization Error Response
	// with a redirect_uri, and the wallet must send the user agent there.
	s.allowSlowResponse(w, config.SlowRequestTimeout)
	select {
	case submission := <-req.SubmissionCh:
		out := map[string]any{"status": "denied"}
		if submission.Error != "" {
			out["error"] = submission.Error
		}
		writeJSON(w, http.StatusOK, withRedirectURI(out, submission.RedirectURI))
	case <-time.After(config.SlowRequestTimeout):
		writeJSON(w, http.StatusOK, map[string]any{"status": "denied"})
	}
}

// consentPick holds the credentials picked for one query. The JSON form is a single
// credential ID, or an array of IDs when the query sets multiple.
type consentPick []string

func (p *consentPick) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*p = nil
		return nil
	}
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*p = consentPick{one}
		return nil
	}
	many := []string{}
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("a pick is a credential ID or an array of them")
	}
	*p = many
	return nil
}
