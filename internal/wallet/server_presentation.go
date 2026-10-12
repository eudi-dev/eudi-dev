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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/oid4vc"
)

// Conformance settings belong to the running wallet and apply to every request. Only
// the options here can vary per presentation.
type presentationRequestOptions struct {
	AutoAccept        bool
	SessionTranscript string
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var authReq *AuthorizationRequestParams
	var err error
	var values map[string][]string

	if r.Method == "GET" {
		// RFC 3986 treats + as a literal character in a URI query. Form encoding
		// instead uses it for a space.
		values = oid4vc.URIQueryValues(r.URL)
	} else {
		if parseErr := r.ParseForm(); parseErr != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}
		values = r.Form
	}
	authReq, err = parseAuthParams(values, s.parseOpts, s.wallet.Mode())

	if err != nil {
		// Report parsing failures to the caller. Do not send a response to an invalid
		// request's destination (RFC 6749 §4.1.2.1, adopted by OpenID4VP §8.5).
		http.Error(w, fmt.Sprintf("invalid authorization request: %v", err), http.StatusBadRequest)
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

func (s *Server) handlePresentationAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URI               string `json:"uri"`
		AutoAccept        bool   `json:"auto_accept,omitempty"`
		Interactive       bool   `json:"interactive,omitempty"`
		SessionTranscript string `json:"session_transcript,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	s.wallet.ClearLastError(callerOwners(r))

	s.log("Received authorization request")
	uriDisplay := format.Truncate(body.URI, 120)
	s.log("  URI: %s", uriDisplay)

	reqServer := s
	opts := presentationRequestOptions{
		AutoAccept:        body.AutoAccept,
		SessionTranscript: body.SessionTranscript,
	}
	if opts.AutoAccept || opts.SessionTranscript != "" {
		reqWallet, err := cloneWalletForPresentation(s.wallet, opts)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		reqServer = &Server{
			wallet:           reqWallet,
			port:             s.port,
			mux:              s.mux,
			onSave:           s.onSave,
			onConsentRequest: s.onConsentRequest,
			onUIRequest: func(requestID string) {
				if !body.AutoAccept {
					s.triggerUIRequest(requestID)
				}
			},
			logFunc:       s.logFunc,
			httpSrv:       s.httpSrv,
			issuerSrv:     s.issuerSrv,
			issuerTLSCert: s.issuerTLSCert,
			issuerPort:    s.issuerPort,
		}
		reqServer.parseOpts = oid4vc.ParseOptions{
			FetchRequestURI: MakeFetchRequestURI(reqWallet, func(format string, args ...any) {
				reqServer.log(format, args...)
			}),
		}
	}

	parsed, err := ParseAuthorizationRequestWithOptions(body.URI, reqServer.parseOpts)
	if err != nil {
		reqServer.log("  ERROR: %v", err)
		reqServer.wallet.AddLog("presentation", fmt.Sprintf("Failed to parse request: %v", err), false)
		reqServer.wallet.NotifyError(WalletError{
			Owner:   requestOwner(r),
			Message: "Failed to parse authorization request",
			Detail:  err.Error(),
		})
		reqServer.triggerUIRequest("")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	reqServer.log("  Client ID:     %s", parsed.ClientID)
	reqServer.log("  Response Mode: %s", parsed.ResponseMode)
	reqServer.log("  Response URI:  %s", parsed.ResponseURI)
	if parsed.State != "" {
		reqServer.log("  State:         %s", parsed.State)
	}
	if parsed.Nonce != "" {
		reqServer.log("  Nonce:         %s", parsed.Nonce)
	}
	if parsed.RequestURIMethod != "" {
		reqServer.log("  Request URI Method: %s", parsed.RequestURIMethod)
	}

	authReq := &AuthorizationRequestParams{
		ClientID:         parsed.ClientID,
		ResponseType:     parsed.ResponseType,
		ResponseMode:     parsed.ResponseMode,
		Nonce:            parsed.Nonce,
		State:            parsed.State,
		RedirectURI:      parsed.RedirectURI,
		ResponseURI:      parsed.ResponseURI,
		Scope:            parsed.Scope,
		RequestURIMethod: parsed.RequestURIMethod,
		RequestURI:       parsed.RequestURI,
		ClientMetadata:   parsed.ClientMetadata,
		DCQLQuery:        parsed.DCQLQuery,
		RequestObject:    parsed.RequestObject,
		RequestPayload:   requestPayload(parsed.RequestObject, parsed.FullJSON),
		FullParams:       parsed.FullParams,
		Source:           "api",
		Session:          requestOwner(r),
	}

	// Validate here to return HTTP 400 for fatal errors. handleAuthFlow logs warnings
	// later, so logging here too would duplicate them.
	vpMode, vpHAIP, _ := reqServer.wallet.ConformanceSettings()
	if _, err := ValidateAuthorizationRequest(vpMode, vpHAIP, authReq); err != nil {
		reqServer.log("  ERROR: %v", err)
		reqServer.wallet.AddLog("presentation", err.Error(), false)
		reqServer.wallet.NotifyError(WalletError{
			Owner:   requestOwner(r),
			Message: "Authorization request validation failed",
			Detail:  err.Error(),
		})
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if body.Interactive {
		// Scheme dispatches still require interactive consent even though they use the
		// API.
		authReq.Source = "interactive"
		s.noteStaleClient(r)
	}

	reqServer.handleAuthFlow(w, authReq)
}

func cloneWalletForPresentation(src *Wallet, opts presentationRequestOptions) (*Wallet, error) {
	if src == nil {
		return nil, fmt.Errorf("wallet is not initialized")
	}

	// Copy conformance settings under the lock because the configuration API can
	// change them concurrently.
	srcMode, srcHAIP, srcEncrypted := src.ConformanceSettings()

	src.mu.RLock()
	verify := src.tlsVerify
	src.mu.RUnlock()

	clone := &Wallet{
		HolderKey:               src.HolderKey,
		IssuerKey:               src.IssuerKey,
		CAKey:                   src.CAKey,
		signers:                 src.signingStore(),
		CertChain:               append([]*x509.Certificate(nil), src.CertChain...),
		IssuedAttestations:      append([]IssuedAttestationSpec(nil), src.IssuedAttestations...),
		AutoAccept:              src.AutoAccept,
		SessionTranscript:       src.SessionTranscript,
		PreferredFormat:         src.PreferredFormat,
		KeyAttestationLevel:     src.KeyAttestationLevelSetting(),
		RequireEncryptedRequest: srcEncrypted,
		RequestEncryptionKey:    src.RequestEncryptionKey,
		RequireHAIP:             srcHAIP,
		ValidationMode:          srcMode,
		tlsVerify:               verify,
		outboundHTTP:            src.HTTPClient(),
		VCIVersion:              src.VCIFeatureVersion(),
		Credentials:             append([]StoredCredential(nil), src.Credentials...),
		StatusEntries:           cloneStatusEntries(src.StatusEntries),
		StatusListCounter:       src.StatusListCounter,
		allocateStatusIndex:     src.allocateStatusIndex,
		BaseURL:                 src.BaseURL,
		IssuerURL:               src.IssuerURL,
		ServingOrigin:           src.ServingOrigin,
		VCIClientID:             src.VCIClientID,
		VCIRedirectURI:          src.VCIRedirectURI,
		Log:                     append([]LogEntry(nil), src.Log...),
		logSink: func(entry LogEntry) {
			src.appendLogEntry(entry)
		},
		// Issuance on the clone must update the original wallet.
		credentialSink: func(cred StoredCredential) {
			src.mu.Lock()
			src.Credentials = append(src.Credentials, cred)
			src.mu.Unlock()
		},
		// Update batch rotation on the original wallet so it is saved after
		// presentation.
		batchPresentedSink: func(id string) {
			src.recordBatchPresentation(id)
		},
		runtime: src.runtimeState(),
	}

	if opts.AutoAccept {
		clone.AutoAccept = true
	}
	if opts.SessionTranscript != "" {
		switch SessionTranscriptMode(opts.SessionTranscript) {
		case SessionTranscriptOID4VP, SessionTranscriptISO:
			clone.SessionTranscript = SessionTranscriptMode(opts.SessionTranscript)
		default:
			return nil, fmt.Errorf("invalid session transcript %q", opts.SessionTranscript)
		}
	}

	return clone, nil
}

func cloneStatusEntries(src map[string]StatusEntry) map[string]StatusEntry {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]StatusEntry, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func mapKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
