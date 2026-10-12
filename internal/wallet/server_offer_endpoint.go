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
	"net/http"
	"net/url"

	"github.com/eudi-dev/eudi-dev/v2/internal/oid4vc"
)

// This web endpoint accepts the same credential_offer and credential_offer_uri
// parameters as openid-credential-offer:// URLs. tx_code can supply the transaction
// code for a pre-authorized offer.
func (s *Server) handleCredentialOfferEndpoint(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	offerParams := url.Values{}
	if v := query.Get("credential_offer"); v != "" {
		offerParams.Set("credential_offer", v)
	}
	if v := query.Get("credential_offer_uri"); v != "" {
		offerParams.Set("credential_offer_uri", v)
	}
	if len(offerParams) == 0 {
		http.Error(w, "missing credential_offer or credential_offer_uri parameter", http.StatusBadRequest)
		return
	}

	browser := isBrowserNavigation(r)
	session := requestOwner(r)
	if browser && session == "" {
		session = newBrowserSession(w, r, s.browserSecure(r))
	}
	s.processOfferURI(w, "openid-credential-offer://?"+oid4vc.EncodeURIQuery(offerParams), query.Get("tx_code"), session, browser, false)
}
