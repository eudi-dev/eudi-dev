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
	"strings"

	"github.com/eudi-dev/eudi-dev/v2/internal/config"
)

// ClientHeader identifies the client and release so the server can detect outdated URL
// handlers.
const ClientHeader = config.ClientHeader

const staleClientNotice = "This client named neither itself nor a page, so what it submits is offered to every open tab " +
	"rather than the one that started it. Re-register the URL handler with 'eudi wallet register', or send " +
	OwnerHeader + " from your own client to say which page a flow belongs to."

func clientName(r *http.Request) string {
	if r == nil {
		return ""
	}
	raw := strings.TrimSpace(r.Header.Get(ClientHeader))
	name, _, _ := strings.Cut(raw, "/")
	return strings.TrimSpace(name)
}

// Older URL handlers identify neither the client nor the browser session. Log the
// warning because their terminal output is not visible to the user.
func (s *Server) noteStaleClient(r *http.Request) {
	if clientName(r) != "" || requestOwner(r) != "" {
		return
	}
	s.staleClientOnce.Do(func() {
		s.wallet.addProtocolWarning("wallet", "client_names_no_page", staleClientNotice, nil)
	})
}
