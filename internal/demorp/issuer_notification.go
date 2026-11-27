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

package demorp

import (
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

// issuedNotification is one notification_id of a Credential Response
// (OpenID4VCI 1.0 §8.3) with the events the wallet sent for it.
type issuedNotification struct {
	offerID  string
	configID string
	// token is the access token of the Credential Request. §11 sends the
	// Notification Request with the same access token.
	token    string
	received []receivedNotification
	expires  time.Time
}

type receivedNotification struct {
	oid4vc.Notification
	ConfigurationID string    `json:"credential_configuration_id"`
	Received        time.Time `json:"received"`
}

// maxNotificationEvents bounds the events kept per notification_id. §11.1
// does not limit how often a wallet sends one.
const maxNotificationEvents = 10

func (d *DemoRP) newNotificationID(token string, granted ticketGrant) string {
	id := randToken()
	d.mu.Lock()
	d.pruneLocked()
	makeRoom(d.notifications, func(n *issuedNotification) time.Time { return n.expires })
	d.notifications[id] = &issuedNotification{
		offerID:  granted.offerID,
		configID: granted.configID,
		token:    token,
		expires:  time.Now().Add(entryTTL),
	}
	d.mu.Unlock()
	return id
}

// handleNotification is the Notification Endpoint of OpenID4VCI 1.0 §11. It
// answers 204 (§11.2) and the 400 errors of §11.3.
func (d *DemoRP) handleNotification(w http.ResponseWriter, r *http.Request) {
	token, _, refused := d.authorizeAccessToken(r, "/notification")
	if refused != nil {
		d.writeAccessTokenError(w, r, refused)
		return
	}
	var req struct {
		NotificationID string `json:"notification_id"`
		oid4vc.Notification
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_notification_request", "the body is not a JSON object: "+err.Error()))
		return
	}
	if req.NotificationID == "" {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_notification_request", "notification_id is required"))
		return
	}
	if err := req.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_notification_request", err.Error()))
		return
	}

	d.mu.Lock()
	issued, known := d.notifications[req.NotificationID]
	known = known && issued.token == token && time.Now().Before(issued.expires)
	if known {
		issued.received = append(issued.received, receivedNotification{
			Notification: req.Notification, ConfigurationID: issued.configID, Received: time.Now().UTC(),
		})
		if len(issued.received) > maxNotificationEvents {
			issued.received = issued.received[len(issued.received)-maxNotificationEvents:]
		}
	}
	d.mu.Unlock()
	// §11.3 invalid_notification_id: "The notification_id in the
	// Notification Request was invalid." An id of another access token is
	// invalid for this one.
	if !known {
		writeJSON(w, http.StatusBadRequest, oauthError("invalid_notification_id", "unknown or expired notification_id"))
		return
	}
	log.Printf("[Demo issuer] notification %s for %s", req.Event, issued.configID)
	w.WriteHeader(http.StatusNoContent)
}

// handleOfferNotifications lists the notifications the wallet sent for the
// credentials of an offer, oldest first.
func (d *DemoRP) handleOfferNotifications(w http.ResponseWriter, r *http.Request) {
	offerID := r.PathValue("id")
	received := []receivedNotification{}
	d.mu.Lock()
	for _, issued := range d.notifications {
		if issued.offerID == offerID && time.Now().Before(issued.expires) {
			received = append(received, issued.received...)
		}
	}
	d.mu.Unlock()
	sort.SliceStable(received, func(i, j int) bool { return received[i].Received.Before(received[j].Received) })
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"notifications": received})
}
