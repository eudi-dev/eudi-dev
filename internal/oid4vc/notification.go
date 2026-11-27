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

package oid4vc

import (
	"fmt"
	"slices"
)

// The events of a Notification Request (OpenID4VCI 1.0 §11.1).
const (
	NotificationAccepted = "credential_accepted"
	NotificationFailure  = "credential_failure"
	NotificationDeleted  = "credential_deleted"
)

// NotificationEvents lists the §11.1 events in the order a picker shows them.
var NotificationEvents = []string{NotificationAccepted, NotificationFailure, NotificationDeleted}

// Notification is the event and description of a Notification Request
// (OpenID4VCI 1.0 §11.1).
type Notification struct {
	Event            string `json:"event"`
	EventDescription string `json:"event_description,omitempty"`
}

// Validate applies §11.1. The event is one of the three case-sensitive values,
// and event_description "MUST NOT include characters outside the set %x20-21 /
// %x23-5B / %x5D-7E".
func (n Notification) Validate() error {
	if !slices.Contains(NotificationEvents, n.Event) {
		return fmt.Errorf("event must be credential_accepted, credential_failure or credential_deleted, not %q", n.Event)
	}
	for _, r := range n.EventDescription {
		if r < 0x20 || r > 0x7E || r == '"' || r == '\\' {
			return fmt.Errorf("event_description must not contain %q (OpenID4VCI 1.0 section 11.1 allows printable ASCII without \" and \\)", r)
		}
	}
	return nil
}

// Discards reports whether the event tells the issuer that the wallet did not
// keep the credentials. §11.1 defines credential_failure and
// credential_deleted as unsuccessful issuance.
func (n Notification) Discards() bool {
	return n.Event == NotificationFailure || n.Event == NotificationDeleted
}
