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
	"slices"

	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc/scheme"
)

type RegisterOptions struct {
	ListenerPort int
	AutoAccept   bool
	ServeArgs    []string
}

// The wallet registers as the OS handler for these URL schemes.
var (
	presentationURLSchemes = scheme.Presentation
	issuanceURLSchemes     = scheme.Issuance
	URLSchemes             = append(slices.Clone(presentationURLSchemes), issuanceURLSchemes...)
)

// Registration describes what RegisterURLSchemes set up. Registered is false
// on a platform without URL scheme registration.
type Registration struct {
	Registered bool     `json:"registered"`
	AppBundle  string   `json:"app_bundle,omitempty"`
	Handler    string   `json:"handler,omitempty"`
	Binary     string   `json:"binary,omitempty"`
	AutoAccept bool     `json:"auto_accept"`
	ServeArgs  []string `json:"serve_args,omitempty"`
	Schemes    []string `json:"schemes,omitempty"`
}

// Unregistration describes what UnregisterURLSchemes removed.
type Unregistration struct {
	Unregistered bool   `json:"unregistered"`
	AppBundle    string `json:"app_bundle,omitempty"`
}
