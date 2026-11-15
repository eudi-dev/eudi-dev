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

// Package experimental lists features based on draft or changing
// specifications. Their behavior can change in any release. A feature is one
// field of Settings and Patch and one entry of All. The command line flags, the
// settings API, the settings view and the startup warnings read that list.
package experimental

import (
	"fmt"
	"io"
)

// Settings holds one switch for each experimental feature. GET /api/config
// reports them under these names.
type Settings struct {
	// TransactionData accepts transaction_data of the TS12 types and of the
	// --transaction-data-type types.
	TransactionData bool `json:"transaction_data"`
	// DelegateSDJWT accepts the transaction data type delegate and answers it
	// with a Delegate SD-JWT (ADR-0033). It needs TransactionData.
	DelegateSDJWT bool `json:"delegate_sd_jwt"`
}

// Patch holds changes to the switches.
type Patch struct {
	TransactionData *bool `json:"transaction_data,omitempty"`
	DelegateSDJWT   *bool `json:"delegate_sd_jwt,omitempty"`
}

// AllFlag is the command line flag that turns every feature on, without the
// leading dashes.
const AllFlag = "experimental"

// Feature is an experimental feature.
type Feature struct {
	// Name is the name shown to people.
	Name string
	// Flag is the command line flag of the feature, without the leading
	// dashes.
	Flag string
	// Setting is the name of the switch in the settings API.
	Setting string
	// Help is the help text of the flag.
	Help string

	setting func(*Settings) *bool
	patch   func(Patch) *bool
}

// TransactionData accepts transaction data in presentation requests.
var TransactionData = Feature{
	Name:    "Transaction data",
	Flag:    "transaction-data",
	Setting: "transaction_data",
	Help:    "Experimental. Accept transaction_data (OpenID4VP 1.0 §5.1) of the EUDI TS12 types and of the --transaction-data-type types. The wallet shows it in the consent dialog and signs its hashes into the Key Binding JWT of an SD-JWT VC. In debug mode it also signs the hashes of entries with an unknown type and reports each of them as a finding",
	setting: func(s *Settings) *bool { return &s.TransactionData },
	patch:   func(p Patch) *bool { return p.TransactionData },
}

// DelegateSDJWT answers delegate transaction data with a Delegate SD-JWT
// (ADR-0033).
var DelegateSDJWT = Feature{
	Name:    "Delegate SD-JWT",
	Flag:    "delegate-sd-jwt",
	Setting: "delegate_sd_jwt",
	Help:    "Experimental. Accept the transaction data type delegate and answer it with a Delegate SD-JWT (draft-ietf-oauth-delegate-sd-jwt-00). Takes effect only with --transaction-data",
	setting: func(s *Settings) *bool { return &s.DelegateSDJWT },
	patch:   func(p Patch) *bool { return p.DelegateSDJWT },
}

// All lists every experimental feature.
func All() []Feature {
	return []Feature{TransactionData, DelegateSDJWT}
}

// On reports whether the feature is on in s.
func (f Feature) On(s Settings) bool {
	return *f.setting(&s)
}

// Set turns the feature on or off in s.
func (f Feature) Set(s *Settings, on bool) {
	*f.setting(s) = on
}

// Active lists the features that are on.
func (s Settings) Active() []Feature {
	active := []Feature{}
	for _, feature := range All() {
		if feature.On(s) {
			active = append(active, feature)
		}
	}
	return active
}

// Delegates reports whether Delegate SD-JWT has an effect. It needs
// transaction data.
func (s Settings) Delegates() bool {
	return s.TransactionData && s.DelegateSDJWT
}

// Effective lists the features that are on and have an effect.
func (s Settings) Effective() []Feature {
	if !s.TransactionData {
		return nil
	}
	return s.Active()
}

// Apply changes the switches of s that p contains.
func (p Patch) Apply(s *Settings) {
	for _, feature := range All() {
		if on := feature.patch(p); on != nil {
			feature.Set(s, *on)
		}
	}
}

// Warn writes one warning for each feature.
func Warn(w io.Writer, features []Feature) {
	for _, feature := range features {
		_, _ = fmt.Fprintf(w, "warning: %s is experimental (--%s). Its behavior can change in any release.\n", feature.Name, feature.Flag)
	}
}
