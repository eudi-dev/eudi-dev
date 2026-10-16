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

// Package urlhandler registers the wallet as the operating system handler for
// OID4VP and OID4VCI URL schemes.
package urlhandler

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc/scheme"
)

// Options are the settings of a registration. A clicked link reaches or
// starts the wallet with them.
type Options struct {
	ListenerPort int      `json:"listener_port"`
	AutoAccept   bool     `json:"auto_accept"`
	ServeArgs    []string `json:"serve_args,omitempty"`
}

func optionsPath() string {
	return filepath.Join(config.BaseDir(), "url-handler.json")
}

// LoadOptions reads the options of the current registration. ok is false
// without a registration.
func LoadOptions() (opts Options, ok bool, err error) {
	data, err := os.ReadFile(optionsPath())
	if errors.Is(err, os.ErrNotExist) {
		return Options{}, false, nil
	}
	if err != nil {
		return Options{}, false, err
	}
	if err := json.Unmarshal(data, &opts); err != nil {
		return Options{}, false, fmt.Errorf("reading %s: %w", optionsPath(), err)
	}
	return opts, true, nil
}

// The wallet registers as the OS handler for these URL schemes.
var (
	presentationURLSchemes = scheme.Presentation
	issuanceURLSchemes     = scheme.Issuance
	URLSchemes             = append(slices.Clone(presentationURLSchemes), issuanceURLSchemes...)
)

// Registration describes what Register set up. Registered is false
// on a platform without URL scheme registration.
type Registration struct {
	Registered  bool     `json:"registered"`
	AppBundle   string   `json:"app_bundle,omitempty"`
	DesktopFile string   `json:"desktop_file,omitempty"`
	Handler     string   `json:"handler,omitempty"`
	Binary      string   `json:"binary,omitempty"`
	AutoAccept  bool     `json:"auto_accept"`
	ServeArgs   []string `json:"serve_args,omitempty"`
	Schemes     []string `json:"schemes,omitempty"`
	// Warnings name what keeps links from reaching the wallet on this machine.
	Warnings []string `json:"warnings,omitempty"`
}

// Unregistration describes what Unregister removed.
type Unregistration struct {
	Unregistered bool   `json:"unregistered"`
	AppBundle    string `json:"app_bundle,omitempty"`
	DesktopFile  string `json:"desktop_file,omitempty"`
}
