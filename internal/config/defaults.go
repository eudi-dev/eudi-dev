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

// Package config provides shared default constants used across the CLI and internal packages.
package config

import (
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultWalletPort = 8085

	DefaultServePort = 8080

	DefaultProxyPort = 9090

	DefaultProxyDashboardPort = 9091

	ConsentTimeout = 5 * time.Minute

	// The CLI stops polling at the moment the wallet stops waiting for sign-in.
	AuthorizationCallbackWait = 5 * time.Minute

	// Sign-in and consent take longer than ordinary HTTP requests. This timeout
	// covers server response writes, remote CLI requests and consent approval waits.
	SlowRequestTimeout = 2 * time.Minute

	// Timeouts of the HTTP servers. A server that waits for sign-in or
	// consent writes with SlowRequestTimeout.
	ServerReadTimeout  = 30 * time.Second
	ServerWriteTimeout = 60 * time.Second
	ServerIdleTimeout  = 120 * time.Second

	// StreamKeepaliveInterval is how often an idle event stream sends a
	// comment line, so proxies keep the connection open.
	StreamKeepaliveInterval = 20 * time.Second
)

// ClientHeader identifies the client behind an API call as "<name>/<version>".
// OwnerHeader identifies the browser when a client submits on its behalf. The wallet
// reads both and the CLI sends both.
const (
	ClientHeader = "X-Eudi-Client"
	OwnerHeader  = "X-Eudi-Owner"
)

// BaseDir returns the tool's state directory: EUDI_DEV_HOME when set, else
// ~/.eudi-dev.
func BaseDir() string {
	if custom := os.Getenv("EUDI_DEV_HOME"); custom != "" {
		return custom
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".eudi-dev")
}
