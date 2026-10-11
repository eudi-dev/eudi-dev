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

// Package mock generates test credentials (SD-JWT and mdoc). The claim sets
// of the PIDs are the predefined templates of the credtemplate package.
package mock

import "github.com/dominikschlosser/eudi-dev/v3/internal/credtype"

const (
	DefaultPIDVCT = credtype.PIDVCT
	// PIDNamespace is the mdoc namespace of the country-independent EUDI PID.
	// Every PID uses it as its doctype too.
	PIDNamespace = credtype.PIDNamespace
	// DefaultIssuer names the issuer of a test credential or status list
	// that has no issuer URL of its own.
	DefaultIssuer = "https://issuer.example"
)
