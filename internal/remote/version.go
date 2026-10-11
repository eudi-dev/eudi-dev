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

package remote

import (
	"strconv"
	"strings"
)

// releaseMajor reads the major release of a semantic version from
// /api/version or the CLI build. Pre-release and build metadata are dropped,
// so 1.19.0-rc.1 counts as 1.19.0. It reports false without a numeric major
// and minor, such as for the "dev" build or an empty version.
func releaseMajor(raw string) (int, bool) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "v")
	if i := strings.IndexAny(raw, "-+"); i >= 0 {
		raw = raw[:i]
	}
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return 0, false
	}
	for _, part := range parts[:min(len(parts), 3)] {
		if n, err := strconv.Atoi(part); err != nil || n < 0 {
			return 0, false
		}
	}
	major, _ := strconv.Atoi(parts[0])
	return major, true
}

type Compatibility int

const (
	// CompatibilityUnknown means one side reports no comparable version, such as
	// a development build or an instance that reports no version.
	CompatibilityUnknown Compatibility = iota
	Compatible
	Incompatible
)

// CheckCompatibility compares the CLI's release with an instance's release.
// Under semantic versioning the same major release is compatible.
func CheckCompatibility(cli, instance string) Compatibility {
	cliMajor, cliOK := releaseMajor(cli)
	instanceMajor, instanceOK := releaseMajor(instance)
	if !cliOK || !instanceOK {
		return CompatibilityUnknown
	}
	if cliMajor != instanceMajor {
		return Incompatible
	}
	return Compatible
}
