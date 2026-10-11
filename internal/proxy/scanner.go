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

package proxy

import (
	"encoding/json"
	"regexp"
	"strings"
	"sync"
)

// OutputScanner scans lines from a subprocess's stdout and stderr for the keys
// that decrypt encrypted responses. It is safe for concurrent use. Detection is
// best effort.
type OutputScanner struct {
	mu      sync.RWMutex
	lastCEK string // most recent base64url-encoded CEK
	lastJWK string // most recent JWK private key JSON (with "d" parameter)
}

var (
	// A CEK log line such as "[VP] JWE content encryption key for proxy debugging: <base64url>",
	// or any line with CEK and then a base64url value.
	cekPattern = regexp.MustCompile(`(?i)(?:CEK|content.encryption.key)[^:]*:\s*([A-Za-z0-9_-]{16,})`)
)

func NewOutputScanner() *OutputScanner {
	return &OutputScanner{}
}

func (s *OutputScanner) Scan(line string) {
	s.scanCEK(line)
	s.scanJWK(line)
}

func (s *OutputScanner) scanCEK(line string) {
	if m := cekPattern.FindStringSubmatch(line); len(m) > 1 {
		s.mu.Lock()
		s.lastCEK = m[1]
		s.mu.Unlock()
	}
}

// scanJWK looks for JWK objects with a "d" (private key) parameter. It stores the
// full JWK JSON for decryption.
func (s *OutputScanner) scanJWK(line string) {
	start := strings.Index(line, "{")
	if start < 0 {
		return
	}

	for i := start; i < len(line); i++ {
		if line[i] != '{' {
			continue
		}
		candidate := line[i:]
		depth := 0
		end := -1
		for j, c := range candidate {
			if c == '{' {
				depth++
			} else if c == '}' {
				depth--
				if depth == 0 {
					end = j + 1
					break
				}
			}
		}
		if end < 0 {
			continue
		}
		jsonStr := candidate[:end]
		var jwk map[string]any
		if err := json.Unmarshal([]byte(jsonStr), &jwk); err != nil {
			continue
		}
		if _, hasKty := jwk["kty"]; !hasKty {
			continue
		}
		if _, hasD := jwk["d"]; !hasD {
			continue
		}
		s.mu.Lock()
		s.lastJWK = jsonStr
		s.mu.Unlock()
		return
	}
}

func (s *OutputScanner) LastCEK() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastCEK
}

func (s *OutputScanner) LastJWK() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastJWK
}
