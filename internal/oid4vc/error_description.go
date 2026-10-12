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

import "strings"

// ErrorDescription limits a message to the characters allowed in
// error_description by RFC 6749 §4.1.2.1 and §5.2: "Values for the error_description parameter
// MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E."
// Quotes become apostrophes, a section sign becomes "section", a backslash a
// slash, and any other character outside the set a space.
func ErrorDescription(message string) string {
	message = strings.ReplaceAll(message, "§", "section ")
	var b strings.Builder
	for _, r := range message {
		switch {
		case r == '"':
			b.WriteByte('\'')
		case r == '\\':
			b.WriteByte('/')
		case r >= 0x20 && r <= 0x7E:
			b.WriteRune(r)
		default:
			b.WriteByte(' ')
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}
