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

package cmd

import (
	"testing"

	"github.com/eudi-dev/eudi-dev/v2/internal/remote"
)

func TestOpensSignInHere(t *testing.T) {
	previous := noOpen
	t.Cleanup(func() { noOpen = previous })

	for _, tc := range []struct {
		name   string
		owner  string
		noOpen bool
		want   bool
	}{
		{"named a page", "a-page-it-opened", false, false},
		{"named none", "", false, true},
		{"named none, headless", "", true, false},
		{"named a page, headless", "a-page-it-opened", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noOpen = tc.noOpen
			c := remote.NewClient("http://wallet.example")
			if tc.owner != "" {
				c.ActingFor(tc.owner)
			}
			if got := opensSignInHere(c); got != tc.want {
				t.Errorf("opensSignInHere = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNavigatesHere(t *testing.T) {
	previous := noOpen
	t.Cleanup(func() { noOpen = previous })

	for _, tc := range []struct {
		name           string
		browserWaiting bool
		noOpen         bool
		want           bool
	}{
		{"a browser holds the flow", true, false, false},
		{"nothing holds the flow", false, false, true},
		{"headless", false, true, false},
		{"headless with a browser waiting", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noOpen = tc.noOpen
			if got := navigatesHere(tc.browserWaiting); got != tc.want {
				t.Errorf("navigatesHere(%v) = %v, want %v", tc.browserWaiting, got, tc.want)
			}
		})
	}
}
