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

package trustedlists

import (
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
)

// PID and PuB-EAA lists anchor their credentials directly. An EAA or QEAA
// list needs a catalogue entry that links it.
func TestUsedDirectly(t *testing.T) {
	for listType, want := range map[string]bool{
		lote.PIDProvidersListType:                          true,
		lote.PubEAAProvidersListType:                       true,
		lote.AccessCertProvidersListType:                   true,
		lote.RegistrationCertProvidersListType:             true,
		lote.WalletProvidersListType:                       true,
		ListOfListsType:                                    true,
		"https://eudi-test.dev/LoTEType/EAAProvidersList":  false,
		"https://eudi-test.dev/LoTEType/QEAAProvidersList": false,
	} {
		if got := UsedDirectly(listType); got != want {
			t.Errorf("UsedDirectly(%s) = %v, want %v", listType, got, want)
		}
	}
}
