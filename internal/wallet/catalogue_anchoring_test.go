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

import "testing"

// Every PID entry lists the mdoc doctype eu.europa.ec.eudi.pid.1 and links the
// same PID list, so anchoring a PID mdoc identifies no single entry. The
// SD-JWT VC type identifies exactly one.
func TestCatalogueAnchoringNamesOnlyAnUnambiguousEntry(t *testing.T) {
	w := generateTestWalletWithPID(t)
	for _, c := range w.GetCredentials() {
		anchoring, found := w.CheckCatalogueAnchoring(c.Raw)
		if !found || anchoring.AnchoredBy == "" || anchoring.Category != "pid" {
			t.Fatalf("%s: anchoring = %+v, want a PID anchored by the PID list", c.Format, anchoring)
		}
		want := "EUDI PID"
		if c.Format == "mso_mdoc" {
			want = ""
		}
		if anchoring.Entry != want {
			t.Errorf("%s: entry = %q, want %q", c.Format, anchoring.Entry, want)
		}
	}
}
