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

package regcert

import (
	"strings"
	"testing"
)

// The finding names the types that aren't registered, not the first accepted one.
func TestOverAskingNamesTheUnregisteredTypes(t *testing.T) {
	cert := map[string]any{"credentials": []any{map[string]any{"format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:eudi:pid:1"}}}}}
	dcql := map[string]any{"credentials": []any{map[string]any{"format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:eudi:pid:1", "urn:eudi:pid:nl:1"}}}}}
	list := OverAskingFindings(cert, dcql)
	if len(list) != 1 || !strings.Contains(list[0].String(), "asks for urn:eudi:pid:nl:1.") {
		t.Errorf("findings = %v", list)
	}
}
