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
	"reflect"
	"testing"
)

func TestTheCatalogCommandAddsAndDeletes(t *testing.T) {
	resetRemoteTestState(t)
	added := runJSON(t, "catalog", "add", "--name", "University diploma",
		"--type", "dc+sd-jwt:urn:example:diploma:1", "--type", "mso_mdoc:org.example.diploma.1",
		"--claim", "dc+sd-jwt:address.locality", "--claim", "mso_mdoc:degree", "--claim", "mso_mdoc:org.example.other:grade",
		"--los", "moderate")
	schema := added["schema"].(map[string]any)
	if schema["attestationLoS"] != "iso_18045_moderate" || len(schema["schemaURIs"].([]any)) != 2 {
		t.Fatalf("added %v", added)
	}
	credentials := added["credentials"].([]any)
	sdjwt := credentials[0].(map[string]any)["claims"]
	mdoc := credentials[1].(map[string]any)["claims"]
	if !reflect.DeepEqual(sdjwt, []any{[]any{"address", "locality"}}) ||
		!reflect.DeepEqual(mdoc, []any{[]any{"org.example.diploma.1", "degree"}, []any{"org.example.other", "grade"}}) {
		t.Fatalf("claims %v and %v", sdjwt, mdoc)
	}

	id := schema["id"].(string)
	if deleted := runJSON(t, "catalog", "rm", id); deleted["removed"] != id {
		t.Fatalf("delete: %v", deleted)
	}
}
