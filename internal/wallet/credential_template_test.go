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

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

// A template read from a credential issues a credential like it: same type,
// claims, lifetime, plain claims and card appearance.
func TestATemplateFromACredentialIssuesTheSameCredential(t *testing.T) {
	for _, tc := range []struct {
		name  string
		issue string
		want  string
	}{
		{"sdjwt", `{"format":"sdjwt","vct":"urn:example:badge","exp":"48h",
			"claims":{"badge_id":"B-7","level":2,"address":{"country":"DE","locality":"Köln"}},
			"always_disclosed":["badge_id","address.country"],
			"display":{"name":"Badge","background_color":"#0f766e","logo":"` + tinyPNGDataURI + `","logo_alt_text":"Badge logo"}}`,
			`{"format":"sdjwt","vct":"urn:example:badge","exp":"48h",
			"claims":{"badge_id":"B-7","level":2,"address":{"country":"DE","locality":"Köln"}},
			"always_disclosed":["address.country","badge_id"],
			"display":{"name":"Badge","background_color":"#0f766e","logo":"` + tinyPNGDataURI + `","logo_alt_text":"Badge logo"}}`},
		{"mdoc", `{"format":"mdoc","doctype":"org.example.badge","exp":"24h",
			"claims":{"badge_id":"B-7","photo":"` + tinyPNGDataURI + `","org.example.extra:note":"hi"}}`,
			`{"format":"mdoc","doctype":"org.example.badge","exp":"24h",
			"claims":{"badge_id":"B-7","photo":"` + tinyPNGDataURI + `","org.example.extra:note":"hi"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t, true)
			resp := serverRequest(t, srv, http.MethodPost, "/api/issue", tc.issue)
			if resp.Code != http.StatusCreated {
				t.Fatalf("issue: %d %s", resp.Code, resp.Body.String())
			}
			id, _ := decodeJSON(t, resp)["id"].(string)

			resp = serverRequest(t, srv, http.MethodGet, "/api/credentials/"+id+"/template", "")
			if resp.Code != http.StatusOK {
				t.Fatalf("template: %d %s", resp.Code, resp.Body.String())
			}
			var got, want map[string]any
			if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("template = %s\nwant %s", resp.Body.String(), tc.want)
			}
		})
	}
}

func TestTheTemplateOfAnUnknownCredentialIsNotFound(t *testing.T) {
	srv := newTestServer(t, true)
	if resp := serverRequest(t, srv, http.MethodGet, "/api/credentials/missing/template", ""); resp.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.Code)
	}
}
