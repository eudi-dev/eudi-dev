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
	"encoding/json"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
)

func signedGroupList(t *testing.T, tr *Set, id string) string {
	t.Helper()
	for _, group := range tr.Groups() {
		if group.ID == id {
			raw, err := tr.SignedGroupList("https://wallet.example", group, provider.TrustedListPath(id))
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
	}
	t.Fatalf("no list %s", id)
	return ""
}

// ETSI TS 119 602 V1.1.1 §6.8.0: the "Country code" and "Organization" of the
// list signer "shall match respectively the "Scheme Territory" and one of the
// "Scheme operator name" values".
func TestTheListSignerMatchesTheSchemeOperator(t *testing.T) {
	tr, _ := newTestTrust(t)
	lists := map[string]string{}
	for _, group := range tr.Groups() {
		lists[group.ID] = signedGroupList(t, tr, group.ID)
	}
	raw, err := tr.ListOfLists("https://wallet.example")
	if err != nil {
		t.Fatal(err)
	}
	lists[ListOfListsID] = raw
	for id, raw := range lists {
		list, err := lote.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		signers, err := validate.X5CCertificates(list.Header)
		if err != nil {
			t.Fatal(err)
		}
		subject := signers[0].Subject
		if len(subject.Country) != 1 || subject.Country[0] != list.SchemeInfo.SchemeTerritory {
			t.Errorf("%s: signer country %v, scheme territory %s", id, subject.Country, list.SchemeInfo.SchemeTerritory)
		}
		if len(subject.Organization) != 1 || subject.Organization[0] != list.SchemeInfo.SchemeOperatorName {
			t.Errorf("%s: signer organization %v, scheme operator %s", id, subject.Organization, list.SchemeInfo.SchemeOperatorName)
		}
	}
}

// ETSI TS 119 602 V1.1.1 §6.6.3.0: the organizationName of a listed
// certificate "should strictly match the 'TE Name' value".
func TestTheListedCAsMatchTheirEntityName(t *testing.T) {
	tr, _ := newTestTrust(t)
	for _, id := range []string{provider.AccessCAListID, provider.RegistrarListID} {
		list, err := lote.Parse(signedGroupList(t, tr, id))
		if err != nil {
			t.Fatal(err)
		}
		entity := list.Entities[0]
		for _, service := range entity.Services {
			certs, err := lote.Certificates(service.Certificates)
			if err != nil {
				t.Fatal(err)
			}
			for _, cert := range certs {
				if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != entity.Name {
					t.Errorf("%s: listed certificate of %v under the entity %q", id, cert.Subject.Organization, entity.Name)
				}
			}
		}
	}
}

// ETSI TS 119 602 V1.1.1 Table E.3: "The ServiceUniqueIdentifier extension
// shall be used to provide the reference number of the wallet solution".
func TestTheWalletProviderListGivesTheWalletSolution(t *testing.T) {
	tr, _ := newTestTrust(t)
	_, payload, _, err := format.ParseJWTParts(signedGroupList(t, tr, provider.WalletProviderListID))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(payload["LoTE"])
	if err != nil {
		t.Fatal(err)
	}
	var content struct {
		TrustedEntitiesList []struct {
			TrustedEntityServices []struct {
				ServiceInformation struct {
					ServiceInformationExtensions []struct {
						ServiceUniqueIdentifier string
					}
				}
			}
		}
	}
	if err := json.Unmarshal(encoded, &content); err != nil {
		t.Fatal(err)
	}
	services := content.TrustedEntitiesList[0].TrustedEntityServices
	if len(services) == 0 {
		t.Fatal("the wallet provider has no services")
	}
	for i, service := range services {
		extensions := service.ServiceInformation.ServiceInformationExtensions
		if len(extensions) != 1 || extensions[0].ServiceUniqueIdentifier != provider.WalletSolutionReference {
			t.Errorf("service %d has the extensions %+v", i, extensions)
		}
	}
}

// A service lists each certificate once, also when one leaf signs both
// credential formats.
func TestAServiceListsEachCertificateOnce(t *testing.T) {
	tr, _ := newTestTrust(t)
	for _, group := range tr.Groups() {
		list, err := lote.Parse(signedGroupList(t, tr, group.ID))
		if err != nil {
			t.Fatal(err)
		}
		for _, entity := range list.Entities {
			for _, service := range entity.Services {
				certs, err := lote.Certificates(service.Certificates)
				if err != nil {
					t.Fatal(err)
				}
				seen := map[string]bool{}
				for _, cert := range certs {
					if seen[string(cert.Raw)] {
						t.Errorf("%s: %q lists %q twice", group.ID, entity.Name, cert.Subject.String())
					}
					seen[string(cert.Raw)] = true
				}
			}
		}
	}
}
