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
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

// IT-Wallet 1.4.7 §11.2.1 keeps sub, date_of_expiry, verification and the issuer
// claims in the plain payload.
func TestItalianPIDKeepsTheIssuerClaimsInThePayload(t *testing.T) {
	w := generateTestWallet(t)
	result, err := w.IssueCredential(IssueOptions{Template: "italian-pid-sdjwt"})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	token, err := sdjwt.Parse(result.Raw)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	for _, claim := range []string{"sub", "date_of_expiry", "verification", "issuing_authority", "issuing_country"} {
		if _, ok := token.Payload[claim]; !ok {
			t.Errorf("%s is not in the plain payload", claim)
		}
	}
	if _, ok := token.Payload["given_name"]; ok {
		t.Error("given_name is not selectively disclosable")
	}
}

func TestNationalPIDsIssueAsMDOC(t *testing.T) {
	for _, name := range []string{"italian-pid-mdoc", "dutch-pid-mdoc"} {
		t.Run(name, func(t *testing.T) {
			w := generateTestWallet(t)
			result, err := w.IssueCredential(IssueOptions{Template: name})
			if err != nil {
				t.Fatalf("issuing: %v", err)
			}
			if result.Credential.DocType != mock.PIDNamespace {
				t.Errorf("doctype %q, want %q", result.Credential.DocType, mock.PIDNamespace)
			}
		})
	}
}

// ARF PID_14: a national PID extends urn:eudi:pid:1, so it answers a request for
// the country-independent type.
func TestNationalPIDsAnswerARequestForTheEUDIPID(t *testing.T) {
	for _, name := range []string{"italian-pid-sdjwt", "dutch-pid-sdjwt"} {
		t.Run(name, func(t *testing.T) {
			w := generateTestWallet(t)
			if _, err := w.IssueCredential(IssueOptions{Template: name}); err != nil {
				t.Fatalf("issuing: %v", err)
			}
			matches := evaluateDCQL(t, w, map[string]any{
				"credentials": []any{map[string]any{
					"id":     "pid",
					"format": "dc+sd-jwt",
					"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
					"claims": []any{map[string]any{"path": []any{"family_name"}}},
				}},
			})
			if len(matches) != 1 {
				t.Fatalf("%d matches, want the %s credential", len(matches), name)
			}
		})
	}
}

// IT-Wallet 1.4.7 §11.1.2.1: "two different Credentials issued MUST NOT use the
// same sub value". That holds for the copies of a batch too.
func TestEveryItalianPIDCopyHasItsOwnSubject(t *testing.T) {
	for name, key := range map[string]string{
		"italian-pid-sdjwt": "sub",
		"italian-pid-mdoc":  "eu.europa.ec.eudi.pid.it.1" + ":sub",
	} {
		t.Run(name, func(t *testing.T) {
			w := generateTestWallet(t)
			w.ClearCredentials()
			if _, err := w.IssueCredential(IssueOptions{Template: name, BatchSize: 3}); err != nil {
				t.Fatalf("issuing: %v", err)
			}
			seen := map[any]bool{}
			for _, c := range w.GetCredentials() {
				sub, ok := c.Claims[key]
				if !ok {
					t.Fatalf("credential %s has no %s in %v", c.ID, key, c.Claims)
				}
				seen[sub] = true
			}
			if len(seen) != 3 {
				t.Errorf("3 copies carry %d distinct sub values", len(seen))
			}
		})
	}
}
