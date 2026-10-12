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
	"fmt"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

// Validity is read from both formats. A credential without an expiry is never
// due for renewal.
func TestCredentialValidityReadsBothFormats(t *testing.T) {
	w := generateTestWallet(t)
	notBefore := time.Now().Add(time.Hour).Truncate(time.Second)

	sdjwtCred, err := w.IssueCredential(IssueOptions{
		Format: "sdjwt", VCT: "urn:test:expiry:1",
		Claims:    map[string]any{"given_name": "Alice"},
		ExpiresIn: 2 * time.Hour,
		NotBefore: &notBefore,
	})
	if err != nil {
		t.Fatalf("issuing the sd-jwt: %v", err)
	}
	mdocCred, err := w.IssueCredential(IssueOptions{
		Format: "mdoc", DocType: "eu.europa.ec.eudi.pid.1",
		Claims:    map[string]any{"eu.europa.ec.eudi.pid.1": map[string]any{"given_name": "Alice"}},
		ExpiresIn: 2 * time.Hour,
		NotBefore: &notBefore,
	})
	if err != nil {
		t.Fatalf("issuing the mdoc: %v", err)
	}

	for name, cred := range map[string]StoredCredential{"sd-jwt": *sdjwtCred.Credential, "mdoc": *mdocCred.Credential} {
		validFrom, expiry := CredentialValidity(cred)
		if !validFrom.Equal(notBefore) {
			t.Errorf("%s: valid from %v, want %v", name, validFrom, notBefore)
		}
		if expiry.IsZero() {
			t.Errorf("%s: no expiry read, so the wallet cannot know when to renew it", name)
			continue
		}
		if delta := time.Until(expiry); delta < 90*time.Minute || delta > 150*time.Minute {
			t.Errorf("%s: expiry is %v away, want about two hours", name, delta.Round(time.Minute))
		}
		if CredentialNeedsRenewal(cred, time.Now()) {
			t.Errorf("%s: a credential valid for two hours was marked as needing renewal", name)
		}
		if !CredentialNeedsRenewal(cred, expiry.Add(-renewalMargin/2)) {
			t.Errorf("%s: a credential expiring within the margin was not marked for renewal", name)
		}
		if CredentialNeedsRenewal(cred, expiry.Add(-2*renewalMargin)) {
			t.Errorf("%s: a credential outside the margin was marked for renewal too early", name)
		}
	}
}

func TestCredentialWithoutAStatedLifetimeNeverExpires(t *testing.T) {
	if _, got := CredentialValidity(StoredCredential{Format: "dc+sd-jwt", Raw: "not-a-credential"}); !got.IsZero() {
		t.Errorf("an unparsable credential reported expiry %v", got)
	}
	if CredentialNeedsRenewal(StoredCredential{Format: "dc+sd-jwt", Raw: "not-a-credential"}, time.Now()) {
		t.Error("a credential with no stated lifetime was marked for renewal")
	}
}

// Ties keep their order so repeated listings are stable.
func TestSortCredentialsNewestFirst(t *testing.T) {
	at := func(unix int64) StoredCredential {
		key, err := mock.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := jws.Sign(
			map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"},
			map[string]any{"vct": "urn:example:ordered", "iat": unix},
			key,
		)
		if err != nil {
			t.Fatal(err)
		}
		return StoredCredential{ID: fmt.Sprintf("c%d", unix), Format: "dc+sd-jwt", Raw: raw}
	}

	oldest, middle, newest := at(1000), at(2000), at(3000)
	creds := []StoredCredential{oldest, middle, newest}
	SortCredentialsNewestFirst(creds)

	var order []string
	for _, c := range creds {
		order = append(order, c.ID)
	}
	if order[0] != "c3000" || order[1] != "c2000" || order[2] != "c1000" {
		t.Fatalf("order = %v, want newest first", order)
	}

	SortCredentialsNewestFirst(creds)
	if creds[0].ID != "c3000" || creds[2].ID != "c1000" {
		t.Error("a second sort reordered an already sorted list")
	}
}

func TestCredentialIssuedAt_ImportedCredentials(t *testing.T) {
	w := generateTestWallet(t)
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	older := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	newer := older.Add(time.Hour)
	var ids []string
	for _, at := range []time.Time{older, newer} {
		raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{Issuer: "https://test.example", VCT: "urn:example:dated", ExpiresIn: 24 * time.Hour, IssuedAt: &at, Claims: map[string]any{"a": 1}, Key: key})
		if err != nil {
			t.Fatal(err)
		}
		cred, err := w.ImportCredential(raw)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, cred.ID)
	}
	creds := w.GetCredentials()
	if !CredentialIssuedAt(creds[0]).Equal(older) || !CredentialIssuedAt(creds[1]).Equal(newer) {
		t.Fatalf("issued at = %v and %v, want %v and %v", CredentialIssuedAt(creds[0]), CredentialIssuedAt(creds[1]), older, newer)
	}
	SortCredentialsNewestFirst(creds)
	if creds[0].ID != ids[1] {
		t.Fatalf("newest first put %s first, want %s", creds[0].ID, ids[1])
	}
}

// Credentials without an issuance time sort after dated ones and keep their
// order.
func TestSortCredentialsNewestFirst_UndatedGoLast(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dated, err := jws.Sign(
		map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"},
		map[string]any{"vct": "urn:example:dated", "iat": int64(5000)},
		key,
	)
	if err != nil {
		t.Fatal(err)
	}

	creds := []StoredCredential{
		{ID: "undated-a", Format: "dc+sd-jwt", Raw: "not-a-credential"},
		{ID: "dated", Format: "dc+sd-jwt", Raw: dated},
		{ID: "undated-b", Format: "dc+sd-jwt", Raw: "also-not-a-credential"},
	}
	SortCredentialsNewestFirst(creds)

	if creds[0].ID != "dated" {
		t.Errorf("first = %q, want the credential that states a time", creds[0].ID)
	}
	if creds[1].ID != "undated-a" || creds[2].ID != "undated-b" {
		t.Errorf("undated order = %q, %q, want their original relative order", creds[1].ID, creds[2].ID)
	}
}
