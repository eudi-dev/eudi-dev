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

package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
)

func testMDoc(t *testing.T, cfg mock.MDOCConfig) *mdoc.Document {
	t.Helper()
	raw, err := mock.GenerateMDOC(cfg)
	if err != nil {
		t.Fatalf("GenerateMDOC: %v", err)
	}
	doc, err := mdoc.Parse(raw)
	if err != nil {
		t.Fatalf("mdoc.Parse: %v", err)
	}
	return doc
}

func pidConfig(t *testing.T) mock.MDOCConfig {
	t.Helper()
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return mock.MDOCConfig{
		DocType:   "eu.europa.ec.eudi.pid.1",
		Namespace: "eu.europa.ec.eudi.pid.1",
		Claims:    templateClaims("pid-mdoc"),
		Key:       key,
	}
}

func mdocCheck(t *testing.T, doc *mdoc.Document, trust validate.Trust, name string) CheckResult {
	t.Helper()
	check, ok := validate.MDOC(doc, trust, validate.Options{Offline: true}).Find(name)
	if !ok {
		t.Fatalf("no %s check", name)
	}
	return check
}

func TestCheckMDOCExpiry(t *testing.T) {
	t.Run("a credential still inside its validity", func(t *testing.T) {
		cfg := pidConfig(t)
		cfg.ExpiresIn = 48 * time.Hour
		got := mdocCheck(t, testMDoc(t, cfg), validate.Trust{}, validate.CheckExpiry)
		if got.Status != "pass" {
			t.Errorf("status = %q (%s), want pass", got.Status, got.Detail)
		}
	})

	t.Run("a credential past validUntil", func(t *testing.T) {
		cfg := pidConfig(t)
		cfg.ExpiresIn = -time.Hour
		got := mdocCheck(t, testMDoc(t, cfg), validate.Trust{}, validate.CheckExpiry)
		if got.Status != "fail" {
			t.Errorf("status = %q (%s), want fail", got.Status, got.Detail)
		}
		if !strings.Contains(got.Detail, "expired") {
			t.Errorf("detail = %q, want it to say expired", got.Detail)
		}
	})

	t.Run("a credential that is not valid yet", func(t *testing.T) {
		cfg := pidConfig(t)
		validFrom := time.Now().Add(72 * time.Hour)
		cfg.ValidFrom = &validFrom
		cfg.ExpiresIn = 30 * 24 * time.Hour
		got := mdocCheck(t, testMDoc(t, cfg), validate.Trust{}, validate.CheckExpiry)
		if got.Status != "fail" {
			t.Errorf("status = %q (%s), want fail", got.Status, got.Detail)
		}
		if !strings.Contains(got.Detail, "not yet valid") {
			t.Errorf("detail = %q, want it to say not yet valid", got.Detail)
		}
	})

	t.Run("no validity info at all", func(t *testing.T) {
		got := mdocCheck(t, &mdoc.Document{}, validate.Trust{}, validate.CheckExpiry)
		if got.Status != "fail" {
			t.Errorf("status = %q, want fail", got.Status)
		}
	})

	t.Run("validity info without validUntil", func(t *testing.T) {
		doc := testMDoc(t, pidConfig(t))
		doc.IssuerAuth.MSO.ValidityInfo.ValidUntil = nil
		got := mdocCheck(t, doc, validate.Trust{}, validate.CheckExpiry)
		if got.Status != "fail" || !strings.Contains(got.Detail, "validUntil") {
			t.Errorf("status = %q (%s), want fail naming validUntil", got.Status, got.Detail)
		}
	})
}

func TestCheckMDOCSignature(t *testing.T) {
	cfg := pidConfig(t)
	doc := testMDoc(t, cfg)

	t.Run("against the issuer's own key", func(t *testing.T) {
		jwk, err := json.Marshal(mock.SigningJWKMap(&cfg.Key.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		got := mdocCheck(t, doc, resolveTrust(ValidateOpts{Key: string(jwk), Offline: true}), validate.CheckSignature)
		if got.Status != "pass" {
			t.Errorf("status = %q (%s), want pass", got.Status, got.Detail)
		}
	})

	t.Run("against somebody else's key", func(t *testing.T) {
		other, err := mock.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		jwk, err := json.Marshal(mock.SigningJWKMap(&other.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		got := mdocCheck(t, doc, resolveTrust(ValidateOpts{Key: string(jwk), Offline: true}), validate.CheckSignature)
		if got.Status != "fail" {
			t.Errorf("status = %q (%s), want fail", got.Status, got.Detail)
		}
	})

	t.Run("a key that does not parse", func(t *testing.T) {
		got := mdocCheck(t, doc, resolveTrust(ValidateOpts{Key: "not a key", Offline: true}), validate.CheckSignature)
		if got.Status != "fail" {
			t.Errorf("status = %q (%s), want fail", got.Status, got.Detail)
		}
		if !strings.Contains(got.Detail, "parsing key") {
			t.Errorf("detail = %q, want it to name the key as the problem", got.Detail)
		}
	})
}

func TestSuppliedTrustErrors(t *testing.T) {
	suppliedTrust := func(opts ValidateOpts) (validate.Trust, error) {
		var trust validate.Trust
		err := addSuppliedTrust(&trust, opts)
		return trust, err
	}

	t.Run("a key that does not parse", func(t *testing.T) {
		if _, err := suppliedTrust(ValidateOpts{Key: "nonsense"}); err == nil {
			t.Error("an unparseable key was accepted")
		}
	})

	t.Run("a trusted list that does not parse", func(t *testing.T) {
		_, err := suppliedTrust(ValidateOpts{TrustListRaw: "not a trusted list"})
		if err == nil || !strings.Contains(err.Error(), "parsing trusted list") {
			t.Errorf("error = %v, want a trusted list parse failure", err)
		}
	})

	t.Run("a trusted list URL that cannot be fetched", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "gone", http.StatusNotFound)
		}))
		defer srv.Close()

		_, err := suppliedTrust(ValidateOpts{TrustListURL: srv.URL})
		if err == nil {
			t.Error("a trusted list URL that answers 404 was accepted")
		}
	})

	t.Run("a trusted list URL serving something that is not a trusted list", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not a trusted list"))
		}))
		defer srv.Close()

		_, err := suppliedTrust(ValidateOpts{TrustListURL: srv.URL})
		if err == nil || !strings.Contains(err.Error(), "parsing trusted list") {
			t.Errorf("error = %v, want a trusted list parse failure", err)
		}
	})

	t.Run("nothing to resolve", func(t *testing.T) {
		trust, err := suppliedTrust(ValidateOpts{})
		if err != nil {
			t.Fatalf("suppliedTrust: %v", err)
		}
		if trust.Supplied || len(trust.Keys) != 0 || len(trust.Issuance) != 0 {
			t.Errorf("trust = %+v, want nothing supplied", trust)
		}
	})
}

// templateClaims returns the claims of a predefined template.
func templateClaims(name string) map[string]any {
	t, ok := credtemplate.Predefined(name)
	if !ok {
		panic("no predefined template " + name)
	}
	return t.Claims
}
