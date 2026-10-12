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

	"github.com/eudi-dev/eudi-dev/v2/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
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
		Claims:    mock.MDOCPIDClaims,
		Key:       key,
	}
}

func TestCheckMDOCExpiry(t *testing.T) {
	t.Run("a credential still inside its validity", func(t *testing.T) {
		cfg := pidConfig(t)
		cfg.ExpiresIn = 48 * time.Hour
		got := checkMDOCExpiry(testMDoc(t, cfg))
		if got.Status != "pass" {
			t.Errorf("status = %q (%s), want pass", got.Status, got.Detail)
		}
	})

	t.Run("a credential past validUntil", func(t *testing.T) {
		cfg := pidConfig(t)
		cfg.ExpiresIn = -time.Hour
		got := checkMDOCExpiry(testMDoc(t, cfg))
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
		got := checkMDOCExpiry(testMDoc(t, cfg))
		if got.Status != "fail" {
			t.Errorf("status = %q (%s), want fail", got.Status, got.Detail)
		}
		if !strings.Contains(got.Detail, "not yet valid") {
			t.Errorf("detail = %q, want it to say not yet valid", got.Detail)
		}
	})

	t.Run("no validity info at all", func(t *testing.T) {
		got := checkMDOCExpiry(&mdoc.Document{})
		if got.Status != "skipped" {
			t.Errorf("status = %q, want skipped", got.Status)
		}
	})

	t.Run("validity info without validUntil", func(t *testing.T) {
		doc := testMDoc(t, pidConfig(t))
		doc.IssuerAuth.MSO.ValidityInfo.ValidUntil = nil
		got := checkMDOCExpiry(doc)
		if got.Status != "skipped" {
			t.Errorf("status = %q (%s), want skipped", got.Status, got.Detail)
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
		got := checkMDOCSignature(doc, ValidateOpts{Key: string(jwk)})
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
		got := checkMDOCSignature(doc, ValidateOpts{Key: string(jwk)})
		if got.Status != "fail" {
			t.Errorf("status = %q (%s), want fail", got.Status, got.Detail)
		}
	})

	t.Run("a key that does not parse", func(t *testing.T) {
		got := checkMDOCSignature(doc, ValidateOpts{Key: "not a key"})
		if got.Status != "fail" {
			t.Errorf("status = %q (%s), want fail", got.Status, got.Detail)
		}
		if !strings.Contains(got.Detail, "parsing key") {
			t.Errorf("detail = %q, want it to name the key as the problem", got.Detail)
		}
	})
}

func TestResolveKeysErrors(t *testing.T) {
	t.Run("a key that does not parse", func(t *testing.T) {
		if _, _, err := resolveKeys(ValidateOpts{Key: "nonsense"}); err == nil {
			t.Error("an unparseable key was accepted")
		}
	})

	t.Run("a trust list that does not parse", func(t *testing.T) {
		_, _, err := resolveKeys(ValidateOpts{TrustListRaw: "not a trust list"})
		if err == nil || !strings.Contains(err.Error(), "parsing trust list") {
			t.Errorf("error = %v, want a trust list parse failure", err)
		}
	})

	t.Run("a trust list URL that cannot be fetched", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "gone", http.StatusNotFound)
		}))
		defer srv.Close()

		_, _, err := resolveKeys(ValidateOpts{TrustListURL: srv.URL})
		if err == nil {
			t.Error("a trust list URL that answers 404 was accepted")
		}
	})

	t.Run("a trust list URL serving something that is not a trust list", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not a trust list"))
		}))
		defer srv.Close()

		_, _, err := resolveKeys(ValidateOpts{TrustListURL: srv.URL})
		if err == nil || !strings.Contains(err.Error(), "parsing trust list") {
			t.Errorf("error = %v, want a trust list parse failure", err)
		}
	})

	t.Run("nothing to resolve", func(t *testing.T) {
		pubKeys, tlCerts, err := resolveKeys(ValidateOpts{})
		if err != nil {
			t.Fatalf("resolveKeys: %v", err)
		}
		if len(pubKeys) != 0 || len(tlCerts) != 0 {
			t.Errorf("keys = %d, certs = %d, want none", len(pubKeys), len(tlCerts))
		}
	})
}

func TestHashForAlgorithm(t *testing.T) {
	for _, alg := range []string{"SHA-256", "SHA-384", "SHA-512"} {
		t.Run(alg, func(t *testing.T) {
			h := hashForAlgorithm(alg)
			if h == nil {
				t.Fatalf("hashForAlgorithm(%q) = nil", alg)
			}
			if h().Size() == 0 {
				t.Error("the returned hash produces no output")
			}
		})
	}

	if hashForAlgorithm("SHA-1") != nil {
		t.Error("an unsupported digest algorithm was accepted")
	}
	if hashForAlgorithm("") != nil {
		t.Error("an empty digest algorithm was accepted")
	}
}
