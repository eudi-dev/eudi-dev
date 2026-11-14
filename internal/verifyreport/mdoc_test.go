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

package verifyreport

import (
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/pkg/mdoc"
)

func generateTestMDoc(t *testing.T, cfg mock.MDOCConfig) *mdoc.Document {
	t.Helper()
	raw, err := mock.GenerateMDOC(cfg)
	if err != nil {
		t.Fatalf("GenerateMDOC: %v", err)
	}
	doc, err := mdoc.ParseLenient(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return doc
}

func TestMDOC(t *testing.T) {
	key1, _ := mock.GenerateKey()
	key2, _ := mock.GenerateKey()

	tests := []struct {
		name         string
		cfg          mock.MDOCConfig
		verifyKey    crypto.PublicKey
		useNilDoc    bool
		wantSigValid bool
		wantExpired  bool
		wantErrors   bool
		checkFields  bool
	}{
		{
			name: "valid signature",
			cfg: mock.MDOCConfig{
				DocType: "org.iso.18013.5.1.mDL", Namespace: "org.iso.18013.5.1",
				Claims: credtemplate.DefaultClaims, Key: key1,
			},
			verifyKey:    &key1.PublicKey,
			wantSigValid: true,
			checkFields:  true,
		},
		{
			name: "wrong key",
			cfg: mock.MDOCConfig{
				DocType: "org.iso.18013.5.1.mDL", Namespace: "org.iso.18013.5.1",
				Claims: credtemplate.DefaultClaims, Key: key1,
			},
			verifyKey:    &key2.PublicKey,
			wantSigValid: false,
			wantErrors:   true,
		},
		{
			name: "expired document",
			cfg: mock.MDOCConfig{
				DocType: "org.iso.18013.5.1.mDL", Namespace: "org.iso.18013.5.1",
				Claims: credtemplate.DefaultClaims, Key: key1,
				ExpiresIn: -1 * time.Hour,
			},
			verifyKey:    &key1.PublicKey,
			wantSigValid: true,
			wantExpired:  true,
		},
		{
			name: "validity dates present",
			cfg: mock.MDOCConfig{
				DocType: "org.iso.18013.5.1.mDL", Namespace: "org.iso.18013.5.1",
				Claims: credtemplate.DefaultClaims, Key: key1,
				ExpiresIn: 30 * 24 * time.Hour,
			},
			verifyKey:    &key1.PublicKey,
			wantSigValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := generateTestMDoc(t, tt.cfg)

			result := MDOC(doc, tt.verifyKey)

			if result.SignatureValid != tt.wantSigValid {
				t.Errorf("SignatureValid = %v, want %v (errors: %v)", result.SignatureValid, tt.wantSigValid, result.Errors)
			}
			if result.Expired != tt.wantExpired {
				t.Errorf("Expired = %v, want %v", result.Expired, tt.wantExpired)
			}
			if tt.wantErrors && len(result.Errors) == 0 {
				t.Error("expected errors, got none")
			}
			if tt.checkFields {
				if result.Algorithm != "ES256" {
					t.Errorf("expected algorithm ES256, got %q", result.Algorithm)
				}
				if result.DocType != "org.iso.18013.5.1.mDL" {
					t.Errorf("expected doctype org.iso.18013.5.1.mDL, got %q", result.DocType)
				}
			}
			if tt.name == "validity dates present" {
				if result.ValidFrom == nil {
					t.Error("expected ValidFrom to be set")
				}
				if result.ValidUntil == nil {
					t.Error("expected ValidUntil to be set")
				}
				if result.Signed == nil {
					t.Error("expected Signed to be set")
				}
			}
		})
	}
}

// ISO 18013-5 requires validityInfo. Without it the dates and validity flags
// stay unset, so the caller can report the missing check.
func TestMDOC_NoValidityInfo(t *testing.T) {
	key, _ := mock.GenerateKey()
	doc := generateTestMDoc(t, mock.MDOCConfig{
		DocType: "org.iso.18013.5.1.mDL", Namespace: "org.iso.18013.5.1",
		Claims: credtemplate.DefaultClaims, Key: key, OmitValidityInfo: true,
	})

	result := MDOC(doc, &key.PublicKey)

	if !result.SignatureValid {
		t.Fatalf("SignatureValid = false, want true (errors: %v)", result.Errors)
	}
	if result.ValidUntil != nil || result.ValidFrom != nil || result.Signed != nil {
		t.Errorf("validity dates = (from %v, until %v, signed %v), want all nil", result.ValidFrom, result.ValidUntil, result.Signed)
	}
	if result.Expired || result.NotYetValid {
		t.Errorf("Expired = %v, NotYetValid = %v, want both false", result.Expired, result.NotYetValid)
	}
}

// ISO 18013-5 requires digestAlgorithm. An MSO without it verifies with
// SHA-256 and gets a warning.
func TestMDOC_NoDigestAlgorithm(t *testing.T) {
	key, _ := mock.GenerateKey()
	doc := generateTestMDoc(t, mock.MDOCConfig{
		DocType: "org.iso.18013.5.1.mDL", Namespace: "org.iso.18013.5.1",
		Claims: credtemplate.DefaultClaims, Key: key, OmitDigestAlgorithm: true,
	})

	result := MDOC(doc, &key.PublicKey)

	if !result.SignatureValid {
		t.Fatalf("SignatureValid = false, want true (errors: %v)", result.Errors)
	}
	found := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "digestAlgorithm") {
			found = true
		}
	}
	if !found {
		t.Errorf("Warnings = %v, want one naming digestAlgorithm", result.Warnings)
	}
}

func TestMDOC_NilIssuerAuth(t *testing.T) {
	doc := &mdoc.Document{
		DocType:    "test",
		IssuerAuth: nil,
	}

	result := MDOC(doc, nil)

	if result.SignatureValid {
		t.Error("expected invalid signature for nil issuerAuth")
	}
	if len(result.Errors) == 0 {
		t.Error("expected error about missing issuerAuth")
	}
}
