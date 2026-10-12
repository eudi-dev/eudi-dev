package wallet

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
)

// A database row of an eudi-dev 2 wallet names the trusted list type and
// entity name trust_list_type and entity_name. Loading keeps both values.
func TestLoadUpgradesTheTrustedListNamesOfAnEntityRow(t *testing.T) {
	store := NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), storage.NewMemory())
	row := `{"format":"dc+sd-jwt","vct":"urn:example:custom","category":"eaa","trust_list_type":"https://example.org/LoTEType/custom","entity_name":"Custom Provider"}`
	if _, err := store.Backend().Write(store.stateKey(attestationsSection, "custom"), []byte(row), 0o600); err != nil {
		t.Fatal(err)
	}

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	var found bool
	for _, spec := range w.IssuedAttestations {
		if spec.VCT != "urn:example:custom" {
			continue
		}
		found = true
		if spec.LoTEType != "https://example.org/LoTEType/custom" || spec.EntityName != "Custom Provider" {
			t.Errorf("spec = %+v, want the stored list type and entity name", spec)
		}
	}
	if !found {
		t.Fatal("the stored credential type was not loaded")
	}
}

func TestIssueAPIRefusesTheRenamedTrustFields(t *testing.T) {
	srv := newTestServer(t, true)
	for old, current := range map[string]string{"trust_list_type": "trust.trusted_list_type", "entity_name": "trust.trusted_entity_name"} {
		t.Run(old, func(t *testing.T) {
			rec := serverRequest(t, srv, "POST", "/api/issue", `{"format":"sdjwt","vct":"urn:test:renamed","claims":{"a":"b"},"trust":{"`+old+`":"x"}}`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
			if msg, _ := decodeJSON(t, rec)["error_description"].(string); !strings.Contains(msg, current) {
				t.Errorf("error = %q, want it to name %s", msg, current)
			}
		})
	}
}
