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
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

// typeMetadataServer serves a type that extends a base type. The base type
// makes given_name mandatory.
func typeMetadataServer(t *testing.T, w *Wallet) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		docs := map[string]string{
			"/base":  `{"vct":"{base}/base","claims":[{"path":["given_name"],"mandatory":true}]}`,
			"/child": `{"vct":"{base}/child","extends":"{base}/base","display":[{"locale":"de","name":"Ausweis"},{"locale":"en","name":"ID card"}]}`,
		}
		doc, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(rw, r)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("Cache-Control", "max-age=60")
		_, _ = rw.Write([]byte(strings.ReplaceAll(doc, "{base}", server.URL)))
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := w.ConfigureOutbound(OutboundConfig{TLSCAPEM: ca}); err != nil {
		t.Fatal(err)
	}
	return server, &requests
}

func importTyped(t *testing.T, w *Wallet, vct string, claims map[string]any) *StoredCredential {
	t.Helper()
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{Issuer: "https://issuer.example", VCT: vct, ExpiresIn: time.Hour, Claims: claims, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := w.ImportCredential(raw)
	if err != nil {
		t.Fatalf("ImportCredential: %v", err)
	}
	return cred
}

// draft-ietf-oauth-sd-jwt-vc-19 §5.4: a Consumer "MAY use the types
// established via the extends property" when matching types. §5.5 gives the
// credential its name.
func TestACredentialAnswersTheTypeItsTypeMetadataExtends(t *testing.T) {
	w := generateTestWallet(t)
	server, _ := typeMetadataServer(t, w)
	cred := importTyped(t, w, server.URL+"/child", map[string]any{"given_name": "Erika"})

	if cred.TypeMetadata == nil || len(cred.TypeMetadata.Types) != 2 {
		t.Fatalf("type metadata = %+v, want the child and the base type", cred.TypeMetadata)
	}
	if cred.Display == nil || cred.Display.Name != "ID card" {
		t.Errorf("display = %+v, want the English name of the type", cred.Display)
	}
	matches, _ := w.matchDCQL(alwaysDisclosedQuery("dc+sd-jwt", "vct_values", server.URL+"/base", []any{"given_name"}))
	if len(matches) != 1 || matches[0].CredentialID != cred.ID {
		t.Errorf("matches = %+v, want the credential for its base type", matches)
	}
}

// §5.7: claim metadata validation fails for a missing mandatory claim. A
// manual import keeps the credential and warns.
func TestImportWarnsAboutACredentialThatBreaksItsTypeMetadata(t *testing.T) {
	w := generateTestWallet(t)
	server, _ := typeMetadataServer(t, w)
	cred := importTyped(t, w, server.URL+"/child", map[string]any{"family_name": "Mustermann"})

	if cred.TypeMetadata == nil {
		t.Fatal("the credential was stored without its Type Metadata")
	}
	entry := findLogEntry(w.GetLog(), "type_metadata")
	if entry == nil {
		t.Fatal("no type_metadata warning in the activity log")
	}
	if list, _ := entry.Details["findings"].([]string); len(list) != 1 || !strings.Contains(list[0], "the mandatory claim given_name is missing") {
		t.Errorf("findings = %v, want the missing mandatory claim", entry.Details["findings"])
	}
}

// RFC 9111: stale metadata is retrieved again in the background, not when the
// credential is presented (§8.4).
func TestStaleTypeMetadataIsRetrievedAgain(t *testing.T) {
	w := generateTestWallet(t)
	server, requests := typeMetadataServer(t, w)
	cred := importTyped(t, w, server.URL+"/child", map[string]any{"given_name": "Erika"})
	srv := NewServer(w, 0, nil)

	before := requests.Load()
	if err := srv.refreshTypeMetadata(time.Now()); err != nil || requests.Load() != before {
		t.Fatalf("err %v, requests %d -> %d, want no request for fresh metadata", err, before, requests.Load())
	}
	if err := srv.refreshTypeMetadata(time.Now().Add(2 * time.Minute)); err != nil || requests.Load() != before+2 {
		t.Fatalf("err %v, requests %d -> %d, want both documents again", err, before, requests.Load())
	}
	refreshed, _ := w.GetCredential(cred.ID)
	if !refreshed.TypeMetadata.Expires.After(cred.TypeMetadata.Expires) {
		t.Errorf("expires %v, want later than %v", refreshed.TypeMetadata.Expires, cred.TypeMetadata.Expires)
	}
}

// The metadata of the server lasts a minute. Retrieving the same metadata again
// renews it without a second warning.
func TestRefreshingUnchangedTypeMetadataWarnsOnce(t *testing.T) {
	w := generateTestWallet(t)
	server, _ := typeMetadataServer(t, w)
	cred := importTyped(t, w, server.URL+"/child", map[string]any{"family_name": "Mustermann"})
	srv := NewServer(w, 0, nil)

	if err := srv.refreshTypeMetadata(time.Now().Add(2 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	warnings := 0
	for _, entry := range w.GetLog() {
		if entry.Details["event"] == "type_metadata" {
			warnings++
		}
	}
	if warnings != 1 {
		t.Errorf("%d type_metadata warnings, want 1", warnings)
	}
	refreshed, _ := w.GetCredential(cred.ID)
	if !refreshed.TypeMetadata.Expires.After(cred.TypeMetadata.Expires) {
		t.Errorf("expires %v, want later than %v", refreshed.TypeMetadata.Expires, cred.TypeMetadata.Expires)
	}
}

// typedIssuer issues an SD-JWT VC of a type whose Type Metadata makes
// birthdate mandatory. The credential has no birthdate.
func typedIssuer(t *testing.T, w *Wallet) string {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		base := server.URL
		switch {
		case r.URL.Path == "/type":
			rw.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(rw, `{"vct":"`+base+`/type","claims":[{"path":["birthdate"],"mandatory":true}]}`)
		case r.URL.Path == "/.well-known/openid-credential-issuer":
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":   base,
				"credential_endpoint": base + "/credential",
				"credential_configurations_supported": map[string]any{"typed": map[string]any{
					"format": "dc+sd-jwt", "vct": base + "/type",
					"proof_types_supported": map[string]any{"jwt": map[string]any{"proof_signing_alg_values_supported": []any{"ES256"}}},
				}},
			})
		case r.URL.Path == "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(rw).Encode(map[string]any{"issuer": base, "token_endpoint": base + "/token"})
		case r.URL.Path == "/token":
			_ = json.NewEncoder(rw).Encode(map[string]any{"access_token": "token", "token_type": "Bearer"})
		case r.URL.Path == "/credential":
			_ = json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": generateTestCredentialOfType(t, w, base+"/type")}}})
		default:
			http.NotFound(rw, r)
		}
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := w.ConfigureOutbound(OutboundConfig{TLSCAPEM: ca}); err != nil {
		t.Fatal(err)
	}
	offer, _ := json.Marshal(map[string]any{
		"credential_issuer":            server.URL,
		"credential_configuration_ids": []string{"typed"},
		"grants":                       map[string]any{preAuthorizedCodeGrant: map[string]any{"pre-authorized_code": "code"}},
	})
	return "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offer))
}

// §5.7: "If claim metadata processing or validation fails, the SD-JWT VC MUST
// be rejected." Debug mode keeps it and reports the finding.
func TestIssuanceRejectsACredentialThatBreaksItsTypeMetadata(t *testing.T) {
	const want = "the mandatory claim birthdate is missing"
	t.Run("strict", func(t *testing.T) {
		w := generateTestWallet(t)
		w.ValidationMode = ValidationModeStrict
		_, err := w.ProcessCredentialOffer(typedIssuer(t, w))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want a refusal naming the missing claim", err)
		}
		if n := len(w.GetCredentials()); n != 0 {
			t.Errorf("stored %d credentials, want none", n)
		}
	})
	t.Run("debug", func(t *testing.T) {
		w := generateTestWallet(t)
		w.ValidationMode = ValidationModeDebug
		result, err := w.ProcessCredentialOffer(typedIssuer(t, w))
		if err != nil {
			t.Fatalf("ProcessCredentialOffer: %v", err)
		}
		if !strings.Contains(strings.Join(result.Findings.Texts(), "\n"), want) {
			t.Errorf("findings = %v, want the missing claim", result.Findings)
		}
	})
}
