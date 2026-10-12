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
	"net/http/httptest"
	"testing"
	"time"
)

func TestCollectDeferredEndpoint(t *testing.T) {
	w := generateTestWallet(t)
	issuer, _ := deferredCollectionIssuer(t, generateTestCredential(t, w), 1, 30)
	defer issuer.Close()
	srv := NewServer(w, 0, func() {})
	pending := pendingFor(t, w, issuer.URL, 30)
	pending.NextAttemptAt = time.Now().Add(time.Hour)
	w.AddDeferredIssuance(pending)

	rec := serverRequest(t, srv, "POST", "/api/deferred/"+pending.ID+"/collect", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	first := decodeJSON(t, rec)
	if first["pending"] != true || first["collected"] != false || first["interval"] != "30s" || first["next_attempt_at"] == nil {
		t.Errorf("the first attempt answered %v, want it pending with the issuer's interval", first)
	}

	rec = serverRequest(t, srv, "POST", "/api/deferred/"+pending.ID+"/collect", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	second := decodeJSON(t, rec)
	if second["collected"] != true || second["format"] != "dc+sd-jwt" {
		t.Errorf("the second attempt answered %v, want the collected credential", second)
	}
	if _, ok := w.GetCredential(second["credential_id"].(string)); !ok {
		t.Errorf("the wallet does not hold the credential %v the endpoint named", second["credential_id"])
	}

	if rec := serverRequest(t, srv, "POST", "/api/deferred/"+pending.ID+"/collect", ""); rec.Code != http.StatusNotFound {
		t.Errorf("collecting a collected credential: status = %d, want 404", rec.Code)
	}
}

func TestAbandonDeferredEndpoint(t *testing.T) {
	w := generateTestWallet(t)
	srv := NewServer(w, 0, func() {})
	pending := pendingFor(t, w, "https://issuer.example/deferred", 10)
	w.AddDeferredIssuance(pending)

	rec := serverRequest(t, srv, "DELETE", "/api/deferred/"+pending.ID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := decodeJSON(t, rec)
	if body["abandoned"] != true || body["issuer"] != "https://issuer.example" || body["transaction_id"] != "test-transaction" {
		t.Errorf("abandoning answered %v, want the issuer and transaction it dropped", body)
	}

	if rec := serverRequest(t, srv, "DELETE", "/api/deferred/"+pending.ID, ""); rec.Code != http.StatusNotFound {
		t.Errorf("abandoning twice: status = %d, want 404", rec.Code)
	}
}

func TestRenewCredentialEndpoint(t *testing.T) {
	w := generateTestWallet(t)
	renewed := generateTestCredential(t, w)
	var issuerURL string
	issuer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-credential-issuer":
			_ = json.NewEncoder(rw).Encode(renewalIssuerMetadata(issuerURL))
		case "/nonce":
			_ = json.NewEncoder(rw).Encode(map[string]any{"c_nonce": "renewal-nonce"})
		case "/token":
			_ = json.NewEncoder(rw).Encode(map[string]any{"access_token": "fresh", "token_type": "Bearer"})
		case "/credential":
			_ = json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": renewed}}})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer issuer.Close()
	issuerURL = issuer.URL

	renewable, err := w.ImportCredential(generateTestCredential(t, w))
	if err != nil {
		t.Fatal(err)
	}
	w.rememberRenewal(renewable.ID, CredentialRenewal{RefreshToken: "refresh-1",
		Issuer: issuer.URL, TokenEndpoint: issuer.URL + "/token",
		CredentialEndpoint: issuer.URL + "/credential", ConfigurationID: "cfg",
	})
	srv := NewServer(w, 0, nil)

	rec := serverRequest(t, srv, "POST", "/api/credentials/"+renewable.ID+"/refresh", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if body := decodeJSON(t, rec); body["id"] != renewable.ID {
		t.Errorf("the renewal answered %v, want the credential under its original id", body)
	}
	if stored, _ := w.GetCredential(renewable.ID); stored.Raw != renewed {
		t.Error("the wallet still stores the credential from before the renewal")
	}

	// A credential without a refresh token cannot be renewed.
	plain, err := w.ImportCredential(generateTestCredential(t, w))
	if err != nil {
		t.Fatal(err)
	}
	rec = serverRequest(t, srv, "POST", "/api/credentials/"+plain.ID+"/refresh", "")
	if rec.Code != http.StatusBadRequest || decodeJSON(t, rec)["error"] == nil {
		t.Errorf("renewing without a refresh token: status = %d, body = %s, want 400 with an error", rec.Code, rec.Body.String())
	}
}
