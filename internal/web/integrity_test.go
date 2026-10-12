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
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/statuslist"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

func TestHandleValidate_SDJWTBasic(t *testing.T) {
	jwt := makeSDJWT(
		map[string]any{
			"iss":     "https://issuer.example",
			"_sd_alg": "sha-256",
			"_sd":     nil,
			"exp":     float64(4102444800), // far future
		},
		[][]any{
			{"salt1", "given_name", "Erika"},
		},
	)

	body, _ := json.Marshal(map[string]any{
		"input": jwt,
	})

	w := apiPostTo(t, "/api/validate", string(body))

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeResponse(t, w)

	val, ok := result["validation"].(map[string]any)
	if !ok {
		t.Fatalf("expected validation object, got %T", result["validation"])
	}

	checks, ok := val["checks"].([]any)
	if !ok {
		t.Fatalf("expected checks array, got %T", val["checks"])
	}

	if len(checks) != 6 {
		t.Errorf("expected 6 checks, got %d", len(checks))
	}

	names := make(map[string]string)
	for _, c := range checks {
		cm := c.(map[string]any)
		names[cm["name"].(string)] = cm["status"].(string)
	}

	if names["type"] != "pass" {
		t.Errorf("type check: got %s, want pass", names["type"])
	}
	if names["expiry"] != "pass" {
		t.Errorf("expiry check: got %s, want pass", names["expiry"])
	}
	if names["integrity"] != "pass" {
		t.Errorf("integrity check: got %s, want pass", names["integrity"])
	}
	if names["signature"] != "skipped" {
		t.Errorf("signature check: got %s, want skipped", names["signature"])
	}
	if names["status"] != "skipped" {
		t.Errorf("status check: got %s, want skipped", names["status"])
	}
}

func TestHandleValidate_EmptyInput(t *testing.T) {
	w := apiPostTo(t, "/api/validate", `{"input":""}`)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleValidate_JWTExpired(t *testing.T) {
	jwt := makeJWT(
		map[string]any{"alg": "none", "typ": "JWT"},
		map[string]any{
			"sub": "user",
			"exp": float64(1000000000), // way in the past
		},
	)

	body, _ := json.Marshal(map[string]any{"input": jwt})
	w := apiPostTo(t, "/api/validate", string(body))

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeResponse(t, w)
	val := result["validation"].(map[string]any)
	checks := val["checks"].([]any)

	for _, c := range checks {
		cm := c.(map[string]any)
		if cm["name"] == "expiry" && cm["status"] != "fail" {
			t.Errorf("expected expiry fail for expired JWT, got %s", cm["status"])
		}
	}
}

func TestHandleValidate_JWTSkipsIntegrity(t *testing.T) {
	jwt := makeJWT(
		map[string]any{"alg": "none", "typ": "JWT"},
		map[string]any{
			"sub": "user",
			"exp": float64(4102444800), // far future
		},
	)

	body, _ := json.Marshal(map[string]any{"input": jwt})
	w := apiPostTo(t, "/api/validate", string(body))

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeResponse(t, w)
	val := result["validation"].(map[string]any)
	checks := val["checks"].([]any)

	if len(checks) != 4 {
		t.Fatalf("expected 4 checks, got %d", len(checks))
	}

	names := make(map[string]string)
	details := make(map[string]string)
	for _, c := range checks {
		cm := c.(map[string]any)
		names[cm["name"].(string)] = cm["status"].(string)
		details[cm["name"].(string)] = cm["detail"].(string)
	}

	if names["integrity"] != "skipped" {
		t.Errorf("integrity check: got %s, want skipped", names["integrity"])
	}
	if details["integrity"] != "Not applicable for plain JWT" {
		t.Errorf("integrity detail: got %q, want %q", details["integrity"], "Not applicable for plain JWT")
	}

	if names["status"] != "skipped" {
		t.Errorf("status check: got %s, want skipped", names["status"])
	}
	if details["status"] != "No status list reference in credential" {
		t.Errorf("status detail: got %q, want %q", details["status"], "No status list reference in credential")
	}

	if names["expiry"] != "pass" {
		t.Errorf("expiry check: got %s, want pass", names["expiry"])
	}

	if names["signature"] != "skipped" {
		t.Errorf("signature check: got %s, want skipped", names["signature"])
	}
}

// Token Status List §6.2 lets any JWT reference a status list, so a plain JWT
// gets the status check of an SD-JWT VC.
func TestHandleValidate_JWTWithoutStatusReference(t *testing.T) {
	jwt := makeJWT(
		map[string]any{"alg": "none", "typ": "JWT"},
		map[string]any{
			"sub": "user",
			"exp": float64(4102444800),
		},
	)

	body, _ := json.Marshal(map[string]any{
		"input":       jwt,
		"checkStatus": true,
	})
	w := apiPostTo(t, "/api/validate", string(body))

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeResponse(t, w)
	val := result["validation"].(map[string]any)
	checks := val["checks"].([]any)

	for _, c := range checks {
		cm := c.(map[string]any)
		if cm["name"] == "status" {
			if cm["status"] != "skipped" {
				t.Errorf("status check: got %s, want skipped", cm["status"])
			}
			if cm["detail"] != "No status list reference in credential" {
				t.Errorf("status detail: got %q, want %q", cm["detail"], "No status list reference in credential")
			}
		}
	}
}

func TestHandleValidate_SDJWTStatusCheckedWhenPresent(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	bitstring := make([]byte, 16)
	var statusSrv *httptest.Server
	statusSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The status token's sub must match the URL in the credential.
		jwt, err := statuslist.GenerateStatusListJWT(bitstring, key, statuslist.StatusListConfig{
			URI: statusSrv.URL,
		})
		if err != nil {
			t.Fatalf("GenerateStatusListJWT: %v", err)
		}
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		_, _ = w.Write([]byte(jwt))
	}))
	defer statusSrv.Close()

	jwt := makeSDJWT(
		map[string]any{
			"iss":     "https://issuer.example",
			"_sd_alg": "sha-256",
			"_sd":     nil,
			"exp":     float64(4102444800),
			"status": map[string]any{
				"status_list": map[string]any{
					"uri": statusSrv.URL,
					"idx": 0,
				},
			},
		},
		[][]any{
			{"salt1", "given_name", "Erika"},
		},
	)

	body, _ := json.Marshal(map[string]any{
		"input":       jwt,
		"checkStatus": true,
	})
	w := apiPostTo(t, "/api/validate", string(body))

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeResponse(t, w)
	val := result["validation"].(map[string]any)
	checks := val["checks"].([]any)

	for _, c := range checks {
		cm := c.(map[string]any)
		if cm["name"] == "status" {
			if cm["status"] != "pass" {
				t.Fatalf("status check: got %s, want pass", cm["status"])
			}
			detail, _ := cm["detail"].(string)
			if detail == "" || detail == "No status list reference in credential" {
				t.Fatalf("expected status validation detail, got %q", detail)
			}
			return
		}
	}

	t.Fatal("expected status check in validation response")
}

func TestHandleValidate_VerifyFormAlwaysPresent(t *testing.T) {
	// A failed signature check must still return all checks, so the UI can show
	// the verification form.
	jwt := makeSDJWT(
		map[string]any{
			"iss":     "https://issuer.example",
			"_sd_alg": "sha-256",
			"_sd":     nil,
			"exp":     float64(4102444800),
		},
		[][]any{
			{"salt1", "given_name", "Erika"},
		},
	)

	body1, _ := json.Marshal(map[string]any{"input": jwt})
	w1 := apiPostTo(t, "/api/validate", string(body1))
	if w1.Code != 200 {
		t.Fatalf("expected 200, got %d", w1.Code)
	}

	result1 := decodeResponse(t, w1)
	val1 := result1["validation"].(map[string]any)
	checks1 := val1["checks"].([]any)

	if len(checks1) != 6 {
		t.Errorf("expected 6 checks without key, got %d", len(checks1))
	}

	body2, _ := json.Marshal(map[string]any{
		"input": jwt,
		"key":   "not-a-valid-key",
	})
	w2 := apiPostTo(t, "/api/validate", string(body2))
	if w2.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	result2 := decodeResponse(t, w2)
	val2 := result2["validation"].(map[string]any)
	checks2 := val2["checks"].([]any)

	if len(checks2) != 6 {
		t.Errorf("expected 6 checks with invalid key, got %d", len(checks2))
	}

	for _, c := range checks2 {
		cm := c.(map[string]any)
		if cm["name"] == "signature" && cm["status"] != "fail" {
			t.Errorf("signature check: got %s, want fail", cm["status"])
		}
	}
}

func TestHandleValidate_SDJWTValidExpiry(t *testing.T) {
	jwt := makeSDJWT(
		map[string]any{
			"iss":     "https://issuer.example",
			"_sd_alg": "sha-256",
			"_sd":     nil,
			"exp":     float64(4102444800), // far future
		},
		[][]any{
			{"salt1", "given_name", "Erika"},
		},
	)

	body, _ := json.Marshal(map[string]any{"input": jwt})
	w := apiPostTo(t, "/api/validate", string(body))

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeResponse(t, w)
	val := result["validation"].(map[string]any)
	checks := val["checks"].([]any)

	for _, c := range checks {
		cm := c.(map[string]any)
		if cm["name"] == "expiry" {
			if cm["status"] != "pass" {
				t.Errorf("expiry: got %s, want pass", cm["status"])
			}
			detail := cm["detail"].(string)
			if len(detail) == 0 {
				t.Error("expiry detail should not be empty")
			}
		}
	}
}

// The revocation service of the wallet's trusted list that anchors a
// credential anchors its status list (ETSI TS 119 602 V1.1.1 Table D.3).
func TestTheDecoderAnchorsAStatusListInTheRevocationServiceOfItsList(t *testing.T) {
	store := wallet.NewWalletStore(t.TempDir())
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(wallet.NewServer(w, 0, nil).Handler())
	defer ts.Close()
	w.IssuerURL = ts.URL
	w.BaseURL = ts.URL
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatal(err)
	}
	for _, cred := range w.GetCredentials() {
		result, err := Validate(cred.Raw, ValidateOpts{Wallet: w, CheckStatus: true})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, c := range result["validation"].(map[string]any)["checks"].([]CheckResult) {
			switch c.Name {
			case "status list signature":
				found = true
				if c.Status != "pass" || c.Anchor == nil || c.Anchor.ListURL != ts.URL+"/api/trustlists/pid" || c.Anchor.Service != "revocation" {
					t.Errorf("%s: status list signature = %+v, want it anchored by the revocation service of the PID list", cred.Format, c)
				}
			case "trust":
				if c.Status != "pass" || c.Anchor == nil || c.Anchor.ListURL != ts.URL+"/api/trustlists/pid" || c.Anchor.Service != "issuance" {
					t.Errorf("%s: trust = %+v, want it anchored by the issuance service of the PID list", cred.Format, c)
				}
			}
		}
		if !found {
			t.Errorf("%s: no status list signature check", cred.Format)
		}
	}
}
