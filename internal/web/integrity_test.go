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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v2/internal/statuslist"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

func TestCheckSDJWTIntegrity_AllMatch(t *testing.T) {
	discRaw1 := base64.RawURLEncoding.EncodeToString([]byte(`["salt1","name","Alice"]`))
	discRaw2 := base64.RawURLEncoding.EncodeToString([]byte(`["salt2","age",30]`))

	digest1 := sha256Sum(discRaw1)
	digest2 := sha256Sum(discRaw2)

	token := &sdjwt.Token{
		Payload: map[string]any{
			"_sd_alg": "sha-256",
			"_sd":     []any{digest1, digest2},
		},
		Disclosures: []sdjwt.Disclosure{
			{Raw: discRaw1, Name: "name", Value: "Alice", Digest: digest1},
			{Raw: discRaw2, Name: "age", Value: float64(30), Digest: digest2},
		},
	}

	result := CheckSDJWTIntegrity(token)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckSDJWTIntegrity_Mismatch(t *testing.T) {
	discRaw := base64.RawURLEncoding.EncodeToString([]byte(`["salt","name","Alice"]`))
	digest := sha256Sum(discRaw)

	token := &sdjwt.Token{
		Payload: map[string]any{
			"_sd": []any{"wrong-digest"},
		},
		Disclosures: []sdjwt.Disclosure{
			{Raw: discRaw, Name: "name", Value: "Alice", Digest: digest},
		},
	}

	result := CheckSDJWTIntegrity(token)
	if result.Status != "fail" {
		t.Errorf("expected fail, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckSDJWTIntegrity_NoDisclosures(t *testing.T) {
	token := &sdjwt.Token{
		Payload: map[string]any{"sub": "user"},
	}

	result := CheckSDJWTIntegrity(token)
	if result.Status != "skipped" {
		t.Errorf("expected skipped, got %s", result.Status)
	}
}

func TestCheckSDJWTIntegrity_NestedSD(t *testing.T) {
	discRaw := base64.RawURLEncoding.EncodeToString([]byte(`["salt","email","test@example.com"]`))
	digest := sha256Sum(discRaw)

	token := &sdjwt.Token{
		Payload: map[string]any{
			"address": map[string]any{
				"_sd": []any{digest},
			},
		},
		Disclosures: []sdjwt.Disclosure{
			{Raw: discRaw, Name: "email", Value: "test@example.com", Digest: digest},
		},
	}

	result := CheckSDJWTIntegrity(token)
	if result.Status != "pass" {
		t.Errorf("expected pass for nested _sd, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckSDJWTIntegrity_NestedDisclosureValue(t *testing.T) {
	// The address disclosure contains the locality digest in its own _sd array.

	addressDiscRaw := base64.RawURLEncoding.EncodeToString([]byte(`["salt-addr","address",{"_sd":["LOCALITY_DIGEST_PLACEHOLDER"]}]`))
	addressDigest := sha256Sum(addressDiscRaw)

	localityDiscRaw := base64.RawURLEncoding.EncodeToString([]byte(`["salt-loc","locality","KOELN"]`))
	localityDigest := sha256Sum(localityDiscRaw)

	addressValue := map[string]any{
		"_sd": []any{localityDigest},
	}

	token := &sdjwt.Token{
		Payload: map[string]any{
			"_sd_alg": "sha-256",
			"_sd":     []any{addressDigest},
		},
		Disclosures: []sdjwt.Disclosure{
			{Raw: addressDiscRaw, Name: "address", Value: addressValue, Digest: addressDigest},
			{Raw: localityDiscRaw, Name: "locality", Value: "KOELN", Digest: localityDigest},
		},
	}

	result := CheckSDJWTIntegrity(token)
	if result.Status != "pass" {
		t.Errorf("expected pass for nested disclosure value with _sd, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckSDJWTIntegrity_NestedArrayDisclosure(t *testing.T) {
	// The array disclosure contains element digest placeholders.

	subDiscRaw := base64.RawURLEncoding.EncodeToString([]byte(`["salt-de","DE"]`))
	subDigest := sha256Sum(subDiscRaw)

	natDiscRaw := base64.RawURLEncoding.EncodeToString([]byte(`["salt-nat","nationalities",[]]`))
	natDigest := sha256Sum(natDiscRaw)

	natValue := []any{
		map[string]any{"...": subDigest},
	}

	token := &sdjwt.Token{
		Payload: map[string]any{
			"_sd": []any{natDigest},
		},
		Disclosures: []sdjwt.Disclosure{
			{Raw: natDiscRaw, Name: "nationalities", Value: natValue, Digest: natDigest},
			{Raw: subDiscRaw, Value: "DE", Digest: subDigest, IsArrayEntry: true},
		},
	}

	result := CheckSDJWTIntegrity(token)
	if result.Status != "pass" {
		t.Errorf("expected pass for nested array disclosure, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckMDOCIntegrity_AllMatch(t *testing.T) {
	rawCBOR1 := []byte{0xa4, 0x01, 0x02, 0x03, 0x04}
	rawCBOR2 := []byte{0xb5, 0x06, 0x07, 0x08, 0x09}

	hash1 := sha256.Sum256(rawCBOR1)
	hash2 := sha256.Sum256(rawCBOR2)

	doc := &mdoc.Document{
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"org.iso.18013.5.1": {
				{DigestID: 0, ElementIdentifier: "family_name", RawCBOR: rawCBOR1},
				{DigestID: 1, ElementIdentifier: "given_name", RawCBOR: rawCBOR2},
			},
		},
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				DigestAlgorithm: "SHA-256",
				ValueDigests: map[string]map[uint64][]byte{
					"org.iso.18013.5.1": {
						0: hash1[:],
						1: hash2[:],
					},
				},
			},
		},
	}

	result := CheckMDOCIntegrity(doc)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckMDOCIntegrity_DigestMismatch(t *testing.T) {
	rawCBOR := []byte{0xa4, 0x01, 0x02, 0x03, 0x04}

	doc := &mdoc.Document{
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"org.iso.18013.5.1": {
				{DigestID: 0, ElementIdentifier: "family_name", RawCBOR: rawCBOR},
			},
		},
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				DigestAlgorithm: "SHA-256",
				ValueDigests: map[string]map[uint64][]byte{
					"org.iso.18013.5.1": {
						0: []byte("wrong-digest-value-that-wont-match"),
					},
				},
			},
		},
	}

	result := CheckMDOCIntegrity(doc)
	if result.Status != "fail" {
		t.Errorf("expected fail, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckMDOCIntegrity_NoMSO(t *testing.T) {
	doc := &mdoc.Document{
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"ns": {{DigestID: 0, ElementIdentifier: "x"}},
		},
	}

	result := CheckMDOCIntegrity(doc)
	if result.Status != "skipped" {
		t.Errorf("expected skipped, got %s", result.Status)
	}
}

func sha256Sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func TestCheckSDJWTIntegrity_ArrayElementDisclosure(t *testing.T) {
	discRaw := base64.RawURLEncoding.EncodeToString([]byte(`["salt","item1"]`))
	digest := sha256Sum(discRaw)

	token := &sdjwt.Token{
		Payload: map[string]any{
			"items": []any{
				map[string]any{"...": digest},
			},
		},
		Disclosures: []sdjwt.Disclosure{
			{Raw: discRaw, Value: "item1", Digest: digest, IsArrayEntry: true},
		},
	}

	result := CheckSDJWTIntegrity(token)
	if result.Status != "pass" {
		t.Errorf("expected pass for array element, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckMDOCIntegrity_Tag24EncodedRawCBOR(t *testing.T) {
	// MSO ValueDigests hash the full Tag-24 encoding (#6.24(bstr)).
	innerCBOR := []byte{0xa4, 0x01, 0x02, 0x03, 0x04}

	// Tag 24 with 5-byte content: 0xd8 0x18 0x45 <5 bytes>
	tag24Bytes := append([]byte{0xd8, 0x18, 0x45}, innerCBOR...)

	hash := sha256.Sum256(tag24Bytes)

	doc := &mdoc.Document{
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"org.iso.18013.5.1": {
				{DigestID: 0, ElementIdentifier: "family_name", RawCBOR: tag24Bytes},
			},
		},
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				DigestAlgorithm: "SHA-256",
				ValueDigests: map[string]map[uint64][]byte{
					"org.iso.18013.5.1": {
						0: hash[:],
					},
				},
			},
		},
	}

	result := CheckMDOCIntegrity(doc)
	if result.Status != "pass" {
		t.Errorf("expected pass for Tag-24 encoded RawCBOR, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckMDOCIntegrity_Tag24FailsWithInnerBytesDigest(t *testing.T) {
	// A digest over only the inner bytes must fail.
	innerCBOR := []byte{0xa4, 0x01, 0x02, 0x03, 0x04}
	tag24Bytes := append([]byte{0xd8, 0x18, 0x45}, innerCBOR...)

	hashInner := sha256.Sum256(innerCBOR)

	doc := &mdoc.Document{
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"org.iso.18013.5.1": {
				{DigestID: 0, ElementIdentifier: "family_name", RawCBOR: tag24Bytes},
			},
		},
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				DigestAlgorithm: "SHA-256",
				ValueDigests: map[string]map[uint64][]byte{
					"org.iso.18013.5.1": {
						0: hashInner[:],
					},
				},
			},
		},
	}

	result := CheckMDOCIntegrity(doc)
	if result.Status != "fail" {
		t.Errorf("expected fail when digest is over inner bytes but RawCBOR is Tag-24, got %s: %s", result.Status, result.Detail)
	}
}

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

	if len(checks) != 5 {
		t.Errorf("expected 5 checks, got %d", len(checks))
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

func TestHandleValidate_JWTSkipsIntegrityAndStatus(t *testing.T) {
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
	if details["status"] != "Not applicable for plain JWT" {
		t.Errorf("status detail: got %q, want %q", details["status"], "Not applicable for plain JWT")
	}

	if names["expiry"] != "pass" {
		t.Errorf("expiry check: got %s, want pass", names["expiry"])
	}

	if names["signature"] != "skipped" {
		t.Errorf("signature check: got %s, want skipped", names["signature"])
	}
}

func TestHandleValidate_JWTStatusSkippedEvenWhenRequested(t *testing.T) {
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
			if cm["detail"] != "Not applicable for plain JWT" {
				t.Errorf("status detail: got %q, want %q", cm["detail"], "Not applicable for plain JWT")
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

func TestValidate_MDOCStatusWrapping(t *testing.T) {
	// MSO.Status is the inner {"status_list": ...} object.
	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				Status: map[string]any{
					"status_list": map[string]any{
						"idx": float64(42),
						"uri": "https://example.com/statuslist",
					},
				},
			},
		},
	}

	result := checkMDOCStatus(doc, ValidateOpts{CheckStatus: false})[0]
	if result.Status != "skipped" {
		t.Errorf("expected skipped when CheckStatus=false, got %s", result.Status)
	}
	if result.Detail != "Not requested" {
		t.Errorf("expected 'Not requested', got %q", result.Detail)
	}
}

func TestValidate_MDOCStatusNoStatus(t *testing.T) {
	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{},
		},
	}

	result := checkMDOCStatus(doc, ValidateOpts{CheckStatus: true})[0]
	if result.Status != "skipped" {
		t.Errorf("expected skipped when no status in MSO, got %s", result.Status)
	}
	if result.Detail != "No status reference in credential" {
		t.Errorf("expected 'No status reference in credential', got %q", result.Detail)
	}
}

func TestValidate_SDJWTExpiryNotYetValid(t *testing.T) {
	token := &sdjwt.Token{
		Payload: map[string]any{
			"nbf": float64(4102444800), // 2100-01-01
			"exp": float64(4102444900),
		},
	}

	result := checkSDJWTExpiry(token)
	if result.Status != "fail" {
		t.Errorf("expected fail for not-yet-valid token, got %s: %s", result.Status, result.Detail)
	}
}

func TestValidate_SDJWTExpiryNoExp(t *testing.T) {
	token := &sdjwt.Token{
		Payload: map[string]any{"sub": "user"},
	}

	result := checkSDJWTExpiry(token)
	if result.Status != "skipped" {
		t.Errorf("expected skipped when no exp, got %s", result.Status)
	}
}

func TestValidate_MDOCExpiryNoValidityInfo(t *testing.T) {
	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{},
		},
	}

	result := checkMDOCExpiry(doc)
	if result.Status != "skipped" {
		t.Errorf("expected skipped when no validity info, got %s", result.Status)
	}
}

func TestValidate_SignatureSkippedNoKey(t *testing.T) {
	token := &sdjwt.Token{
		Payload: map[string]any{"sub": "user"},
	}

	result := checkSDJWTSignature(token, ValidateOpts{})
	if result.Status != "skipped" {
		t.Errorf("expected skipped when no key, got %s", result.Status)
	}
	if result.Detail != "No key provided" {
		t.Errorf("expected 'No key provided', got %q", result.Detail)
	}
}

func TestValidate_SignatureSkippedWhenIssuerMetadataLookupFails(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://localhost:1",
		VCT:       "urn:test",
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "Erika"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	result := checkSDJWTSignature(token, ValidateOpts{})
	if result.Status != "skipped" {
		t.Fatalf("expected skipped when issuer metadata lookup fails, got %s (%s)", result.Status, result.Detail)
	}
	if result.Detail == "" || result.Detail == "No key provided" {
		t.Fatalf("expected issuer metadata lookup detail, got %q", result.Detail)
	}
}

func TestValidate_SignatureUsesLocalWalletFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	walletDir := filepath.Join(home, ".oid4vc-dev", "wallet")
	if err := os.MkdirAll(walletDir, 0700); err != nil {
		t.Fatalf("mkdir wallet dir: %v", err)
	}

	store := wallet.NewWalletStore("")
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://localhost:1",
		VCT:       "urn:test",
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "Erika"},
		Key:       w.IssuerKey,
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	result := checkSDJWTSignature(token, ValidateOpts{})
	if result.Status != "pass" {
		t.Fatalf("expected local wallet fallback pass, got %s (%s)", result.Status, result.Detail)
	}
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

	if len(checks1) != 5 {
		t.Errorf("expected 5 checks without key, got %d", len(checks1))
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

	if len(checks2) != 5 {
		t.Errorf("expected 5 checks with invalid key, got %d", len(checks2))
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

func TestValidate_MDOCStatusNilIssuerAuth(t *testing.T) {
	doc := &mdoc.Document{}

	result := checkMDOCStatus(doc, ValidateOpts{CheckStatus: true})[0]
	if result.Status != "skipped" {
		t.Errorf("expected skipped when no issuerAuth, got %s", result.Status)
	}
}

func TestValidate_MDOCExpiryNilIssuerAuth(t *testing.T) {
	doc := &mdoc.Document{}

	result := checkMDOCExpiry(doc)
	if result.Status != "skipped" {
		t.Errorf("expected skipped when no issuerAuth, got %s", result.Status)
	}
}

func TestValidate_MDOCSignatureSkippedNoKey(t *testing.T) {
	doc := &mdoc.Document{}

	result := checkMDOCSignature(doc, ValidateOpts{})
	if result.Status != "skipped" {
		t.Errorf("expected skipped when no key, got %s", result.Status)
	}
	if result.Detail != "No key provided" {
		t.Errorf("expected 'No key provided', got %q", result.Detail)
	}
}

func TestValidate_SDJWTExpiryPass(t *testing.T) {
	token := &sdjwt.Token{
		Payload: map[string]any{
			"exp": float64(4102444800), // far future
		},
	}

	result := checkSDJWTExpiry(token)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
}

func TestValidate_SDJWTExpiryExpired(t *testing.T) {
	token := &sdjwt.Token{
		Payload: map[string]any{
			"exp": float64(1000000000), // way in the past
		},
	}

	result := checkSDJWTExpiry(token)
	if result.Status != "fail" {
		t.Errorf("expected fail, got %s: %s", result.Status, result.Detail)
	}
}

func TestValidate_SDJWTStatusSkippedNotRequested(t *testing.T) {
	token := &sdjwt.Token{
		ResolvedClaims: map[string]any{
			"sub": "user",
			"status": map[string]any{
				"status_list": map[string]any{
					"idx": float64(7),
					"uri": "https://issuer.example/status-list/1",
				},
			},
		},
	}

	result := checkSDJWTStatus(token, ValidateOpts{CheckStatus: false})[0]
	if result.Status != "skipped" {
		t.Errorf("expected skipped, got %s", result.Status)
	}
	if result.Detail != "Not requested" {
		t.Errorf("expected 'Not requested', got %q", result.Detail)
	}
}

func TestValidate_SDJWTStatusNoRef(t *testing.T) {
	token := &sdjwt.Token{
		ResolvedClaims: map[string]any{"sub": "user"},
	}

	result := checkSDJWTStatus(token, ValidateOpts{CheckStatus: true})[0]
	if result.Status != "skipped" {
		t.Errorf("expected skipped when no status ref, got %s", result.Status)
	}
	if result.Detail != "No status list reference in credential" {
		t.Errorf("expected 'No status list reference in credential', got %q", result.Detail)
	}
}
