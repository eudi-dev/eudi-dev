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

package cmd

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/statuslist"
)

// validate fails an mdoc before its validFrom, also when only the embedded
// certificate verifies its signature.
func TestValidateFailsAnMDOCThatIsNotYetValid(t *testing.T) {
	caCert, caKey, _ := generateCACert(t)
	leafCert, leafKey, _ := generateLeafCert(t, caCert, caKey)
	validFrom := time.Now().Add(time.Hour)
	raw, err := mock.GenerateMDOC(mock.MDOCConfig{
		DocType:   "eu.example.test.1",
		Namespace: "eu.example.test.1",
		Claims:    map[string]any{"family_name": "Mustermann"},
		Key:       leafKey,
		ValidFrom: &validFrom,
		ExpiresIn: 2 * time.Hour,
		CertChain: []*x509.Certificate{leafCert, caCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runValidateArgs(t, raw); err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Errorf("validate = %v, want the not yet valid error", err)
	}
	if err := runValidateArgs(t, raw, "--allow-expired"); err != nil {
		t.Errorf("validate --allow-expired = %v, want success", err)
	}
}

// A status list signed by a chain that no trusted list anchors is reported
// as unanchored.
func TestValidateMarksAnUnanchoredStatusListSignature(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	caCert, caKey, _ := generateCACert(t)
	leafCert, leafKey, _ := generateLeafCert(t, caCert, caKey)
	var statusSrv *httptest.Server
	statusSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwt, err := statuslist.GenerateStatusListJWT(make([]byte, 16), leafKey, statuslist.StatusListConfig{URI: statusSrv.URL, CertChain: []*x509.Certificate{leafCert, caCert}})
		if err != nil {
			t.Errorf("GenerateStatusListJWT: %v", err)
			return
		}
		w.Header().Set("Content-Type", statuslist.MediaTypeJWT)
		_, _ = w.Write([]byte(jwt))
	}))
	defer statusSrv.Close()
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:        "https://localhost:1",
		VCT:           "urn:test:status",
		ExpiresIn:     time.Hour,
		Claims:        map[string]any{"given_name": "Erika"},
		Key:           key,
		StatusListURI: statusSrv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	var runErr error
	out := captureStdout(t, func() { runErr = runValidateArgs(t, raw) })
	if runErr != nil {
		t.Fatalf("validate: %v", runErr)
	}
	if !strings.Contains(out, "! Status list signature:") {
		t.Errorf("output lacks the unanchored status list signature:\n%s", out)
	}
}

// validate reports a status claim that is no Token Status List and does not
// fail on it.
func TestValidateWarnsAboutAnotherStatusFormat(t *testing.T) {
	jwt := unsignedTestJWT(t, map[string]any{"status": map[string]any{"type": "StatusList2021Entry"}, "exp": time.Now().Add(time.Hour).Unix()})
	var runErr error
	out := captureStdout(t, func() { runErr = runValidateArgs(t, jwt) })
	if runErr != nil {
		t.Fatalf("validate: %v", runErr)
	}
	if !strings.Contains(out, "! status:") || !strings.Contains(out, "StatusList2021Entry") {
		t.Errorf("output lacks the status format warning:\n%s", out)
	}
}

// The credential format comes from the encoding, so a JWT with
// credential_issuer in its payload validates as a JWT.
func TestValidateDetectsAJWTByItsEncoding(t *testing.T) {
	jwt := unsignedTestJWT(t, map[string]any{"credential_issuer": "https://issuer.example", "exp": time.Now().Add(time.Hour).Unix()})
	if err := runValidateArgs(t, jwt); err != nil {
		t.Errorf("validate: %v", err)
	}
}

// A DeviceResponse that names another docType than the signed MSO fails the
// integrity check.
func TestValidateFailsAnMDOCRelabelledByItsDeviceResponse(t *testing.T) {
	caCert, caKey, _ := generateCACert(t)
	leafCert, leafKey, _ := generateLeafCert(t, caCert, caKey)
	raw, err := mock.GenerateMDOC(mock.MDOCConfig{
		DocType:   "eu.example.test.1",
		Namespace: "eu.example.test.1",
		Claims:    map[string]any{"family_name": "Mustermann"},
		Key:       leafKey,
		ExpiresIn: time.Hour,
		CertChain: []*x509.Certificate{leafCert, caCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	issuerSigned, err := format.DecodeHexOrBase64URL(raw)
	if err != nil {
		t.Fatal(err)
	}
	response, err := cbor.Marshal(map[string]any{
		"version": "1.0",
		"status":  0,
		"documents": []any{map[string]any{
			"docType":      "eu.europa.ec.eudi.pid.1",
			"issuerSigned": cbor.RawMessage(issuerSigned),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runValidateArgs(t, hex.EncodeToString(response)); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Errorf("validate = %v, want an integrity failure", err)
	}
}

func unsignedTestJWT(t *testing.T, payload map[string]any) string {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(body) + "."
}
