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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/certinfo"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

type certificatesResponse struct {
	Format       string `json:"format"`
	Certificates []struct {
		Subject string `json:"subject"`
		Issuer  string `json:"issuer"`
		PEM     string `json:"pem"`
	} `json:"certificates"`
	Validation struct {
		Checks []validationCheck `json:"checks"`
	} `json:"validation"`
}

type validationCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

func signerChain(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := mock.GenerateNamedCACert(caKey, "Test CA")
	if err != nil {
		t.Fatal(err)
	}
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := mock.GenerateLeafCertWithOptions(caKey, ca, &key.PublicKey, mock.LeafCertOptions{CommonName: "Signer"})
	if err != nil {
		t.Fatal(err)
	}
	return key, leaf, ca
}

func postInput(t *testing.T, input string) certificatesResponse {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"input": input})
	w := apiPost(t, string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var got certificatesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestValidateDecodesPastedCertificates(t *testing.T) {
	_, leaf, ca := signerChain(t)
	x5c, _ := json.Marshal([]string{base64.StdEncoding.EncodeToString(leaf.Raw), base64.StdEncoding.EncodeToString(ca.Raw)})
	inputs := map[string]string{
		"PEM": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})) +
			string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})),
		"x5c": string(x5c),
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			got := postInput(t, input)

			if got.Format != "x509" || len(got.Certificates) != 2 {
				t.Fatalf("format %q with %d certificates, want x509 with the leaf and the CA", got.Format, len(got.Certificates))
			}
			if got.Certificates[0].Subject != certinfo.Describe(leaf).Subject || got.Certificates[0].Issuer != got.Certificates[1].Subject {
				t.Errorf("certificates %+v, want the signer issued by the CA", got.Certificates)
			}
			if block, _ := pem.Decode([]byte(got.Certificates[0].PEM)); block == nil || string(block.Bytes) != string(leaf.Raw) {
				t.Errorf("PEM %q is not the leaf", got.Certificates[0].PEM)
			}
			if !slices.Contains(got.Validation.Checks, validationCheck{Name: "signature", Status: "pass"}) {
				t.Errorf("checks %+v, want a passing signature check", got.Validation.Checks)
			}
		})
	}
}

func TestValidateShowsTheSignerCertificatesOfACredential(t *testing.T) {
	key, leaf, ca := signerChain(t)
	sdjwt, err := mock.GenerateSDJWT(mock.SDJWTConfig{Issuer: "https://issuer.example", VCT: "urn:test", ExpiresIn: time.Hour, Claims: map[string]any{"a": 1}, Key: key, CertChain: []*x509.Certificate{leaf, ca}})
	if err != nil {
		t.Fatal(err)
	}
	mdoc, err := mock.GenerateMDOC(mock.MDOCConfig{DocType: "org.example.test", Namespace: "org.example.test", Claims: map[string]any{"a": 1}, Key: key, CertChain: []*x509.Certificate{leaf, ca}})
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]string{"x5c of an SD-JWT": sdjwt, "x5chain of an mdoc": mdoc} {
		t.Run(name, func(t *testing.T) {
			got := postInput(t, input)

			if len(got.Certificates) == 0 || got.Certificates[0].Subject != certinfo.Describe(leaf).Subject {
				t.Errorf("%s certificates %+v, want the signer first", got.Format, got.Certificates)
			}
		})
	}
}
