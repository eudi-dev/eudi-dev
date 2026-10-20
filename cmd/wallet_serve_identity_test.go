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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

// writeSigningBundle writes a PEM file with an EC key and a certificate for it.
func writeSigningBundle(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Sandbox Relying Party"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Sandbox Relying Party"}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, dir, "signing.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))+
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDemoIdentityFlagsLoadTheInfo(t *testing.T) {
	dir := t.TempDir()
	key := writeSigningBundle(t, dir)
	const certificate = "eyJ0eXAiOiJyYy13cnArand0In0.eyJzdWIiOiJzYW5kYm94In0.c2ln"

	tests := []struct {
		name  string
		flags demoIdentityFlags
		info  []any
	}{
		{name: "key alone", flags: demoIdentityFlags{SigningKey: key}},
		{
			name:  "info file",
			flags: demoIdentityFlags{SigningKey: key, Info: writeFile(t, dir, "info.json", `[{"format":"registration_cert","data":"x"}]`)},
			info:  []any{map[string]any{"format": "registration_cert", "data": "x"}},
		},
		{
			name:  "registration certificate",
			flags: demoIdentityFlags{SigningKey: key, RegistrationCert: writeFile(t, dir, "rc.jwt", certificate+"\n")},
			info:  []any{map[string]any{"format": "registration_cert", "data": base64.RawURLEncoding.EncodeToString([]byte(certificate))}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := tt.flags.load("verifier", registrar.VerifierInfoValue)
			if err != nil {
				t.Fatal(err)
			}
			if identity == nil || len(identity.Chain) != 1 {
				t.Fatalf("identity = %+v, want the key with its certificate", identity)
			}
			if !reflect.DeepEqual(identity.Info, tt.info) {
				t.Errorf("info = %v, want %v", identity.Info, tt.info)
			}
		})
	}
}

func TestDemoIdentityFlagsWithoutAKeyKeepTheRegisteredIdentity(t *testing.T) {
	identity, err := demoIdentityFlags{}.load("issuer", registrar.IssuerInfoValue)
	if err != nil || identity != nil {
		t.Fatalf("identity = %v, err = %v, want neither", identity, err)
	}
}

func TestDemoIdentityFlagsRefuseInconsistentFiles(t *testing.T) {
	dir := t.TempDir()
	key := writeSigningBundle(t, dir)
	info := writeFile(t, dir, "info.json", `[]`)
	cert := writeFile(t, dir, "rc.jwt", "a.b.c")
	tests := []struct {
		name  string
		flags demoIdentityFlags
		want  string
	}{
		{name: "info without key", flags: demoIdentityFlags{Info: info}, want: "need --demo-issuer-signing-key"},
		{name: "info and certificate", flags: demoIdentityFlags{SigningKey: key, Info: info, RegistrationCert: cert}, want: "use either"},
		{name: "info not an array", flags: demoIdentityFlags{SigningKey: key, Info: writeFile(t, dir, "object.json", `{}`)}, want: "JSON array"},
		{name: "certificate not a JWT", flags: demoIdentityFlags{SigningKey: key, RegistrationCert: writeFile(t, dir, "bad.jwt", "not a jwt")}, want: "compact JWT"},
		{name: "key without certificate", flags: demoIdentityFlags{SigningKey: writeFile(t, dir, "empty.pem", "")}, want: "--demo-issuer-signing-key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.flags.load("issuer", registrar.IssuerInfoValue)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}
