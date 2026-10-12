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

package registrar

import (
	"crypto/ecdsa"
	"crypto/x509"
	"sync"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

// testWallet gives a registrar its own state, CAs and signing material, as a
// wallet does.
type testWallet struct {
	*Registrar
	*State
	env *testEnv
}

type testEnv struct {
	base           string
	caKey          *ecdsa.PrivateKey
	ca             *x509.Certificate
	registrarKey   *ecdsa.PrivateKey
	registrarChain []*x509.Certificate
	accessCAKey    *ecdsa.PrivateKey
	accessCA       *x509.Certificate
	templates      credtemplate.Location
	// signErr makes the registrar signer fail.
	signErr           error
	maxRelyingParties int
}

func (e *testEnv) RegistrarBase() string { return e.base }
func (e *testEnv) RegistrarSigningMaterial() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	return e.registrarKey, e.registrarChain, e.signErr
}
func (e *testEnv) RelyingPartyAccessCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	return e.accessCAKey, e.accessCA, nil
}
func (e *testEnv) TemplateLocation() credtemplate.Location { return e.templates }
func (e *testEnv) MaxRelyingParties() int                  { return e.maxRelyingParties }
func (e *testEnv) TrustedListURL(category string) string {
	return e.base + "/api/trustlists/" + category
}
func generateTestWallet(t testing.TB) *testWallet {
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		k, err := mock.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	env := &testEnv{base: "https://wallet.example", caKey: key(), registrarKey: key(), accessCAKey: key()}
	var err error
	if env.ca, err = mock.GenerateNamedCACert(env.caKey, "Test Wallet CA"); err != nil {
		t.Fatal(err)
	}
	if env.accessCA, err = mock.GenerateNamedCACert(env.accessCAKey, "Test Relying Party Access CA"); err != nil {
		t.Fatal(err)
	}
	leaf := func(k *ecdsa.PrivateKey, opts mock.LeafCertOptions) []*x509.Certificate {
		cert, err := mock.GenerateLeafCertWithOptions(env.caKey, env.ca, &k.PublicKey, opts)
		if err != nil {
			t.Fatal(err)
		}
		return []*x509.Certificate{cert, env.ca}
	}
	env.registrarChain = leaf(env.registrarKey, mock.LeafCertOptions{CommonName: "Test Registrar", Role: mock.RegistrarCertificate})
	env.templates = credtemplate.FileLocation(t.TempDir())
	state := &State{}
	return &testWallet{Registrar: New(&sync.RWMutex{}, state, env), State: state, env: env}
}

func (w *testWallet) RegistrarBase() string { return w.env.base }

const testDiplomaVCT = "urn:example:diploma:1"
