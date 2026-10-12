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

package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

func TestParsePublicKey_PEM_EC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	pub, err := ParsePublicKey(pemData)
	if err != nil {
		t.Fatalf("ParsePublicKey() error: %v", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	if ecPub.Curve != elliptic.P256() {
		t.Error("expected P-256 curve")
	}
}

func TestParsePublicKey_PEM_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	pub, err := ParsePublicKey(pemData)
	if err != nil {
		t.Fatalf("ParsePublicKey() error: %v", err)
	}

	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}
}

func TestParseJWK_EC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	data := ecJWK(t, &key.PublicKey, "P-256")

	pub, err := ParseJWK(data)
	if err != nil {
		t.Fatalf("ParseJWK() error: %v", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	if !ecPub.Equal(&key.PublicKey) {
		t.Error("parsed key does not match original")
	}
}

func TestParseJWK_UnsupportedType(t *testing.T) {
	data := []byte(`{"kty":"OKP","crv":"Ed25519"}`)
	_, err := ParseJWK(data)
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

func TestLoadPublicKey_FileNotFound(t *testing.T) {
	_, err := LoadPublicKey("/nonexistent/path/key.pem")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadPublicKey_FromFile(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "key.pem")
	os.WriteFile(path, pemData, 0644)

	pub, err := LoadPublicKey(path)
	if err != nil {
		t.Fatalf("LoadPublicKey() error: %v", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
}

func TestParsePublicKey_InvalidData(t *testing.T) {
	_, err := ParsePublicKey([]byte("not a key"))
	if err == nil {
		t.Error("expected error for invalid key data")
	}
}

func TestParsePrivateKey_PEM_EC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	priv, err := ParsePrivateKey(pemData)
	if err != nil {
		t.Fatalf("ParsePrivateKey() error: %v", err)
	}
	if _, ok := priv.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", priv)
	}
}

func TestParsePrivateKey_PEM_RSA_PKCS1(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der := x509.MarshalPKCS1PrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	priv, err := ParsePrivateKey(pemData)
	if err != nil {
		t.Fatalf("ParsePrivateKey() error: %v", err)
	}
	if _, ok := priv.(*rsa.PrivateKey); !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", priv)
	}
}

func TestParsePrivateKey_PEM_PKCS8(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	priv, err := ParsePrivateKey(pemData)
	if err != nil {
		t.Fatalf("ParsePrivateKey() error: %v", err)
	}
	if _, ok := priv.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", priv)
	}
}

func TestParsePrivateKey_InvalidPEM(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")})
	_, err := ParsePrivateKey(pemData)
	if err == nil {
		t.Error("expected error for invalid PEM private key")
	}
}

func TestLoadPrivateKey_FromFile(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		t.Fatal(err)
	}

	priv, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadPrivateKey() error: %v", err)
	}
	if _, ok := priv.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", priv)
	}
}

func TestLoadPrivateKey_FileNotFound(t *testing.T) {
	_, err := LoadPrivateKey("/nonexistent/path/key.pem")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestParseJWKPrivate_EC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	data := ecPrivateJWK(t, key, "P-256")

	priv, err := ParseJWKPrivate(data)
	if err != nil {
		t.Fatalf("ParseJWKPrivate() error: %v", err)
	}
	ecKey, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", priv)
	}
	if !ecKey.Equal(key) {
		t.Error("private key does not match")
	}
}

func TestParseJWKPrivate_EC_MissingD(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	data := ecJWK(t, &key.PublicKey, "P-256")

	_, err := ParseJWKPrivate(data)
	if err == nil {
		t.Error("expected error for missing 'd' parameter")
	}
}

func TestParseJWKPrivate_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := map[string]any{
		"kty": "RSA",
		"n":   format.EncodeBase64URL(key.N.Bytes()),
		"e":   format.EncodeBase64URL(big.NewInt(int64(key.E)).Bytes()),
		"d":   format.EncodeBase64URL(key.D.Bytes()),
		"p":   format.EncodeBase64URL(key.Primes[0].Bytes()),
		"q":   format.EncodeBase64URL(key.Primes[1].Bytes()),
	}
	data, _ := json.Marshal(jwk)

	priv, err := ParseJWKPrivate(data)
	if err != nil {
		t.Fatalf("ParseJWKPrivate() error: %v", err)
	}
	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", priv)
	}
	if rsaKey.D.Cmp(key.D) != 0 {
		t.Error("private key D does not match")
	}
	if len(rsaKey.Primes) < 2 {
		t.Error("expected at least 2 primes")
	}
}

func TestParseJWKPrivate_RSA_MissingD(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := map[string]any{
		"kty": "RSA",
		"n":   format.EncodeBase64URL(key.N.Bytes()),
		"e":   format.EncodeBase64URL(big.NewInt(int64(key.E)).Bytes()),
	}
	data, _ := json.Marshal(jwk)

	_, err := ParseJWKPrivate(data)
	if err == nil {
		t.Error("expected error for missing 'd' parameter")
	}
}

func TestParseJWKPrivate_UnsupportedType(t *testing.T) {
	data := []byte(`{"kty":"OKP","crv":"Ed25519","d":"abc"}`)
	_, err := ParseJWKPrivate(data)
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

func TestParseJWKPrivate_InvalidJSON(t *testing.T) {
	_, err := ParseJWKPrivate([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseJWK_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := map[string]any{
		"kty": "RSA",
		"n":   format.EncodeBase64URL(key.N.Bytes()),
		"e":   format.EncodeBase64URL(big.NewInt(int64(key.E)).Bytes()),
	}
	data, _ := json.Marshal(jwk)

	pub, err := ParseJWK(data)
	if err != nil {
		t.Fatalf("ParseJWK() error: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}
	if rsaPub.N.Cmp(key.N) != 0 {
		t.Error("public key N does not match")
	}
}

func TestParsePublicKey_Certificate(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	pub, err := ParsePublicKey(pemData)
	if err != nil {
		t.Fatalf("ParsePublicKey() error: %v", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
}

func TestParsePrivateKey_JWK(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	data := ecPrivateJWK(t, key, "P-256")

	priv, err := ParsePrivateKey(data)
	if err != nil {
		t.Fatalf("ParsePrivateKey() error: %v", err)
	}
	if _, ok := priv.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", priv)
	}
}

func TestParseJWK_EC_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data := ecJWK(t, &key.PublicKey, "P-384")

	pub, err := ParseJWK(data)
	if err != nil {
		t.Fatalf("ParseJWK() error: %v", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	if ecPub.Curve != elliptic.P384() {
		t.Error("expected P-384 curve")
	}
	if !ecPub.Equal(&key.PublicKey) {
		t.Error("parsed key does not match original")
	}
}

func TestParseJWK_EC_P521(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	x, y, err := format.ECPublicCoords(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-521",
		// RFC 7518 requires full-width coordinates. P-521 coordinates often
		// have a zero leading byte.
		"x": format.EncodeBase64URL(x),
		"y": format.EncodeBase64URL(y),
	}
	data, _ := json.Marshal(jwk)

	pub, err := ParseJWK(data)
	if err != nil {
		t.Fatalf("ParseJWK() error: %v", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	if ecPub.Curve != elliptic.P521() {
		t.Error("expected P-521 curve")
	}
	if !ecPub.Equal(&key.PublicKey) {
		t.Error("parsed key does not match original")
	}
}

func TestParseJWK_EC_UnsupportedCurve(t *testing.T) {
	data := []byte(`{"kty":"EC","crv":"P-192","x":"dGVzdA","y":"dGVzdA"}`)
	_, err := ParseJWK(data)
	if err == nil {
		t.Error("expected error for unsupported curve P-192")
	}
}

func TestParsePublicKey_PEM_RSA_PKCS1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	derBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derBytes,
	})

	pub, err := ParsePublicKey(pemData)
	if err != nil {
		t.Fatalf("ParsePublicKey() error: %v", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}
	if rsaPub.N.Cmp(key.N) != 0 {
		t.Error("public key N does not match")
	}
}

func TestParsePublicKey_UnsupportedPEMType(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "DSA PUBLIC KEY",
		Bytes: []byte("garbage data that is not a valid key"),
	})

	_, err := ParsePublicKey(pemData)
	if err == nil {
		t.Error("expected error for unsupported PEM block type")
	}
}

func TestParseJWK_InvalidJSON(t *testing.T) {
	_, err := ParseJWK([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
