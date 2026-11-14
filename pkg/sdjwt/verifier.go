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

package sdjwt

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/validity"
)

// Match these errors with errors.Is.
var (
	// ErrSignature reports a signature that does not verify with the key.
	ErrSignature = errors.New("signature verification failed")
	// ErrExpired reports a verification time after exp.
	ErrExpired = errors.New("expired")
	// ErrNotYetValid reports a verification time before nbf.
	ErrNotYetValid = errors.New("not valid before")
	// ErrAudience reports a Key Binding JWT for another verifier.
	ErrAudience = errors.New("aud does not match")
	// ErrNonce reports a Key Binding JWT for another request.
	ErrNonce = errors.New("nonce does not match")
	// ErrSDHash reports a Key Binding JWT for another presentation.
	ErrSDHash = errors.New("sd_hash does not match")
)

// Verify checks the signature of the Issuer-signed JWT with key. The caller
// decides whether it trusts that key. ValidAt checks the validity period.
func Verify(token *Token, key crypto.PublicKey) error {
	if strings.Count(signedJWT(token), ".") != 2 {
		return errors.New("invalid JWT structure")
	}
	return verifySignature(token, key)
}

// ValidAt checks exp and nbf of the Processed SD-JWT Payload against now (RFC
// 9901 §7.1 step 6). It allows a clock skew of 1 minute. An exp, nbf or iat
// claim that is not a NumericDate (RFC 7519 §2) is an error.
func (t *Token) ValidAt(now time.Time) error {
	if t.ResolvedClaims == nil {
		return errors.New("the token has no processed payload")
	}
	return validAt(t.ResolvedClaims, now)
}

// ConfirmationKey returns the key of the cnf claim in the Processed SD-JWT
// Payload (RFC 9901 §4.1.2). It reads the jwk member of RFC 7800 §3.2. The key
// is authentic only after Verify succeeded.
func (t *Token) ConfirmationKey() (crypto.PublicKey, error) {
	jwk := jsonutil.GetMap(jsonutil.GetMap(t.ResolvedClaims, "cnf"), "jwk")
	if jwk == nil {
		return nil, errors.New("no cnf claim with a jwk")
	}
	encoded, err := json.Marshal(jwk)
	if err != nil {
		return nil, err
	}
	key, err := keys.ParseJWK(encoded)
	if err != nil {
		return nil, fmt.Errorf("an unreadable cnf key: %w", err)
	}
	return key, nil
}

// IssuerCertificates returns the certificates of the x5c header parameter of
// the Issuer-signed JWT, leaf first (RFC 7515 §4.1.6). It returns none when
// the header has no x5c. The chain is not validated. The caller decides
// whether it trusts the chain before it passes the key of the leaf to Verify.
func (t *Token) IssuerCertificates() ([]*x509.Certificate, error) {
	return certchain.FromX5C(t.Header["x5c"])
}

// KeyBinding holds what the verifier expects of a Key Binding JWT.
type KeyBinding struct {
	// Audience is the expected aud claim. It is required. An empty value
	// matches no Key Binding JWT.
	Audience string
	// Nonce is the nonce of the verifier's request. It is required. An empty
	// value matches no Key Binding JWT.
	Nonce string
	// Now is the verification time. The zero value means the current time.
	Now time.Time
	// MaxAge is the maximum age of the Key Binding JWT, measured from its iat
	// claim. A clock skew of 1 minute is added on both sides. With the zero
	// value, only a Key Binding JWT created within that skew passes.
	MaxAge time.Duration
}

// VerifyKeyBinding checks the Key Binding JWT of a presentation as RFC 9901
// §7.3 step 5 requires:
//
//   - a to c: the signature with the cnf key of the credential
//   - d: the typ kb+jwt
//   - e: iat within expected.MaxAge of expected.Now
//   - f: nonce and aud
//   - g: sd_hash
//   - h: exp and nbf when the Key Binding JWT has them
//
// Call it after Verify succeeded. The cnf key comes from the credential, and
// only the issuer signature makes it authentic.
func VerifyKeyBinding(token *Token, expected KeyBinding) error {
	kb := token.KeyBindingJWT
	if kb == nil {
		return errors.New("the presentation has no Key Binding JWT")
	}
	key, err := token.ConfirmationKey()
	if err != nil {
		return fmt.Errorf("the credential has %w", err)
	}
	if err := verifySignature(&Token{Raw: kb.Raw, Header: kb.Header}, key); err != nil {
		return fmt.Errorf("Key Binding JWT: %w", err)
	}
	if typ, _ := kb.Header["typ"].(string); !format.JOSETypeIs(typ, TypeKeyBinding) {
		return fmt.Errorf("Key Binding JWT: typ is %q, expected %q", typ, TypeKeyBinding)
	}
	now := expected.Now
	if now.IsZero() {
		now = time.Now()
	}
	iat, err := numericDate(kb.Payload, "iat")
	if err != nil {
		return fmt.Errorf("Key Binding JWT: %w", err)
	}
	if iat == nil {
		return errors.New("Key Binding JWT: iat is missing")
	}
	if validity.NotYet(iat, now) {
		return fmt.Errorf("Key Binding JWT: iat %s is in the future", iat.UTC().Format(time.RFC3339))
	}
	if oldest := iat.Add(expected.MaxAge); validity.Expired(&oldest, now) {
		return fmt.Errorf("Key Binding JWT: iat %s is older than %s", iat.UTC().Format(time.RFC3339), expected.MaxAge)
	}
	if aud, _ := kb.Payload["aud"].(string); aud == "" || aud != expected.Audience {
		return fmt.Errorf("Key Binding JWT: %w: got %q, expected %q", ErrAudience, aud, expected.Audience)
	}
	if nonce, _ := kb.Payload["nonce"].(string); nonce == "" || nonce != expected.Nonce {
		return fmt.Errorf("Key Binding JWT: %w: got %q, expected %q", ErrNonce, nonce, expected.Nonce)
	}
	// sd_hash covers the presentation up to and including the tilde before the
	// KB-JWT (RFC 9901 §4.3.1).
	want, err := SDHash(token.Raw[:strings.LastIndex(token.Raw, "~")+1], token.SDAlg())
	if err != nil {
		return err
	}
	if got, _ := kb.Payload["sd_hash"].(string); got != want {
		return fmt.Errorf("Key Binding JWT: %w the presentation", ErrSDHash)
	}
	if err := validAt(kb.Payload, now); err != nil {
		return fmt.Errorf("Key Binding JWT: %w", err)
	}
	return nil
}

func validAt(claims map[string]any, now time.Time) error {
	exp, err := numericDate(claims, "exp")
	if err != nil {
		return err
	}
	nbf, err := numericDate(claims, "nbf")
	if err != nil {
		return err
	}
	if _, err := numericDate(claims, "iat"); err != nil {
		return err
	}
	if validity.Expired(exp, now) {
		return fmt.Errorf("%w at %s", ErrExpired, exp.UTC().Format(time.RFC3339))
	}
	if validity.NotYet(nbf, now) {
		return fmt.Errorf("%w %s", ErrNotYetValid, nbf.UTC().Format(time.RFC3339))
	}
	return nil
}

// maxNumericDate is 9999-12-31T23:59:59Z. time.Time formats no later year.
const maxNumericDate = 253402300799

// numericDate reads a time claim. It returns nil for an absent claim. RFC 7519
// §2 makes a NumericDate a JSON number of seconds since the epoch.
func numericDate(claims map[string]any, name string) (*time.Time, error) {
	value, present := claims[name]
	if !present {
		return nil, nil
	}
	seconds, ok := value.(float64)
	if !ok || math.IsNaN(seconds) || seconds < 0 || seconds > maxNumericDate {
		return nil, fmt.Errorf("%s is not a NumericDate", name)
	}
	t := time.Unix(int64(seconds), 0)
	return &t, nil
}

func signedJWT(token *Token) string {
	return strings.SplitN(token.Raw, "~", 2)[0]
}

func verifySignature(token *Token, key crypto.PublicKey) error {
	alg := jsonutil.GetString(token.Header, "alg")
	if !isSupportedAlgorithm(alg) {
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
	if _, err := jws.Verify(signedJWT(token), key); err != nil {
		if errors.Is(err, josev4.ErrCryptoFailure) {
			return ErrSignature
		}
		// A missing key or an unreadable JWS is not ErrSignature. The error
		// keeps the text of ErrSignature, which the validate report shows.
		return errors.New(ErrSignature.Error())
	}
	return nil
}

func isSupportedAlgorithm(alg string) bool {
	for _, supported := range jws.SupportedAlgorithms {
		if string(supported) == alg {
			return true
		}
	}
	return false
}
