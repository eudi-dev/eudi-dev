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

package mdoc

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/veraison/go-cose"

	"github.com/eudi-dev/eudi-dev/v3/internal/cborview"
	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/coseutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/validity"
)

// Match these errors with errors.Is.
var (
	// ErrSignature reports a signature that does not verify with the key.
	ErrSignature = errors.New("signature verification failed")
	// ErrExpired reports a verification time after validUntil.
	ErrExpired = errors.New("expired")
	// ErrNotYetValid reports a verification time before validFrom.
	ErrNotYetValid = errors.New("not valid before")
	// ErrNoDeviceKey reports an MSO without a device key. Such a credential is
	// not bound to a holder.
	ErrNoDeviceKey = errors.New("no device key")
)

// Verify checks the issuerAuth signature over the MSO with key. The caller
// decides whether to trust that key. ValidAt checks the validity period.
// VerifyValueDigests checks the data elements.
func Verify(doc *Document, key crypto.PublicKey) error {
	msg, alg, err := issuerAuthMessage(doc)
	if err != nil {
		return err
	}
	verifier, err := coseutil.NewVerifier(alg, key)
	if err != nil {
		return fmt.Errorf("creating verifier: %w", err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return signatureError("", err)
	}
	return nil
}

// signatureError reports a failed COSE_Sign1 verification. Only a signature
// that does not verify is ErrSignature. Every error starts with the text of
// ErrSignature, which the validate report shows.
func signatureError(context string, err error) error {
	if errors.Is(err, cose.ErrVerification) || errors.Is(err, cose.ErrEmptySignature) {
		return fmt.Errorf("%w: %s%w", ErrSignature, context, err)
	}
	return fmt.Errorf("%s: %s%w", ErrSignature.Error(), context, err)
}

// SignatureAlgorithm returns the COSE algorithm of the issuerAuth signature,
// for example ES256.
func (d *Document) SignatureAlgorithm() (string, error) {
	_, alg, err := issuerAuthMessage(d)
	if err != nil {
		return "", err
	}
	return coseutil.AlgorithmName(alg), nil
}

func issuerAuthMessage(doc *Document) (*cose.Sign1Message, cose.Algorithm, error) {
	if doc == nil {
		return nil, 0, errors.New("no document to verify")
	}
	if doc.IssuerAuth == nil {
		return nil, 0, errors.New("no issuerAuth found")
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(doc.IssuerAuth.RawCOSE); err != nil {
		return nil, 0, fmt.Errorf("parsing COSE_Sign1: %w", err)
	}
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		return nil, 0, errors.New("cannot determine COSE algorithm from protected header")
	}
	return &msg, alg, nil
}

// ValidAt checks validFrom and validUntil of the MSO against now. It allows a
// clock skew of 1 minute. ISO/IEC 18013-5 §9.1.2.4 requires both dates, so a
// missing or unreadable one is an error.
func (d *Document) ValidAt(now time.Time) error {
	if d == nil || d.IssuerAuth == nil || d.IssuerAuth.MSO == nil || d.IssuerAuth.MSO.ValidityInfo == nil {
		return errors.New("the MSO has no validityInfo")
	}
	info := d.IssuerAuth.MSO.ValidityInfo
	if info.ValidFrom == nil {
		return errors.New("validityInfo has no readable validFrom")
	}
	if info.ValidUntil == nil {
		return errors.New("validityInfo has no readable validUntil")
	}
	if validity.Expired(info.ValidUntil, now) {
		return fmt.Errorf("%w at %s", ErrExpired, info.ValidUntil.UTC().Format(time.RFC3339))
	}
	if validity.NotYet(info.ValidFrom, now) {
		return fmt.Errorf("%w %s", ErrNotYetValid, info.ValidFrom.UTC().Format(time.RFC3339))
	}
	return nil
}

// IssuerCertificates returns the certificates of the x5chain header parameter
// of issuerAuth, leaf first (RFC 9360 §2). It returns none when the document
// has no issuerAuth or issuerAuth has no x5chain. The chain is not validated.
// The caller decides whether it trusts the chain before it passes the key of
// the leaf to Verify.
func (d *Document) IssuerCertificates() ([]*x509.Certificate, error) {
	if d == nil || d.IssuerAuth == nil {
		return nil, nil
	}
	return certchain.FromCOSE(cborview.Sign1Headers(d.IssuerAuth.RawCOSE))
}
