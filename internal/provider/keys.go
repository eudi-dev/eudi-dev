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

package provider

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
)

// RenewBefore is how long before expiry a long running wallet renews a
// signing certificate.
const RenewBefore = 30 * 24 * time.Hour

// Keys stores the signing keys, CAs and certificates of the providers under
// a key prefix of a storage backend. A seed derives each key from its name
// (ADR-0017).
type Keys struct {
	backend storage.Store
	prefix  string
	seed    mock.Seed
}

func NewKeys(backend storage.Store, prefix string, seed mock.Seed) *Keys {
	return &Keys{backend: backend, prefix: prefix, seed: seed}
}

// ListedCertificates returns the base64 DER certificates listed for a signer
// in a trusted list: every stored current certificate of the leaf's subject
// and key, each with its issuing CA below root.
func (s *Keys) ListedCertificates(leaf, root *x509.Certificate) ([]string, error) {
	blobs, err := s.backend.ReadAll(path.Join(s.prefix, "certificates"))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(blobs))
	for key := range blobs {
		names = append(names, key)
	}
	sort.Strings(names)
	certificates := make([]*x509.Certificate, 0, len(names)+1)
	for _, key := range names {
		cert, err := keys.ParseCertificatePEM(blobs[key].Data, "signing")
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, cert)
	}
	certificates = append(certificates, root)
	var published []string
	for _, cert := range certificates {
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || cert.IsCA || cert.Subject.CommonName != leaf.Subject.CommonName || !pub.Equal(leaf.PublicKey) || !time.Now().Before(cert.NotAfter) {
			continue
		}
		published = append(published, base64.StdEncoding.EncodeToString(cert.Raw))
		// The root anchors every role. A root with path length zero signs the
		// leaves directly, so the list then holds only the leaves.
		for _, parent := range certificates {
			if parent.IsCA && !parent.Equal(root) && cert.CheckSignatureFrom(parent) == nil {
				published = append(published, base64.StdEncoding.EncodeToString(parent.Raw))
				break
			}
		}
	}
	return published, nil
}

// Key loads the named key, or creates and stores it.
func (s *Keys) Key(name string) (*ecdsa.PrivateKey, error) {
	at := path.Join(s.prefix, "signing-keys", name+".pem")
	data, err := s.backend.Read(at)
	if err == nil {
		return keys.ParseECKeyPEM(data, name)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	key, err := s.seed.Key(name)
	if err != nil {
		return nil, err
	}
	if _, err := s.backend.WriteIf(at, keys.ECKeyPEM(key), 0600, ""); err != nil {
		if !errors.Is(err, storage.ErrConflict) {
			return nil, err
		}
		data, err := s.backend.Read(at)
		if err != nil {
			return nil, err
		}
		return keys.ParseECKeyPEM(data, name)
	}
	return key, nil
}

// hasProviderCA reports whether the provider CA of the role and country
// exists. It returns an error that wraps fs.ErrNotExist when it doesn't.
func (s *Keys) hasProviderCA(role, country string) error {
	role, err := s.caRole(role, country)
	if err != nil {
		return err
	}
	_, err = s.backend.Stat(s.caKeyPath(role, country))
	return err
}

func (s *Keys) caKeyPath(role, country string) string {
	return path.Join(s.prefix, "signing-keys", caKeyName(role, country)+".pem")
}

func caKeyName(role, country string) string {
	return role + "-ca-" + country
}

// legacyEAARole is the provider CA of the EAA list of an eudi-dev 2 wallet.
const legacyEAARole = "local"

// caRole returns the role of the CA that signs for the role in the country.
// The EAA list keeps the CA of an eudi-dev 2 wallet, so EAAs issued by that
// wallet stay anchored.
func (s *Keys) caRole(role, country string) (string, error) {
	if role != credtemplate.CategoryEAA {
		return role, nil
	}
	for _, candidate := range []string{credtemplate.CategoryEAA, legacyEAARole} {
		_, err := s.backend.Stat(s.caKeyPath(candidate, country))
		if err == nil {
			return candidate, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	return role, nil
}

// storedCA returns the stored CA certificate of key under root with the
// latest expiry, or nil when none is valid beyond RenewBefore.
func (s *Keys) storedCA(key *ecdsa.PrivateKey, root *x509.Certificate) (*x509.Certificate, error) {
	blobs, err := s.backend.ReadAll(path.Join(s.prefix, "certificates"))
	if err != nil {
		return nil, err
	}
	var found *x509.Certificate
	for _, blob := range blobs {
		cert, err := keys.ParseCertificatePEM(blob.Data, "signing")
		if err != nil {
			return nil, err
		}
		if !cert.IsCA || !key.PublicKey.Equal(cert.PublicKey) || cert.CheckSignatureFrom(root) != nil || !time.Now().Add(RenewBefore).Before(cert.NotAfter) {
			continue
		}
		if found == nil || cert.NotAfter.After(found.NotAfter) {
			found = cert
		}
	}
	return found, nil
}

// ProviderCA returns the CA under root that issues the signing certificates
// of the role in the country. A root with path length zero issues them
// itself.
func (s *Keys) ProviderCA(rootKey *ecdsa.PrivateKey, root *x509.Certificate, origin Root, role, country string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	if root.MaxPathLenZero {
		return rootKey, root, nil
	}
	if country == "" {
		country = mock.DefaultCertificateCountry
	}
	role, err := s.caRole(role, country)
	if err != nil {
		return nil, nil, err
	}
	key, err := s.Key(caKeyName(role, country))
	if err != nil {
		return nil, nil, err
	}
	if role == legacyEAARole {
		// The issuer name of an eudi-dev 2 EAA is the subject of the CA
		// certificate stored by eudi-dev 2. RFC 5280 §6.1.3 chains by name, so
		// the wallet keeps that certificate until it is due for renewal.
		if cert, err := s.storedCA(key, root); err != nil || cert != nil {
			return key, cert, err
		}
	}
	cert, err := s.Certificate(rootKey, root, &key.PublicKey, mock.LeafCertOptions{
		CommonName:            "EUDI Dev Test " + role + " CA " + country,
		Country:               country,
		CertificateAuthority:  true,
		IssuingCertificateURL: issuingCertificateURLs(origin.IssuerURL),
		CRLDistributionPoints: origin.CRLDistributionPoints(RootCRLPath),
	}, false)
	return key, cert, err
}

// selfSignedCA loads or creates a self-signed CA with its own key. The
// certificate is stored, so it stays the same across restarts.
func (s *Keys) selfSignedCA(role, commonName string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := s.Key(role)
	if err != nil {
		return nil, nil, err
	}
	at := path.Join(s.prefix, "authorities", role+".pem")
	for range 2 {
		data, err := s.backend.Read(at)
		if err == nil {
			cert, err := keys.ParseCertificatePEM(data, role)
			return key, cert, err
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, err
		}
		cert, err := mock.GenerateNamedCACert(key, commonName)
		if err != nil {
			return nil, nil, err
		}
		if _, err := s.backend.WriteIf(at, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600, ""); err == nil {
			return key, cert, nil
		} else if !errors.Is(err, storage.ErrConflict) {
			return nil, nil, err
		}
	}
	return nil, nil, fmt.Errorf("storing the %s certificate failed after repeated conflicts", role)
}

// Certificate returns the stored certificate for pub under ca with the
// options, or issues and stores one.
func (s *Keys) Certificate(caKey *ecdsa.PrivateKey, ca *x509.Certificate, pub *ecdsa.PublicKey, opts mock.LeafCertOptions, renew bool) (*x509.Certificate, error) {
	options, err := json.Marshal(opts)
	if err != nil {
		return nil, err
	}
	return s.CachedCertificate(options, ca, pub, renew, func() (*x509.Certificate, error) {
		return mock.GenerateLeafCertWithOptions(caKey, ca, pub, opts)
	})
}

// CachedCertificate stores the certificate created by issue for pub under ca.
// identity describes the subject and is part of the cache key. A new
// certificate is issued before the stored one expires or when renew is set.
func (s *Keys) CachedCertificate(identity []byte, ca *x509.Certificate, pub *ecdsa.PublicKey, renew bool, issue func() (*x509.Certificate, error)) (*x509.Certificate, error) {
	publicKey, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	digest := sha256.New()
	digest.Write(ca.Raw)
	digest.Write(publicKey)
	digest.Write(identity)
	key := path.Join(s.prefix, "certificates", fmt.Sprintf("%x.pem", digest.Sum(nil)))
	for range 5 {
		data, version, exists, err := readVersioned(s.backend, key)
		if err != nil {
			return nil, fmt.Errorf("reading signing certificate: %w", err)
		}
		if exists {
			block, _ := pem.Decode(data)
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("invalid signing certificate at %s", key)
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing signing certificate: %w", err)
			}
			if err := cert.CheckSignatureFrom(ca); err != nil || !pub.Equal(cert.PublicKey) {
				return nil, fmt.Errorf("signing certificate does not match its key or CA")
			}
			if !renew && time.Now().Add(RenewBefore).Before(cert.NotAfter) {
				return s.retainCertificate(cert)
			}
		}
		cert, err := issue()
		if err != nil {
			return nil, err
		}
		data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if _, err := s.backend.WriteIf(key, data, 0644, version); err != nil {
			if errors.Is(err, storage.ErrConflict) {
				renew = false
				continue
			}
			return nil, fmt.Errorf("saving signing certificate: %w", err)
		}
		return s.retainCertificate(cert)
	}
	return nil, fmt.Errorf("storing the signing certificate failed after repeated conflicts")
}

// readVersioned reads one blob and its version for WriteIf. The version is
// read first, so a write in between fails the WriteIf and the caller tries
// again.
func readVersioned(backend storage.Store, key string) (data []byte, version string, exists bool, err error) {
	stamp, err := backend.Stat(key)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	data, err = backend.Read(key)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	return data, stamp.Version, true, nil
}

func (s *Keys) retainCertificate(cert *x509.Certificate) (*x509.Certificate, error) {
	digest := sha256.Sum256(cert.Raw)
	key := s.retainedCertificateKey(fmt.Sprintf("%x", digest))
	exists, err := s.backend.Exists(key)
	if err == nil && !exists {
		if _, err = s.backend.WriteIf(key, cert.Raw, 0644, ""); errors.Is(err, storage.ErrConflict) {
			err = nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("publishing signing certificate: %w", err)
	}
	return cert, nil
}

func (s *Keys) retainedCertificateKey(fingerprint string) string {
	return path.Join(s.prefix, "certificate-der", fingerprint+".der")
}

// RetainedCertificate returns the DER of a certificate issued or loaded by
// Keys, looked up by the hex SHA-256 of its DER.
func (s *Keys) RetainedCertificate(fingerprint string) ([]byte, error) {
	return s.backend.Read(s.retainedCertificateKey(fingerprint))
}
