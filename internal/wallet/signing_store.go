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

package wallet

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

	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/storage"
)

type signingStore struct {
	backend storage.Store
	prefix  string
	seed    mock.Seed
}

func (s *signingStore) profileCertificates(leaf, root *x509.Certificate) ([]string, error) {
	blobs, err := s.backend.ReadAll(path.Join(s.prefix, "certificates"))
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(blobs))
	for key := range blobs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	certificates := make([]*x509.Certificate, 0, len(keys)+1)
	for _, key := range keys {
		cert, err := parsePEMCertificate(blobs[key].Data, "signing")
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
		for _, parent := range certificates {
			if parent.IsCA && cert.CheckSignatureFrom(parent) == nil {
				published = append(published, base64.StdEncoding.EncodeToString(parent.Raw))
				break
			}
		}
	}
	return published, nil
}

func (s *signingStore) key(role string) (*ecdsa.PrivateKey, error) {
	at := path.Join(s.prefix, "signing-keys", role+".pem")
	data, err := s.backend.Read(at)
	if err == nil {
		return parsePEMKey(data, role)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	key, err := s.seed.Key(role)
	if err != nil {
		return nil, err
	}
	if _, err := s.backend.WriteIf(at, keyPEM(key), 0600, ""); err != nil {
		if !errors.Is(err, storage.ErrConflict) {
			return nil, err
		}
		data, err := s.backend.Read(at)
		if err != nil {
			return nil, err
		}
		return parsePEMKey(data, role)
	}
	return key, nil
}

func (s *signingStore) providerCA(rootKey *ecdsa.PrivateKey, root *x509.Certificate, issuer, role, country string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	if root.MaxPathLenZero {
		return rootKey, root, nil
	}
	if country == "" {
		country = mock.DefaultCertificateCountry
	}
	key, err := s.key(role + "-ca-" + country)
	if err != nil {
		return nil, nil, err
	}
	cert, err := s.certificate(rootKey, root, &key.PublicKey, mock.LeafCertOptions{
		CommonName:            "EUDI Dev Test " + role + " CA " + country,
		Country:               country,
		CertificateAuthority:  true,
		IssuingCertificateURL: issuingCertificateURLs(issuer),
		CRLDistributionPoints: crlDistributionPoints(issuer),
	}, false)
	return key, cert, err
}

func (w *Wallet) signingStore() *signingStore {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.signers == nil {
		w.signers = &signingStore{backend: storage.NewMemory()}
	}
	return w.signers
}

func (s *signingStore) certificate(caKey *ecdsa.PrivateKey, ca *x509.Certificate, pub *ecdsa.PublicKey, opts mock.LeafCertOptions, renew bool) (*x509.Certificate, error) {
	publicKey, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	options, err := json.Marshal(opts)
	if err != nil {
		return nil, err
	}
	identity := sha256.New()
	identity.Write(ca.Raw)
	identity.Write(publicKey)
	identity.Write(options)
	key := path.Join(s.prefix, "certificates", fmt.Sprintf("%x.pem", identity.Sum(nil)))
	for range 5 {
		blobs, err := s.backend.ReadAll(path.Dir(key))
		if err != nil {
			return nil, fmt.Errorf("reading signing certificate: %w", err)
		}
		blob, exists := blobs[key]
		if exists {
			block, _ := pem.Decode(blob.Data)
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
			if !renew && time.Now().Add(signingCertificateRenewBefore).Before(cert.NotAfter) {
				return s.retainCertificate(cert)
			}
		}
		cert, err := mock.GenerateLeafCertWithOptions(caKey, ca, pub, opts)
		if err != nil {
			return nil, err
		}
		data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if _, err := s.backend.WriteIf(key, data, 0644, blob.Stamp.Version); err != nil {
			if errors.Is(err, storage.ErrConflict) {
				renew = false
				continue
			}
			return nil, fmt.Errorf("saving signing certificate: %w", err)
		}
		return s.retainCertificate(cert)
	}
	return nil, fmt.Errorf("signing certificate changed concurrently too often")
}

func (s *signingStore) retainCertificate(cert *x509.Certificate) (*x509.Certificate, error) {
	digest := sha256.Sum256(cert.Raw)
	key := path.Join(s.prefix, "certificate-der", fmt.Sprintf("%x.der", digest))
	if _, exists := s.backend.Stat(key); !exists {
		if _, err := s.backend.WriteIf(key, cert.Raw, 0644, ""); err != nil && !errors.Is(err, storage.ErrConflict) {
			return nil, fmt.Errorf("publishing signing certificate: %w", err)
		}
	}
	return cert, nil
}
