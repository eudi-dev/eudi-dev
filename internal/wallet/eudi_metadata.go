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
	"encoding/hex"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
)

func (w *Wallet) issuedAttestationSpecs() []provider.IssuedAttestationSpec {
	if w == nil {
		return nil
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if len(w.IssuedAttestations) > 0 {
		return provider.DedupeIssuedAttestations(w.IssuedAttestations)
	}

	seen := make(map[string]bool)
	out := make([]provider.IssuedAttestationSpec, 0)
	for _, cred := range w.Credentials {
		spec := provider.IssuedAttestationSpec{Format: cred.Format, VCT: cred.VCT, DocType: cred.DocType}
		switch cred.Format {
		case credtype.FormatSDJWT:
			if strings.TrimSpace(spec.VCT) == "" {
				continue
			}
		case credtype.FormatMDOC:
			if strings.TrimSpace(spec.DocType) == "" {
				continue
			}
		default:
			continue
		}
		key := spec.Format + "|" + spec.VCT + "|" + spec.DocType
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, spec)
	}
	return out
}

// sanitizeMetadataID turns a credential type into a configuration id of at
// most 50 characters. A URN such as urn:eudi:pid:1 maps its ':' to '_'. Any
// other type could share that readable form with another type, so it gets a
// hash suffix and each type keeps its own configuration.
func sanitizeMetadataID(s string) string {
	readable := strings.NewReplacer(":", "_", ".", "_", "/", "_").Replace(s)
	trimmed := strings.TrimLeft(readable, "_")
	if trimmed != "" && trimmed == readable && !strings.ContainsAny(s, "_./") && len(trimmed) <= 50 {
		return trimmed
	}
	if trimmed == "" {
		trimmed = "credential"
	}
	sum := sha256.Sum256([]byte(s))
	return trimmed[:min(len(trimmed), 41)] + "_" + hex.EncodeToString(sum[:4])
}

func buildCredentialConfiguration(spec provider.IssuedAttestationSpec) (string, map[string]any, bool) {
	switch spec.Format {
	case credtype.FormatSDJWT:
		if strings.TrimSpace(spec.VCT) == "" {
			return "", nil, false
		}
		id := "sdjwt_" + sanitizeMetadataID(spec.VCT)
		return id, map[string]any{
			"format": credtype.FormatSDJWT,
			"scope":  id,
			"vct":    spec.VCT,
			"cryptographic_binding_methods_supported": []string{"jwk"},
			"credential_signing_alg_values_supported": []string{jws.AlgES256},
			"proof_types_supported": map[string]any{
				"jwt": map[string]any{
					"proof_signing_alg_values_supported": []string{jws.AlgES256},
				},
			},
		}, true
	case credtype.FormatMDOC:
		if strings.TrimSpace(spec.DocType) == "" {
			return "", nil, false
		}
		id := "mdoc_" + sanitizeMetadataID(spec.DocType)
		return id, map[string]any{
			"format":  credtype.FormatMDOC,
			"scope":   id,
			"doctype": spec.DocType,
			"cryptographic_binding_methods_supported": []string{"cose_key"},
			"credential_signing_alg_values_supported": []int{-7},
			"proof_types_supported": map[string]any{
				"jwt": map[string]any{
					"proof_signing_alg_values_supported": []string{jws.AlgES256},
				},
			},
		}, true
	default:
		return "", nil, false
	}
}

func buildOpenIDCredentialIssuerMetadata(w *Wallet, issuer string) (map[string]any, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	configs := make(map[string]any)
	for _, spec := range w.issuedAttestationSpecs() {
		id, cfg, ok := buildCredentialConfiguration(spec)
		if !ok {
			continue
		}
		configs[id] = cfg
	}

	metadata := map[string]any{
		"credential_issuer":                   issuer,
		"credential_endpoint":                 issuer + "/credential",
		"credential_configurations_supported": configs,
	}
	// Without a registration the metadata has no issuer_info, and a wallet
	// with --arf reports that (ETSI TS 119 472-3 §4.2.3).
	info, err := w.DemoIssuerInfo()
	if err != nil {
		return nil, err
	}
	if info != nil {
		metadata["issuer_info"] = info
	}
	return metadata, nil
}

func signJSONWebSignature(payload any, signingKey *ecdsa.PrivateKey, header map[string]any) (string, error) {
	if signingKey == nil {
		return "", fmt.Errorf("signing key is required")
	}
	return jws.Sign(header, payload, signingKey)
}

func signCredentialIssuerMetadataJWT(w *Wallet, issuer string, exp time.Time) (string, error) {
	metadata, err := buildOpenIDCredentialIssuerMetadata(w, issuer)
	if err != nil {
		return "", err
	}
	signingKey, signerCerts, err := w.AccessSigningMaterial()
	if err != nil {
		return "", err
	}
	return SignCredentialIssuerMetadata(signingKey, signerCerts, issuer, metadata, exp)
}

// SignCredentialIssuerMetadata signs the metadata with an access certificate,
// as TS 119 472-3 V1.1.1 §4.2.2 requires. The chain goes into x5c.
func SignCredentialIssuerMetadata(signingKey *ecdsa.PrivateKey, signerCerts []*x509.Certificate, issuer string, metadata map[string]any, exp time.Time) (string, error) {
	payload := maps.Clone(metadata)
	payload["iss"] = issuer
	payload["sub"] = issuer
	payload["iat"] = time.Now().Unix()
	if !exp.IsZero() {
		payload["exp"] = exp.Unix()
	}
	header := map[string]any{
		"alg": jws.AlgES256,
		"typ": "openidvci-issuer-metadata+jwt",
	}
	if x5c := certchain.X5C(signerCerts); len(x5c) > 0 {
		header["x5c"] = x5c
	}
	return signJSONWebSignature(payload, signingKey, header)
}
