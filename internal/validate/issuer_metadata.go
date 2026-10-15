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

package validate

import (
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/issuermetadata"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

func CanResolveJWTIssuerMetadata(token *sdjwt.Token) bool {
	if token == nil {
		return false
	}
	// SD-JWT VC §4 only defines this mechanism for an iss that is "a
	// case-sensitive URL using the HTTPS scheme that contains scheme, host
	// and, optionally, port number and path components, but no query or
	// fragment components".
	if _, err := issuermetadata.URL(jsonutil.GetString(token.Payload, "iss")); err != nil {
		return false
	}
	alg, _ := token.Header["alg"].(string)
	if strings.EqualFold(strings.TrimSpace(alg), "none") {
		return false
	}
	return len(token.Signature) > 0
}

// ResolveJWTIssuerMetadataKeys returns the candidate signing keys from the
// JWT VC Issuer Metadata of the token's iss.
func ResolveJWTIssuerMetadataKeys(token *sdjwt.Token, tlCerts []lote.CertInfo, clients ...*http.Client) ([]crypto.PublicKey, string, error) {
	if !CanResolveJWTIssuerMetadata(token) {
		return nil, "", nil
	}

	iss := jsonutil.GetString(token.Payload, "iss")
	kid, _ := token.Header["kid"].(string)
	jwks, err := issuermetadata.JWKs(iss, kid, clients...)
	if err != nil {
		return nil, "", err
	}

	// With trust anchors, a metadata key counts only when its x5c chains to
	// them. A bare key from the issuer's host is not anchored.
	var keys []crypto.PublicKey
	if len(tlCerts) > 0 {
		var chainErr error
		for _, jwk := range jwks {
			key, err := extractAndValidateJWKX5C(jwk, tlCerts)
			switch {
			case err != nil:
				chainErr = fmt.Errorf("the issuer metadata key does not chain to the trusted list: %w", err)
			case key == nil:
				chainErr = fmt.Errorf("the issuer metadata key has no x5c to chain to the trusted list")
			default:
				keys = append(keys, key)
			}
		}
		if len(keys) == 0 {
			return nil, "", chainErr
		}
		return keys, "issuer metadata (x5c chain verified)", nil
	}

	var parseErr error
	for _, jwk := range jwks {
		key, err := jwkPublicKey(jwk)
		if err != nil {
			parseErr = err
			continue
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 && parseErr != nil {
		return nil, "", parseErr
	}
	return keys, "issuer metadata", nil
}

func jwkPublicKey(jwk map[string]any) (crypto.PublicKey, error) {
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		return nil, fmt.Errorf("encoding issuer JWK: %w", err)
	}
	key, err := keys.ParsePublicKey(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing issuer JWK: %w", err)
	}
	return key, nil
}

// verifyWithIssuerMetadata verifies the token with the first metadata key
// that matches its signature.
func verifyWithIssuerMetadata(token *sdjwt.Token, tlCerts []lote.CertInfo, clients ...*http.Client) (*sdjwt.VerifyResult, string, error) {
	keys, source, err := ResolveJWTIssuerMetadataKeys(token, tlCerts, clients...)
	if err != nil || len(keys) == 0 {
		return nil, "", err
	}
	var result *sdjwt.VerifyResult
	for _, key := range keys {
		if result = sdjwt.Verify(token, key); result.SignatureValid {
			break
		}
	}
	return result, source, nil
}

// IssuerMetadataError is a failed lookup of the issuer's key in its JWT VC
// Issuer Metadata (SD-JWT VC §4).
type IssuerMetadataError struct{ Err error }

func (e *IssuerMetadataError) Error() string { return e.Err.Error() }
func (e *IssuerMetadataError) Unwrap() error { return e.Err }

// Sources of a verified signature.
const (
	// SourceX5CChain is the leaf of a chain that ends in a trust anchor.
	SourceX5CChain = "x5c chain"
	// SourceProvidedKey is a key supplied by the caller.
	SourceProvidedKey = "provided key"
	// SourceX5CLeaf is the embedded leaf of an unvalidated chain. It proves
	// integrity only. Issuer trust needs a trust list to validate the chain.
	SourceX5CLeaf = "x5c certificate, chain not validated"
)

// VerifyJWTSignature verifies the token signature. It tries in order x5c with
// the trust list, the given keys, and without given keys the embedded x5c leaf
// (only without a trust list) and the issuer metadata. Given keys are the
// whole trust, so a key that fails is not replaced by a metadata key. The leaf
// step keeps validation offline for credentials that carry their issuer
// certificate.
func VerifyJWTSignature(token *sdjwt.Token, pubKeys []crypto.PublicKey, tlCerts []lote.CertInfo, clients ...*http.Client) (*sdjwt.VerifyResult, string, error) {
	return verifyJWTSignature(token, pubKeys, tlCerts, true, clients...)
}

// VerifyJWTSignatureOffline uses only supplied keys and certificates. This path must
// complete without network access.
func VerifyJWTSignatureOffline(token *sdjwt.Token, pubKeys []crypto.PublicKey, tlCerts []lote.CertInfo) (*sdjwt.VerifyResult, string, error) {
	return verifyJWTSignature(token, pubKeys, tlCerts, false)
}

func verifyJWTSignature(token *sdjwt.Token, pubKeys []crypto.PublicKey, tlCerts []lote.CertInfo, resolveIssuerMetadata bool, clients ...*http.Client) (*sdjwt.VerifyResult, string, error) {
	if token == nil {
		return nil, "", fmt.Errorf("token is nil")
	}

	x5cKey, chainErr := ExtractAndValidateX5C(token.Header, tlCerts)
	if x5cKey != nil {
		return sdjwt.Verify(token, x5cKey), SourceX5CChain, nil
	}

	var best *sdjwt.VerifyResult
	bestSource := SourceProvidedKey
	for _, key := range pubKeys {
		result := sdjwt.Verify(token, key)
		best = result
		if result.SignatureValid {
			return result, SourceProvidedKey, nil
		}
	}

	// Without supplied trust the embedded leaf still proves the signature is
	// intact. A metadata lookup fails whenever the issuer is unreachable.
	if len(pubKeys) == 0 && len(tlCerts) == 0 {
		leafKey, err := ExtractX5CLeafKey(token.Header)
		if err != nil {
			return nil, "", err
		}
		if leafKey != nil {
			result := sdjwt.Verify(token, leafKey)
			if result.SignatureValid {
				return result, SourceX5CLeaf, nil
			}
			best, bestSource = result, SourceX5CLeaf
		}
	}

	if best != nil {
		if chainErr != nil {
			best.Errors = append(best.Errors, chainErr.Error())
		}
		if resolveIssuerMetadata && len(pubKeys) == 0 {
			result, source, err := verifyWithIssuerMetadata(token, tlCerts, clients...)
			switch {
			case err != nil:
				best.Errors = append(best.Errors, err.Error())
			case result != nil && result.SignatureValid:
				return result, source, nil
			}
		}
		return best, bestSource, nil
	}
	if chainErr != nil {
		return nil, "", chainErr
	}

	if !resolveIssuerMetadata {
		return nil, "", nil
	}

	result, source, err := verifyWithIssuerMetadata(token, tlCerts, clients...)
	if err != nil {
		return nil, "", &IssuerMetadataError{Err: err}
	}
	return result, source, nil
}

func extractAndValidateJWKX5C(jwk map[string]any, tlCerts []lote.CertInfo) (crypto.PublicKey, error) {
	if len(tlCerts) == 0 {
		return nil, nil
	}
	certs, err := certchain.FromX5C(jwk["x5c"])
	if err != nil {
		return nil, fmt.Errorf("reading the jwk x5c: %w", err)
	}
	if len(certs) == 0 {
		return nil, nil
	}
	return ValidateCertChain(certs, tlCerts)
}
