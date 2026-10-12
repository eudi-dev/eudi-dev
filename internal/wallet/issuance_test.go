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
	"crypto/x509"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/certchain"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jwe"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
	"github.com/dominikschlosser/eudi-dev/v3/internal/regcert"
)

func TestResolveCredentialIdentifier_FromAuthDetails(t *testing.T) {
	tokenResp := map[string]any{
		"access_token": "token123",
		"authorization_details": []any{
			map[string]any{
				"type":                        "openid_credential",
				"credential_configuration_id": "pid-config",
				"credential_identifiers":      []any{"cred-id-abc", "cred-id-def"},
			},
		},
	}

	got, other := resolveCredentialIdentifier(tokenResp, "pid-config")
	if got != "cred-id-abc" || other != "" {
		t.Errorf("expected cred-id-abc, got %s", got)
	}
}

// The identifier comes from the entry for the offered configuration at any
// position in the array.
func TestResolveCredentialIdentifier_PrefersTheOfferedConfiguration(t *testing.T) {
	tokenResp := map[string]any{
		"authorization_details": []any{
			map[string]any{"type": "openid_credential", "credential_configuration_id": "sdjwt-pid", "credential_identifiers": []any{"sdjwt-id"}},
			map[string]any{"type": "openid_credential", "credential_configuration_id": "mdoc-pid", "credential_identifiers": []any{"mdoc-id"}},
		},
	}
	if got, other := resolveCredentialIdentifier(tokenResp, "mdoc-pid"); got != "mdoc-id" || other != "" {
		t.Errorf("got %q (other %q), want mdoc-id", got, other)
	}
}

func TestResolveCredentialIdentifier_ReportsAnotherConfiguration(t *testing.T) {
	tokenResp := map[string]any{
		"authorization_details": []any{
			map[string]any{"type": "openid_credential", "credential_configuration_id": "sdjwt-pid", "credential_identifiers": []any{"sdjwt-id"}},
		},
	}
	if got, other := resolveCredentialIdentifier(tokenResp, "mdoc-pid"); got != "sdjwt-id" || other != "sdjwt-pid" {
		t.Errorf("got %q (other %q), want sdjwt-id authorized for sdjwt-pid", got, other)
	}
}

func TestResolveCredentialIdentifier_FallbackToConfigID(t *testing.T) {
	tokenResp := map[string]any{
		"access_token": "token123",
	}

	got, _ := resolveCredentialIdentifier(tokenResp, "")
	if got != "" {
		t.Errorf("expected empty string, got %s", got)
	}
}

func TestResolveCredentialIdentifier_EmptyAuthDetails(t *testing.T) {
	tokenResp := map[string]any{
		"access_token":          "token123",
		"authorization_details": []any{},
	}

	got, _ := resolveCredentialIdentifier(tokenResp, "")
	if got != "" {
		t.Errorf("expected empty string, got %s", got)
	}
}

func TestResolveCredentialIdentifier_NoConfigIDs(t *testing.T) {
	tokenResp := map[string]any{
		"access_token": "token123",
	}

	got, _ := resolveCredentialIdentifier(tokenResp, "")
	if got != "" {
		t.Errorf("expected empty string, got %s", got)
	}
}

// OpenID4VCI 1.0 §8.3 defines one shape for issued credentials. It is a
// credentials array whose "elements of the array MUST be objects", each with a
// credential member. The wallet reads only this shape, so the batch and binding
// checks see every credential it imports.
func TestCredentialStringsFromResponse_CredentialsArray(t *testing.T) {
	resp := map[string]any{
		"credentials": []any{
			map[string]any{"credential": "first"},
			map[string]any{"credential": "second"},
		},
	}

	got := credentialStringsFromResponse(resp)
	if len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Errorf("credentials = %v, want [first second]", got)
	}
}

func TestCredentialStringsFromResponse_RejectsDraftShapes(t *testing.T) {
	for name, resp := range map[string]map[string]any{
		"a top-level credential string": {"credential": "eyJhbGci..."},
		"an array of raw strings":       {"credentials": []any{"raw-credential-string"}},
		"nothing at all":                {"status": "ok"},
		"an empty credentials array":    {"credentials": []any{}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := credentialStringsFromResponse(resp); len(got) != 0 {
				t.Errorf("credentials = %v, want none", got)
			}
		})
	}
}

func requestEncryptionMetadata(t *testing.T, required bool) (map[string]any, *ecdsa.PrivateKey) {
	t.Helper()
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubJWK := mock.PublicKeyJWKMap(&issuerKey.PublicKey)
	return map[string]any{
		"jwks": map[string]any{
			"keys": []any{map[string]any{
				"kty": pubJWK["kty"],
				"crv": pubJWK["crv"],
				"x":   pubJWK["x"],
				"y":   pubJWK["y"],
				"kid": "issuer-enc-key",
				"use": "enc",
				"alg": "ECDH-ES",
			}},
		},
		"enc_values_supported": []any{"A256GCM", "A128GCM"},
		"encryption_required":  required,
	}, issuerKey
}

func TestBuildCredentialResponseEncryptionRequest(t *testing.T) {
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	requestEncryption, _ := requestEncryptionMetadata(t, false)

	metadata := map[string]any{
		"credential_request_encryption": requestEncryption,
		"credential_response_encryption": map[string]any{
			"alg_values_supported": []any{"ECDH-ES+A256KW", "ECDH-ES"},
			"enc_values_supported": []any{"A256GCM", "A128GCM"},
		},
	}

	got, err := buildCredentialResponseEncryptionRequest(ValidationModeStrict, metadata, holderKey)
	if err != nil {
		t.Fatalf("buildCredentialResponseEncryptionRequest: %v", err)
	}
	if got == nil {
		t.Fatal("expected credential response encryption request")
	}
	if got["enc"] != "A128GCM" {
		t.Fatalf("expected preferred enc A128GCM, got %v", got["enc"])
	}
	jwk, ok := got["jwk"].(map[string]any)
	if !ok {
		t.Fatalf("expected jwk object, got %T", got["jwk"])
	}
	if jwk["alg"] != "ECDH-ES" {
		t.Fatalf("expected preferred alg ECDH-ES, got %v", jwk["alg"])
	}
	if jwk["use"] != "enc" {
		t.Fatalf("expected use=enc, got %v", jwk["use"])
	}
}

// §8.2: "Credential Request encryption MUST be used if the
// credential_response_encryption parameter is included, to prevent it being
// substituted by an attacker." An issuer without a request encryption key gets
// no response encryption request. An issuer that also demands an encrypted
// response cannot be served.
func TestBuildCredentialResponseEncryptionRequest_NeedsRequestEncryption(t *testing.T) {
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	responseEncryption := map[string]any{
		"alg_values_supported": []any{"ECDH-ES"},
		"enc_values_supported": []any{"A128GCM"},
	}

	t.Run("no request encryption offered", func(t *testing.T) {
		got, err := buildCredentialResponseEncryptionRequest(ValidationModeStrict, map[string]any{
			"credential_response_encryption": responseEncryption,
		}, holderKey)
		if err != nil {
			t.Fatalf("buildCredentialResponseEncryptionRequest: %v", err)
		}
		if got != nil {
			t.Fatalf("asked for an encrypted response the request cannot be paired with: %v", got)
		}
	})

	t.Run("an encrypted response is required but the request cannot be encrypted", func(t *testing.T) {
		required := map[string]any{
			"alg_values_supported": []any{"ECDH-ES"},
			"enc_values_supported": []any{"A128GCM"},
			"encryption_required":  true,
		}
		if _, err := buildCredentialResponseEncryptionRequest(ValidationModeStrict, map[string]any{
			"credential_response_encryption": required,
		}, holderKey); err == nil {
			t.Fatal("an issuer that requires response encryption without offering request encryption was accepted")
		}
	})
}

func TestPrepareCredentialRequestBody_EncryptsWhenIssuerAdvertisesRequestEncryption(t *testing.T) {
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubJWK := mock.PublicKeyJWKMap(&issuerKey.PublicKey)
	encJWK := map[string]any{
		"kty": pubJWK["kty"],
		"crv": pubJWK["crv"],
		"x":   pubJWK["x"],
		"y":   pubJWK["y"],
		"kid": "issuer-enc-key",
		"use": "enc",
		"alg": "ECDH-ES",
	}
	metadata := map[string]any{
		"credential_request_encryption": map[string]any{
			"jwks": map[string]any{
				"keys": []any{encJWK},
			},
			"enc_values_supported": []any{"A256GCM", "A128GCM"},
			"encryption_required":  false,
		},
	}
	reqBody := map[string]any{
		"credential_configuration_id": "test-config",
		"proofs": map[string]any{
			"jwt": []string{"proof-jwt"},
		},
	}

	body, contentType, err := prepareCredentialRequestBody(ValidationModeStrict, metadata, reqBody)
	if err != nil {
		t.Fatalf("prepareCredentialRequestBody: %v", err)
	}
	if contentType != "application/jwt" {
		t.Fatalf("contentType = %q, want application/jwt", contentType)
	}
	parts := strings.Split(string(body), ".")
	if len(parts) != 5 {
		t.Fatalf("expected compact JWE with 5 parts, got %d", len(parts))
	}
	headerJSON, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		t.Fatalf("decode JWE header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("parse JWE header: %v", err)
	}
	if header["alg"] != "ECDH-ES" || header["enc"] != "A256GCM" || header["kid"] != "issuer-enc-key" || header["cty"] != "json" {
		t.Fatalf("unexpected JWE header: %v", header)
	}
	decrypted, err := oid4vp.DecryptCompactJWE(string(body), issuerKey)
	if err != nil {
		t.Fatalf("oid4vp.DecryptCompactJWE: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(decrypted), &got); err != nil {
		t.Fatalf("parse decrypted payload: %v", err)
	}
	if got["credential_configuration_id"] != "test-config" {
		t.Fatalf("decrypted credential_configuration_id = %v", got["credential_configuration_id"])
	}
}

func TestParseCredentialResponseBody_EncryptedJWE(t *testing.T) {
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	jwe, _, err := jwe.EncryptECDHES([]byte(`{"credential":"encrypted-credential"}`), &holderKey.PublicKey, "kid1", "A128GCM", "", nil, nil)
	if err != nil {
		t.Fatalf("EncryptJWE: %v", err)
	}

	payload := &LogPayload{}
	got, encrypted, err := parseCredentialResponseBody([]byte(jwe), holderKey, payload)
	if err != nil || !encrypted {
		t.Fatalf("parseCredentialResponseBody: %v", err)
	}
	if got["credential"] != "encrypted-credential" {
		t.Fatalf("expected decrypted credential, got %v", got["credential"])
	}
	if !payload.Encrypted || payload.Wire != jwe || payload.Body != `{"credential":"encrypted-credential"}` {
		t.Fatalf("incorrect encrypted activity payload: %+v", payload)
	}
}

func TestResolveCredentialFormat(t *testing.T) {
	metadata := map[string]any{
		"credential_configurations_supported": map[string]any{
			"pid-sdjwt": map[string]any{
				"format": "dc+sd-jwt",
			},
			"pid-mdoc": map[string]any{
				"format": "mso_mdoc",
			},
		},
	}

	tests := []struct {
		name     string
		configID string
		want     string
	}{
		{"sd-jwt config", "pid-sdjwt", "dc+sd-jwt"},
		{"mdoc config", "pid-mdoc", "mso_mdoc"},
		{"unknown config", "unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveCredentialFormat(metadata, tt.configID)
			if got != tt.want {
				t.Errorf("resolveCredentialFormat(%s) = %s, want %s", tt.configID, got, tt.want)
			}
		})
	}
}

func TestResolveCredentialFormat_NoConfigs(t *testing.T) {
	metadata := map[string]any{}
	got := resolveCredentialFormat(metadata, "anything")
	if got != "" {
		t.Errorf("expected empty, got %s", got)
	}
}

func TestResolveTokenEndpoint_FromMetadata(t *testing.T) {
	w := generateTestWallet(t)
	got, err := w.resolveTokenEndpoint(map[string]any{}, map[string]any{"token_endpoint": "https://as.example/token"}, "https://issuer.example")
	if err != nil || got != "https://as.example/token" {
		t.Errorf("token endpoint = %q, err = %v, want the authorization server value", got, err)
	}
}

func TestResolveCredentialEndpoint_FromMetadata(t *testing.T) {
	w := generateTestWallet(t)
	got, err := w.resolveCredentialEndpoint(map[string]any{"credential_endpoint": "https://issuer.example/credential"}, "https://issuer.example")
	if err != nil || got != "https://issuer.example/credential" {
		t.Errorf("credential endpoint = %q, err = %v", got, err)
	}
}

// A required endpoint that the metadata omits or leaves empty is a deviation.
// Debug mode warns and uses the conventional path. Strict mode refuses.
func TestResolveEndpoint_MissingOrEmptyIsADeviation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		resolve func(w *Wallet) (string, error)
		want    string
	}{
		{"token missing", func(w *Wallet) (string, error) {
			return w.resolveTokenEndpoint(map[string]any{}, nil, "https://issuer.example")
		}, "https://issuer.example/token"},
		{"credential missing", func(w *Wallet) (string, error) {
			return w.resolveCredentialEndpoint(map[string]any{}, "https://issuer.example")
		}, "https://issuer.example/credential"},
		{"credential empty", func(w *Wallet) (string, error) {
			return w.resolveCredentialEndpoint(map[string]any{"credential_endpoint": ""}, "https://issuer.example")
		}, "https://issuer.example/credential"},
		{"credential trailing slash", func(w *Wallet) (string, error) {
			return w.resolveCredentialEndpoint(map[string]any{}, "https://issuer.example/")
		}, "https://issuer.example/credential"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			debug := generateTestWallet(t)
			got, err := tc.resolve(debug)
			if err != nil || got != tc.want {
				t.Errorf("debug: endpoint = %q, err = %v, want %q", got, err, tc.want)
			}
			if findLogEntry(debug.GetLog(), "server_deviation") == nil {
				t.Error("debug: expected a server_deviation warning")
			}

			strict := generateTestWallet(t)
			strict.ValidationMode = ValidationModeStrict
			if _, err := tc.resolve(strict); err == nil {
				t.Error("strict: expected a refusal for a missing required endpoint")
			}
		})
	}
}

func TestWellKnownURL_PathlessIssuer(t *testing.T) {
	got, err := wellKnownURL("https://issuer.example", "openid-credential-issuer")
	if err != nil {
		t.Fatalf("wellKnownURL: %v", err)
	}
	if got != "https://issuer.example/.well-known/openid-credential-issuer" {
		t.Fatalf("expected pathless well-known URL, got %s", got)
	}
}

func TestWellKnownURL_PreservesTrailingSlashInIssuerPath(t *testing.T) {
	got, err := wellKnownURL("https://issuer.example/test/issuer/", "openid-credential-issuer")
	if err != nil {
		t.Fatalf("wellKnownURL: %v", err)
	}
	if got != "https://issuer.example/.well-known/openid-credential-issuer/test/issuer/" {
		t.Fatalf("expected trailing slash to be preserved, got %s", got)
	}
}

func trustSignedIssuerMetadataFrom(t *testing.T, w *Wallet) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(w.CertChain[len(w.CertChain)-1])
	previous := issuerMetadataTrustAnchors
	issuerMetadataTrustAnchors = pool
	t.Cleanup(func() { issuerMetadataTrustAnchors = previous })
}

func TestParseIssuerMetadataResponse_SignedJWT(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example:8443"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	trustSignedIssuerMetadataFrom(t, w)

	if _, err := w.RegisterMissingDemoParties(); err != nil {
		t.Fatal(err)
	}
	raw, err := signCredentialIssuerMetadataJWT(w, w.IssuerURL, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("signing issuer metadata: %v", err)
	}

	metadata, _, err := parseIssuerMetadataDocument([]byte(raw), "application/jwt", w.IssuerURL, refuseMetadataProblem)
	if err != nil {
		t.Fatalf("parsing signed issuer metadata: %v", err)
	}
	if metadata["credential_issuer"] != w.IssuerURL {
		t.Fatalf("expected credential_issuer %s, got %v", w.IssuerURL, metadata["credential_issuer"])
	}

	registrations, problems := regcert.Verify(regcert.InfoEntries(metadata, "issuer_info"))
	if len(registrations) != 1 || len(problems) != 0 {
		t.Fatalf("issuer_info %v, want one registration certificate (problems %v)", metadata["issuer_info"], problems)
	}
	cert := registrations[0].Claims
	if want := "NTRNL-" + ownProviderIdentifier(t, w); cert["sub"] != want {
		t.Fatalf("registration certificate sub %v, want %s", cert["sub"], want)
	}
	provided := regcert.ProvidedAttestations(cert)
	if !regcert.Provides(provided, "dc+sd-jwt", []string{mock.DefaultPIDVCT}) || !regcert.Provides(provided, "mso_mdoc", []string{mock.PIDNamespace}) {
		t.Fatalf("provides_attestations %v, want the PID types", cert["provides_attestations"])
	}
}

func TestParseIssuerMetadataResponse_RejectsTamperedSignedJWT(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example:8443"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	trustSignedIssuerMetadataFrom(t, w)

	raw, err := signCredentialIssuerMetadataJWT(w, w.IssuerURL, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("signing issuer metadata: %v", err)
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("expected compact JWT, got %q", raw)
	}
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	tamperedPayload := strings.Replace(string(payloadBytes), mock.DefaultPIDVCT, "urn:example:tampered", 1)
	if tamperedPayload == string(payloadBytes) {
		t.Fatal("expected signed issuer metadata payload to contain default PID VCT")
	}
	parts[1] = format.EncodeBase64URL([]byte(tamperedPayload))
	tampered := strings.Join(parts, ".")

	if _, _, err := parseIssuerMetadataDocument([]byte(tampered), "application/jwt", w.IssuerURL, refuseMetadataProblem); err == nil {
		t.Fatal("expected tampered signed issuer metadata to fail verification")
	}
}

// §12.2.3: "When requesting signed metadata, the Wallet MUST establish trust in
// the signer of the metadata. Otherwise, the Wallet MUST reject the signed
// metadata." A token with no x5c gives the wallet nothing to establish trust
// from. Accepting it would let whoever answered the request choose the
// endpoints for the rest of the flow.
func TestParseIssuerMetadataResponse_SignedMetadataTrust(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example:8443"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}

	payload := map[string]any{
		"credential_issuer":   w.IssuerURL,
		"credential_endpoint": w.IssuerURL + "/credential",
		"sub":                 w.IssuerURL,
		"iat":                 time.Now().Unix(),
	}

	t.Run("no x5c at all", func(t *testing.T) {
		raw, err := signJSONWebSignature(payload, w.IssuerKey, map[string]any{
			"alg": "ES256",
			"typ": signedIssuerMetadataTyp,
		})
		if err != nil {
			t.Fatalf("signing: %v", err)
		}
		if _, _, err := parseIssuerMetadataDocument([]byte(raw), "application/jwt", w.IssuerURL, refuseMetadataProblem); err == nil {
			t.Fatal("signed issuer metadata with no way to establish trust in its signer was accepted")
		}
	})

	// An unknown signer CA stays usable for testing. The signature must still
	// verify and the missing trust must be reported.
	t.Run("an x5c chain that anchors nowhere", func(t *testing.T) {
		raw, err := signCredentialIssuerMetadataJWT(w, w.IssuerURL, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("signing issuer metadata: %v", err)
		}
		issuerMetadataTrustAnchors = x509.NewCertPool()
		t.Cleanup(func() { issuerMetadataTrustAnchors = nil })
		metadata, _, err := parseIssuerMetadataDocument([]byte(raw), "application/jwt", w.IssuerURL, refuseMetadataProblem)
		if err != nil {
			t.Fatalf("signed issuer metadata from an unanchored signer was refused: %v", err)
		}
		if got, _ := metadata["credential_issuer"].(string); got != w.IssuerURL {
			t.Errorf("credential_issuer = %q, want %q", got, w.IssuerURL)
		}

		parts := strings.Split(raw, ".")
		sig, err := format.DecodeBase64URL(parts[2])
		if err != nil {
			t.Fatalf("decoding signature: %v", err)
		}
		sig[0] ^= 0xFF
		parts[2] = format.EncodeBase64URL(sig)
		if _, _, err := parseIssuerMetadataDocument([]byte(strings.Join(parts, ".")), "application/jwt", w.IssuerURL, refuseMetadataProblem); err == nil {
			t.Fatal("signed issuer metadata whose signature does not verify was accepted")
		}
	})
}

// §12.2.3 requires "sub: REQUIRED. String matching the Credential Issuer
// Identifier".
func TestParseIssuerMetadataResponse_RejectsSignedMetadataForAnotherIssuer(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example:8443"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	trustSignedIssuerMetadataFrom(t, w)

	// Only sub differs, so the test reaches the issuer identity check alone.
	_, chain, err := w.Signer().Default()
	if err != nil {
		t.Fatalf("building the signing chain: %v", err)
	}
	raw, err := signJSONWebSignature(map[string]any{
		"credential_issuer":   w.IssuerURL,
		"credential_endpoint": w.IssuerURL + "/credential",
		"sub":                 "https://elsewhere.example",
		"iat":                 time.Now().Unix(),
	}, w.IssuerKey, map[string]any{
		"alg": "ES256",
		"typ": signedIssuerMetadataTyp,
		"x5c": certchain.X5C(chain),
	})
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	if _, _, err := parseIssuerMetadataDocument([]byte(raw), "application/jwt", w.IssuerURL, refuseMetadataProblem); err == nil {
		t.Fatal("signed issuer metadata whose sub names another issuer was accepted")
	}
}

// §12.2.4 on credential_issuer: "If these values are not identical (when
// compared using a simple string comparison with no normalization), the data
// contained in the response MUST NOT be used."
func TestParseIssuerMetadataResponse_RejectsMismatchedCredentialIssuer(t *testing.T) {
	raw := []byte(`{"credential_issuer":"https://attacker.example","credential_endpoint":"https://attacker.example/credential"}`)

	if _, _, err := parseIssuerMetadataDocument(raw, "application/json", "https://issuer.example", refuseMetadataProblem); err == nil {
		t.Fatal("metadata declaring a different credential_issuer was used")
	}

	missing := []byte(`{"credential_endpoint":"https://issuer.example/credential"}`)
	if _, _, err := parseIssuerMetadataDocument(missing, "application/json", "https://issuer.example", refuseMetadataProblem); err == nil {
		t.Fatal("metadata carrying no credential_issuer was used")
	}

	slashed := []byte(`{"credential_issuer":"https://issuer.example/"}`)
	if _, _, err := parseIssuerMetadataDocument(slashed, "application/json", "https://issuer.example", refuseMetadataProblem); err == nil {
		t.Fatal("metadata whose credential_issuer differs only by a trailing slash was used")
	}
}

func TestParseIssuerMetadataResponse_JSONWithDots(t *testing.T) {
	raw := []byte(`{
		"credential_issuer":"http://localhost:8080/realms/wallet-app-demo",
		"credential_configurations_supported":{
			"membership-credential":{
				"format":"dc+sd-jwt",
				"vct":"https://credentials.example.com/membership"
			}
		}
	}`)

	metadata, _, err := parseIssuerMetadataDocument(raw, "application/json", "http://localhost:8080/realms/wallet-app-demo", refuseMetadataProblem)
	if err != nil {
		t.Fatalf("parsing metadata JSON: %v", err)
	}
	if metadata["credential_issuer"] != "http://localhost:8080/realms/wallet-app-demo" {
		t.Fatalf("unexpected credential_issuer: %v", metadata["credential_issuer"])
	}
}

// §12.2.4: "When the Wallet is using authorization_server parameter in the
// Credential Offer as a hint to determine which Authorization Server to use out
// of multiple, the Wallet MUST NOT proceed with the flow if the
// authorization_server Credential Offer parameter value does not match any of
// the entries in the authorization_servers array."
func TestSelectAuthorizationServer(t *testing.T) {
	offerWithHint := func(hint string) *oid4vc.CredentialOffer {
		grant := map[string]any{"pre-authorized_code": "code"}
		if hint != "" {
			grant["authorization_server"] = hint
		}
		return &oid4vc.CredentialOffer{
			CredentialIssuer: "https://issuer.example",
			FullJSON: map[string]any{
				"grants": map[string]any{
					"urn:ietf:params:oauth:grant-type:pre-authorized_code": grant,
				},
			},
		}
	}
	metadata := map[string]any{
		"authorization_servers": []any{"https://as-one.example", "https://as-two.example"},
	}

	t.Run("the hint selects the named server", func(t *testing.T) {
		got, err := selectAuthorizationServer(metadata, offerWithHint("https://as-two.example"), preAuthorizedCodeGrant)
		if err != nil {
			t.Fatalf("selectAuthorizationServer: %v", err)
		}
		if got != "https://as-two.example" {
			t.Errorf("authorization server = %q, want the one the offer named", got)
		}
	})

	t.Run("a hint matching no entry stops the flow", func(t *testing.T) {
		if _, err := selectAuthorizationServer(metadata, offerWithHint("https://attacker.example"), preAuthorizedCodeGrant); err == nil {
			t.Fatal("an authorization server the issuer metadata does not list was accepted")
		}
	})

	t.Run("no hint falls back to the first entry", func(t *testing.T) {
		got, err := selectAuthorizationServer(metadata, offerWithHint(""), preAuthorizedCodeGrant)
		if err != nil {
			t.Fatalf("selectAuthorizationServer: %v", err)
		}
		if got != "https://as-one.example" {
			t.Errorf("authorization server = %q, want the first entry", got)
		}
	})

	t.Run("the hint of another grant does not apply", func(t *testing.T) {
		got, err := selectAuthorizationServer(metadata, offerWithHint("https://as-two.example"), "authorization_code")
		if err != nil {
			t.Fatalf("selectAuthorizationServer: %v", err)
		}
		if got != "https://as-one.example" {
			t.Errorf("authorization server = %q, want the first entry for the authorization_code grant", got)
		}
	})

	t.Run("no authorization_servers at all is the issuer itself", func(t *testing.T) {
		got, err := selectAuthorizationServer(map[string]any{}, offerWithHint(""), preAuthorizedCodeGrant)
		if err != nil {
			t.Fatalf("selectAuthorizationServer: %v", err)
		}
		if got != "https://issuer.example" {
			t.Errorf("authorization server = %q, want the credential issuer", got)
		}
	})
}

// token_endpoint is an authorization server metadata parameter (RFC 8414 §2).
// §12.2.4 defines none for the Credential Issuer, so the authorization server
// document wins when the two disagree.
func TestResolveTokenEndpoint_PrefersTheAuthorizationServerMetadata(t *testing.T) {
	w := generateTestWallet(t)
	metadata := map[string]any{"token_endpoint": "https://issuer.example/token"}
	oauthMeta := map[string]any{"token_endpoint": "https://as.example/token"}

	if got, err := w.resolveTokenEndpoint(metadata, oauthMeta, "https://issuer.example"); err != nil || got != "https://as.example/token" {
		t.Errorf("token endpoint = %q, err = %v, want the authorization server's", got, err)
	}
	if got, err := w.resolveTokenEndpoint(metadata, nil, "https://issuer.example"); err != nil || got != "https://issuer.example/token" {
		t.Errorf("token endpoint = %q, err = %v, want the issuer's own when no AS metadata was reachable", got, err)
	}
}

// Without any token_endpoint, debug mode assumes the conventional path on the
// authorization server in use, not on the first one the issuer lists.
func TestResolveTokenEndpoint_FallbackUsesTheChosenAuthorizationServer(t *testing.T) {
	w := generateTestWallet(t)
	metadata := map[string]any{"authorization_servers": []any{"https://as-one.example", "https://as-two.example/"}}
	if got, err := w.resolveTokenEndpoint(metadata, nil, "https://as-two.example/"); err != nil || got != "https://as-two.example/token" {
		t.Errorf("token endpoint = %q, err = %v, want the chosen server's /token", got, err)
	}
}

// A proof without a challenge has no nonce claim. An empty string is still a
// nonce value and can fail issuer checks.
func TestCreateProofJWT_OmitsEmptyNonce(t *testing.T) {
	key := testKey(t)

	withoutNonce, err := createProofJWT(key, "https://issuer.example", "", "", nil)
	if err != nil {
		t.Fatalf("createProofJWT: %v", err)
	}
	payload := decodeJWTPart(t, withoutNonce, 1)
	if _, present := payload["nonce"]; present {
		t.Errorf("proof carries a nonce claim %v when the issuer gave none", payload["nonce"])
	}

	withNonce, err := createProofJWT(key, "https://issuer.example", "", "abc123", nil)
	if err != nil {
		t.Fatalf("createProofJWT with nonce: %v", err)
	}
	payload = decodeJWTPart(t, withNonce, 1)
	if payload["nonce"] != "abc123" {
		t.Errorf("nonce = %v, want abc123", payload["nonce"])
	}
}

// The key proof carries the client_id as iss when the wallet has one (OID4VCI
// 1.0 Appendix F.1). An issuer that binds the access token to a client matches
// it. An anonymous flow leaves iss out, because an unbound client would fail
// that match.
func TestCreateProofJWT_IssMatchesClientID(t *testing.T) {
	key := testKey(t)

	withClient, err := createProofJWT(key, "https://issuer.example", "wallet-client-id", "", nil)
	if err != nil {
		t.Fatalf("createProofJWT: %v", err)
	}
	if got := decodeJWTPart(t, withClient, 1)["iss"]; got != "wallet-client-id" {
		t.Errorf("iss = %v, want wallet-client-id", got)
	}

	anonymous, err := createProofJWT(key, "https://issuer.example", "", "", nil)
	if err != nil {
		t.Fatalf("createProofJWT anonymous: %v", err)
	}
	if _, present := decodeJWTPart(t, anonymous, 1)["iss"]; present {
		t.Error("proof carries an iss claim when the flow named no client")
	}
}

// OpenID4VCI 1.0 §12.2.3 requires iat in signed metadata, and metadata past
// its exp is not used. Strict mode refuses such metadata. Debug mode reads it.
func TestParseIssuerMetadataResponse_RequiresIatAndRejectsExpiredMetadata(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example:8443"
	trustSignedIssuerMetadataFrom(t, w)
	_, chain, err := w.Signer().Default()
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		times map[string]any
		want  string
	}{
		"current": {map[string]any{"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}, ""},
		"no iat":  {map[string]any{}, "iat"},
		"expired": {map[string]any{"iat": time.Now().Add(-2 * time.Hour).Unix(), "exp": time.Now().Add(-time.Hour).Unix()}, "expired"},
	} {
		payload := map[string]any{"credential_issuer": w.IssuerURL, "credential_endpoint": w.IssuerURL + "/credential", "sub": w.IssuerURL}
		maps.Copy(payload, tc.times)
		raw, err := signJSONWebSignature(payload, w.IssuerKey, map[string]any{"alg": "ES256", "typ": signedIssuerMetadataTyp, "x5c": certchain.X5C(chain)})
		if err != nil {
			t.Fatal(err)
		}
		var reported []string
		if _, _, err := parseIssuerMetadataDocument([]byte(raw), "application/jwt", w.IssuerURL, w.reportMetadataProblem(func(f ...string) { reported = append(reported, f...) })); err != nil {
			t.Errorf("%s in debug mode: %v", name, err)
		}
		if tc.want != "" && (len(reported) != 1 || !strings.Contains(reported[0], "§12.2.3")) {
			t.Errorf("%s in debug mode reported %v, want the §12.2.3 finding", name, reported)
		}
		_, _, err = parseIssuerMetadataDocument([]byte(raw), "application/jwt", w.IssuerURL, refuseMetadataProblem)
		if tc.want == "" && err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: error %v, want one about %s", name, err, tc.want)
		}
	}
}

// refuseMetadataProblem refuses issuer metadata with a §12.2.3 problem, as
// strict mode does.
func refuseMetadataProblem(problem string) error { return errors.New(problem) }

// RFC 7515 §4.1.9: typ values are case insensitive and "application/" is
// implied when the value has no '/'.
func TestParseIssuerMetadataResponse_SignedMetadataTypIsAMediaType(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example:8443"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	trustSignedIssuerMetadataFrom(t, w)
	_, chain, err := w.Signer().Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{strings.ToUpper(signedIssuerMetadataTyp), "application/" + signedIssuerMetadataTyp} {
		raw, err := signJSONWebSignature(map[string]any{
			"credential_issuer":   w.IssuerURL,
			"credential_endpoint": w.IssuerURL + "/credential",
			"sub":                 w.IssuerURL,
			"iat":                 time.Now().Unix(),
		}, w.IssuerKey, map[string]any{"alg": "ES256", "typ": typ, "x5c": certchain.X5C(chain)})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := parseIssuerMetadataDocument([]byte(raw), "application/jwt", w.IssuerURL, refuseMetadataProblem); err != nil {
			t.Errorf("typ %s: %v", typ, err)
		}
	}
}
