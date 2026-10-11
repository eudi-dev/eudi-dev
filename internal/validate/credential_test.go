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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/statuslist"
)

// issuerChain is a CA and an issuer key with a leaf certificate under it.
type issuerChain struct {
	ca        *x509.Certificate
	leaf      *x509.Certificate
	issuerKey *ecdsa.PrivateKey
}

func newIssuerChain(t *testing.T) issuerChain {
	t.Helper()
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := mock.GenerateLeafCertWithOptions(caKey, ca, &issuerKey.PublicKey, mock.LeafCertOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return issuerChain{ca: ca, leaf: leaf, issuerKey: issuerKey}
}

func (c issuerChain) sdjwt(t *testing.T, cfg mock.SDJWTConfig) string {
	t.Helper()
	if cfg.Issuer == "" {
		cfg.Issuer = "https://localhost:1"
	}
	if cfg.VCT == "" {
		cfg.VCT = "urn:example:test:1"
	}
	if cfg.ExpiresIn == 0 {
		cfg.ExpiresIn = time.Hour
	}
	if cfg.Claims == nil {
		cfg.Claims = map[string]any{"given_name": "Erika"}
	}
	cfg.Key = c.issuerKey
	cfg.CertChain = []*x509.Certificate{c.leaf, c.ca}
	raw, err := mock.GenerateSDJWT(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (c issuerChain) mdoc(t *testing.T, cfg mock.MDOCConfig) string {
	t.Helper()
	cfg.DocType, cfg.Namespace = "eu.example.test.1", "eu.example.test.1"
	cfg.Claims = map[string]any{"family_name": "Mustermann"}
	cfg.Key = c.issuerKey
	cfg.CertChain = []*x509.Certificate{c.leaf, c.ca}
	if cfg.ExpiresIn == 0 {
		cfg.ExpiresIn = time.Hour
	}
	raw, err := mock.GenerateMDOC(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func validated(t *testing.T, raw string, trust Trust, opts Options) *Result {
	t.Helper()
	result, err := Credential(raw, trust, opts)
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	return result
}

// fakeCatalogue answers every credential with the same anchoring.
type fakeCatalogue struct{ anchoring CatalogueAnchoring }

func (f fakeCatalogue) CheckCatalogueAnchoring(string) (CatalogueAnchoring, bool) {
	return f.anchoring, true
}

func anchoredBy(c issuerChain) fakeCatalogue {
	return fakeCatalogue{CatalogueAnchoring{Entry: "Test", AnchoredBy: "https://lists.example/pid", IssuanceAnchors: []*x509.Certificate{c.ca}}}
}

// Without a supplied key or list, the catalogue list anchors the issuer
// chain of both formats.
func TestTheCatalogueListAnchorsTheSignature(t *testing.T) {
	c := newIssuerChain(t)
	for name, raw := range map[string]string{
		"SD-JWT VC": c.sdjwt(t, mock.SDJWTConfig{}),
		"mdoc":      c.mdoc(t, mock.MDOCConfig{}),
	} {
		result := validated(t, raw, Trust{Catalogue: anchoredBy(c)}, Options{})
		if got := mustFind(t, result, CheckSignature); got.Status != Pass || got.Detail != "Valid, ES256" {
			t.Errorf("%s: signature = %+v, want Valid, ES256", name, got)
		}
		want := Anchor{Entry: "Test", ListURL: "https://lists.example/pid", Service: ServiceIssuance}
		if got := mustFind(t, result, CheckTrust); got.Status != Pass || got.Anchor == nil || *got.Anchor != want || got.Detail != "Test, trusted list pid" {
			t.Errorf("%s: trust = %+v, want anchored by %+v", name, got, want)
		}
	}
}

// A catalogue entry whose lists do not anchor the credential leaves the
// embedded leaf to prove integrity.
func TestAnUnanchoredCatalogueEntryKeepsTheLeafCheck(t *testing.T) {
	c := newIssuerChain(t)
	unanchored := fakeCatalogue{CatalogueAnchoring{Entry: "Test", Findings: []string{"ARF ISSU_07: not on the list"}}}
	for name, raw := range map[string]string{
		"SD-JWT VC": c.sdjwt(t, mock.SDJWTConfig{}),
		"mdoc":      c.mdoc(t, mock.MDOCConfig{}),
	} {
		result := validated(t, raw, Trust{Catalogue: unanchored}, Options{})
		if got := mustFind(t, result, CheckSignature); got.Status != Pass || !strings.Contains(got.Detail, SourceX5CLeaf) {
			t.Errorf("%s: signature = %+v, want it verified with the leaf", name, got)
		}
		if got := mustFind(t, result, CheckTrust); got.Status != Fail || !strings.Contains(got.Detail, "ISSU_07") {
			t.Errorf("%s: trust = %+v, want the catalogue finding", name, got)
		}
	}
}

// A supplied key that does not verify fails the signature. The embedded leaf
// proves integrity only when nothing was supplied.
func TestAWrongSuppliedKeyFailsTheSignature(t *testing.T) {
	c := newIssuerChain(t)
	other, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	var trust Trust
	trust.AddKey(&other.PublicKey)
	for name, raw := range map[string]string{
		"SD-JWT VC": c.sdjwt(t, mock.SDJWTConfig{}),
		"mdoc":      c.mdoc(t, mock.MDOCConfig{}),
	} {
		if got := mustFind(t, validated(t, raw, trust, Options{}), CheckSignature); got.Status != Fail {
			t.Errorf("%s: signature = %+v, want fail", name, got)
		}
	}
}

// A signature that does not verify with the embedded leaf fails.
func TestASignatureThatTheLeafDoesNotVerifyFails(t *testing.T) {
	c := newIssuerChain(t)
	raw := c.sdjwt(t, mock.SDJWTConfig{})
	jwt, rest, _ := strings.Cut(raw, "~")
	parts := strings.Split(jwt, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(payload), "urn:example:test:1", "urn:example:test:2", 1)))
	tampered := strings.Join(parts, ".") + "~" + rest

	if got := mustFind(t, validated(t, tampered, Trust{}, Options{}), CheckSignature); got.Status != Fail || !strings.Contains(got.Detail, SourceX5CLeaf) {
		t.Errorf("signature = %+v, want it failed with the leaf", got)
	}
}

// One validity rule with one minute of clock skew (RFC 7519 §4.1.4) applies
// to exp, nbf and iat, and to the MSO validFrom and validUntil, whether or
// not a key verifies the signature.
func TestTheValidityCheckUsesOneRule(t *testing.T) {
	c := newIssuerChain(t)
	now := time.Now()
	at := func(d time.Duration) *time.Time { t := now.Add(d); return &t }

	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"SD-JWT VC expired within the skew", c.sdjwt(t, mock.SDJWTConfig{IssuedAt: at(-time.Hour), ExpiresIn: time.Hour - 30*time.Second}), Pass},
		{"SD-JWT VC expired", c.sdjwt(t, mock.SDJWTConfig{IssuedAt: at(-time.Hour), ExpiresIn: time.Hour - 2*time.Minute}), Fail},
		{"SD-JWT VC not valid within the skew", c.sdjwt(t, mock.SDJWTConfig{NotBefore: at(30 * time.Second)}), Pass},
		{"SD-JWT VC not yet valid", c.sdjwt(t, mock.SDJWTConfig{NotBefore: at(2 * time.Minute)}), Fail},
		{"SD-JWT VC issued in the future", c.sdjwt(t, mock.SDJWTConfig{IssuedAt: at(time.Hour)}), Warning},
		{"mdoc not yet valid", c.mdoc(t, mock.MDOCConfig{ValidFrom: at(time.Hour), ExpiresIn: 2 * time.Hour}), Fail},
		{"mdoc expired", c.mdoc(t, mock.MDOCConfig{ExpiresIn: -2 * time.Minute}), Fail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustFind(t, validated(t, tc.raw, Trust{}, Options{Offline: true, Now: now}), CheckExpiry); got.Status != tc.want {
				t.Errorf("expiry = %+v, want %s", got, tc.want)
			}
		})
	}
}

// A plain JWT without a key still gets its nbf checked.
func TestAnUnsignedJWTGetsItsValidityChecked(t *testing.T) {
	jwt := unsignedJWT(t, map[string]any{"iss": "https://issuer.example", "nbf": time.Now().Add(time.Hour).Unix()})
	result := validated(t, jwt, Trust{}, Options{})
	if got := mustFind(t, result, CheckSignature); got.Status != Skipped {
		t.Fatalf("signature = %+v, want skipped", got)
	}
	if got := mustFind(t, result, CheckExpiry); got.Status != Fail || !strings.Contains(got.Detail, "not yet valid") {
		t.Errorf("expiry = %+v, want not yet valid", got)
	}
}

func unsignedJWT(t *testing.T, payload map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body) + "."
}

// The format comes from the encoding. A JWT whose payload has
// credential_issuer is still validated as a JWT.
func TestAJWTIsDetectedByItsEncoding(t *testing.T) {
	jwt := unsignedJWT(t, map[string]any{"credential_issuer": "https://issuer.example", "exp": time.Now().Add(time.Hour).Unix()})
	if got := validated(t, jwt, Trust{}, Options{Offline: true}); got.Format != FormatJWT {
		t.Errorf("format = %s, want %s", got.Format, FormatJWT)
	}
}

// serveStatusList serves a JWT Status List Token signed by the leaf of a
// chain. It counts the requests.
func serveStatusList(t *testing.T, c issuerChain, bits []byte) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		token, err := statuslist.GenerateStatusListJWT(bits, c.issuerKey, statuslist.StatusListConfig{URI: srv.URL, CertChain: []*x509.Certificate{c.leaf, c.ca}})
		if err != nil {
			t.Errorf("GenerateStatusListJWT: %v", err)
			return
		}
		w.Header().Set("Content-Type", statuslist.MediaTypeJWT)
		_, _ = w.Write([]byte(token))
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

// A status list whose chain no trusted list anchors gets a warning on its
// signature. With the revocation service of a supplied list it passes.
func TestTheStatusListSignatureNeedsATrustAnchor(t *testing.T) {
	c := newIssuerChain(t)
	srv, _ := serveStatusList(t, c, make([]byte, 16))
	raw := c.sdjwt(t, mock.SDJWTConfig{StatusListURI: srv.URL, StatusListIdx: 3})

	result := validated(t, raw, Trust{}, Options{Status: true})
	if got := mustFind(t, result, CheckStatus); got.Status != Pass || got.Detail != "Valid (index 3)" {
		t.Fatalf("status = %+v, want Valid (index 3)", got)
	}
	if got := mustFind(t, result, CheckStatusSignature); got.Status != Warning {
		t.Errorf("status list signature = %+v, want a warning", got)
	}

	trust := Trust{Supplied: true, Revocation: []*x509.Certificate{c.ca}}
	if got := mustFind(t, validated(t, raw, trust, Options{Status: true}), CheckStatusSignature); got.Status != Pass || got.Detail != "Valid, signed by "+c.leaf.Subject.CommonName {
		t.Errorf("status list signature = %+v, want Valid, signed by the leaf", got)
	}
}

// draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3: the Status List Token of an SD-JWT
// VC "MUST be in JWT format".
func TestASDJWTVCWithACWTStatusListIsReported(t *testing.T) {
	c := newIssuerChain(t)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := statuslist.GenerateStatusListCWT(make([]byte, 16), c.issuerKey, statuslist.StatusListConfig{URI: srv.URL, CertChain: []*x509.Certificate{c.leaf, c.ca}})
		if err != nil {
			t.Errorf("GenerateStatusListCWT: %v", err)
			return
		}
		w.Header().Set("Content-Type", statuslist.MediaTypeCWT)
		_, _ = w.Write(token)
	}))
	t.Cleanup(srv.Close)
	raw := c.sdjwt(t, mock.SDJWTConfig{StatusListURI: srv.URL})

	result := validated(t, raw, Trust{}, Options{Status: true})
	if result.Status == nil || !strings.Contains(strings.Join(result.Status.Warnings, "\n"), "requires a JWT") {
		t.Fatalf("status = %+v, want a finding about the CWT status list", result.Status)
	}
}

// The status list is fetched with the HTTP client of the trust context.
func TestTheStatusListIsFetchedWithTheTrustClient(t *testing.T) {
	c := newIssuerChain(t)
	srv, _ := serveStatusList(t, c, make([]byte, 16))
	raw := c.sdjwt(t, mock.SDJWTConfig{StatusListURI: srv.URL})

	var used atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		used.Add(1)
		return http.DefaultTransport.RoundTrip(r)
	})}
	validated(t, raw, Trust{HTTPClient: client}, Options{Status: true})
	if used.Load() == 0 {
		t.Error("the status list was fetched with another client")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A status other than a Token Status List is a warning and is not fetched.
// The HAIP 1.0 §6.1 finding belongs to the HAIP check.
func TestAStatusOtherThanAStatusListIsAWarning(t *testing.T) {
	jwt := unsignedJWT(t, map[string]any{"status": map[string]any{"type": "StatusList2021Entry"}})
	got := mustFind(t, validated(t, jwt, Trust{}, Options{Status: true}), CheckStatus)
	want := `the status claim uses "StatusList2021Entry", not a Token Status List (status.status_list). This status is not checked.`
	if got.Status != Warning || got.Detail != want {
		t.Errorf("status = %+v, want a warning %q", got, want)
	}
}

// With Options.HAIP an SD-JWT VC gets the HAIP 1.0 §6.1 checks.
func TestTheHAIPCheckListsTheFindings(t *testing.T) {
	c := newIssuerChain(t)
	withAnchor := c.sdjwt(t, mock.SDJWTConfig{KeepTrustAnchor: true})
	result := validated(t, withAnchor, Trust{}, Options{Offline: true, HAIP: true})
	if got := mustFind(t, result, CheckHAIP); got.Status != Warning || len(result.HAIPFindings) != 1 {
		t.Errorf("haip = %+v with %v, want the trust anchor finding", got, result.HAIPFindings)
	}
	clean := validated(t, c.sdjwt(t, mock.SDJWTConfig{}), Trust{}, Options{Offline: true, HAIP: true})
	if got := mustFind(t, clean, CheckHAIP); got.Status != Pass || clean.HAIPFindings == nil {
		t.Errorf("haip = %+v, want pass with an empty finding list", got)
	}
}

// A supplied trusted list past its NextUpdate is discarded (ETSI TS 119 602
// V1.1.1 §6.3.15), so it anchors nothing.
func TestASuppliedExpiredTrustedListIsDiscarded(t *testing.T) {
	list := unsignedList(t, time.Now().Add(-time.Hour))
	var trust Trust
	err := trust.AddTrustedList(list, time.Now())
	if err == nil || !strings.Contains(err.Error(), "§6.3.15") {
		t.Fatalf("AddTrustedList = %v, want the §6.3.15 error", err)
	}
	if !trust.Supplied || len(trust.Issuance) != 0 {
		t.Errorf("trust = %+v, want supplied without anchors", trust)
	}
}

func unsignedList(t *testing.T, nextUpdate time.Time) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "ES256"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"LoTE": map[string]any{
		"ListAndSchemeInformation": map[string]any{"NextUpdate": nextUpdate.UTC().Format(time.RFC3339)},
		"TrustedEntitiesList":      []any{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body) + ".c2ln"
}

// A wallet that cannot be read fails the trust check with the reason.
func TestAnUnreadableWalletFailsTheTrustCheck(t *testing.T) {
	c := newIssuerChain(t)
	trust := Trust{CatalogueErr: errTest("the store is locked")}
	if got := mustFind(t, validated(t, c.sdjwt(t, mock.SDJWTConfig{}), trust, Options{}), CheckTrust); got.Status != Fail || !strings.Contains(got.Detail, "the store is locked") {
		t.Errorf("trust = %+v, want the wallet error", got)
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }
