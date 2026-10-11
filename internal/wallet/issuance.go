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
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/certchain"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jwe"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/v3/internal/validate"
)

var preferredCredentialResponseEncryptionAlgs = []string{jwe.AlgECDHES}
var preferredCredentialResponseEncryptionEncs = []string{jwe.EncA128GCM, jwe.EncA256GCM, "A128CBC-HS256"}
var preferredCredentialRequestEncryptionEncs = []string{jwe.EncA256GCM, jwe.EncA128GCM, "A128CBC-HS256"}

const metadataFetchAttempts = 3

var metadataRetryDelay = 500 * time.Millisecond

// Retry transport failures and 5xx responses. A 4xx response describes a request error
// and is not retried.
func fetchMetadataDocument(newRequest func() (*http.Request, error), client *http.Client) (*http.Response, error) {
	var lastErr error
	for attempt := 1; attempt <= metadataFetchAttempts; attempt++ {
		req, err := newRequest()
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("%s answered HTTP %d", req.URL, resp.StatusCode)
		}
		if attempt < metadataFetchAttempts {
			log.Printf("[VCI] metadata read from %s did not complete (%v), retrying", req.URL, lastErr)
			time.Sleep(metadataRetryDelay)
		}
	}
	return nil, lastErr
}

type IssuanceResult struct {
	CredentialID       string `json:"credential_id"`
	Format             string `json:"format"`
	Issuer             string `json:"issuer"`
	VerificationStatus string `json:"verification_status,omitempty"`
	VerificationDetail string `json:"verification_detail,omitempty"`
	Error              string `json:"error,omitempty"`
	// Pending means the issuer deferred the credential. TransactionID identifies it
	// and RetryInterval sets the collection schedule.
	Pending       bool   `json:"pending,omitempty"`
	TransactionID string `json:"transaction_id,omitempty"`
	RetryInterval string `json:"retry_interval,omitempty"`
	// Findings are the checks that failed in debug mode, as for a
	// presentation.
	Findings []string `json:"findings,omitempty"`
}

type OfferOptions struct {
	// PresentationConsented is true when the caller already consented for the
	// user. When the issuer then asks for a presentation during the flow
	// (OID4VCI 1.1 §6), the wallet skips the consent prompt.
	PresentationConsented bool
	// TxCode is the transaction code for a pre-authorized offer that requires
	// one. Each flow carries its own code because concurrent offers can share a
	// wallet.
	TxCode string
	// Owner identifies the browser that started this issuance. A presentation
	// requested by the issuer during the flow goes to the same browser.
	Owner string
	// Flow tags the sign-in prompt of this issuance, so the caller that
	// started it picks up its own prompt.
	Flow string
	// ResolvedOffer is the offer that the caller already resolved from the same
	// URI, for example for a consent dialog. The flow uses it only when reading
	// the URI again fails.
	ResolvedOffer *oid4vc.CredentialOffer
	// ConfigurationID is the entry of credential_configuration_ids the user
	// or the API caller chose. Empty requests the first entry.
	ConfigurationID string

	// findings collects the debug findings of the flow for its result.
	findings *[]string
}

func (o OfferOptions) addFindings(findings ...string) {
	if o.findings != nil {
		*o.findings = append(*o.findings, findings...)
	}
}

// resolveOffer reads the credential offer at the URI. approved is the offer
// that the caller resolved earlier from the same URI.
//
// §4.1.3 asks the wallet to fetch the URI "unless it is already cached", so
// the URI is read again. An issuer that consumes the offer on the first read
// answers the second with an error. The flow then continues with the approved
// offer.
func (w *Wallet) resolveOffer(offerURI string, approved *oid4vc.CredentialOffer) (*oid4vc.CredentialOffer, error) {
	reqType, result, err := oid4vc.ParseWithOptions(offerURI, oid4vc.ParseOptions{HTTPClient: w.HTTPClient()})
	if err != nil {
		return w.keepApprovedOffer(offerURI, approved, err)
	}
	if reqType != oid4vc.TypeVCI {
		return nil, fmt.Errorf("expected VCI credential offer, got VP")
	}
	offer, ok := result.(*oid4vc.CredentialOffer)
	if !ok {
		return nil, fmt.Errorf("unexpected credential offer type")
	}
	// §4.1.1 makes credential_issuer required, so a response without one is
	// not an offer. Some issuers answer a spent offer with HTTP 200 and an error
	// body.
	if strings.TrimSpace(offer.CredentialIssuer) == "" {
		return w.keepApprovedOffer(offerURI, approved, fmt.Errorf("the response carried no credential_issuer"))
	}
	// An offer with a different issuer or different credentials is not the one
	// the user approved.
	if approved != nil && !sameCredentialOffer(approved, offer) {
		w.addProtocolWarning("issuance", "credential_offer_changed",
			fmt.Sprintf("The credential_offer_uri now offers %s rather than the %s this issuance was approved for, continuing with what was approved",
				offerSummary(offer), offerSummary(approved)),
			map[string]any{
				"issuer":          approved.CredentialIssuer,
				"offered_issuer":  offer.CredentialIssuer,
				"offered_configs": offer.CredentialConfigurationIDs,
				"offer_uri":       offerURI,
			})
		return approved, nil
	}
	return offer, nil
}

func (w *Wallet) keepApprovedOffer(offerURI string, approved *oid4vc.CredentialOffer, cause error) (*oid4vc.CredentialOffer, error) {
	if approved == nil {
		return nil, fmt.Errorf("parsing credential offer: %w", cause)
	}
	w.addProtocolWarning("issuance", "credential_offer_reread_failed",
		"The credential_offer_uri could not be read a second time, continuing with the offer this issuance was approved for",
		map[string]any{
			"issuer":    approved.CredentialIssuer,
			"offer_uri": offerURI,
			"error":     cause.Error(),
		})
	return approved, nil
}

// Compare issuer and credential configurations with the approved offer. Grants may
// change because issuers can generate a fresh pre-authorized code on each fetch.
func sameCredentialOffer(approved, offered *oid4vc.CredentialOffer) bool {
	if approved.CredentialIssuer != offered.CredentialIssuer {
		return false
	}
	return slices.Equal(approved.CredentialConfigurationIDs, offered.CredentialConfigurationIDs)
}

func offerSummary(offer *oid4vc.CredentialOffer) string {
	issuer := strings.TrimSpace(offer.CredentialIssuer)
	if issuer == "" {
		issuer = "an unnamed issuer"
	}
	if len(offer.CredentialConfigurationIDs) == 0 {
		return issuer
	}
	return fmt.Sprintf("%s from %s", strings.Join(offer.CredentialConfigurationIDs, ", "), issuer)
}

// ProcessCredentialOffer processes an OID4VCI credential offer URI for a user
// who is present. When the issuer asks for an interaction during the flow,
// the wallet shows it to that user.
func (w *Wallet) ProcessCredentialOffer(offerURI string) (*IssuanceResult, error) {
	return w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{})
}

func (w *Wallet) ProcessCredentialOfferWithOptions(offerURI string, opts OfferOptions) (*IssuanceResult, error) {
	var findings []string
	opts.findings = &findings
	result, err := w.processCredentialOffer(offerURI, opts)
	if result != nil && result.Findings == nil {
		result.Findings = findings
	}
	return result, err
}

func (w *Wallet) processCredentialOffer(offerURI string, opts OfferOptions) (_ *IssuanceResult, err error) {
	offer, err := w.resolveOffer(offerURI, opts.ResolvedOffer)
	if err != nil {
		w.addProtocolLog("issuance", "issuance_failed", fmt.Sprintf("The credential offer could not be read: %v", err), false, map[string]any{
			"offer_uri": offerURI,
			"error":     err.Error(),
		})
		return nil, err
	}
	w.addProtocolLog("issuance", "credential_offer", fmt.Sprintf("Received credential offer from %s", offer.CredentialIssuer), true, map[string]any{
		"direction":                    "inbound",
		"offer_uri":                    offerURI,
		"issuer":                       offer.CredentialIssuer,
		"credential_configuration_ids": offer.CredentialConfigurationIDs,
		"grants":                       offer.Grants,
	})

	// Record terminal errors so the activity log explains why issuance stopped,
	// including failures after the credential response.
	defer func() {
		if err != nil {
			w.addProtocolLog("issuance", "issuance_failed",
				fmt.Sprintf("Issuance from %s did not finish: %v", offer.CredentialIssuer, err), false, map[string]any{
					"issuer": offer.CredentialIssuer,
					"error":  err.Error(),
				})
		}
	}()

	configID, err := chooseOfferConfiguration(offer, opts.ConfigurationID)
	if err != nil {
		return nil, err
	}
	metadata, err := w.loadIssuerMetadata(offer.CredentialIssuer, []string{configID}, opts.addFindings)
	if err != nil {
		return nil, err
	}

	grantType := preAuthorizedCodeGrant
	if offer.Grants.PreAuthorizedCode == "" {
		grantType = "authorization_code"
	}
	// A missing authorization server document is not fatal. The endpoints fall
	// back to the issuer's own metadata, so oauthErr is kept for later checks.
	authServer, err := selectAuthorizationServer(metadata, offer, grantType)
	if err != nil {
		return nil, err
	}
	oauthMeta, oauthErr := w.fetchLoggedMetadata(oauthMetadataFetch(authServer))
	// Check support before consuming the grant so the offer can still be used with
	// another wallet.
	if err := w.checkAuthorizationServerGrant(authServer, oauthMeta, grantType); err != nil {
		return nil, err
	}
	if server, meta, ok := w.fallbackAuthorizationServer(metadata, authServer, oauthMeta, grantType); ok {
		authServer, oauthMeta, oauthErr = server, meta, nil
	}

	tokenEndpoint, err := w.resolveTokenEndpoint(metadata, oauthMeta, authServer)
	if err != nil {
		return nil, err
	}
	credentialEndpoint, err := w.resolveCredentialEndpoint(metadata, offer.CredentialIssuer)
	if err != nil {
		return nil, err
	}

	// Strict mode rejects HAIP findings. Debug mode logs them and continues.
	if w.HAIPChecks() {
		violations := append(ValidateHAIPIssuanceCompliance(offer, oauthMeta), haipIssuerMetadataViolations(metadata, configID)...)
		if len(violations) > 0 {
			if err := w.reportHAIPViolations("Credential offer", offer.CredentialIssuer, violations); err != nil {
				return nil, err
			}
			opts.addFindings(violations...)
		}
	}

	session := issuanceSession{
		metadata: metadata,
		renewal: CredentialRenewal{
			Issuer:             offer.CredentialIssuer,
			TokenEndpoint:      tokenEndpoint,
			CredentialEndpoint: credentialEndpoint,
			ConfigurationID:    configID,
			UseDPoP:            usesDPoP(oauthMeta),
		},
		nonces: &dpopNonceState{},
		report: opts.addFindings,
	}

	// A pre-authorized flow can take its token endpoint from the issuer
	// metadata, so only the authorization code flow needs the server's own
	// document. A document that is there is checked for both grants.
	authServerErr := oauthErr
	if authServerErr == nil {
		authServerErr = validateAuthorizationServerIssuer(authServer, oauthMeta)
	} else if offer.Grants.PreAuthorizedCode != "" {
		authServerErr = nil
	}
	if authServerErr != nil {
		if err := w.reportServerDeviation(fmt.Sprintf("authorization server metadata of %s: %v", authServer, authServerErr)); err != nil {
			return nil, err
		}
	}
	if offer.Grants.PreAuthorizedCode == "" {
		return w.processAuthorizationCodeOffer(offer, session, oauthMeta, opts)
	}

	// An issuer may protect the pre-authorized token request with DPoP,
	// attestation-based client authentication and key attestation. Its metadata
	// says which of them apply.
	session.renewal.ClientAuth = w.resolveClientAuthentication("", clientAuthContext{oauthMeta: oauthMeta, tokenEndpoint: tokenEndpoint})
	if session.renewal.ClientAuth != nil {
		// A pre-authorized offer carries no client_id, and the wallet is not
		// registered with the issuer. The attestation identifies the wallet
		// itself, so the wallet's own identifier is the client.
		session.renewal.ClientID = w.walletClientIdentifier()
	}

	txCode := opts.TxCode
	// §4.1.1 puts tx_code in the grant when the Authorization Server expects
	// one. An auto-accepting wallet shows no dialog. An API caller supplies the
	// code with the call.
	if offer.Grants.RequiresTxCode() && strings.TrimSpace(txCode) == "" {
		hint := ""
		if h := offer.Grants.TxCodeHint(); h != "" {
			hint = " (" + h + ")"
		}
		return nil, fmt.Errorf("this offer requires a transaction code, which the issuer delivers separately: supply it as tx_code on the call, or --tx-code on the command line%s", hint)
	}
	// OID4VCI 1.0 §6.1: "the client_id parameter is only needed when a form of
	// Client Authentication that relies on this parameter is used."
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", preAuthorizedCodeGrant)
	tokenForm.Set("pre-authorized_code", offer.Grants.PreAuthorizedCode)
	if txCode != "" {
		tokenForm.Set("tx_code", txCode)
	}
	return w.issueWithToken(session, tokenForm)
}

// walletClientIdentifier is the client identifier the wallet attests for
// itself: the configured OID4VCI client_id, or else its base URL.
func (w *Wallet) walletClientIdentifier() string {
	if id := strings.TrimSpace(w.VCIClientID); id != "" {
		return id
	}
	return strings.TrimSpace(w.BaseURL)
}

func verifyImportedJWTMetadataSignature(raw string, client *http.Client) (string, string) {
	token, err := sdjwt.Parse(raw)
	if err != nil {
		return "", ""
	}
	result, source, err := validate.VerifyJWTSignature(token, nil, nil, client)
	if err != nil {
		return "fail", err.Error()
	}
	if result == nil {
		return "skipped", "Issuer metadata verification unavailable"
	}
	if result.SignatureValid {
		if source != "" {
			return "pass", fmt.Sprintf("Signature valid (%s, via %s)", result.Algorithm, source)
		}
		return "pass", fmt.Sprintf("Signature valid (%s)", result.Algorithm)
	}
	if source != "" {
		return "fail", fmt.Sprintf("Signature invalid via %s", source)
	}
	return "fail", "Signature invalid"
}

type metadataFetch struct {
	event         string // log event prefix, e.g. "issuer_metadata"
	fetchLabel    string // reads as "Fetch <fetchLabel> from <issuer>"
	responseLabel string // reads as "<responseLabel> response from <issuer>"
	wellKnown     string // the .well-known suffix, for the logged URL
	issuer        string
	fetch         func(*http.Client, string, ...*LogPayload) (map[string]any, error)
}

func (w *Wallet) fetchLoggedMetadata(f metadataFetch) (map[string]any, error) {
	url, _ := wellKnownURL(f.issuer, f.wellKnown)
	w.addProtocolLog("issuance", f.event+"_request", fmt.Sprintf("Fetch %s from %s", f.fetchLabel, f.issuer), true, map[string]any{
		"direction": "outbound",
		"method":    "GET",
		"url":       url,
		"issuer":    f.issuer,
	})

	payload := &LogPayload{Label: "Response"}
	metadata, err := f.fetch(w.HTTPClient(), f.issuer, payload)

	details := map[string]any{
		"direction": "inbound",
		"url":       url,
		"issuer":    f.issuer,
	}
	if err != nil {
		details["error"] = err.Error()
	} else {
		details["metadata"] = metadata
	}
	w.addProtocolLog("issuance", f.event+"_response", fmt.Sprintf("%s response from %s", f.responseLabel, f.issuer), err == nil, details, payload)

	return metadata, err
}

// metadataProblem receives a problem with signed issuer metadata, such as a
// missing iat or a past exp (§12.2.3). An error refuses the metadata.
type metadataProblem func(problem string) error

// reportMetadataProblem reports a metadata problem as a deviation and hands it
// to report.
func (w *Wallet) reportMetadataProblem(report func(findings ...string)) metadataProblem {
	return func(problem string) error {
		if err := w.reportDeviation(deviation{action: "issuance", event: "issuer_metadata_freshness", detail: problem}); err != nil {
			return err
		}
		report(problem)
		return nil
	}
}

// fetchIssuerMetadataDocument also returns the certificate chain of signed
// metadata. preferSigned asks for the signed form first. The ARF requires
// issuers to provide it (ISSU_22, ISSU_32).
func fetchIssuerMetadataDocument(client *http.Client, issuer string, preferSigned bool, onProblem metadataProblem, payloads ...*LogPayload) (map[string]any, []*x509.Certificate, error) {
	metadataURL, err := wellKnownURL(issuer, "openid-credential-issuer")
	if err != nil {
		return nil, nil, fmt.Errorf("building issuer metadata URL: %w", err)
	}

	resp, err := fetchMetadataDocument(func() (*http.Request, error) {
		req, err := http.NewRequest("GET", metadataURL, nil)
		if err != nil {
			return nil, fmt.Errorf("creating metadata request: %w", err)
		}
		// §12.2.2 allows application/json and application/jwt. Listing both
		// tells the issuer that signed metadata is supported, and the quality
		// value says which one the wallet prefers.
		// openidvci-issuer-metadata+jwt is the typ header of the signed form
		// (§12.2.3). It is not a media type.
		accept := "application/json, application/jwt"
		if preferSigned {
			accept = "application/jwt, application/json;q=0.5"
		}
		req.Header.Set("Accept", accept)
		return req, nil
	}, client)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := format.ReadRemoteBody(resp.Body, "issuer response")
		if payload := firstLogPayload(payloads); payload != nil {
			payload.Body = string(body)
		}
		return nil, nil, fmt.Errorf("metadata request failed (%d): %s", resp.StatusCode, string(body))
	}

	body, err := format.ReadRemoteBody(resp.Body, "issuer response")
	if err != nil {
		return nil, nil, fmt.Errorf("reading metadata: %w", err)
	}
	if payload := firstLogPayload(payloads); payload != nil {
		payload.Body = string(body)
	}
	return parseIssuerMetadataDocument(body, resp.Header.Get("Content-Type"), issuer, onProblem)
}

func wellKnownURL(issuerOrServer, wellKnownType string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(issuerOrServer))
	if err != nil {
		return "", fmt.Errorf("parsing issuer URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("issuer URL must be absolute")
	}
	path := parsed.EscapedPath()
	if wellKnownType == "oauth-authorization-server" {
		// RFC 8414 §3.1: remove a terminating "/" from the issuer path before
		// inserting the well-known segment. OID4VCI 1.0 §12.2.2 preserves the
		// Credential Issuer Identifier path verbatim, so only the OAuth AS
		// metadata URL strips it.
		path = strings.TrimSuffix(path, "/")
	}
	return fmt.Sprintf("%s://%s/.well-known/%s%s", parsed.Scheme, parsed.Host, wellKnownType, path), nil
}

// parseIssuerMetadataDocument also returns the certificate chain that signed
// the metadata, or nil for unsigned metadata. OpenID4VCI 1.0 §12.2.3 requires
// iat in signed metadata, and exp limits its use. onProblem decides what
// happens to metadata that breaks this.
func parseIssuerMetadataDocument(body []byte, contentType, issuer string, onProblem metadataProblem) (map[string]any, []*x509.Certificate, error) {
	raw := strings.TrimSpace(string(body))
	if raw == "" {
		return nil, nil, fmt.Errorf("issuer metadata response was empty")
	}

	var metadata map[string]any
	var chain []*x509.Certificate
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if mediaType == "application/jwt" || strings.Contains(mediaType, "openidvci-issuer-metadata+jwt") || isLikelyCompactJWT(raw) {
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing signed issuer metadata: %w", err)
		}
		if err := verifySignedIssuerMetadata(token, issuer); err != nil {
			return nil, nil, err
		}
		if problem := signedIssuerMetadataFreshness(token); problem != "" {
			if err := onProblem("OpenID4VCI 1.0 §12.2.3: " + problem); err != nil {
				return nil, nil, err
			}
		}
		metadata = token.Payload
		chain, _ = signedIssuerMetadataChain(token)
	} else if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, nil, fmt.Errorf("parsing metadata JSON: %w", err)
	}

	if err := checkCredentialIssuerIdentifier(metadata, issuer); err != nil {
		return nil, nil, err
	}
	return metadata, chain, nil
}

// checkCredentialIssuerIdentifier checks that the metadata matches the
// identifier it was fetched for.
//
// OpenID4VCI 1.0 §12.2.4 on credential_issuer: "The value MUST be identical to
// the Credential Issuer's identifier value into which the well-known URI string
// was inserted to create the URL used to retrieve the metadata. If these values
// are not identical (when compared using a simple string comparison with no
// normalization), the data contained in the response MUST NOT be used."
func checkCredentialIssuerIdentifier(metadata map[string]any, issuer string) error {
	declared, _ := metadata["credential_issuer"].(string)
	if sameIdentifier(declared, issuer) {
		return nil
	}
	if declared == "" {
		return fmt.Errorf("issuer metadata for %q carries no credential_issuer identifier", issuer)
	}
	return fmt.Errorf("issuer metadata declares credential_issuer %q but was fetched for %q, so it cannot be used", declared, issuer)
}

func isLikelyCompactJWT(raw string) bool {
	if strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "[") {
		return false
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return false
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				continue
			}
			return false
		}
	}
	return true
}

// issuerMetadataTrustAnchors holds the roots for signed Credential Issuer
// Metadata. The signer's certificate chain must end in one of them. nil means
// the host's root store, because the wallet has no issuer anchors of its own.
// Tests set it to their own CA.
var issuerMetadataTrustAnchors *x509.CertPool

// signedIssuerMetadataTyp is the typ header value §12.2.3 requires on signed
// Credential Issuer Metadata. It is a JWT type, not a media type.
const signedIssuerMetadataTyp = "openidvci-issuer-metadata+jwt"

// verifySignedIssuerMetadata checks signed Credential Issuer Metadata against
// §12.2.3: typ openidvci-issuer-metadata+jwt, an asymmetric alg, a sub
// matching the Credential Issuer Identifier, an iat, an exp that has not
// passed, and the signature.
//
// §12.2.3 also asks the wallet to "establish trust in the signer" and leaves
// the mechanism out of scope. The wallet tries to build an x5c chain to a
// trusted root. It holds no issuer CAs (ADR-0009), so it also accepts a signer
// without such a chain.
func verifySignedIssuerMetadata(token *sdjwt.Token, issuer string) error {
	if token == nil {
		return fmt.Errorf("signed issuer metadata token is nil")
	}
	if typ, _ := token.Header["typ"].(string); !format.JOSETypeIs(typ, signedIssuerMetadataTyp) {
		return fmt.Errorf("signed issuer metadata has typ %q, want %q", typ, signedIssuerMetadataTyp)
	}
	alg, _ := token.Header["alg"].(string)
	if alg == "" || strings.EqualFold(alg, "none") || strings.HasPrefix(strings.ToUpper(alg), "HS") {
		return fmt.Errorf("signed issuer metadata alg %q is not an asymmetric digital signature algorithm", alg)
	}
	sub, _ := token.Payload["sub"].(string)
	if sub != issuer {
		return fmt.Errorf("signed issuer metadata sub %q does not match the credential issuer identifier %q", sub, issuer)
	}
	certs, err := signedIssuerMetadataChain(token)
	if err != nil {
		return err
	}
	result := sdjwt.Verify(token, certs[0].PublicKey)
	if result == nil || !result.SignatureValid {
		return fmt.Errorf("issuer metadata signature is invalid")
	}
	if err := verifyIssuerMetadataChainTrust(certs); err != nil {
		log.Printf("[VCI] signed issuer metadata signer could not be anchored (%v). The wallet holds no issuer trust anchors, so the metadata is read as signed but unplaced", err)
	}
	return nil
}

func signedIssuerMetadataFreshness(token *sdjwt.Token) string {
	if _, ok := token.Payload["iat"].(float64); !ok {
		return "the signed issuer metadata has no iat"
	}
	if exp, ok := token.Payload["exp"].(float64); ok && time.Unix(int64(exp), 0).Before(time.Now()) {
		return fmt.Sprintf("the signed issuer metadata expired at %s", time.Unix(int64(exp), 0).UTC().Format(time.RFC3339))
	}
	return ""
}

func signedIssuerMetadataChain(token *sdjwt.Token) ([]*x509.Certificate, error) {
	x5cRaw, ok := token.Header["x5c"]
	if !ok {
		return nil, fmt.Errorf("signed issuer metadata carries no x5c, so its signer cannot be trusted")
	}
	certs, err := certchain.FromX5C(x5cRaw)
	if err != nil {
		return nil, fmt.Errorf("parsing issuer metadata x5c: %w", err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("signed issuer metadata x5c is empty, so its signer cannot be trusted")
	}
	return certs, nil
}

// verifyIssuerMetadataChainTrust reports whether a signed metadata chain ends
// in one of issuerMetadataTrustAnchors.
func verifyIssuerMetadataChainTrust(certs []*x509.Certificate) error {
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         issuerMetadataTrustAnchors,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

// preAuthorizedCodeGrant is the grant type of the pre-authorized code flow
// (§4.1.1).
const preAuthorizedCodeGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// authorizationServersFromMetadata lists the authorization_servers entries of
// the Credential Issuer Metadata. §12.2.4 makes the parameter optional: "If
// this parameter is omitted, the entity providing the Credential Issuer is also
// acting as the Authorization Server".
func authorizationServersFromMetadata(metadata map[string]any) []string {
	raw, ok := metadata["authorization_servers"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		if s, _ := entry.(string); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// offerAuthorizationServer reads the optional authorization_server hint in
// the offer's grant of grantType. §4.1.1 defines it as "OPTIONAL string that
// the Wallet can use to identify the Authorization Server to use with this
// grant type when authorization_servers parameter in the Credential Issuer
// metadata has multiple entries."
func offerAuthorizationServer(offer *oid4vc.CredentialOffer, grantType string) string {
	if offer == nil {
		return ""
	}
	grants, _ := offer.FullJSON["grants"].(map[string]any)
	grant, _ := grants[grantType].(map[string]any)
	server, _ := grant["authorization_server"].(string)
	return server
}

// selectAuthorizationServer picks the authorization server for this offer.
// §12.2.4: the wallet "MUST NOT proceed with the flow if the
// authorization_server Credential Offer parameter value does not match any of
// the entries in the authorization_servers array". A hint that matches no
// entry is an error.
func selectAuthorizationServer(metadata map[string]any, offer *oid4vc.CredentialOffer, grantType string) (string, error) {
	servers := authorizationServersFromMetadata(metadata)
	hint := offerAuthorizationServer(offer, grantType)
	issuer := ""
	if offer != nil {
		issuer = offer.CredentialIssuer
	}
	if hint == "" {
		if len(servers) == 0 {
			return issuer, nil
		}
		return servers[0], nil
	}
	for _, candidate := range servers {
		if candidate == hint {
			return hint, nil
		}
	}
	return "", fmt.Errorf("credential offer names authorization server %q, which the issuer metadata of %s does not list", hint, issuer)
}

// grantTypesSupported reports false when the metadata has no
// grant_types_supported. The RFC 8414 default (authorization_code and implicit)
// says nothing about pre-authorized issuance.
func grantTypesSupported(oauthMeta map[string]any) ([]string, bool) {
	raw, ok := oauthMeta["grant_types_supported"].([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		if s, _ := entry.(string); s != "" {
			out = append(out, s)
		}
	}
	return out, len(out) > 0
}

// checkAuthorizationServerGrant reports an authorization server whose metadata
// does not list the grant type of this issuance. §12.2.4: "by examining the
// grant_types_supported values, the Wallet can filter the server to use based
// on the grant type it plans to use". §4.1.1 defines the offer's
// authorization_server as the server to use "with this grant type".
func (w *Wallet) checkAuthorizationServerGrant(authServer string, oauthMeta map[string]any, grantType string) error {
	supported, stated := grantTypesSupported(oauthMeta)
	if !stated || slices.Contains(supported, grantType) {
		return nil
	}
	detail := fmt.Sprintf("Authorization server %s does not support %s, which this issuance uses. Its metadata supports %s.",
		authServer, grantType, strings.Join(supported, ", "))
	details := map[string]any{
		"authorization_server":  authServer,
		"grant_type":            grantType,
		"grant_types_supported": supported,
	}
	return w.reportDeviation(deviation{action: "issuance", event: "authorization_server_grant_unsupported", detail: detail, details: details})
}

func oauthMetadataFetch(issuer string) metadataFetch {
	return metadataFetch{
		event:         "oauth_metadata",
		fetchLabel:    "OAuth metadata",
		responseLabel: "OAuth metadata",
		wellKnown:     "oauth-authorization-server",
		issuer:        issuer,
		fetch:         fetchOAuthMetadata,
	}
}

// fallbackAuthorizationServer finds another advertised authorization server
// that lists the grant type of this issuance. It runs only when the metadata
// of the selected server leaves that grant out. §4.1.1 makes the offer's
// authorization_server a value the wallet "can use". Strict mode refuses in
// checkAuthorizationServerGrant before this runs.
func (w *Wallet) fallbackAuthorizationServer(metadata map[string]any, authServer string, oauthMeta map[string]any, grantType string) (string, map[string]any, bool) {
	supported, stated := grantTypesSupported(oauthMeta)
	if !stated || slices.Contains(supported, grantType) {
		return "", nil, false
	}
	for _, candidate := range authorizationServersFromMetadata(metadata) {
		if candidate == authServer {
			continue
		}
		candidateMeta, err := w.fetchLoggedMetadata(oauthMetadataFetch(candidate))
		if err != nil {
			continue
		}
		candidateGrants, candidateStated := grantTypesSupported(candidateMeta)
		if !candidateStated || !slices.Contains(candidateGrants, grantType) {
			continue
		}
		w.addProtocolWarning("issuance", "authorization_server_fallback",
			fmt.Sprintf("Continuing with authorization server %s, which lists %s in its grant_types_supported, instead of %s.",
				candidate, grantType, authServer),
			map[string]any{
				"authorization_server": candidate,
				"replaced_server":      authServer,
				"grant_type":           grantType,
			})
		return candidate, candidateMeta, true
	}
	w.addProtocolWarning("issuance", "authorization_server_fallback_unavailable",
		fmt.Sprintf("No other advertised authorization server states support for %s, continuing with %s.",
			grantType, authServer),
		map[string]any{
			"authorization_server": authServer,
			"grant_type":           grantType,
		})
	return "", nil, false
}

// validateAuthorizationServerIssuer applies RFC 8414 §3.3: "The "issuer" value
// returned MUST be identical to the authorization server's issuer identifier
// value into which the well-known URI string was inserted to create the URL
// used to retrieve the metadata."
func validateAuthorizationServerIssuer(authServer string, oauthMeta map[string]any) error {
	issuer, _ := oauthMeta["issuer"].(string)
	if issuer == "" {
		return fmt.Errorf("authorization server metadata missing issuer")
	}
	if !sameIdentifier(issuer, authServer) {
		return fmt.Errorf("authorization server issuer %q did not match authorization server %q", issuer, authServer)
	}
	return nil
}

// sameIdentifier compares issuer identifiers by simple string comparison (RFC
// 3986 §6.2.1). RFC 8414 §3.3, RFC 9207 §2.4 and OID4VCI 1.0 §12.2.4 each
// require it for the identifier they define.
func sameIdentifier(a, b string) bool {
	return a == b
}

// resolveTokenEndpoint resolves the token endpoint. token_endpoint is an
// authorization server metadata parameter (RFC 8414 §2). §12.2.4 defines no
// Credential Issuer Metadata equivalent, so the issuer metadata is only a
// fallback. Without either, strict mode refuses and debug mode warns and uses
// the conventional path on the authorization server in use.
func (w *Wallet) resolveTokenEndpoint(metadata map[string]any, oauthMeta map[string]any, authServer string) (string, error) {
	if ep, ok := oauthMeta["token_endpoint"].(string); ok && ep != "" {
		return ep, nil
	}
	if ep, ok := metadata["token_endpoint"].(string); ok && ep != "" {
		return ep, nil
	}
	fallback := strings.TrimRight(authServer, "/") + "/token"
	if err := w.reportServerDeviation(fmt.Sprintf("the authorization server metadata has no token_endpoint, which RFC 8414 requires (assuming %s)", fallback)); err != nil {
		return "", err
	}
	return fallback, nil
}

// fetchOAuthMetadata reads the OAuth 2.0 Authorization Server Metadata
// (RFC 8414) from /.well-known/oauth-authorization-server.
func fetchOAuthMetadata(client *http.Client, authServer string, payloads ...*LogPayload) (map[string]any, error) {
	oauthURL, err := wellKnownURL(authServer, "oauth-authorization-server")
	if err != nil {
		return nil, err
	}
	resp, err := fetchMetadataDocument(func() (*http.Request, error) {
		req, err := http.NewRequest("GET", oauthURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		return req, nil
	}, client)
	if err != nil {
		return nil, fmt.Errorf("no OAuth metadata found at %s: %w", authServer, err)
	}
	defer resp.Body.Close()
	payload := firstLogPayload(payloads)
	if resp.StatusCode != http.StatusOK {
		if payload != nil {
			body, _ := format.ReadRemoteBody(resp.Body, "OAuth metadata")
			payload.Body = string(body)
		}
		return nil, fmt.Errorf("no OAuth metadata found at %s: HTTP %d", authServer, resp.StatusCode)
	}
	var meta map[string]any
	body, decodeErr := format.DecodeRemoteJSON(resp.Body, "OAuth metadata", &meta)
	if payload != nil {
		payload.Body = string(body)
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("parsing OAuth metadata from %s: %w", authServer, decodeErr)
	}
	return meta, nil
}

// resolveCredentialEndpoint resolves the credential endpoint. OpenID4VCI 1.0
// makes credential_endpoint REQUIRED in the Credential Issuer Metadata. Strict
// mode refuses metadata without it. Debug mode warns and uses the conventional
// path.
func (w *Wallet) resolveCredentialEndpoint(metadata map[string]any, issuer string) (string, error) {
	if ep, ok := metadata["credential_endpoint"].(string); ok && ep != "" {
		return ep, nil
	}
	fallback := strings.TrimRight(issuer, "/") + "/credential"
	if err := w.reportServerDeviation(fmt.Sprintf("the credential issuer metadata has no credential_endpoint, which OID4VCI 1.0 requires (assuming %s)", fallback)); err != nil {
		return "", err
	}
	return fallback, nil
}

func resolveCredentialFormat(metadata map[string]any, configID string) string {
	configs, ok := metadata["credential_configurations_supported"].(map[string]any)
	if !ok {
		return ""
	}
	cfg, ok := configs[configID].(map[string]any)
	if !ok {
		return ""
	}
	f, _ := cfg["format"].(string)
	return f
}

func createProofJWT(holderKey *ecdsa.PrivateKey, audience, clientID, cNonce string, extraHeader map[string]any) (string, error) {
	jwkJSON := mock.PublicKeyJWK(&holderKey.PublicKey)
	var jwk map[string]any
	if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
		return "", fmt.Errorf("parsing holder JWK: %w", err)
	}

	header := map[string]any{
		"alg": jws.AlgES256,
		"typ": format.TypeKeyProof,
		"jwk": jwk,
	}
	for key, value := range extraHeader {
		header[key] = value
	}

	payload := map[string]any{
		"aud": audience,
		"iat": time.Now().Unix(),
	}
	// OID4VCI 1.0 Appendix F.1: iss is the client_id of the client making the
	// credential request. An anonymous pre-authorized flow has no client_id.
	if clientID != "" {
		payload["iss"] = clientID
	}
	// The nonce claim repeats the issuer's c_nonce. Without a c_nonce the
	// issuer expects no nonce claim.
	if cNonce != "" {
		payload["nonce"] = cNonce
	}

	return signJWT(header, payload, holderKey)
}

// resolveCredentialIdentifier returns a credential_identifier from the token
// response's authorization_details and prefers the entry for configID. OID4VCI
// 1.0 has the credential request send it in place of the
// credential_configuration_id from the offer. authorizedOther is the
// configuration of the returned identifier when no entry matches configID.
func resolveCredentialIdentifier(tokenResp map[string]any, configID string) (identifier, authorizedOther string) {
	authDetails, _ := tokenResp["authorization_details"].([]any)
	var firstID, firstConfig string
	for _, detail := range authDetails {
		d, ok := detail.(map[string]any)
		if !ok {
			continue
		}
		ids, _ := d["credential_identifiers"].([]any)
		if len(ids) == 0 {
			continue
		}
		id, ok := ids[0].(string)
		if !ok {
			continue
		}
		config, _ := d["credential_configuration_id"].(string)
		if configID != "" && config == configID {
			return id, ""
		}
		if firstID == "" {
			firstID, firstConfig = id, config
		}
	}
	if firstID != "" && configID != "" && firstConfig != configID {
		return firstID, firstConfig
	}
	return firstID, ""
}

// OID4VCI 1.0 §6.1 only RECOMMENDS that "the Credential Issuer issues an Access
// Token valid only for the Credentials indicated in the Credential Offer". A
// token for another configuration is therefore a warning in every mode.
func (w *Wallet) reportAuthorizedConfiguration(issuer, offered, authorized string) {
	if authorized == "" {
		return
	}
	detail := fmt.Sprintf("the token response from %s authorizes credential configuration %q, not the offered %q. The credential request names the identifier it returned", issuer, authorized, offered)
	log.Printf("[VCI] WARNING: %s", detail)
	w.addProtocolWarning("issuance", "token_authorizes_other_configuration", detail, map[string]any{
		"offered_configuration":    offered,
		"authorized_configuration": authorized,
	})
}

// buildCredentialResponseEncryptionRequest builds the
// credential_response_encryption object of §8.2. It returns nil when the
// wallet must not ask for an encrypted response. §8.2: "Credential Request
// encryption MUST be used if the credential_response_encryption parameter is
// included". An issuer without a usable request encryption key therefore gets
// no response encryption request.
func buildCredentialResponseEncryptionRequest(mode ValidationMode, metadata map[string]any, holderKey *ecdsa.PrivateKey) (map[string]any, error) {
	if holderKey == nil {
		return nil, nil
	}
	raw, ok := metadata["credential_response_encryption"].(map[string]any)
	if !ok {
		return nil, nil
	}
	required, _ := raw["encryption_required"].(bool)

	alg := firstSupportedString(raw["alg_values_supported"], preferredCredentialResponseEncryptionAlgs)
	enc := firstSupportedString(raw["enc_values_supported"], preferredCredentialResponseEncryptionEncs)
	if alg == "" || enc == "" {
		if required {
			return nil, fmt.Errorf("issuer requires an encrypted credential response but advertised no alg or enc value the wallet supports")
		}
		return nil, nil
	}

	requestEncryption, err := selectCredentialRequestEncryption(mode, metadata)
	if err != nil {
		return nil, err
	}
	if requestEncryption == nil {
		if required {
			return nil, fmt.Errorf("issuer requires an encrypted credential response but published no usable credential_request_encryption key, and the credential request must be encrypted whenever credential_response_encryption is sent")
		}
		log.Printf("[VCI] Not requesting credential response encryption: the credential request itself cannot be encrypted")
		return nil, nil
	}

	return map[string]any{
		"jwk": publicCredentialResponseEncryptionJWK(&holderKey.PublicKey, alg),
		"enc": enc,
	}, nil
}

func publicCredentialResponseEncryptionJWK(key *ecdsa.PublicKey, alg string) map[string]any {
	jwk := mock.PublicKeyJWKMap(key)
	return map[string]any{
		"kty": jwk["kty"],
		"crv": jwk["crv"],
		"x":   jwk["x"],
		"y":   jwk["y"],
		"kid": mock.KeyIDForPublicKey(key),
		"use": "enc",
		"alg": alg,
	}
}

func firstSupportedString(raw any, preferred []string) string {
	values := supportedStringValues(raw)
	if len(values) == 0 {
		return ""
	}
	for _, want := range preferred {
		for _, got := range values {
			if got == want {
				return got
			}
		}
	}
	return ""
}

func supportedStringValues(raw any) []string {
	switch values := raw.(type) {
	case []any:
		out := make([]string, 0, len(values))
		for _, candidate := range values {
			if got, _ := candidate.(string); got != "" {
				out = append(out, got)
			}
		}
		return out
	case []string:
		return values
	default:
		return nil
	}
}

type credentialRequestEncryptionParams struct {
	key *ecdsa.PublicKey
	kid string
	alg string
	enc string
}

func prepareCredentialRequestBody(mode ValidationMode, metadata map[string]any, reqBody map[string]any) ([]byte, string, error) {
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "", fmt.Errorf("marshaling request: %w", err)
	}
	encryption, err := selectCredentialRequestEncryption(mode, metadata)
	if err != nil {
		return nil, "", err
	}
	if encryption == nil {
		return bodyJSON, "application/json", nil
	}
	jwe, _, err := EncryptJWEWithContentType(bodyJSON, encryption.key, encryption.kid, encryption.alg, encryption.enc, "json", nil, nil)
	if err != nil {
		return nil, "", fmt.Errorf("encrypting credential request: %w", err)
	}
	return []byte(jwe), "application/jwt", nil
}

func selectCredentialRequestEncryption(mode ValidationMode, metadata map[string]any) (*credentialRequestEncryptionParams, error) {
	raw, ok := metadata["credential_request_encryption"].(map[string]any)
	if !ok {
		return nil, nil
	}
	enc := firstSupportedString(raw["enc_values_supported"], preferredCredentialRequestEncryptionEncs)
	if enc == "" {
		if credentialRequestEncryptionRequired(raw) {
			return nil, fmt.Errorf("credential request encryption is required but no supported enc value was advertised")
		}
		return nil, nil
	}
	jwks, ok := raw["jwks"].(map[string]any)
	if !ok {
		if credentialRequestEncryptionRequired(raw) {
			return nil, fmt.Errorf("credential request encryption is required but jwks is missing")
		}
		return nil, nil
	}
	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) == 0 {
		if credentialRequestEncryptionRequired(raw) {
			return nil, fmt.Errorf("credential request encryption is required but jwks.keys is missing")
		}
		return nil, nil
	}
	for _, keyRaw := range keys {
		jwk, ok := keyRaw.(map[string]any)
		if !ok {
			continue
		}
		if use, _ := jwk["use"].(string); use != "" && use != "enc" {
			continue
		}
		alg, _ := jwk["alg"].(string)
		if alg != jwe.AlgECDHES {
			continue
		}
		kid, _ := jwk["kid"].(string)
		if kid == "" {
			continue
		}
		x, _ := jwk["x"].(string)
		y, _ := jwk["y"].(string)
		key, finding, err := ecdsaPublicKeyFromJWK(mode, x, y)
		if err != nil {
			continue
		}
		// Debug mode continued past a specification violation. No wallet is in
		// scope, so the finding goes to the process log.
		if finding != "" {
			log.Printf("[VCI] WARNING: %s", finding)
		}
		return &credentialRequestEncryptionParams{
			key: key,
			kid: kid,
			alg: alg,
			enc: enc,
		}, nil
	}
	if credentialRequestEncryptionRequired(raw) {
		return nil, fmt.Errorf("credential request encryption is required but no usable ECDH-ES encryption key was advertised")
	}
	return nil, nil
}

func credentialRequestEncryptionRequired(raw map[string]any) bool {
	required, _ := raw["encryption_required"].(bool)
	return required
}

// Group HAIP findings in one activity entry. Return an error only in strict mode.
func (w *Wallet) reportHAIPViolations(subject, issuer string, violations []string) error {
	return w.reportDeviation(deviation{
		action: "issuance", event: "haip_violation",
		detail:  findingsSummary(specCitedSummary(subject, violations), violations),
		details: map[string]any{"issuer": issuer, "findings": violations},
		refusal: fmt.Errorf("%s: %s", strings.ToLower(subject), strings.Join(violations, ", ")),
	})
}

// issuanceChallenge obtains the c_nonce for signing the key proofs. §8.2
// leaves one source: "The c_nonce value is retrieved from the Nonce Endpoint
// as defined in Section 7." A c_nonce in the token response comes from a
// pre-1.0 issuer. Strict mode ignores it. Debug mode uses it with a warning.
func (w *Wallet) issuanceChallenge(metadata, tokenResp map[string]any, issuer string, dpopNonce *string) (string, error) {
	if cNonce := w.fetchNonce(metadata, dpopNonce); cNonce != "" {
		return cNonce, nil
	}
	// An advertised nonce endpoint that returns no challenge deviates from
	// §7.1. Strict mode refuses. Debug mode warns and sends the proof without a
	// c_nonce, so the issuer's rejection shows the result.
	if ep, _ := metadata["nonce_endpoint"].(string); ep != "" {
		return "", w.reportServerDeviation(fmt.Sprintf("the nonce endpoint %s that %s advertises returned no c_nonce (OID4VCI 1.0 §7.1)", ep, issuer))
	}
	cNonce, _ := tokenResp["c_nonce"].(string)
	if cNonce == "" {
		return "", nil
	}
	if w.Mode() == ValidationModeStrict {
		log.Printf("[VCI] WARNING: ignoring the c_nonce in the token response of %s: OID4VCI 1.0 defines the Nonce Endpoint as its only source", issuer)
		w.AddWarning("issuance", fmt.Sprintf("Ignored the c_nonce %s returned in its token response: OID4VCI 1.0 has no such parameter and defines the Nonce Endpoint as the only source of a challenge", issuer), nil)
		return "", nil
	}
	log.Printf("[VCI] WARNING: %s returned a c_nonce in its token response, which OID4VCI 1.0 does not define, so this issuer is pre-1.0", issuer)
	w.AddWarning("issuance", fmt.Sprintf("Using the c_nonce %s returned in its token response: OID4VCI 1.0 defines no such parameter, so this issuer is pre-1.0", issuer), nil)
	return cNonce, nil
}

// Keep request inputs, including proof keys, so invalid_nonce can retry the same
// request with a fresh challenge (§8.3.1.2).
type credentialRequestAttempt struct {
	metadata                  map[string]any
	endpoint                  string
	issuer                    string
	configID                  string
	accessToken               string
	authScheme                string
	credentialIdentifier      string
	credentialConfigurationID string
	responseEncryption        map[string]any
	dpopKey                   *ecdsa.PrivateKey
	proofKeys                 []*ecdsa.PrivateKey
	// clientID is the OAuth client_id of the access token. The key proof sends
	// it as iss. It is empty for an anonymous pre-authorized flow.
	clientID string
	// nonce is the DPoP nonce state of the resource server, not the c_nonce.
	nonce *string
}

// credentialProofs is the proofs object of a credential request (§8.2). It
// holds proofs of one proof type.
type credentialProofs struct {
	Type   string
	Values []string
}

// buildCredentialProofs builds the key proofs over one challenge. With the
// attestation proof type the proof is a key attestation that lists every batch
// key (Appendix F.3). With the jwt proof type there is one proof per key. When
// a key attestation is required, a single holder-key proof carries an
// attestation that lists every batch key (Appendix F.1, HAIP §4.5.1).
func (w *Wallet) buildCredentialProofs(a credentialRequestAttempt, cNonce string) (credentialProofs, error) {
	if finding := proofSigningAlgFinding(a.metadata, a.configID, w.HAIPChecks()); finding != "" {
		if err := w.reportServerDeviation(finding); err != nil {
			return credentialProofs{}, err
		}
	}
	attestation, err := createKeyAttestation(w, a.metadata, a.configID, cNonce, a.proofKeys)
	if err != nil {
		return credentialProofs{}, fmt.Errorf("building key attestation: %w", err)
	}
	if credentialProofType(a.metadata, a.configID) == "attestation" {
		return credentialProofs{Type: "attestation", Values: []string{attestation}}, nil
	}
	keys := a.proofKeys
	var header map[string]any
	if attestation != "" {
		header = map[string]any{"key_attestation": attestation}
		if len(keys) > 1 {
			keys = keys[:1]
		}
	}
	proofs, err := createProofJWTs(keys, a.issuer, a.clientID, cNonce, header)
	if err != nil {
		return credentialProofs{}, fmt.Errorf("creating proof JWT: %w", err)
	}
	return credentialProofs{Type: "jwt", Values: proofs}, nil
}

// Retry invalid_nonce once with a fresh challenge (§8.3.1.2). Return a second
// rejection instead of looping.
func (w *Wallet) requestCredentialWithNonceRetry(a credentialRequestAttempt, proofs credentialProofs) (map[string]any, error) {
	credResp, err := w.sendCredentialRequest(a, proofs)
	if err == nil || !isInvalidNonceError(err) {
		return credResp, err
	}
	cNonce := w.fetchNonce(a.metadata, a.nonce)
	if cNonce == "" {
		return nil, err
	}
	retryProofs, buildErr := w.buildCredentialProofs(a, cNonce)
	if buildErr != nil {
		return nil, buildErr
	}
	log.Printf("[VCI] Issuer rejected the proof nonce, retrying once with a fresh nonce from the Nonce Endpoint")
	return w.sendCredentialRequest(a, retryProofs)
}

func (w *Wallet) sendCredentialRequest(a credentialRequestAttempt, proofs credentialProofs) (map[string]any, error) {
	trace := &credentialExchangeLog{
		Request: func(payload *LogPayload) {
			w.addProtocolLog("issuance", "credential_request", fmt.Sprintf("Request credential from %s", a.endpoint), true,
				credentialRequestLogDetails(a.endpoint, a.accessToken, proofs, a.credentialIdentifier, a.credentialConfigurationID, a.responseEncryption), payload)
		},
	}
	credResp, err := w.requestCredentialWithDPoP(a, proofs, trace)
	w.addProtocolLog("issuance", "credential_response", fmt.Sprintf("Credential response from %s", a.endpoint), err == nil,
		credentialResponseLogDetails(a.endpoint, credResp, err), trace.Response)
	return credResp, err
}

// parseCredentialResponseBody reads a plain JSON or an encrypted (compact JWE)
// credential response. encrypted reports which one arrived.
func parseCredentialResponseBody(body []byte, holderKey *ecdsa.PrivateKey, payloads ...*LogPayload) (out map[string]any, encrypted bool, err error) {
	payload := firstLogPayload(payloads)
	if payload != nil {
		payload.Label, payload.Body = "Response", string(body)
	}
	trimmed := strings.TrimSpace(string(body))
	if err := json.Unmarshal([]byte(trimmed), &out); err == nil {
		return out, false, nil
	}
	if holderKey == nil {
		return nil, false, fmt.Errorf("credential response is not valid JSON")
	}
	if payload != nil && format.IsJWE(trimmed) {
		payload.Encrypted, payload.Wire, payload.Body = true, string(body), nil
	}
	decrypted, err := oid4vp.DecryptCompactJWE(trimmed, holderKey)
	if err != nil {
		return nil, false, fmt.Errorf("credential response is neither valid JSON nor decryptable compact JWE: %w", err)
	}
	if payload != nil {
		payload.Body = decrypted
	}
	if err := json.Unmarshal([]byte(decrypted), &out); err != nil {
		return nil, true, fmt.Errorf("parsing decrypted credential response JSON: %w", err)
	}
	return out, true, nil
}

// checkResponseEncryption reports a plaintext answer to a request that asked
// for an encrypted response. OID4VCI 1.0 §8.3 and §9.2: the issuer "MUST
// encode the information" as specified by Section 10 "regardless of the
// content". §10: an unencrypted message where encryption was required "SHOULD
// be rejected". §8.3.1.2: "Credential Error Responses are never encrypted".
func (w *Wallet) checkResponseEncryption(requested map[string]any, encrypted bool, out map[string]any, endpoint string) error {
	if requested == nil || encrypted {
		return nil
	}
	if code, _ := out["error"].(string); code != "" {
		return nil
	}
	detail := fmt.Sprintf("%s answered in plaintext although the request asked for an encrypted response (OID4VCI 1.0 §8.3, §10)", endpoint)
	return w.reportDeviation(deviation{
		action: "issuance", event: "credential_response_not_encrypted", detail: detail,
		details: map[string]any{"endpoint": endpoint},
	})
}

func credentialRequestLogDetails(endpoint, accessToken string, proofs credentialProofs, credentialIdentifier, credentialConfigurationID string, credentialResponseEncryption map[string]any) map[string]any {
	reqBody := credentialRequestBody(proofs, credentialIdentifier, credentialConfigurationID, credentialResponseEncryption)
	details := map[string]any{
		"direction": "outbound",
		"method":    "POST",
		"url":       endpoint,
		"endpoint":  "credential",
		"request":   reqBody,
	}
	addStringDetail(details, "access_token", accessToken)
	if len(proofs.Values) > 0 {
		addStringDetail(details, "proof_"+proofs.Type, proofs.Values[0])
	}
	addStringDetail(details, "credential_identifier", credentialIdentifier)
	addStringDetail(details, "credential_configuration_id", credentialConfigurationID)
	return details
}

func credentialResponseLogDetails(endpoint string, response map[string]any, err error) map[string]any {
	details := map[string]any{
		"direction": "inbound",
		"url":       endpoint,
		"endpoint":  "credential",
	}
	if response != nil {
		details["response"] = response
	}
	if err != nil {
		details["error"] = err.Error()
	}
	return details
}
