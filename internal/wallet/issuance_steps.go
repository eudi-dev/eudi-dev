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
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

// ignoreFindings is the report for a flow without a result to carry findings.
// The steps still log them.
func ignoreFindings(...string) {}

// chooseOfferConfiguration picks the credential configuration to request.
// OID4VCI 1.0 §4.1.1 makes credential_configuration_ids a non-empty array.
// chosen is the entry picked by the user or the API caller. Without a choice the
// wallet requests the first entry.
func chooseOfferConfiguration(offer *oid4vc.CredentialOffer, chosen string) (string, error) {
	ids := offer.CredentialConfigurationIDs
	if chosen != "" {
		if !slices.Contains(ids, chosen) {
			return "", fmt.Errorf("the credential offer from %s does not offer credential configuration %q (it offers %v)", offer.CredentialIssuer, chosen, ids)
		}
		return chosen, nil
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("the credential offer from %s lists no credential_configuration_ids, which OID4VCI 1.0 §4.1.1 requires", offer.CredentialIssuer)
	}
	return ids[0], nil
}

// readIssuerMetadata also returns the certificate chain of signed metadata and
// the problems that debug mode accepts in it.
func (w *Wallet) readIssuerMetadata(issuer string) (map[string]any, []*x509.Certificate, []string, error) {
	var signerChain []*x509.Certificate
	var problems []string
	preferSigned := w.ARFChecks()
	onProblem := w.collectMetadataProblems(&problems)
	metadata, err := w.fetchLoggedMetadata(metadataFetch{
		event:         "issuer_metadata",
		fetchLabel:    "issuer metadata",
		responseLabel: "Issuer metadata",
		wellKnown:     "openid-credential-issuer",
		issuer:        issuer,
		fetch: func(client *http.Client, issuer string, payloads ...*LogPayload) (map[string]any, error) {
			metadata, chain, err := fetchIssuerMetadataDocument(client, issuer, preferSigned, onProblem, payloads...)
			signerChain = chain
			return metadata, err
		},
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fetching issuer metadata: %w", err)
	}
	return metadata, signerChain, problems, nil
}

// checkIssuer runs the issuer checks for the requested configurations and
// returns the findings. The ARF has the wallet check the issuer before it
// requests a credential, so strict mode refuses an ARF finding. The other
// findings only warn.
func (w *Wallet) checkIssuer(issuer string, metadata map[string]any, signerChain []*x509.Certificate, configurations []string) ([]string, error) {
	arf := w.issuerARFCheck(metadata, signerChain, configurations)
	if len(arf) > 0 && w.Mode() == ValidationModeStrict {
		return nil, w.reportARFIssuanceFindings(issuer, arf)
	}
	return slices.Concat(arf, w.issuerARFAdvisories(metadata), w.catalogueFindings(metadata, configurations)), nil
}

// loadIssuerMetadata reads and checks the metadata of an issuer. The caller
// logs the findings with logIssuerFindings.
func (w *Wallet) loadIssuerMetadata(issuer string, configurations []string) (map[string]any, []string, error) {
	metadata, signerChain, problems, err := w.readIssuerMetadata(issuer)
	if err != nil {
		return nil, nil, err
	}
	findings, err := w.checkIssuer(issuer, metadata, signerChain, configurations)
	if err != nil {
		return nil, nil, err
	}
	return metadata, append(problems, findings...), nil
}

// logIssuerFindings logs the findings about an issuer in one entry.
func (w *Wallet) logIssuerFindings(issuer string, findings []string) {
	w.warnFindings("issuance", "issuer_findings", "Findings about the issuer", findings, map[string]any{"issuer": issuer})
}

// accessGrant is an accepted token response (RFC 6749 §5.1).
type accessGrant struct {
	accessToken  string
	authScheme   string
	refreshToken string
	expiresIn    int
	response     map[string]any
}

func (g *accessGrant) expiresAt(now time.Time) time.Time {
	if g.expiresIn <= 0 {
		return time.Time{}
	}
	return now.Add(time.Duration(g.expiresIn) * time.Second)
}

// dpopKeyForRenewal returns the DPoP key of an issuance with DPoP-bound
// tokens, and nil otherwise.
func (w *Wallet) dpopKeyForRenewal(r CredentialRenewal) *ecdsa.PrivateKey {
	if r.UseDPoP {
		return w.clientKey(r)
	}
	return nil
}

// requestAccessToken sends form to the token endpoint of r, with the client
// authentication and DPoP binding of r. When the server answered, the grant
// is returned even if a check of the answer fails, so the caller can keep a
// rotated refresh token.
func (w *Wallet) requestAccessToken(r CredentialRenewal, form url.Values, nonce *string) (*accessGrant, error) {
	dpopKey := w.dpopKeyForRenewal(r)
	authenticator := w.clientAuthenticatorFor(r.ClientAuth, r.ClientID, w.clientKey(r))
	payload := &LogPayload{}
	var sent http.Header
	resp, err := postFormWithDPoP(w.HTTPClient(), r.TokenEndpoint, form, dpopKey, "", nonce, authenticator, &sent, payload)
	details := formRequestLogDetails(r.TokenEndpoint, "token", form)
	details["grant_type"] = form.Get("grant_type")
	addRequestHeaders(details, sent)
	w.addProtocolLog("issuance", "token_request", fmt.Sprintf("Request token from %s", r.TokenEndpoint), true, details, formLogPayload("Request", form))
	w.addProtocolLog("issuance", "token_response", fmt.Sprintf("Token response from %s", r.TokenEndpoint), err == nil, responseMapLogDetails(r.TokenEndpoint, "token", resp, err), payload)
	if err != nil {
		return nil, err
	}

	grant := &accessGrant{response: resp}
	grant.refreshToken, grant.expiresIn = tokenGrantRenewal(resp)
	grant.accessToken, _ = resp["access_token"].(string)
	// RFC 6749 §5.1 makes access_token REQUIRED.
	if grant.accessToken == "" {
		return grant, fmt.Errorf("the token response carried no access_token")
	}
	if err := w.checkTokenType(resp, dpopKey != nil); err != nil {
		return grant, err
	}
	grant.authScheme = accessTokenScheme(resp, dpopKey != nil)
	return grant, nil
}

// refreshAccessToken uses the refresh token grant (RFC 6749 §6).
func (w *Wallet) refreshAccessToken(r CredentialRenewal) (*accessGrant, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", r.RefreshToken)
	if r.ClientID != "" {
		form.Set("client_id", r.ClientID)
	}
	nonce := ""
	return w.requestAccessToken(r, form, &nonce)
}

// credentialRequest holds what a Credential Request (OID4VCI 1.0 §8.2) needs.
type credentialRequest struct {
	renewal   CredentialRenewal
	metadata  map[string]any
	grant     *accessGrant
	proofKeys []*ecdsa.PrivateKey
	// nonce is the DPoP nonce state of the resource server.
	nonce *string
}

func (w *Wallet) requestCredential(r credentialRequest) (map[string]any, error) {
	issuer := r.renewal.Issuer
	configID := r.renewal.ConfigurationID
	cNonce, err := w.issuanceChallenge(r.metadata, r.grant.response, issuer, r.nonce)
	if err != nil {
		return nil, err
	}
	responseEncryption, err := buildCredentialResponseEncryptionRequest(w.Mode(), r.metadata, w.HolderKeyPair())
	if err != nil {
		return nil, err
	}

	// OID4VCI 1.0 §8.2 requires credential_identifier "when an Authorization
	// Details of type openid_credential was returned from the Token Response",
	// and credential_configuration_id otherwise.
	identifier, authorizedOther := resolveCredentialIdentifier(r.grant.response, configID)
	w.reportAuthorizedConfiguration(issuer, configID, authorizedOther)
	configurationID := ""
	if identifier == "" {
		configurationID = configID
	}

	attempt := credentialRequestAttempt{
		metadata:                  r.metadata,
		endpoint:                  r.renewal.CredentialEndpoint,
		issuer:                    issuer,
		configID:                  configID,
		accessToken:               r.grant.accessToken,
		authScheme:                r.grant.authScheme,
		credentialIdentifier:      identifier,
		credentialConfigurationID: configurationID,
		responseEncryption:        responseEncryption,
		dpopKey:                   w.dpopKeyForRenewal(r.renewal),
		proofKeys:                 r.proofKeys,
		clientID:                  r.renewal.ClientID,
		nonce:                     r.nonce,
	}
	proofs, err := w.buildCredentialProofs(attempt, cNonce)
	if err != nil {
		return nil, err
	}
	credResp, err := w.requestCredentialWithNonceRetry(attempt, proofs)
	if err != nil {
		return nil, fmt.Errorf("requesting credential: %w", err)
	}
	return credResp, nil
}

// resourceAccess authorizes requests to the credential issuer's endpoints.
type resourceAccess struct {
	accessToken string
	authScheme  string
	dpopKey     *ecdsa.PrivateKey
	nonce       *string
}

// credentialDelivery is what the wallet keeps with a credential response.
type credentialDelivery struct {
	metadata map[string]any
	// renewal is stored with the credential. It renews the credential when it
	// carries a refresh token.
	renewal   CredentialRenewal
	display   *oid4vc.CredentialDisplay
	proofKeys []*ecdsa.PrivateKey
	// replaceID is the credential replaced by a renewal. Without it the
	// credential is stored as a new one.
	replaceID string
	// deferredID is the deferred issuance completed by this credential.
	deferredID string
	access     resourceAccess
	// logSummary starts the activity log line, as in "Imported credential".
	logSummary string
	logDetails map[string]any
	report     func(...string)
}

// storeIssuedCredential returns the stored primary credential and its raw
// form. The credentials are stored and saved in one change under the store
// lock, so a reload during the network calls of the flow keeps them.
func (w *Wallet) storeIssuedCredential(credResp map[string]any, d credentialDelivery) (*StoredCredential, string, error) {
	// OpenID4VCI 1.0 §11.1: the wallet tells the issuer whether it kept the
	// credential (credential_accepted) or refused it (credential_failure).
	stored, raw, err := w.storeReceivedCredential(credResp, d)
	event := "credential_accepted"
	if err != nil {
		event = "credential_failure"
	}
	w.notifyCredential(event, d.metadata, credResp, d.access.accessToken, d.access.authScheme, d.access.dpopKey, d.access.nonce)
	return stored, raw, err
}

func (w *Wallet) storeReceivedCredential(credResp map[string]any, d credentialDelivery) (*StoredCredential, string, error) {
	issuer := d.renewal.Issuer
	received, err := w.checkReceivedCredentials(credResp, d.metadata, d.renewal.ConfigurationID, issuer)
	if err != nil {
		return nil, "", err
	}
	d.report(received...)
	batch, err := w.sortBatch(credResp, d.proofKeys, d.report)
	if err != nil {
		return nil, "", err
	}
	primary, err := w.parseDetectedFormat(strings.TrimSpace(batch.primary), "", primaryBindingKeyPEM(batch.primary, d.proofKeys))
	if err != nil {
		return nil, "", fmt.Errorf("importing received credential: %w", err)
	}
	typed := w.typeMetadata(primary.Raw, "issuance")
	if len(typed.problems) > 0 {
		if err := w.reportDeviation(deviation{action: "issuance", event: "type_metadata", summary: typeMetadataSummary(primary.VCT), findings: typed.problems}); err != nil {
			return nil, "", err
		}
		d.report(typed.problems...)
	}
	primary.TypeMetadata = typed.metadata
	if d.display == nil {
		d.display = typeDisplay(typed.metadata)
	}

	var stored []StoredCredential
	w.saveChange(func() bool {
		if d.replaceID == "" {
			stored = w.storeIssuedBatch(primary, batch.copies, d.display, d.renewal)
		} else if stored, err = w.storeRenewedBatch(d.replaceID, primary, batch.copies, d.renewal); err != nil {
			return false
		}
		if d.deferredID != "" {
			w.RemoveDeferredIssuance(d.deferredID)
		}
		details := credentialImportLogDetails(&stored[0], batch.primary)
		for key, value := range d.logDetails {
			details[key] = value
		}
		details["issuer"] = issuer
		w.addProtocolLog("issuance", "credential_imported", fmt.Sprintf("%s %s from %s", d.logSummary, stored[0].ID, issuer), true, details, credentialImportLogPayload(stored))
		return true
	})
	if err != nil {
		return nil, "", err
	}
	for i := range stored {
		w.noteUnheldKeyBinding(&stored[i])
		w.noteDIDIssuerKey(&stored[i])
	}

	return &stored[0], batch.primary, nil
}

// issuanceSession holds the state shared by the token and credential requests
// of one offer.
type issuanceSession struct {
	metadata map[string]any
	display  *oid4vc.CredentialDisplay
	// renewal holds the issuer, its endpoints, the configuration and the
	// client of this issuance.
	renewal CredentialRenewal
	nonces  *dpopNonceState
	report  func(...string)
}

// issueWithToken ends a pre-authorized and an authorization code issuance. A
// deferred answer goes to background collection.
func (w *Wallet) issueWithToken(s issuanceSession, tokenForm url.Values) (*IssuanceResult, error) {
	grant, err := w.requestAccessToken(s.renewal, tokenForm, &s.nonces.authzServer)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	renewal := s.renewal
	renewal.RefreshToken = grant.refreshToken

	proofKeys, err := issuanceProofKeys(s.metadata, renewal.ReusePolicy)
	if err != nil {
		return nil, fmt.Errorf("preparing proof keys: %w", err)
	}
	credResp, err := w.requestCredential(credentialRequest{
		renewal:   renewal,
		metadata:  s.metadata,
		grant:     grant,
		proofKeys: proofKeys,
		nonce:     &s.nonces.resource,
	})
	if err != nil {
		return nil, err
	}

	display := s.display
	credFormat := resolveCredentialFormat(s.metadata, renewal.ConfigurationID)
	transactionID, _ := credResp["transaction_id"].(string)
	if _, issued := credResp["credentials"]; issued && transactionID != "" {
		// OpenID4VCI 1.0 §8.3: credentials "MUST NOT be used if the
		// transaction_id parameter is present". Debug mode keeps the issued
		// credentials.
		if err := w.reportDeviation(deviation{
			action: "issuance", event: "credential_response_deviation",
			detail:  "OpenID4VCI 1.0 §8.3: the credential response carries both credentials and transaction_id. Only one of them is allowed",
			details: map[string]any{"transaction_id": transactionID},
		}); err != nil {
			return nil, err
		}
		transactionID = ""
	}
	if transactionID != "" {
		pending, err := newDeferredIssuance(deferredTransaction{
			transactionID: transactionID,
			interval:      deferredInterval(credResp),
			renewal:       renewal,
			metadata:      s.metadata,
			format:        credFormat,
			display:       display,
			grant:         grant,
			proofKeys:     proofKeys,
		})
		if err != nil {
			return nil, err
		}
		return w.recordDeferredIssuance(pending), nil
	}

	imported, raw, err := w.storeIssuedCredential(credResp, credentialDelivery{
		metadata:  s.metadata,
		renewal:   renewal,
		display:   display,
		proofKeys: proofKeys,
		access: resourceAccess{
			accessToken: grant.accessToken,
			authScheme:  grant.authScheme,
			dpopKey:     w.dpopKeyForRenewal(renewal),
			nonce:       &s.nonces.resource,
		},
		logSummary: "Imported credential",
		logDetails: map[string]any{"credential_requested": renewal.ConfigurationID},
		report:     s.report,
	})
	if err != nil {
		return nil, err
	}
	if credFormat == "" {
		credFormat = imported.Format
	}
	verificationStatus, verificationDetail := verifyImportedJWTMetadataSignature(raw, w.HTTPClient())
	return &IssuanceResult{
		CredentialID:       imported.ID,
		Format:             credFormat,
		Issuer:             renewal.Issuer,
		VerificationStatus: verificationStatus,
		VerificationDetail: verificationDetail,
	}, nil
}
