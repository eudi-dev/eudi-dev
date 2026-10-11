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

// Package remote lets the CLI manage a running wallet server over its REST API.
// It holds the REST client, the saved active remote target and the discovery of
// local wallet instances.
package remote

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/config"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
	// owner identifies the browser the client acts for. The client sets it
	// when it opens a wallet UI page for a flow.
	owner string
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// apiPath escapes every segment, so an identifier with a slash or a question mark
// stays one segment.
func apiPath(segments ...string) string {
	escaped := make([]string, len(segments))
	for i, segment := range segments {
		escaped[i] = url.PathEscape(segment)
	}
	return "/api/" + strings.Join(escaped, "/")
}

func (c *Client) do(method, path string, body any, out any) error {
	return c.doWithTimeout(0, method, path, body, out)
}

// doWithTimeout is do with a per-request deadline. Some calls outlast a normal
// round trip, such as accepting an offer whose issuer defers the credential. A
// zero timeout keeps the client's default.
func (c *Client) doWithTimeout(timeout time.Duration, method, path string, body any, out any) error {
	var reader io.Reader
	contentType := ""
	switch b := body.(type) {
	case nil:
	case string:
		reader = strings.NewReader(b)
	default:
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		reader = bytes.NewReader(data)
		contentType = "application/json"
	}

	req, err := http.NewRequest(method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	// The registrar API signs its answers unless the client asks for JSON.
	req.Header.Set("Accept", "application/json")
	// The server tells a named client from an outdated URL handler, which
	// sends no name.
	req.Header.Set(config.ClientHeader, "eudi-cli/"+version)
	if c.owner != "" {
		req.Header.Set(config.OwnerHeader, c.owner)
	}

	client := c.HTTP
	if timeout > 0 && client != nil && client.Timeout < timeout {
		withDeadline := *client
		withDeadline.Timeout = timeout
		client = &withDeadline
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("calling %s: %w", c.BaseURL+path, err)
	}
	defer resp.Body.Close()

	data, err := format.ReadRemoteBody(resp.Body, "wallet response")
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var apiErr struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if json.Unmarshal(data, &apiErr) == nil && apiErr.Error != "" {
			if apiErr.Description != "" {
				return fmt.Errorf("remote wallet: %s: %s (HTTP %d)", apiErr.Error, apiErr.Description, resp.StatusCode)
			}
			return fmt.Errorf("remote wallet: %s (HTTP %d)", apiErr.Error, resp.StatusCode)
		}
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return fmt.Errorf("remote wallet: %s (HTTP %d)", msg, resp.StatusCode)
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if raw, ok := out.(*[]byte); ok {
		*raw = data
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

func (c *Client) Version() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, apiPath("version"), nil, &out)
	return out, err
}

func (c *Client) ServerConfig() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, apiPath("config"), nil, &out)
	return out, err
}

func (c *Client) Credentials() ([]map[string]any, error) {
	var out []map[string]any
	err := c.do(http.MethodGet, apiPath("credentials"), nil, &out)
	return out, err
}

func (c *Client) Credential(id string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, apiPath("credentials", id), nil, &out)
	return out, err
}

func (c *Client) ImportCredential(raw string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodPost, apiPath("credentials"), raw, &out)
	return out, err
}

func (c *Client) RefreshCredential(id string) (map[string]any, error) {
	var out map[string]any
	err := c.doWithTimeout(config.SlowRequestTimeout, http.MethodPost, apiPath("credentials", id, "refresh"), nil, &out)
	return out, err
}

func (c *Client) RemoveCredential(id string) error {
	return c.do(http.MethodDelete, apiPath("credentials", id), nil, nil)
}

// RemoveAllCredentials removes every deletable credential and decodes the
// counts into out.
func (c *Client) RemoveAllCredentials(out any) error {
	return c.do(http.MethodDelete, apiPath("credentials"), nil, out)
}

// Issue issues a credential with the remote wallet's issuer key. The request
// map uses the POST /api/issue field names.
func (c *Client) Issue(req map[string]any) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodPost, apiPath("issue"), req, &out)
	return out, err
}

// RegistrationCertificate asks the wallet's registrar to sign a registration
// certificate for a relying party and decodes the answer into out.
func (c *Client) RegistrationCertificate(req, out any) error {
	return c.do(http.MethodPost, apiPath("registrar", "registration-certificates"), req, out)
}

// RegisterRelyingParty stores a relying party with the wallet's registrar
// (TS05 v1.5 POST /wrp) and decodes the stored record into out.
func (c *Client) RegisterRelyingParty(rp, out any) error {
	return c.do(http.MethodPost, apiPath("registrar", "wrp"), rp, out)
}

// Enrol registers a relying party, or with update changes its registration,
// and issues its certificates in one step. It decodes the enrolment result
// into out.
func (c *Client) Enrol(enrolment any, update bool, out any) error {
	method := http.MethodPost
	if update {
		method = http.MethodPut
	}
	return c.do(method, apiPath("registrar", "enrolments"), enrolment, out)
}

// RegistrationCertificateViews lists the registration certificates of a
// relying party with the value of each stored certificate.
func (c *Client) RegistrationCertificateViews(identifier string, out any) error {
	return c.do(http.MethodGet, apiPath("registrar", "registration-certificates")+"?identifier="+url.QueryEscape(identifier), nil, out)
}

// SetRegistrationCertificateStatus revokes or reactivates the registration
// certificates of a relying party or one of its intended uses and decodes the
// count into out.
func (c *Client) SetRegistrationCertificateStatus(req, out any) error {
	return c.do(http.MethodPost, apiPath("registrar", "registration-certificates", "status"), req, out)
}

// RegistrarRecords reads every record of the wallet's registrar (TS05 v1.5
// GET /wrp). It follows the cursor, because the registrar caps the page size.
func (c *Client) RegistrarRecords(out any) error {
	var records []json.RawMessage
	query := url.Values{}
	for {
		var envelope struct {
			Data       []json.RawMessage `json:"data"`
			Pagination struct {
				NextCursor string `json:"next_cursor"`
			} `json:"pagination"`
		}
		path := apiPath("registrar", "wrp")
		if len(query) > 0 {
			path += "?" + query.Encode()
		}
		if err := c.do(http.MethodGet, path, nil, &envelope); err != nil {
			return err
		}
		records = append(records, envelope.Data...)
		if envelope.Pagination.NextCursor == "" {
			break
		}
		query.Set("cursor", envelope.Pagination.NextCursor)
	}
	data, err := json.Marshal(records)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

// DeleteRelyingParty deletes a registration and revokes its certificates.
func (c *Client) DeleteRelyingParty(identifier string) error {
	return c.do(http.MethodDelete, apiPath("registrar", "wrp", identifier), nil, nil)
}

// TrustState reads the providers and external lists that users added to the
// wallet's trusted lists.
func (c *Client) TrustState(out any) error {
	return c.do(http.MethodGet, apiPath("trust"), nil, out)
}

// AddTrustedEntity puts a provider on one of the wallet's lists.
func (c *Client) AddTrustedEntity(entity, out any) error {
	return c.do(http.MethodPost, apiPath("trust", "entities"), entity, out)
}

// RemoveTrustedEntity takes a provider off its list.
func (c *Client) RemoveTrustedEntity(id string) error {
	return c.do(http.MethodDelete, apiPath("trust", "entities", id), nil, nil)
}

// AddTrustedList puts an external list on the wallet's list of trusted lists.
func (c *Client) AddTrustedList(listURL string, out any) error {
	return c.do(http.MethodPost, apiPath("trust", "lists"), map[string]string{"url": listURL}, out)
}

// RemoveTrustedList takes an external list off the list of trusted lists.
func (c *Client) RemoveTrustedList(listURL string) error {
	return c.do(http.MethodDelete, apiPath("trust", "lists")+"?url="+url.QueryEscape(listURL), nil, nil)
}

// CatalogAttestations reads the wallet's attestation catalogue with names and
// credential types.
func (c *Client) CatalogAttestations(out any) error {
	return c.do(http.MethodGet, apiPath("catalog", "attestations"), nil, out)
}

// AddCatalogAttestation adds an attestation to the catalogue and decodes the
// stored entry into out.
func (c *Client) AddCatalogAttestation(entry, out any) error {
	return c.do(http.MethodPost, apiPath("catalog", "attestations"), entry, out)
}

// DeleteCatalogAttestation deletes an added attestation (EC TS11 v1.0
// DELETE /schemas/{schemaId}).
func (c *Client) DeleteCatalogAttestation(id string) error {
	return c.do(http.MethodDelete, apiPath("catalog", "schemas", id), nil, nil)
}

// AccessCertificate asks the wallet's access certificate authority to sign an
// access certificate for a CSR and decodes the answer into out.
func (c *Client) AccessCertificate(req, out any) error {
	return c.do(http.MethodPost, apiPath("registrar", "access-certificates"), req, out)
}

func (c *Client) Log() ([]byte, error) {
	var out []byte
	err := c.do(http.MethodGet, apiPath("log"), nil, &out)
	return out, err
}

func (c *Client) ClearLog() error {
	return c.do(http.MethodDelete, apiPath("log"), nil, nil)
}

func (c *Client) Templates() ([]map[string]any, error) {
	var out []map[string]any
	err := c.do(http.MethodGet, apiPath("templates"), nil, &out)
	return out, err
}

func (c *Client) Template(name string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, apiPath("templates", name), nil, &out)
	return out, err
}

func (c *Client) PutTemplate(name string, doc any) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodPut, apiPath("templates", name), doc, &out)
	return out, err
}

func (c *Client) DeleteTemplate(name string) error {
	return c.do(http.MethodDelete, apiPath("templates", name), nil, nil)
}

// Certificate exports the remote wallet's CA or TLS certificate. kind is
// "ca" or "tls", format is "pem" or "jwks".
func (c *Client) Certificate(kind, format string) ([]byte, error) {
	path := apiPath("certificates", kind)
	if format != "" && format != "pem" {
		path += "?format=" + format
	}
	var out []byte
	err := c.do(http.MethodGet, path, nil, &out)
	return out, err
}

// The timeout covers consent and the protocol exchange after it.
const interactiveTimeout = config.ConsentTimeout + config.SlowRequestTimeout

// Present sends a presentation request URI to the remote wallet. With
// interactive set, the wallet shows its consent dialog and holds the response
// until the user decides.
func (c *Client) Present(uri string, interactive bool, sessionTranscript string) (map[string]any, error) {
	var out map[string]any
	body := map[string]any{"uri": uri}
	if sessionTranscript != "" {
		body["session_transcript"] = sessionTranscript
	}
	timeout := time.Duration(0)
	if interactive {
		body["interactive"] = true
		timeout = interactiveTimeout
	}
	err := c.doWithTimeout(timeout, http.MethodPost, apiPath("presentations"), body, &out)
	return out, err
}

// AcceptOffer sends a credential offer URI to the remote wallet. A
// pre-authorized grant with a transaction code needs txCode. An empty txCode
// is omitted so the wallet keeps the code it already holds. With interactive
// set, the wallet shows its consent dialog.
func (c *Client) AcceptOffer(uri, txCode string, interactive bool) (map[string]any, error) {
	var out map[string]any
	body := map[string]any{"uri": uri}
	if txCode != "" {
		body["tx_code"] = txCode
	}
	// Issuance requests can outlast an ordinary API call.
	timeout := config.SlowRequestTimeout
	if interactive {
		body["interactive"] = true
		timeout = interactiveTimeout
	}
	err := c.doWithTimeout(timeout, http.MethodPost, apiPath("offers"), body, &out)
	return out, err
}

// TrustList fetches an ETSI trust list JWT from the remote wallet. Without a
// selector it returns the default list of /api/trustlist.
func (c *Client) TrustList(id, vct, docType string) (string, error) {
	var out []byte
	if err := c.do(http.MethodGet, TrustListPath(id, vct, docType), nil, &out); err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// TrustListPath maps a trust list selection to its endpoint. The CLI both
// prints and fetches this path.
func TrustListPath(id, vct, docType string) string {
	if id != "" {
		return apiPath("trustlists", id)
	}
	query := url.Values{}
	if vct != "" {
		query.Set("vct", vct)
	}
	if docType != "" {
		query.Set("doctype", docType)
	}
	if encoded := query.Encode(); encoded != "" {
		return apiPath("trustlist") + "?" + encoded
	}
	return apiPath("trustlist")
}

func (c *Client) TrustLists() ([]map[string]any, error) {
	var out struct {
		TrustLists []map[string]any `json:"trust_lists"`
	}
	if err := c.do(http.MethodGet, apiPath("trustlists"), nil, &out); err != nil {
		return nil, err
	}
	return out.TrustLists, nil
}

// OfferStatus reports the outcome of an offer that paused for an interactive
// sign-in. The id is the offer_id of the authorization_required response.
func (c *Client) OfferStatus(id string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, apiPath("offers", id), nil, &out)
	return out, err
}

func (c *Client) DeferredIssuances() ([]map[string]any, error) {
	var out []map[string]any
	err := c.do(http.MethodGet, apiPath("deferred"), nil, &out)
	return out, err
}

func (c *Client) CollectDeferred(id string) (map[string]any, error) {
	var out map[string]any
	err := c.doWithTimeout(config.SlowRequestTimeout, http.MethodPost, apiPath("deferred", id, "collect"), nil, &out)
	return out, err
}

func (c *Client) AbandonDeferred(id string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodDelete, apiPath("deferred", id), nil, &out)
	return out, err
}

func (c *Client) Shutdown() error {
	return c.do(http.MethodPost, apiPath("shutdown"), nil, nil)
}

// version is the release of this binary. The cmd package sets it.
var version = "dev"

func SetVersion(v string) {
	if v = strings.TrimSpace(v); v != "" {
		version = v
	}
}

func NewOwnerToken() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (c *Client) ActsForAPage() bool {
	return c.owner != ""
}

func (c *Client) ActingFor(owner string) {
	c.owner = strings.TrimSpace(owner)
}
