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

package demorp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

// The Digital Credentials API protocols of OpenID4VP 1.0 Appendix A.
const (
	dcAPIUnsigned    = "openid4vp-v1-unsigned"
	dcAPISigned      = "openid4vp-v1-signed"
	dcAPIMultiSigned = "openid4vp-v1-multisigned"
)

// dcAPIDelivery returns the origin of the verifier page and the protocol of a
// request over the Digital Credentials API. A redirect request gets empty
// strings. signedScheme reports a client identifier prefix that signs the
// request. Without a choice, a request with such a prefix is signed and any
// other is unsigned.
func (d *DemoRP) dcAPIDelivery(body createRequestBody, signedScheme bool) (origin, protocol string, err error) {
	signing := strings.TrimSpace(body.Signing)
	switch strings.TrimSpace(body.Delivery) {
	case "", "redirect":
		if signing != "" {
			return "", "", fmt.Errorf(`signing applies only to the delivery "dc_api"`)
		}
		return "", "", nil
	case "dc_api":
	default:
		return "", "", fmt.Errorf(`delivery must be "redirect" or "dc_api"`)
	}
	switch signing {
	case "":
		protocol = dcAPISigned
		if !signedScheme {
			protocol = dcAPIUnsigned
		}
	case "signed":
		protocol = dcAPISigned
	case "multisigned":
		protocol = dcAPIMultiSigned
	case "unsigned":
		protocol = dcAPIUnsigned
	default:
		return "", "", fmt.Errorf(`signing must be "signed", "unsigned" or "multisigned"`)
	}
	if protocol != dcAPIUnsigned && !signedScheme {
		return "", "", fmt.Errorf("a signed request needs the client_id scheme x509_hash or x509_san_dns")
	}
	return originOf(d.baseURL()), protocol, nil
}

// multiSignedRequest builds the request of openid4vp-v1-multisigned: the JWS
// JSON serialization with one signature per client identifier (OpenID4VP 1.0
// Appendix A.3.2). The verifier's own signature comes first. The second comes
// from a new key whose certificate no registrar knows. The wallet must handle
// a signer it can't trust.
func multiSignedRequest(claims map[string]any, key *ecdsa.PrivateKey, chain []*x509.Certificate, clientID string, verifierInfo []any) (map[string]any, error) {
	// Appendix A.3.2.2: client_id and verifier_info "MUST be present only in
	// the protected header of the respective signature object". iss would
	// name only one of the signers.
	payload := maps.Clone(claims)
	delete(payload, "client_id")
	delete(payload, "verifier_info")
	delete(payload, "iss")

	otherKey, otherChain, err := unregisteredSigner()
	if err != nil {
		return nil, err
	}
	signers := []struct {
		key      *ecdsa.PrivateKey
		chain    []*x509.Certificate
		clientID string
		info     []any
	}{
		{key, chain, clientID, verifierInfo},
		{otherKey, otherChain, oid4vp.X509HashClientID(otherChain[0]), nil},
	}
	var encodedPayload string
	var signatures []any
	for _, signer := range signers {
		header := map[string]any{
			"alg":       jws.AlgES256,
			"typ":       format.TypeRequestObject,
			"iat":       time.Now().Unix(),
			"x5c":       certchain.X5C(signer.chain),
			"client_id": signer.clientID,
		}
		if len(signer.info) > 0 {
			header["verifier_info"] = signer.info
		}
		compact, err := jws.Sign(header, payload, signer.key)
		if err != nil {
			return nil, fmt.Errorf("signing the request: %w", err)
		}
		parts := strings.Split(compact, ".")
		if encodedPayload != "" && parts[1] != encodedPayload {
			return nil, fmt.Errorf("the signatures cover different payloads")
		}
		encodedPayload = parts[1]
		signatures = append(signatures, map[string]any{"protected": parts[0], "signature": parts[2]})
	}
	return map[string]any{"payload": encodedPayload, "signatures": signatures}, nil
}

// unregisteredSigner returns a new key with a self-signed certificate.
func unregisteredSigner() (*ecdsa.PrivateKey, []*x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "EUDI Dev unregistered verifier"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(entryTTL + time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return key, []*x509.Certificate{cert}, nil
}

// writeCreatedDCAPIRequest returns the argument of navigator.credentials.get()
// with one request of the given protocol (W3C Digital Credentials §5).
func writeCreatedDCAPIRequest(w http.ResponseWriter, req *requestState, protocol string, data map[string]any) {
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":             req.id,
		"transaction_id": req.transactionID,
		"dc_api": map[string]any{
			"digital": map[string]any{
				"requests": []any{map[string]any{"protocol": protocol, "data": data}},
			},
		},
	})
}

// handleDCAPIResponse takes the result of navigator.credentials.get() from
// the page that created the request. Only that page knows the transaction_id.
// The data holds the response parameters (OpenID4VP 1.0 Appendix A.4).
func (d *DemoRP) handleDCAPIResponse(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Protocol string         `json:"protocol"`
		Data     map[string]any `json:"data"`
	}
	if err := decodeJSONBody(r, &body); err != nil {
		apierror.InvalidJSON(w, err)
		return
	}
	key := r.PathValue("key")
	d.mu.Lock()
	var req *requestState
	for _, candidate := range d.requests {
		if candidate.transactionID == key {
			req = candidate
		}
	}
	ok := req != nil && time.Now().Before(req.expires)
	replay := ok && req.answered
	d.mu.Unlock()
	switch {
	case !ok:
		apierror.WriteStatus(w, http.StatusNotFound, "unknown or expired request")
		return
	case req.dcAPIOrigin == "":
		apierror.Write(w, http.StatusBadRequest, apierror.InvalidRequest, "this request expects its response at its response_uri")
		return
	case replay:
		writeAnswered(w)
		return
	}

	form := url.Values{}
	for name, value := range body.Data {
		if text, isText := value.(string); isText {
			form.Set(name, text)
		}
	}
	recorded, err := d.recordResponse(req, form)
	switch {
	case err != nil:
		apierror.Write(w, http.StatusBadRequest, apierror.InvalidRequest, err.Error())
	case !recorded:
		writeAnswered(w)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
