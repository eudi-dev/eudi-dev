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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/typemetadata"
)

// The demo payment account is an SCA Attestation (EUDI TS12 v1.0.1 §3). Its
// vct is an HTTPS URL of the demo issuer, so a wallet retrieves its Type
// Metadata (SD-JWT VC §5.3.1) and finds the SCA category (TS12 §3) and the
// transaction_data_types of the four TS12 types (TS12 §4.1).
const (
	paymentAccountConfigurationID = "demo-payment-account"
	paymentAccountTypePath        = "/types/payment-account"
)

// paymentAccountVCT is on the issuer's HTTPS origin. A local issuer with a
// plain HTTP base URL also listens on IssuerURL with TLS.
func (d *DemoRP) paymentAccountVCT() string {
	issuer := d.issuerID()
	if !typemetadata.IsRetrievable(issuer) {
		if secure := strings.TrimRight(d.wallet.IssuerURL, "/"); secure != "" {
			issuer = secure + "/issuer"
		}
	}
	return issuer + paymentAccountTypePath
}

// paymentAccountTypeMetadata is the Type Metadata document as served. The
// credential carries its integrity in vct#integrity (TS12 §4.1.2).
func (d *DemoRP) paymentAccountTypeMetadata() ([]byte, error) {
	data, err := staticFiles.ReadFile("static/payment-account-type.json")
	if err != nil {
		return nil, err
	}
	var doc typemetadata.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("the payment account Type Metadata: %w", err)
	}
	doc.VCT = d.paymentAccountVCT()
	return json.Marshal(doc)
}

// handlePaymentAccountType serves the Type Metadata.
func (d *DemoRP) handlePaymentAccountType(w http.ResponseWriter, _ *http.Request) {
	body, err := d.paymentAccountTypeMetadata()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(body)
}

// IssuedVCT returns the vct issued by the demo issuer for an SD-JWT VC template.
func (d *DemoRP) IssuedVCT(tpl credtemplate.Template) string {
	if cfg, ok := configurationOf(tpl); ok {
		return d.withIssuerVCT(cfg).vct
	}
	return tpl.VCT
}

// withIssuerVCT gives the payment account configuration its HTTPS vct.
func (d *DemoRP) withIssuerVCT(cfg templateConfiguration) templateConfiguration {
	if cfg.id == paymentAccountConfigurationID && cfg.format == credtype.FormatSDJWT {
		cfg.vct = d.paymentAccountVCT()
	}
	return cfg
}
