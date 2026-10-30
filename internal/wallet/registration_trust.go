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
	"fmt"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
)

// registrationCertificateAnchoring anchors a registration certificate in the
// wallet's lists of registration certificate providers, as a presentation
// does under --arf (ARF RPRC_02a). The revocation service of that list
// anchors the certificate's status list (ARF RPRC_17). found is false for
// any other token.
func (w *Wallet) registrationCertificateAnchoring(raw string) (anchoring CatalogueAnchoring, found bool) {
	header, _, _, err := format.ParseJWTParts(raw)
	if err != nil {
		return CatalogueAnchoring{}, false
	}
	if typ, _ := header["typ"].(string); !format.JOSETypeIs(typ, registrar.RegistrationCertificateTyp) {
		return CatalogueAnchoring{}, false
	}
	result := CatalogueAnchoring{Category: "registrar"}
	chain, err := validate.X5CCertificates(header)
	if err != nil || len(chain) == 0 {
		result.Findings = findings.List{findings.ARF.Registration("RPRC_02").New("the registration certificate has no readable x5c certificate")}
		return result, true
	}
	var problems []string
	for _, tl := range w.TrustedLists().Lists() {
		if tl.Err != nil || tl.List.SchemeInfo.LoTEType != lote.RegistrationCertProvidersListType {
			continue
		}
		issuance := tl.Anchors(lote.IssuanceServices)
		if _, err := certchain.Verify(chain, issuance); err != nil {
			problems = append(problems, fmt.Sprintf("%s (%v)", tl.URL, err))
			continue
		}
		if _, err := jws.Verify(raw, chain[0].PublicKey); err != nil {
			problems = append(problems, fmt.Sprintf("%s (%v)", tl.URL, err))
			continue
		}
		result.AnchoredBy = tl.URL
		result.IssuanceAnchors = issuance
		result.StatusAnchors = tl.Anchors(lote.RevocationServices)
		return result, true
	}
	finding := findings.ARF.Registration("RPRC_02a").New("the registration certificate does not chain to a trusted registrar")
	if len(problems) > 0 {
		finding.Text += ": " + strings.Join(problems, ", ")
	}
	result.Findings = findings.List{finding}
	return result, true
}
