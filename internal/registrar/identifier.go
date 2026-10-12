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

package registrar

import (
	"fmt"
	"regexp"
	"strings"
)

// The identifier types of ETSI TS 119 475 V1.2.1 clause B.2.5.
const (
	EORIIdentifierType   = "http://data.europa.eu/eudi/id/EORI-No"
	LEIIdentifierType    = "http://data.europa.eu/eudi/id/LEI"
	EUIDIdentifierType   = "http://data.europa.eu/eudi/id/EUID"
	VATINIdentifierType  = "http://data.europa.eu/eudi/id/VATIN"
	TINIdentifierType    = "http://data.europa.eu/eudi/id/TIN"
	ExciseIdentifierType = "http://data.europa.eu/eudi/id/Excise"
)

var (
	// An EUID is the country code and the business register identifier, a
	// dot and the registration number (Implementing Regulation (EU)
	// 2021/1042, ETSI EN 319 412-1 V1.6.1 LEG-5.1.4-07 b).
	euidPattern = regexp.MustCompile(`^[A-Z]{2}[A-Za-z0-9]+\.[A-Za-z0-9.-]+$`)
	// A LEI has 20 characters (ISO 17442-1).
	leiPattern = regexp.MustCompile(`^[A-Z0-9]{18}[0-9]{2}$`)
	// VATIN, EORI and excise numbers start with the country prefix.
	prefixedNumberPattern = regexp.MustCompile(`^[A-Z]{2}[A-Za-z0-9+*]+$`)
	tinPattern            = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
)

// SemanticIdentifier is the legal person semantics identifier of a registered
// identifier (ETSI EN 319 412-1 V1.6.1 §5.1.4). The organizationIdentifier of
// an access certificate and the sub of a registration certificate carry it
// (ETSI TS 119 475 V1.2.1 GEN-5.1.3-01 to -03, Table 2). A TIN takes the
// country of the relying party.
func SemanticIdentifier(id Identifier, country string) (string, error) {
	value := strings.TrimSpace(id.Identifier)
	switch id.Type {
	case EUIDIdentifierType:
		if !euidPattern.MatchString(value) {
			return "", fmt.Errorf("identifier %q is not an EUID such as NLTEST.1A2B3C4D (country code and register, dot, registration number)", value)
		}
		// The EUID's country prefix for Greece is EL. Access certificates use
		// it too (ETSI TS 119 411-8 V1.1.1 GEN-6.6.1-05).
		return "NTR" + value[:2] + "-" + value, nil
	case LEIIdentifierType:
		if !leiPattern.MatchString(value) {
			return "", fmt.Errorf("identifier %q is not a LEI of 20 characters", value)
		}
		return "LEIXG-" + value, nil
	case VATINIdentifierType:
		// LEG-5.1.4-04 allows the VAT country prefix, such as EL, here.
		if !prefixedNumberPattern.MatchString(value) {
			return "", fmt.Errorf("identifier %q is not a VAT identification number with its country prefix, such as BE0876866142", value)
		}
		return "VAT" + value[:2] + "-" + value[2:], nil
	case TINIdentifierType:
		if !tinPattern.MatchString(value) || !countryCodePattern.MatchString(country) {
			return "", fmt.Errorf("identifier %q is not a TIN of a relying party with a country", value)
		}
		return "VAT" + country + "-" + value, nil
	// ETSI EN 319 412-1 V1.6.1 doesn't define EOR and EXC yet (TS 119 475
	// Table 2 note). They take the structure of LEG-5.1.4-02 like VAT.
	case EORIIdentifierType:
		if !prefixedNumberPattern.MatchString(value) {
			return "", fmt.Errorf("identifier %q is not an EORI number with its country prefix, such as DE1234567", value)
		}
		return "EOR" + value[:2] + "-" + value[2:], nil
	case ExciseIdentifierType:
		if !prefixedNumberPattern.MatchString(value) {
			return "", fmt.Errorf("identifier %q is not an excise number with its country prefix", value)
		}
		return "EXC" + value[:2] + "-" + value[2:], nil
	}
	return "", fmt.Errorf("identifier type %q is not one of the types of ETSI TS 119 475 clause B.2.5", id.Type)
}

// identifierKeys are the semantics identifiers of all of a relying party's
// identifiers. Two identifiers with the same key identify the same party, such
// as a VATIN and a TIN that both map to VATBE-0876866142.
func identifierKeys(rp WalletRelyingParty) []string {
	keys := make([]string, 0, len(rp.Identifier))
	for _, id := range rp.Identifier {
		if key, err := SemanticIdentifier(id, rp.Country); err == nil {
			keys = append(keys, key)
		}
	}
	return keys
}

// semanticIdentifier is the semantics identifier of a relying party's first
// identifier. Its certificates carry this value.
func semanticIdentifier(rp WalletRelyingParty) string {
	if len(rp.Identifier) == 0 {
		return ""
	}
	semantic, err := SemanticIdentifier(rp.Identifier[0], rp.Country)
	if err != nil {
		return ""
	}
	return semantic
}

// NewEUID assigns a test EUID in the business register TEST of a country.
func NewEUID(country string) string {
	country = strings.ToUpper(country)
	return country + "TEST." + strings.ToUpper(newRegistrarID())
}

var semanticPattern = regexp.MustCompile(`^(NTR|LEI|VAT|EOR|EXC)([A-Z]{2})-(.+)$`)

// typedIdentifier derives the type of an untyped identifier from its value.
// A semantics identifier from an access certificate maps back to the
// registered value. Any other value is an EUID. VAT maps to a VATIN, the more
// common of the two types with that prefix.
func typedIdentifier(value string) Identifier {
	m := semanticPattern.FindStringSubmatch(value)
	if m == nil {
		return Identifier{Type: EUIDIdentifierType, Identifier: value}
	}
	switch m[1] {
	case "NTR":
		return Identifier{Type: EUIDIdentifierType, Identifier: m[3]}
	case "LEI":
		return Identifier{Type: LEIIdentifierType, Identifier: m[3]}
	case "VAT":
		return Identifier{Type: VATINIdentifierType, Identifier: m[2] + m[3]}
	case "EOR":
		return Identifier{Type: EORIIdentifierType, Identifier: m[2] + m[3]}
	}
	return Identifier{Type: ExciseIdentifierType, Identifier: m[2] + m[3]}
}
