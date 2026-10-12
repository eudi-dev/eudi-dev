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

// Package mock generates test credentials (SD-JWT and mdoc) with default EUDI PID claims.
package mock

import (
	"encoding/base64"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/credtype"
)

// German and base PIDs use distinct SD-JWT types. In mdoc both share the doctype,
// and German attributes use an additional namespace.
const (
	DefaultPIDVCT = credtype.PIDVCT
	GermanPIDVCT  = credtype.GermanPIDVCT
	// PIDNamespace is the mdoc namespace of the country-independent EUDI PID,
	// and also the doctype of both PIDs.
	PIDNamespace       = credtype.PIDNamespace
	GermanPIDNamespace = credtype.GermanPIDNamespace
)

// The rulebook requires a portrait. The test identity uses a neutral 120x150
// grayscale JPEG silhouette.
const portraitJPEGBase64 = "/9j/2wCEAAoHBwgHBgoICAgLCgoLDhgQDg0NDh0VFhEYIx8lJCIfIiEmKzcvJik0KSEiMEExNDk7Pj4+JS5ESUM8SDc9PjsBCgsLDg0OHBAQHDsoIig7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O//AAAsIAJYAeAEBEQD/xADSAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgsQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+v/aAAgBAQAAPwD0WiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiisHWPFdnp3mQQfv7pcrtA+VG/wBo/wBB6Y4rlbzxPq16Tm6MCZBCQfJjjHXr+ZqmdU1EuHN/c7wCA3nNkA4yOvsPyqzaeI9WtH3LeySAkErMd4OO3PI/DFdNpPjK2uQsWoYt5icbwD5Z549x178cda6Wiiiiiiiiub8W65Lp0SWdq2yeZSzOM5RenHueee2Poa4Siiiiuw8H65K8q6VctuG0+QxzkY/h+mMkemMemOvooooooprusaM7sFRRlmY4AHqa8qvrtr6+nunyDK5bBbO0dhn2HH4VXoooopyO0bq6MVdTlWU4IPqK9Vsbtb6xgukwBKgbAbO09xn2PH4VYoooooqlrTBNEvSQf9Q44BPUEdq8toooooor0bwkwbw5bAA/KXByCP4iePXr2rZoooooqtqUTz6ZdQxLukkhdVGcZJUgV5TRRRRRRXpXhmJ4fDtoki7SVLAZ7FiR+hFatFFFFFFeb+JNKbTNVfAHkzkyRbVwACfu+nHt2x61kUUUUVc0rTZdV1CO0iO3dyz4JCKOp/z3Ir1FEWNFRFCoowqqMAD0FOooooooqhq+kW+sWnkzDa68xyAcof6j1H/1q861DTbvTLgw3URXkhXx8r+4PfqKqUUVNa2lxezCG2heWQ9lHTnGT6Dnqa9D0HQYdGt8nEl1IP3knp/sj2/n+QGtRRRRRRRRUVxbw3du9vcRiSKQYZT3rn7zwRYzEtaTSWxJHyn51Ax2zz+tUz4CbeANRGzByfJ5B4xxu+tWbTwNaRvuurqScAghUXYD6g9T+WK6CzsbbT7cQWkQijBJwMnJ9STyasUUUUUUUUUUUUUUUUUUUUUUUyWaK3iMs0iRxr1Z2AA/E1zOpeNoIsx6dF5zf89ZAQvboOp7jt+NcxLrmqzSmR9QuAT1CSFB+QwKZ/a+p/8AQRu/+/7f40f2vqf/AEEbv/v+3+NH9r6n/wBBG7/7/t/jTk1rVEdXGo3JKnI3SsR+IPBrotL8bfdi1OL0HnRj6clfzJI/Kuptbu3vYRNbTJLGe6npxnB9Dz0NTUUUUyWaK3iMs0iRxr1Z2AA/E1zOpeNoIsx6dF5zf89ZAQvboOp7jt+Ncle6jeajKJLu4eUjoDwF+gHA6DpVaiiiiiiprW7uLKYTW0zxSDupxnnOD6jjoa6rS/G33YtTi9B50Y+nJX8ySPyrqbW7t72ETW0ySxnup6cZwfQ89DU1ctqXjaCLMenRec3/AD1kBC9ug6nuO341yV7qN5qMoku7h5SOgPAX6AcDoOlVqKKKKKKKKKKmtbu4sphNbTPFIO6nGec4PqOOhrqtL8bfdi1OL0HnRj6clfzJI/KuPoooooooooooooooooooooooooooooooooooooooooooor//2Q=="

func PortraitJPEG() []byte {
	data, err := base64.StdEncoding.DecodeString(portraitJPEGBase64)
	if err != nil {
		panic(err)
	}
	return data
}

func PortraitDataURL() string {
	return "data:image/jpeg;base64," + portraitJPEGBase64
}

var DefaultClaims = map[string]any{
	"given_name":  "Jan Wijnand",
	"family_name": "'t Hart",
	"birthdate":   "1978-02-12",
}

// The country-independent claim sets follow the EUDI PID Rulebook v1.7
// (github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog,
// rulebooks/pid/pid-rulebook.md) and carry its worked example, the Dutch
// Jan Wijnand 't Hart identity. The German ones follow the German PID Rulebook
// 1.0.0 of the BMI blueprint (https://bmi.usercontent.opencode.de/eudi-wallet/eidas-2.0-architekturkonzept/content/features/PID/german-pid-rulebook/)
// and carry the Erika Mustermann specimen from the German ID card.
//
// The German PID adds national attributes to the shared set. It encodes some
// shared ones differently, such as birth_name and a street with the house number.
//
// The rulebook's data identifiers differ from the encoding identifiers (its
// §2.1), so birth_place appears as place_of_birth.

// SDJWTPIDClaims holds the SD-JWT VC claims of the country-independent EUDI
// PID (vct urn:eudi:pid:1). address and place_of_birth are nested objects
// with individually disclosable subclaims. nationalities is a selectively
// disclosable array.
var SDJWTPIDClaims = map[string]any{
	"family_name":       "'t Hart",
	"given_name":        "Jan Wijnand",
	"birthdate":         "1978-02-12",
	"birth_family_name": "'t Hart",
	// ISO/IEC 5218: 0 unknown, 1 male, 2 female, 9 not applicable.
	"sex": 1,
	"place_of_birth": map[string]any{
		"locality": "Amsterdam",
		"country":  "NL",
	},
	"address": map[string]any{
		// resident_street includes the house number (rulebook §2.3). The rulebook
		// also defines address.house_number as a separate member.
		"street_address": "Rietveld 1",
		"house_number":   "1",
		"postal_code":    "2312 JD",
		"locality":       "Leiden",
		"region":         "Zuid-Holland",
		"country":        "NL",
	},
	"nationalities": []any{"NL"},
	// CIR 2024/2977 makes the portrait mandatory unless the user opts out
	// (rulebook §2.2). SD-JWT uses a JPEG data URL in the OIDC picture claim.
	// mdoc uses raw JPEG bytes.
	"picture": PortraitDataURL(),
	// The rulebook defines no age thresholds (CIR 2024/2977). The German claim
	// set has its own.
	"personal_administrative_number": "123456782",
	"document_number":                "A01234567",
	"date_of_issuance":               PIDIssuanceDate(),
	"date_of_expiry":                 PIDExpiryDate(),
	"issuing_authority":              "Rijksdienst voor Identiteitsgegevens",
	"issuing_country":                "NL",
}

// SDJWTGermanPIDClaims holds the SD-JWT VC claims of the German PID (vct
// urn:eudi:pid:de:1) from the German PID Rulebook 1.0.0 of the BMI blueprint.
// It has every claim of that SD-JWT payload.
var SDJWTGermanPIDClaims = map[string]any{
	// This credential also answers a request for urn:eudi:pid:1
	// (draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.2).
	credtype.AkaVCTsClaim: []any{credtype.PIDVCT},

	"family_name": "MUSTERMANN",
	"given_name":  "ERIKA",
	// The German birth_name may hold both given and family name at birth.
	// It differs from the rulebook's birth_family_name.
	"birth_name": "GABLER",
	// Present and empty when the eID carries no title.
	"academic_title": "",
	"birthdate":      "1964-08-12",
	// The eID stores the birth date with 00 for an unknown day or month.
	"raw_eid_birth_date": "1964-08-12",
	"age_equal_or_over": map[string]any{
		"12": true,
		"14": true,
		"16": true,
		"18": true,
		"21": true,
		"65": false,
	},
	// locality is empty when the eID has no place of birth.
	"place_of_birth": map[string]any{
		"locality": "BERLIN",
	},
	"address": map[string]any{
		"street_address": "HEIDESTRAẞE 17",
		"postal_code":    "51147",
		"locality":       "KÖLN",
		"region":         "NW",
		"country":        "DE",
	},
	"nationalities":        []any{"DE"},
	"issuing_authority":    "DE",
	"issuing_country":      "DE",
	"source_document_type": "ID",
}

// MDOCPIDClaims holds the ISO 18013-5 elements of the country-independent EUDI
// PID (eu.europa.ec.eudi.pid.1). It is the identity of SDJWTPIDClaims under the
// mdoc attribute identifiers. The address is flat with the house number in
// resident_street.
var MDOCPIDClaims = map[string]any{
	"family_name":                    "'t Hart",
	"given_name":                     "Jan Wijnand",
	"birth_date":                     "1978-02-12",
	"family_name_birth":              "'t Hart",
	"sex":                            1,
	"portrait":                       PortraitJPEG(),
	"place_of_birth":                 map[string]any{"locality": "Amsterdam", "country": "NL"},
	"nationality":                    []any{"NL"},
	"resident_street":                "Rietveld 1",
	"resident_postal_code":           "2312 JD",
	"resident_city":                  "Leiden",
	"resident_state":                 "Zuid-Holland",
	"resident_country":               "NL",
	"personal_administrative_number": "123456782",
	"document_number":                "A01234567",
	"issuance_date":                  PIDIssuanceDate(),
	"expiry_date":                    PIDExpiryDate(),
	"issuing_authority":              "Rijksdienst voor Identiteitsgegevens",
	"issuing_country":                "NL",
}

// MDOCGermanPIDClaims puts German attributes in a second namespace because ISO/IEC
// 18013-5 has no doctype inheritance. Keys of the form namespace:element select it.
var MDOCGermanPIDClaims = map[string]any{
	"family_name":          "MUSTERMANN",
	"given_name":           "ERIKA",
	"birth_date":           "1964-08-12",
	"expiry_date":          PIDExpiryDate(),
	"place_of_birth":       map[string]any{"locality": "BERLIN"},
	"nationality":          []any{"DE"},
	"resident_street":      "HEIDESTRAẞE 17",
	"resident_postal_code": "51147",
	"resident_city":        "KÖLN",
	"resident_state":       "NW",
	"resident_country":     "DE",
	"issuing_authority":    "DE",
	"issuing_country":      "DE",

	GermanPIDNamespace + ":birth_name":           "GABLER",
	GermanPIDNamespace + ":academic_title":       "",
	GermanPIDNamespace + ":raw_eid_birth_date":   "1964-08-12",
	GermanPIDNamespace + ":age_over_12":          true,
	GermanPIDNamespace + ":age_over_14":          true,
	GermanPIDNamespace + ":age_over_16":          true,
	GermanPIDNamespace + ":age_over_18":          true,
	GermanPIDNamespace + ":age_over_21":          true,
	GermanPIDNamespace + ":age_over_65":          false,
	GermanPIDNamespace + ":source_document_type": "ID",
}

func PIDIssuanceDate() string {
	return time.Now().UTC().Format(time.DateOnly)
}

var pidDateClaims = map[string]func() string{
	"date_of_issuance": PIDIssuanceDate,
	"issuance_date":    PIDIssuanceDate,
	"date_of_expiry":   PIDExpiryDate,
	"expiry_date":      PIDExpiryDate,
}

// RefreshPIDDates sets the dates to the issuance time, so a long-running server issues
// current dates. It updates only existing claims because the German PID has no
// issuance date.
func RefreshPIDDates(claims map[string]any) map[string]any {
	for name, value := range pidDateClaims {
		if _, ok := claims[name]; ok {
			claims[name] = value()
		}
	}
	return claims
}

// PIDExpiryDate follows the German PID rulebook's five year administrative expiry (§10a
// (2) PAuswG). This calendar date is independent of the credential's technical validity.
func PIDExpiryDate() string {
	return time.Now().UTC().AddDate(5, 0, 0).Format(time.DateOnly)
}
