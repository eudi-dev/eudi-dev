package wallet

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/provider"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

// TS 119 602 V1.1.1 §§6.1, 6.3 and Annexes D/E define these publication rules.
func TestTrustListProfilePublication(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.IssuerURL = "https://issuer.example"
	for _, group := range w.TrustedLists().Groups() {
		t.Run(group.ID, func(t *testing.T) {
			path := "/api/trustlists/" + group.ID
			first, err := w.TrustedLists().SignedGroupList(w.IssuerURL, group, path)
			if err != nil {
				t.Fatal(err)
			}
			second, err := w.TrustedLists().SignedGroupList(w.IssuerURL, group, path)
			if err != nil {
				t.Fatal(err)
			}
			if first != second {
				t.Error("unchanged trusted list was reissued")
			}
			token, err := sdjwt.Parse(first)
			if err != nil {
				t.Fatal(err)
			}
			if token.Header["iat"] == nil || token.Header["sigT"] != nil {
				t.Errorf("JAdES signing time header = %v", token.Header)
			}
			list := token.Payload["LoTE"].(map[string]any)
			info := list["ListAndSchemeInformation"].(map[string]any)
			x5c := token.Header["x5c"].([]any)
			der, err := base64.StdEncoding.DecodeString(x5c[0].(string))
			if err != nil {
				t.Fatal(err)
			}
			operator, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			postal := info["SchemeOperatorAddress"].(map[string]any)["SchemeOperatorPostalAddress"].([]any)[0].(map[string]any)
			if len(operator.Subject.Country) != 1 || operator.Subject.Country[0] != postal["Country"] {
				t.Errorf("operator certificate country = %v, address country = %v", operator.Subject.Country, postal["Country"])
			}
			date := info["ListIssueDateTime"].(string)
			if _, err := time.Parse("2006-01-02T15:04:05Z", date); err != nil || strings.Contains(date, ".") {
				t.Errorf("invalid ETSI timestamp %q", date)
			}
			name := info["SchemeOperatorName"].([]any)[0].(map[string]any)
			if name["lang"] != "en" {
				t.Errorf("missing required English language representation: %v", name)
			}
			entity := list["TrustedEntitiesList"].([]any)[0].(map[string]any)["TrustedEntityInformation"].(map[string]any)
			address, ok := entity["TEAddress"].(map[string]any)
			if !ok || address["TEPostalAddress"] == nil {
				t.Error("missing required TEPostalAddress")
			}
			group.List.EntityName += " updated"
			updated, err := w.TrustedLists().SignedGroupList(w.IssuerURL, group, path)
			if err != nil {
				t.Fatal(err)
			}
			updatedToken, err := sdjwt.Parse(updated)
			if err != nil {
				t.Fatal(err)
			}
			updatedInfo := updatedToken.Payload["LoTE"].(map[string]any)["ListAndSchemeInformation"].(map[string]any)
			if updatedInfo["LoTESequenceNumber"] != float64(2) {
				t.Errorf("updated sequence = %v, want 2", updatedInfo["LoTESequenceNumber"])
			}
		})
	}
}

func TestTrustListRetainsProviderTrustAcrossCountriesAndUpdates(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.IssuerURL = "https://issuer.example"
	group := w.TrustedLists().DefaultGroup()
	listPath := "/api/trustlists/" + group.ID
	first, err := w.TrustedLists().SignedGroupList(w.IssuerURL, group, listPath)
	if err != nil {
		t.Fatal(err)
	}
	spec := categorySpec(provider.IssuedAttestationSpec{Category: credtemplate.CategoryPID, Format: "mso_mdoc", DocType: mock.PIDNamespace})
	_, chain, err := w.Signer().ForCredential(spec, map[string]any{"issuing_country": "FR"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := w.TrustedLists().SignedGroupList(w.IssuerURL, group, listPath)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("adding a provider CA did not update the trusted list")
	}
	token, err := sdjwt.Parse(second)
	if err != nil {
		t.Fatal(err)
	}
	list := token.Payload["LoTE"].(map[string]any)
	info := list["ListAndSchemeInformation"].(map[string]any)
	if info["LoTESequenceNumber"] != float64(2) {
		t.Fatalf("sequence = %v", info["LoTESequenceNumber"])
	}
	entity := list["TrustedEntitiesList"].([]any)[0].(map[string]any)
	services := entity["TrustedEntityServices"].([]any)
	service := services[0].(map[string]any)["ServiceInformation"].(map[string]any)
	trusted := false
	for _, identity := range service["ServiceDigitalIdentity"].(map[string]any)["X509Certificates"].([]any) {
		encoded := identity.(map[string]any)["val"].(string)
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if cert.IsCA && chain[0].CheckSignatureFrom(cert) == nil {
			trusted = true
		}
	}
	if !trusted {
		t.Error("French credential provider CA is absent from the trusted list")
	}
	store := w.providerKeys()
	for sequence, expected := range []string{first, second} {
		raw, err := store.TrustListHistory(w.IssuerURL, listPath, sequence+1)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != expected {
			t.Errorf("history instance %d changed", sequence+1)
		}
	}
	third, err := w.TrustedLists().SignedGroupList(w.IssuerURL, group, listPath)
	if err != nil {
		t.Fatal(err)
	}
	if third != second {
		t.Error("unchanged provider material reissued the list")
	}
}

// The PID and PuB-EAA lists follow the profiles of ETSI TS 119 602 V1.1.1
// Annex D and Annex H.
func TestTheCategoryListsFollowTheirLoTEProfiles(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.IssuerURL = "https://issuer.example"
	type service struct {
		ServiceInformation struct {
			ServiceStatus          string `json:"ServiceStatus"`
			ServiceDigitalIdentity struct {
				X509Certificates []struct{ Val string } `json:"X509Certificates"`
			} `json:"ServiceDigitalIdentity"`
		} `json:"ServiceInformation"`
	}
	type uriValue struct {
		URIValue string `json:"uriValue"`
	}
	var lists = map[string]struct {
		LoTE struct {
			ListAndSchemeInformation struct {
				HistoricalInformationPeriod *int  `json:"HistoricalInformationPeriod"`
				PointersToOtherLoTE         []any `json:"PointersToOtherLoTE"`
			} `json:"ListAndSchemeInformation"`
			TrustedEntitiesList []struct {
				TrustedEntityInformation struct {
					TETradeName      []struct{ Value string } `json:"TETradeName"`
					TEInformationURI []uriValue               `json:"TEInformationURI"`
					TEAddress        struct {
						TEElectronicAddress []uriValue `json:"TEElectronicAddress"`
					} `json:"TEAddress"`
				} `json:"TrustedEntityInformation"`
				TrustedEntityServices []service `json:"TrustedEntityServices"`
			} `json:"TrustedEntitiesList"`
		}
	}{}
	for _, category := range []string{credtemplate.CategoryPID, credtemplate.CategoryPubEAA} {
		group, _ := w.TrustedLists().FindGroup(category, "", "")
		jwt, err := w.TrustedLists().SignedGroupList(w.IssuerURL, group, "/api/trustlists/"+category)
		if err != nil {
			t.Fatal(err)
		}
		token, err := sdjwt.Parse(jwt)
		if err != nil {
			t.Fatal(err)
		}
		list := lists[category]
		if err := json.Unmarshal([]byte(mustJSON(t, token.Payload)), &list); err != nil {
			t.Fatal(err)
		}
		lists[category] = list
	}
	uris := func(values []uriValue) []string {
		var out []string
		for _, v := range values {
			out = append(out, v.URIValue)
		}
		return out
	}

	pid := lists[credtemplate.CategoryPID].LoTE
	pidEntity := pid.TrustedEntitiesList[0].TrustedEntityInformation
	if len(pid.ListAndSchemeInformation.PointersToOtherLoTE) != 1 || pid.ListAndSchemeInformation.HistoricalInformationPeriod != nil {
		t.Error("the PID list needs a pointer to itself and no history period (Table D.1)")
	}
	if pidEntity.TETradeName[0].Value != "NTRNL-"+demoIdentifier(demoIssuer) || !slices.Contains(uris(pidEntity.TEInformationURI), "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/NL") {
		t.Errorf("PID provider %+v, want the registration identifier and the Member State URI (Table D.2)", pidEntity)
	}

	pubEAA := lists[credtemplate.CategoryPubEAA].LoTE
	if len(pubEAA.ListAndSchemeInformation.PointersToOtherLoTE) != 0 || pubEAA.ListAndSchemeInformation.HistoricalInformationPeriod == nil || *pubEAA.ListAndSchemeInformation.HistoricalInformationPeriod != 65535 {
		t.Error("the PuB-EAA list needs no pointers and a history period of 65535 (Table H.1)")
	}
	pubEntity := pubEAA.TrustedEntitiesList[0]
	if !slices.Contains(uris(pubEntity.TrustedEntityInformation.TEAddress.TEElectronicAddress), "http://uri.etsi.org/19602/ListOfTrustedEntities/PubEAAProvider/NL") || len(pubEntity.TrustedEntityInformation.TETradeName) != 2 {
		t.Errorf("PuB-EAA provider %+v, want the Member State URI and the law reference (Table H.2)", pubEntity.TrustedEntityInformation)
	}
	if len(pubEntity.TrustedEntityServices) == 0 {
		t.Fatal("the PuB-EAA provider has no services")
	}
	for _, s := range pubEntity.TrustedEntityServices {
		if s.ServiceInformation.ServiceStatus != lote.PubEAANotifiedStatus || len(s.ServiceInformation.ServiceDigitalIdentity.X509Certificates) != 1 {
			t.Errorf("service %+v, want the notified status and one certificate (Table H.3)", s.ServiceInformation)
		}
	}
}
