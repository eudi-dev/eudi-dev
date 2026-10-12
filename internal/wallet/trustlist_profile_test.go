package wallet

import (
	"crypto/x509"
	"encoding/base64"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
)

// TS 119 602 V1.1.1 §§6.1, 6.3 and Annexes D/E define these publication rules.
func TestTrustListProfilePublication(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.IssuerURL = "https://issuer.example"
	for _, group := range TrustListGroupsForWallet(w) {
		t.Run(group.ID, func(t *testing.T) {
			path := "/api/trustlists/" + group.ID
			first, err := GenerateTrustListJWTForWalletGroup(w, w.IssuerURL, group, path)
			if err != nil {
				t.Fatal(err)
			}
			second, err := GenerateTrustListJWTForWalletGroup(w, w.IssuerURL, group, path)
			if err != nil {
				t.Fatal(err)
			}
			if first != second {
				t.Error("unchanged trust list was reissued")
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
			group.Profile.EntityName += " updated"
			updated, err := GenerateTrustListJWTForWalletGroup(w, w.IssuerURL, group, path)
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
	group, ok := DefaultTrustListGroupForWallet(w)
	if !ok {
		t.Fatal("PID trust list is missing")
	}
	listPath := "/api/trustlists/" + group.ID
	first, err := GenerateTrustListJWTForWalletGroup(w, w.IssuerURL, group, listPath)
	if err != nil {
		t.Fatal(err)
	}
	spec := applyPIDTrustProfileDefaults(IssuedAttestationSpec{Format: "mso_mdoc", DocType: mock.PIDNamespace})
	chain, err := w.SigningCertChainForIssuedCredential(spec, map[string]any{"issuing_country": "FR"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateTrustListJWTForWalletGroup(w, w.IssuerURL, group, listPath)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("adding a provider CA did not update the trust list")
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
		t.Error("French credential provider CA is absent from the trust list")
	}
	store := w.signingStore()
	for sequence, expected := range []string{first, second} {
		raw, err := store.backend.Read(path.Join(store.trustListDir(w.IssuerURL, listPath), "history", strconv.Itoa(sequence+1)+".jwt"))
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != expected {
			t.Errorf("history instance %d changed", sequence+1)
		}
	}
	third, err := GenerateTrustListJWTForWalletGroup(w, w.IssuerURL, group, listPath)
	if err != nil {
		t.Fatal(err)
	}
	if third != second {
		t.Error("unchanged provider material reissued the list")
	}
}
