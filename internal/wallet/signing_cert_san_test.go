package wallet

import (
	"net/url"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
)

// SD-JWT VC draft-08 requires the issuer identifier in the signing leaf's SANs.
func TestIssuedCredentialLeafNamesTheIssuer(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://eudi-test.dev"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("GenerateDefaultCredentials: %v", err)
	}

	var raw string
	for _, c := range w.GetCredentials() {
		if c.Format == "dc+sd-jwt" {
			raw = c.Raw
		}
	}
	if raw == "" {
		t.Fatal("no SD-JWT credential was issued")
	}
	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("parsing the issued credential: %v", err)
	}
	iss, _ := token.Payload["iss"].(string)
	if iss == "" {
		t.Fatal("the issued credential carries no iss")
	}

	chain, err := w.SigningCertChainForIssuedAttestation(IssuedAttestationSpec{Format: "dc+sd-jwt", VCT: token.Payload["vct"].(string)})
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	leaf := chain[0]

	host := iss
	if parsed, err := url.Parse(iss); err == nil {
		host = parsed.Hostname()
	}
	found := false
	for _, name := range leaf.DNSNames {
		if strings.EqualFold(name, host) {
			found = true
		}
	}
	if !found {
		t.Errorf("leaf has no dNSName for %q (DNSNames=%v)", host, leaf.DNSNames)
	}

	uriFound := false
	for _, u := range leaf.URIs {
		if u.String() == iss {
			uriFound = true
		}
	}
	if !uriFound {
		t.Errorf("leaf has no uniformResourceIdentifier for %q (URIs=%v)", iss, leaf.URIs)
	}
}

// IP hosts require an IP SAN.
func TestIssuedCredentialLeafNamesAnAddressIssuer(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://159.195.213.172:8443"
	chain, err := w.SigningCertChainForIssuedAttestation(IssuedAttestationSpec{Format: "dc+sd-jwt", VCT: "urn:eudi:pid:1"})
	if err != nil {
		t.Fatalf("signing chain: %v", err)
	}
	leaf := chain[0]
	if len(leaf.DNSNames) != 0 {
		t.Errorf("an address became a dNSName: %v", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "159.195.213.172" {
		t.Errorf("IPAddresses = %v, want the issuer address", leaf.IPAddresses)
	}
}
