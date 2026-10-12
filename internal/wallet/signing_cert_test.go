package wallet

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/asn1"
	"sync"
	"testing"

	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/storage"
)

func TestSigningCertificatesRemainStable(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example"
	spec := applyPIDTrustProfileDefaults(IssuedAttestationSpec{Format: "dc+sd-jwt", VCT: mock.DefaultPIDVCT})
	first, err := w.SigningCertChainForIssuedCredential(spec, map[string]any{"issuing_country": "NL"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := w.SigningCertChainForIssuedCredential(spec, map[string]any{"issuing_country": "NL"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first[0].Raw, second[0].Raw) {
		t.Error("repeated issuance replaced the signing certificate")
	}
	german, err := w.SigningCertChainForIssuedCredential(spec, map[string]any{"issuing_country": "DE"})
	if err != nil {
		t.Fatal(err)
	}
	if first[0].SerialNumber.Cmp(german[0].SerialNumber) == 0 {
		t.Error("different certificates share a serial number under the same CA")
	}
	_, statusFirst, err := w.StatusListSigningMaterial()
	if err != nil {
		t.Fatal(err)
	}
	_, statusSecond, err := w.StatusListSigningMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(statusFirst[0].Raw, statusSecond[0].Raw) {
		t.Error("repeated status publication replaced the signing certificate")
	}
}

// ETSI TS 119 412-6 V1.1.1 §§4.3, 4.5 and 5 define the provider subjects and QcTypes.
func TestSigningCertificatesIdentifyProviderRoles(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example"
	pid := applyPIDTrustProfileDefaults(IssuedAttestationSpec{Format: "dc+sd-jwt", VCT: mock.DefaultPIDVCT})
	pidChain, err := w.SigningCertChainForIssuedAttestation(pid)
	if err != nil {
		t.Fatal(err)
	}
	walletChain, err := w.SigningCertChainForProfile(walletProviderTrustListProfile())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		chainRole string
		role      asn1.ObjectIdentifier
	}{
		{"pid", asn1.ObjectIdentifier{0, 4, 0, 194126, 1, 1}},
		{"wallet", asn1.ObjectIdentifier{0, 4, 0, 194126, 1, 2}},
	} {
		t.Run(tc.chainRole, func(t *testing.T) {
			chain := pidChain
			if tc.chainRole == "wallet" {
				chain = walletChain
			}
			leaf := chain[0]
			if len(leaf.Subject.Organization) == 0 {
				t.Error("provider certificate has no organization")
			}
			identifier := false
			for _, name := range leaf.Subject.Names {
				if name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 97}) {
					identifier = true
				}
			}
			if !identifier {
				t.Error("provider certificate has no organizationIdentifier")
			}
			if len(leaf.IssuingCertificateURL) == 0 {
				t.Error("provider certificate has no caIssuers AIA")
			}
			found := false
			for _, ext := range leaf.Extensions {
				if !ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}) {
					continue
				}
				var statements []struct {
					ID   asn1.ObjectIdentifier
					Info []asn1.ObjectIdentifier
				}
				if rest, err := asn1.Unmarshal(ext.Value, &statements); err != nil || len(rest) != 0 {
					t.Fatalf("invalid QCStatements: %v", err)
				}
				for _, statement := range statements {
					if statement.ID.Equal(asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6}) && len(statement.Info) == 1 && statement.Info[0].Equal(tc.role) {
						found = true
					}
				}
			}
			if !found {
				t.Errorf("missing QcType %s", tc.role)
			}
		})
	}
	if walletChain[0].PublicKey.(*ecdsa.PublicKey).Equal(pidChain[0].PublicKey) {
		t.Error("wallet provider and PID provider share a signing key")
	}
}

func TestSigningCertificatesSurviveReload(t *testing.T) {
	backend := storage.NewMemory()
	dir := t.TempDir()
	spec := applyPIDTrustProfileDefaults(IssuedAttestationSpec{Format: "dc+sd-jwt", VCT: mock.DefaultPIDVCT})
	w, err := NewWalletStoreOn(dir, backend).LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	w.IssuerURL = "https://issuer.example"
	chain, err := w.SigningCertChainForIssuedAttestation(spec)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			reloaded, err := NewWalletStoreOn(dir, backend).LoadOrCreate()
			if err != nil {
				t.Error(err)
				return
			}
			reloaded.IssuerURL = w.IssuerURL
			got, err := reloaded.SigningCertChainForIssuedAttestation(spec)
			if err != nil {
				t.Error(err)
				return
			}
			if !bytes.Equal(chain[0].Raw, got[0].Raw) {
				t.Error("reload replaced the persisted signing certificate")
			}
		})
	}
	wg.Wait()
}
