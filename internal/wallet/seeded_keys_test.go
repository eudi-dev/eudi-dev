package wallet

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
	"github.com/dominikschlosser/eudi-dev/v3/internal/lote"
	"github.com/dominikschlosser/eudi-dev/v3/internal/provider"
	"github.com/dominikschlosser/eudi-dev/v3/internal/storage"
)

// A seed derives every key from its name (ADR-0017), so a seeded wallet keeps
// its keys across versions. The golden file holds the public key of each
// signing role.
func TestSeededKeysMatchTheGoldenFile(t *testing.T) {
	store := NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), storage.NewMemory())
	store.SetSeed("golden-seed")
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	w.IssuerURL = "https://issuer.example"
	thumbprints := map[string]string{}
	add := func(name string, pub any) {
		t.Helper()
		sum, err := keys.PublicKeyThumbprint(pub)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		thumbprints[name] = base64.RawURLEncoding.EncodeToString(sum)
	}
	material := func(name string, key *ecdsa.PrivateKey, chain []*x509.Certificate, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		add(name, &key.PublicKey)
		for i, cert := range chain[1:] {
			add(name+"/chain/"+string(rune('1'+i)), cert.PublicKey)
		}
	}
	add("holder", &w.HolderKey.PublicKey)
	add("issuer", &w.IssuerKey.PublicKey)
	add("ca", &w.CAKey.PublicKey)
	spec := func(vct, category string) provider.IssuedAttestationSpec {
		t.Helper()
		spec, err := provider.NormalizeIssuedAttestationSpec(provider.IssuedAttestationSpec{Format: credtype.FormatSDJWT, VCT: vct}, category)
		if err != nil {
			t.Fatal(err)
		}
		return spec
	}
	for _, category := range credtemplate.Categories {
		key, chain, err := w.Signer().ForList(spec("urn:golden", category).List(), "")
		material("category/"+category, key, chain, err)
	}
	custom, err := provider.NormalizeIssuedAttestationSpec(provider.IssuedAttestationSpec{Format: credtype.FormatSDJWT, VCT: "urn:golden:custom", Scheme: lote.Scheme{LoTEType: "https://example.org/LoTEType/custom", EntityName: "Custom Provider", SchemeTerritory: "DE"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	key, chain, err := w.Signer().ForList(custom.List(), "")
	material("custom", key, chain, err)
	key, chain, err = w.Signer().ForList(spec("urn:golden:unlisted", provider.UnlistedCategory).List(), "")
	material("unlisted", key, chain, err)
	key, chain, err = w.Signer().ForCredential(spec("urn:golden", credtemplate.CategoryPID), map[string]any{"issuing_country": "DE"})
	material("pid/DE", key, chain, err)
	key, chain, err = w.Signer().WalletProvider()
	material("wallet-provider", key, chain, err)
	key, chain, err = w.Signer().StatusList()
	material("status", key, chain, err)
	key, chain, err = w.Signer().Registrar()
	material("registrar", key, chain, err)
	key, chain, err = w.Signer().TrustList("Operator", "NL")
	material("trustlist", key, chain, err)
	key, chain, err = w.AccessSigningMaterial()
	material("access", key, chain, err)
	key, chain, err = w.DemoVerifierAccessSigningMaterial()
	material("demo-verifier-access", key, chain, err)
	caKey, _, err := w.Signer().RelyingPartyAccessCA()
	if err != nil {
		t.Fatal(err)
	}
	add("relying-party-access-ca", &caKey.PublicKey)
	data, err := json.MarshalIndent(thumbprints, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	compareGolden(t, "seeded-keys.json", data)
}
