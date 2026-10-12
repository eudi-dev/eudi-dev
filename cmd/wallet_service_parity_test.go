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

package cmd

// Compare the document fields returned by local and remote management. Their IDs and
// timestamps differ, but the CLI must be able to read the same fields from both.

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v2/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v2/internal/remote"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

func parityWallets(t *testing.T, seed func(*wallet.Wallet)) (local walletService, remoteSvc walletService) {
	t.Helper()

	// Create the wallet through its store so the saved holder key matches the
	// credentials. Saving only wallet.json would make a reload generate a different
	// key.
	newWallet := func(store *wallet.WalletStore) *wallet.Wallet {
		w, err := store.LoadOrCreate()
		if err != nil {
			t.Fatal(err)
		}
		w.AutoAccept = true
		w.Templates = credtemplate.FileLocation(t.TempDir())
		seed(w)
		if err := store.Save(w); err != nil {
			t.Fatal(err)
		}
		return w
	}

	servedStore := wallet.NewWalletStore(t.TempDir())
	served := newWallet(servedStore)
	// Without a save hook, triggerSave would write nothing and the next withFreshStore
	// reload would discard the changes.
	srv := wallet.NewServer(served, 0, func() {
		if err := servedStore.Save(served); err != nil {
			t.Errorf("saving the served wallet: %v", err)
		}
	})
	srv.SetStore(servedStore)
	srv.ShutdownFunc = func() {}
	addr, err := srv.ListenAndServeBackground()
	if err != nil {
		t.Fatalf("starting the wallet server: %v", err)
	}

	store := wallet.NewWalletStore(t.TempDir())
	stored := newWallet(store)

	localSvc := &localWallet{load: func() (*wallet.Wallet, *wallet.WalletStore, error) {
		return stored, store, nil
	}}
	return localSvc, &remoteWallet{c: remote.NewClient(addr)}
}

func keysOf(doc map[string]any) []string {
	out := make([]string, 0, len(doc))
	for k, v := range doc {
		// A backend that returns the key with an empty value still lets the
		// CLI read it, so only a missing key counts as a difference.
		if v == nil {
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The table compares document shapes. This test checks one value. On both
// backends a deferred credential identifies the credential type being issued.
func TestDeferredDocumentsCarryTheCredentialType(t *testing.T) {
	resetRemoteTestState(t)
	localSvc, remoteSvc := parityWallets(t, func(w *wallet.Wallet) {
		w.AddDeferredIssuance(&wallet.DeferredIssuance{
			ID: "pending-1", TransactionID: "tx-1", Issuer: "https://issuer.example",
			ConfigurationID: "msisdn-sd-jwt-key-attestations", Format: "dc+sd-jwt",
			VCT: "eu.europa.ec.eudi.msisdn.1", IntervalSeconds: 60,
		})
	})

	for name, svc := range map[string]walletService{"local": localSvc, "remote": remoteSvc} {
		docs, err := svc.DeferredIssuances()
		if err != nil {
			t.Fatalf("%s deferred: %v", name, err)
		}
		if len(docs) != 1 {
			t.Fatalf("%s backend returned %d deferred records, want 1", name, len(docs))
		}
		if got := docs[0]["vct"]; got != "eu.europa.ec.eudi.msisdn.1" {
			t.Errorf("%s backend reports vct %v, so the row is labelled by the issuer's configuration id", name, got)
		}
	}
}

func TestConfigDocumentsMatchAcrossBackends(t *testing.T) {
	resetRemoteTestState(t)
	localSvc, remoteSvc := parityWallets(t, func(*wallet.Wallet) {})

	localCfg, err := localSvc.Config()
	if err != nil {
		t.Fatalf("local config: %v", err)
	}
	remoteCfg, err := remoteSvc.Config()
	if err != nil {
		t.Fatalf("remote config: %v", err)
	}
	inRemote := make(map[string]bool, len(remoteCfg))
	for _, k := range keysOf(remoteCfg) {
		inRemote[k] = true
	}
	for _, k := range keysOf(localCfg) {
		if !inRemote[k] {
			t.Errorf("config document: the local backend reports %q and a remote wallet does not", k)
		}
	}
}

// Compare API fields and normalized values across local and remote backends. IDs,
// paths and timestamps differ between independently created wallets. Seed through
// walletService so the test uses each backend's normal storage route.
type parityCase struct {
	method  string
	observe func(t *testing.T, svc walletService) any
	skip    string
}

// Select by format because issuance timestamps can order independently created wallets
// differently.
func credentialID(t *testing.T, s walletService, format string) string {
	t.Helper()
	docs, err := s.Credentials()
	if err != nil {
		t.Fatalf("listing credentials: %v", err)
	}
	for _, doc := range docs {
		if doc["format"] == format {
			return doc["id"].(string)
		}
	}
	t.Fatalf("no %s credential among %d stored", format, len(docs))
	return ""
}

// importedCredential puts one deletable credential in the wallet and returns
// its id. The PID baseline is protected and refuses deletion on both backends.
func importedCredential(t *testing.T, s walletService) string {
	t.Helper()
	full, err := s.Credential(credentialID(t, s, "dc+sd-jwt"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := full["raw"].(string)
	if raw == "" {
		t.Fatal("no raw credential to import")
	}
	imported, err := s.ImportCredential(raw)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := imported["id"].(string)
	if id == "" {
		t.Fatalf("import returned no id: %v", imported)
	}
	return id
}

func saveParityTemplate(t *testing.T, s walletService) {
	t.Helper()
	if _, err := s.SaveTemplate(credtemplate.Template{
		Name: "parity", Format: "sdjwt", VCT: "urn:test:parity:1",
		Claims: map[string]any{"given_name": "Alice"},
	}); err != nil {
		t.Fatal(err)
	}
}

func parityCases() []parityCase {
	return []parityCase{
		{method: "URL", skip: "the local store has no URL by definition, which is what distinguishes the backends"},
		{method: "Config", skip: "a running server knows its port, build and listeners and a store on disk does not. TestConfigDocumentsMatchAcrossBackends pins the direction that must hold"},

		{method: "Credentials", observe: func(t *testing.T, s walletService) any {
			docs, err := s.Credentials()
			if err != nil {
				t.Fatal(err)
			}
			return docKeys(t, docs)
		}},
		{method: "Credential", observe: func(t *testing.T, s walletService) any {
			doc, err := s.Credential(credentialID(t, s, "dc+sd-jwt"))
			if err != nil {
				t.Fatal(err)
			}
			return keysOf(doc)
		}},
		{method: "DeferredIssuances", observe: func(t *testing.T, s walletService) any {
			docs, err := s.DeferredIssuances()
			if err != nil {
				t.Fatal(err)
			}
			return docKeys(t, docs)
		}},
		{method: "ImportCredential", observe: func(t *testing.T, s walletService) any {
			full, err := s.Credential(credentialID(t, s, "dc+sd-jwt"))
			if err != nil {
				t.Fatal(err)
			}
			imported, err := s.ImportCredential(full["raw"].(string))
			if err != nil {
				t.Fatal(err)
			}
			return keysOf(imported)
		}},
		{method: "RefreshCredential", skip: "renewing needs a live issuer to exchange a refresh token with. internal/wallet covers the operation against a stub"},
		{method: "RemoveCredential", observe: func(t *testing.T, s walletService) any {
			id := importedCredential(t, s)
			before, err := s.Credentials()
			if err != nil {
				t.Fatal(err)
			}
			if err := s.RemoveCredential(id); err != nil {
				t.Fatal(err)
			}
			after, err := s.Credentials()
			if err != nil {
				t.Fatal(err)
			}
			return len(before) - len(after)
		}},
		{method: "RemoveAllCredentials", observe: func(t *testing.T, s walletService) any {
			importedCredential(t, s)
			deleted, err := s.RemoveAllCredentials()
			if err != nil {
				t.Fatal(err)
			}
			left, err := s.Credentials()
			if err != nil {
				t.Fatal(err)
			}
			return []int{deleted, len(left)}
		}},
		{method: "Issue", observe: func(t *testing.T, s walletService) any {
			doc, err := s.Issue(map[string]any{
				"format": "sdjwt", "vct": "urn:test:parity:1",
				"claims": map[string]any{"given_name": "Alice"}, "wallet": true,
			})
			if err != nil {
				t.Fatal(err)
			}
			return keysOf(doc)
		}},
		{method: "Logs", observe: func(t *testing.T, s walletService) any {
			entries, err := s.Logs()
			if err != nil {
				t.Fatal(err)
			}
			// The compiler checks the entry type on both sides. Only the presence of
			// entries can differ.
			return len(entries) > 0
		}},
		{method: "ClearLogs", observe: func(t *testing.T, s walletService) any {
			if err := s.ClearLogs(); err != nil {
				t.Fatal(err)
			}
			entries, err := s.Logs()
			if err != nil {
				t.Fatal(err)
			}
			return len(entries)
		}},
		{method: "SaveTemplate", observe: func(t *testing.T, s walletService) any {
			saveParityTemplate(t, s)
			tpl, err := s.Template("parity")
			if err != nil {
				t.Fatal(err)
			}
			// The returned path is documented to differ: only a store has one.
			return []string{tpl.Name, tpl.Format, tpl.VCT}
		}},
		{method: "Templates", observe: func(t *testing.T, s walletService) any {
			saveParityTemplate(t, s)
			templates, err := s.Templates()
			if err != nil {
				t.Fatal(err)
			}
			for _, tpl := range templates {
				if tpl.Name == "parity" {
					return tpl.VCT
				}
			}
			t.Fatalf("the saved template is missing from %d templates", len(templates))
			return nil
		}},
		{method: "Template", observe: func(t *testing.T, s walletService) any {
			saveParityTemplate(t, s)
			tpl, err := s.Template("parity")
			if err != nil {
				t.Fatal(err)
			}
			return []string{tpl.Name, tpl.Format, tpl.VCT}
		}},
		{method: "DeleteTemplate", observe: func(t *testing.T, s walletService) any {
			saveParityTemplate(t, s)
			if err := s.DeleteTemplate("parity"); err != nil {
				t.Fatal(err)
			}
			_, err := s.Template("parity")
			return err != nil
		}},
		{method: "Certificate", observe: func(t *testing.T, s walletService) any {
			pem, err := s.Certificate("ca", "pem", walletCertOptions{port: 8085})
			if err != nil {
				t.Fatal(err)
			}
			return strings.HasPrefix(string(pem), "-----BEGIN CERTIFICATE-----")
		}},
	}
}

// Require a parity case for every walletService method so new methods are checked on
// both backends.
func TestEveryWalletServiceMethodHasAParityCase(t *testing.T) {
	covered := make(map[string]bool)
	for _, c := range parityCases() {
		covered[c.method] = true
	}
	iface := reflect.TypeOf((*walletService)(nil)).Elem()
	for i := range iface.NumMethod() {
		if name := iface.Method(i).Name; !covered[name] {
			t.Errorf("walletService.%s has no parity case: a command using it can behave differently against a local store and a remote instance", name)
		}
	}
}

func TestWalletServiceBackendsAgree(t *testing.T) {
	for _, c := range parityCases() {
		if c.skip != "" {
			t.Run(c.method, func(t *testing.T) { t.Skip(c.skip) })
			continue
		}
		t.Run(c.method, func(t *testing.T) {
			resetRemoteTestState(t)
			localSvc, remoteSvc := parityWallets(t, seedPID)

			localObs := c.observe(t, localSvc)
			remoteObs := c.observe(t, remoteSvc)
			if !reflect.DeepEqual(localObs, remoteObs) {
				t.Errorf("%s differs between backends:\n  local:  %v\n  remote: %v", c.method, localObs, remoteObs)
			}
		})
	}
}

// docKeys reduces a listing to the key set each format exposes. Reading only
// the first document would compare an SD-JWT against an mdoc whenever the two
// wallets ordered their listings differently (see credentialID).
func docKeys(t *testing.T, docs []map[string]any) any {
	t.Helper()
	byFormat := map[string][]string{}
	for _, doc := range docs {
		format, _ := doc["format"].(string)
		keys := keysOf(doc)
		if prev, ok := byFormat[format]; ok && !reflect.DeepEqual(prev, keys) {
			t.Fatalf("two %s documents expose different keys: %v vs %v", format, prev, keys)
		}
		byFormat[format] = keys
	}
	return byFormat
}

func seedPID(w *wallet.Wallet) {
	if err := w.GenerateProtectedDefaults(); err != nil {
		panic(err)
	}
}
