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

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v2/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
	"github.com/eudi-dev/eudi-dev/v2/internal/remote"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

func startRemoteTestWallet(t *testing.T) (string, *wallet.Server) {
	t.Helper()
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	w := wallet.New(holderKey, issuerKey, false)
	w.AutoAccept = true
	w.Templates = credtemplate.FileLocation(t.TempDir())

	srv := wallet.NewServer(w, 0, nil)
	srv.ShutdownFunc = func() {}
	addr, err := srv.ListenAndServeBackground()
	if err != nil {
		t.Fatalf("starting wallet server: %v", err)
	}
	url := "http://" + strings.TrimPrefix(addr, "http://")
	return url, srv
}

func resetRemoteTestState(t *testing.T) {
	t.Helper()
	t.Setenv("OID4VC_DEV_HOME", t.TempDir())
	resetTemplateTestState(t)
	remoteFlag = ""
	t.Cleanup(func() { remoteFlag = "" })
}

func TestRemoteWalletLifecycleViaCLI(t *testing.T) {
	resetRemoteTestState(t)
	url, _ := startRemoteTestWallet(t)

	rootCmd.SetArgs([]string{"wallet", "use", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet use: %v", err)
	}
	if remote.Active() != url {
		t.Fatalf("active remote not persisted: %q", remote.Active())
	}

	remoteFlag = ""
	rootCmd.SetArgs([]string{"issue", "sdjwt", "--wallet", "--template", "german-pid-sdjwt"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote issue: %v", err)
	}

	client := remote.NewClient(url)
	creds, err := client.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 remote credential, got %d", len(creds))
	}
	id, _ := creds[0]["id"].(string)

	rootCmd.SetArgs([]string{"wallet", "remove", id})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote remove: %v", err)
	}
	creds, err = client.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 0 {
		t.Fatalf("expected empty remote wallet, got %d credentials", len(creds))
	}

	rootCmd.SetArgs([]string{"wallet", "use", "local"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet use local: %v", err)
	}
	if remote.Active() != "" {
		t.Fatalf("expected local management, got %q", remote.Active())
	}
}

func TestAutoRouteThroughInstanceForSameWalletDir(t *testing.T) {
	resetRemoteTestState(t)
	url, _ := startRemoteTestWallet(t)

	// The registry says this running server owns the local wallet dir. The
	// registered pid must match the pid the server reports, otherwise
	// discovery prunes the file as stale.
	resolvedDir := wallet.NewWalletStore(walletDir).Dir
	if err := remote.RegisterInstance(remote.Instance{
		PID: os.Getpid(), Port: portFromURL(t, url), URL: url,
		WalletDir: resolvedDir, StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	// Issuing without --remote routes through the running instance instead
	// of writing the store directly (single-writer rule).
	rootCmd.SetArgs([]string{"issue", "sdjwt", "--wallet", "--template", "german-pid-sdjwt"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("auto-routed issue: %v", err)
	}
	client := remote.NewClient(url)
	creds, err := client.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected the credential on the running instance, got %d", len(creds))
	}
	if wallet.NewWalletStore(walletDir).Exists() {
		t.Error("auto-routed issue must not write the local store")
	}

	resetIssueFlagChanges(t)
	rootCmd.SetArgs([]string{"issue", "sdjwt", "--wallet", "--template", "german-pid-sdjwt", "--remote", "local"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue with --remote local: %v", err)
	}
	store := wallet.NewWalletStore(walletDir)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if len(w.GetCredentials()) != 1 {
		t.Fatalf("expected 1 local credential after --remote local, got %d", len(w.GetCredentials()))
	}
	creds, err = client.Credentials()
	if err != nil || len(creds) != 1 {
		t.Fatalf("instance credentials must be untouched by --remote local: %v %v", creds, err)
	}

	resetIssueFlagChanges(t)
	tplDir := t.TempDir()
	rootCmd.SetArgs([]string{"issue", "sdjwt", "--wallet", "--template", "german-pid-sdjwt", "--templates-dir", tplDir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue with --templates-dir: %v", err)
	}
	w, err = store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if len(w.GetCredentials()) != 2 {
		t.Fatalf("expected 2 local credentials after --templates-dir issue, got %d", len(w.GetCredentials()))
	}
}

// resetIssueFlagChanges clears cobra's Changed state between Execute calls
// in a single test, mirroring fresh CLI invocations.
func resetIssueFlagChanges(t *testing.T) {
	t.Helper()
	saved := walletDir
	resetTemplateTestState(t)
	walletDir = saved
	remoteFlag = ""
}

func TestRemoteTemplatesViaCLI(t *testing.T) {
	resetRemoteTestState(t)
	url, _ := startRemoteTestWallet(t)
	remoteFlag = url

	rootCmd.SetArgs([]string{"templates", "save", "remote-card",
		"--format", "sdjwt", "--vct", "urn:example:remote",
		"--claims", `{"a": "1"}`, "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote templates save: %v", err)
	}

	client := remote.NewClient(url)
	tpl, err := client.Template("remote-card")
	if err != nil {
		t.Fatalf("template not on remote wallet: %v", err)
	}
	if tpl["vct"] != "urn:example:remote" {
		t.Errorf("unexpected remote template: %v", tpl)
	}

	rootCmd.SetArgs([]string{"templates", "delete", "remote-card", "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote templates delete: %v", err)
	}
	if _, err := client.Template("remote-card"); err == nil {
		t.Error("template still on remote wallet after delete")
	}
}

func TestWalletUseRejectsUnreachable(t *testing.T) {
	resetRemoteTestState(t)
	rootCmd.SetArgs([]string{"wallet", "use", "http://localhost:1"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected error for unreachable wallet")
	}
	if remote.Active() != "" {
		t.Errorf("unreachable target must not be persisted, got %q", remote.Active())
	}
}

func TestWalletUseChecksVersionCompatibility(t *testing.T) {
	resetRemoteTestState(t)
	url, srv := startRemoteTestWallet(t)
	srv.SetVersion("2.4.0")
	withCLIVersion(t, "1.19.0")

	rootCmd.SetArgs([]string{"wallet", "use", url})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected an instance a major release apart to be refused")
	}
	if !strings.Contains(err.Error(), "2.4.0") || !strings.Contains(err.Error(), "1.19.0") {
		t.Errorf("the error must name both releases, got %q", err)
	}
	if remote.Active() != "" {
		t.Errorf("an incompatible instance must not become the target, got %q", remote.Active())
	}

	rootCmd.SetArgs([]string{"wallet", "use", url, "--force"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet use --force: %v", err)
	}
	if remote.Active() != url {
		t.Errorf("--force must select the instance, got %q", remote.Active())
	}
	t.Cleanup(func() {
		rootCmd.SetArgs([]string{"wallet", "use", url, "--force=false"})
		_ = rootCmd.Execute()
	})

	srv.SetVersion("1.18.0")
	if err := remote.ClearActive(); err != nil {
		t.Fatal(err)
	}
	rootCmd.SetArgs([]string{"wallet", "use", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("an older minor release must still be selectable: %v", err)
	}
	if remote.Active() != url {
		t.Errorf("expected the instance to be selected, got %q", remote.Active())
	}
}

func TestWalletPsShowsInstanceVersion(t *testing.T) {
	resetRemoteTestState(t)
	url, srv := startRemoteTestWallet(t)
	srv.SetVersion("1.42.0")
	withCLIVersion(t, "1.42.0")

	if err := remote.RegisterInstance(remote.Instance{
		PID: os.Getpid(), Port: portFromURL(t, url), URL: url, StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"wallet", "ps"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("wallet ps: %v", err)
		}
	})
	if !strings.Contains(out, "VERSION") || !strings.Contains(out, "1.42.0") {
		t.Errorf("the listing must report the instance version, got:\n%s", out)
	}

	out = captureStdout(t, func() {
		rootCmd.SetArgs([]string{"wallet", "instances", "list"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("wallet instances list: %v", err)
		}
	})
	if !strings.Contains(out, "1.42.0") {
		t.Errorf("the deprecated listing must report the instance version, got:\n%s", out)
	}
}

func withCLIVersion(t *testing.T, version string) {
	t.Helper()
	previous := Version
	Version = version
	t.Cleanup(func() { Version = previous })
}

// captureStdout collects what fn writes to os.Stdout. The instance listing
// writes to os.Stdout directly and bypasses the cobra output writer.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = writer
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, reader)
		done <- buf.String()
	}()
	fn()
	os.Stdout = previous
	_ = writer.Close()
	out := <-done
	_ = reader.Close()
	return out
}

func TestWalletKillViaShutdownEndpoint(t *testing.T) {
	resetRemoteTestState(t)
	url, srv := startRemoteTestWallet(t)

	shutdownCalled := make(chan struct{})
	srv.ShutdownFunc = func() { close(shutdownCalled) }

	port := portFromURL(t, url)
	if err := remote.RegisterInstance(remote.Instance{PID: 999999, Port: port, URL: url, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"wallet", "kill", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet kill: %v", err)
	}
	select {
	case <-shutdownCalled:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown endpoint was not invoked")
	}
}

func portFromURL(t *testing.T, url string) int {
	t.Helper()
	idx := strings.LastIndex(url, ":")
	if idx < 0 {
		t.Fatalf("no port in %q", url)
	}
	port, err := strconv.Atoi(url[idx+1:])
	if err != nil {
		t.Fatalf("parsing port from %q: %v", url, err)
	}
	return port
}

func TestRemoteShowImportLogsInfoViaCLI(t *testing.T) {
	resetRemoteTestState(t)
	url, _ := startRemoteTestWallet(t)
	remoteFlag = url
	t.Cleanup(func() { remoteFlag = "" })

	rootCmd.SetArgs([]string{"issue", "sdjwt", "--wallet", "--template", "german-pid-sdjwt", "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote issue: %v", err)
	}
	client := remote.NewClient(url)
	creds, err := client.Credentials()
	if err != nil || len(creds) != 1 {
		t.Fatalf("expected 1 remote credential: %v %v", creds, err)
	}
	id, _ := creds[0]["id"].(string)
	// The listing carries no raw credential, so the raw string comes from the
	// per-credential fetch.
	one, err := client.Credential(id)
	if err != nil {
		t.Fatalf("fetch credential %s: %v", id, err)
	}
	raw, _ := one["raw"].(string)

	rootCmd.SetArgs([]string{"wallet", "show", id, "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote show: %v", err)
	}
	rootCmd.SetArgs([]string{"wallet", "show", id, "--decoded", "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote show --decoded: %v", err)
	}

	if _, err := client.RemoveAllCredentials(); err != nil {
		t.Fatal(err)
	}
	credFile := filepath.Join(t.TempDir(), "cred.txt")
	if err := os.WriteFile(credFile, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	rootCmd.SetArgs([]string{"wallet", "import", credFile, "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote import: %v", err)
	}
	creds, err = client.Credentials()
	if err != nil || len(creds) != 1 {
		t.Fatalf("expected re-imported credential: %v %v", creds, err)
	}

	rootCmd.SetArgs([]string{"wallet", "logs", "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote logs: %v", err)
	}
	rootCmd.SetArgs([]string{"wallet", "logs", "--follow", "--remote", url})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected error for remote --follow")
	}
	rootCmd.SetArgs([]string{"wallet", "info", "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote info: %v", err)
	}
}

func TestRemoteTemplatesListShowUseRemoteStore(t *testing.T) {
	resetRemoteTestState(t)
	url, _ := startRemoteTestWallet(t)

	client := remote.NewClient(url)
	if _, err := client.PutTemplate("remote-only", map[string]any{"format": "sdjwt", "claims": map[string]any{"a": 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := credtemplate.Save(wallet.NewWalletStore(walletDir).Templates(), credtemplate.Template{
		Name: "local-only", Format: "sdjwt", Claims: map[string]any{"b": 2},
	}); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"templates", "show", "remote-only", "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote show must find the remote template: %v", err)
	}
	rootCmd.SetArgs([]string{"templates", "show", "local-only", "--remote", url})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("remote show must not fall back to the local store")
	}

	rootCmd.SetArgs([]string{"templates", "list", "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote list: %v", err)
	}
}

func TestCompletionFunctions(t *testing.T) {
	resetRemoteTestState(t)

	names, directive := completeTemplateNames(nil, nil, "")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("unexpected directive: %v", directive)
	}
	joined := strings.Join(names, "\n")
	if !strings.Contains(joined, "german-pid-sdjwt") || !strings.Contains(joined, "german-pid-mdoc") {
		t.Errorf("expected pre-defined templates in completion, got %v", names)
	}

	// Credential completion never creates a wallet as a side effect.
	ids, _ := completeCredentialIDs(nil, nil, "")
	if len(ids) != 0 {
		t.Errorf("expected no completions without a wallet, got %v", ids)
	}
	if wallet.NewWalletStore(walletDir).Exists() {
		t.Error("completion must not create a wallet store")
	}

	url, _ := startRemoteTestWallet(t)
	remoteFlag = url
	client := remote.NewClient(url)
	if _, err := client.PutTemplate("completion-card", map[string]any{"format": "sdjwt", "claims": map[string]any{"a": 1}}); err != nil {
		t.Fatal(err)
	}
	names, _ = completeTemplateNames(nil, nil, "")
	if !strings.Contains(strings.Join(names, "\n"), "completion-card") {
		t.Errorf("expected remote template in completion, got %v", names)
	}

	if err := remote.RegisterInstance(remote.Instance{PID: 424242, Port: portFromURL(t, url), URL: url, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	targets, _ := completeUseTargets(nil, nil, "")
	joined = strings.Join(targets, "\n")
	if !strings.Contains(joined, "local") || !strings.Contains(joined, url) {
		t.Errorf("expected local and instance url in completion, got %v", targets)
	}
}

func TestCompletionInstall(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	rootCmd.SetArgs([]string{"completion", "install", "zsh"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("completion install zsh: %v", err)
	}
	rootCmd.SetArgs([]string{"completion", "install", "zsh"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("second install: %v", err)
	}
	rc, err := os.ReadFile(filepath.Join(home, ".zshrc"))
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(rc), "completion zsh"); count != 1 {
		t.Errorf("expected exactly one source line, got %d:\n%s", count, rc)
	}

	rootCmd.SetArgs([]string{"completion", "install", "fish"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("completion install fish: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "fish", "completions", rootCmd.Name()+".fish")); err != nil {
		t.Errorf("fish completion file missing: %v", err)
	}

	rootCmd.SetArgs([]string{"completion", "install", "tcsh"})
	if err := rootCmd.Execute(); err == nil {
		t.Error("expected error for unsupported shell")
	}
}

// A remote wallet may use a different CA. Its trust list must come from the remote
// API.
func TestTrustListFollowsTheRemoteWallet(t *testing.T) {
	resetRemoteTestState(t)
	url, _ := startRemoteTestWallet(t)

	localHolder, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	localIssuer, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	local := wallet.New(localHolder, localIssuer, false)
	if err := wallet.NewWalletStore(walletDir).Save(local); err != nil {
		t.Fatal(err)
	}

	served, err := remote.NewClient(url).TrustList("", "", "")
	if err != nil {
		t.Fatalf("fetching the remote trust list: %v", err)
	}
	// Compare CA certificates because each fetch signs a new trust list JWT.
	wantAnchors := trustListAnchors(t, served)

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"wallet", "trust-list", "--remote", url})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("wallet trust-list --remote: %v", err)
		}
	})

	anchors := trustListAnchors(t, strings.TrimSpace(out))
	if len(anchors) == 0 {
		t.Fatal("the printed trust list carries no certificate")
	}
	for der := range wantAnchors {
		if !anchors[der] {
			t.Error("trust-list --remote does not anchor the remote wallet's CA")
		}
	}
	if anchors[string(local.CertChain[len(local.CertChain)-1].Raw)] {
		t.Error("trust-list --remote anchored the local CA, which validates nothing the remote issues")
	}
}

func trustListAnchors(t *testing.T, jwt string) map[string]bool {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		t.Fatalf("not a JWT: %.40s", jwt)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding the trust list payload: %v", err)
	}
	var doc any
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("parsing the trust list payload: %v", err)
	}
	found := map[string]bool{}
	var walk func(any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			if raw, ok := v["val"].(string); ok {
				if der, err := base64.StdEncoding.DecodeString(raw); err == nil {
					found[string(der)] = true
				}
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(doc)
	return found
}

func TestTrustListListsProfiles(t *testing.T) {
	resetRemoteTestState(t)
	url, _ := startRemoteTestWallet(t)

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"wallet", "trust-list", "--list", "--remote", url})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("wallet trust-list --list: %v", err)
		}
	})

	for _, want := range []string{"wallet-provider", "/api/trustlists/"} {
		if !strings.Contains(out, want) {
			t.Errorf("the listing does not mention %q:\n%s", want, out)
		}
	}

	// Combining a listing with a selection is an error.
	rootCmd.SetArgs([]string{"wallet", "trust-list", "--list", "--id", "pid", "--remote", url})
	if err := rootCmd.Execute(); err == nil {
		t.Error("--list with --id was accepted")
	}
}

// Remote JSON numbers become float64. Local documents retain Go types. Both must
// produce the same status label.
func TestCredentialLabelsReadBothNumberShapes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status any
		want   string
	}{
		{"from JSON", float64(1), "revoked"},
		{"from this process", 1, "revoked"},
		{"active from this process", 0, "active"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cred := map[string]any{"status": map[string]any{
				"managed": true,
				"status":  tc.status,
				"uri":     "https://wallet.example/api/statuslist",
				"idx":     2,
			}}
			if got := credStatusLabel(cred); got != tc.want {
				t.Errorf("credStatusLabel = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCredStatusLabelMarksBatch(t *testing.T) {
	batch := map[string]any{"batch": true, "batch_size": float64(3)}
	if got := credStatusLabel(batch); got != "batch of 3" {
		t.Errorf("credStatusLabel for a batch = %q, want %q", got, "batch of 3")
	}
	if got := credStatusLabel(map[string]any{"batch": true}); got != "batch" {
		t.Errorf("credStatusLabel for a batch without a size = %q, want %q", got, "batch")
	}
	protectedBatch := map[string]any{"protected": true, "batch": true, "batch_size": float64(2)}
	if got := credStatusLabel(protectedBatch); got != "protected, batch of 2" {
		t.Errorf("credStatusLabel for a protected batch = %q, want %q", got, "protected, batch of 2")
	}
	if got := credStatusLabel(map[string]any{}); got != "-" {
		t.Errorf("credStatusLabel with nothing to say = %q, want %q", got, "-")
	}
}

// A remote wallet sends the display name and description as a JSON object.
// A local wallet passes the struct value. The CLI must read both.
func TestCredDisplayReadsMapAndStruct(t *testing.T) {
	fromMap := map[string]any{"display": map[string]any{"name": "EUDI PID", "description": "a sample"}}
	if got := credDisplayName(fromMap); got != "EUDI PID" {
		t.Errorf("name from a JSON map = %q, want %q", got, "EUDI PID")
	}
	if got := credDisplayDescription(fromMap); got != "a sample" {
		t.Errorf("description from a JSON map = %q, want %q", got, "a sample")
	}

	fromStruct := map[string]any{"display": &wallet.CredentialDisplay{Name: "Badge", Description: "issued locally"}}
	if got := credDisplayName(fromStruct); got != "Badge" {
		t.Errorf("name from a struct = %q, want %q", got, "Badge")
	}
	if got := credDisplayDescription(fromStruct); got != "issued locally" {
		t.Errorf("description from a struct = %q, want %q", got, "issued locally")
	}

	if got := credDisplayName(map[string]any{}); got != "" {
		t.Errorf("name with no display = %q, want empty", got)
	}
	if got := orDash(""); got != "-" {
		t.Errorf("orDash(empty) = %q, want %q", got, "-")
	}
}

// Distinguish an expired credential from one with no expiry claim.
func TestCredentialValidityLabel(t *testing.T) {
	// RFC 3339 carries whole seconds and the label rounds down, so the stamps
	// get one second of slack.
	stamp := func(d time.Duration) map[string]any {
		return map[string]any{"expires_at": time.Now().Add(d + time.Second).UTC().Format(time.RFC3339)}
	}
	for _, tc := range []struct {
		name string
		cred map[string]any
		want string
	}{
		{"no expiry", map[string]any{}, "-"},
		{"unparseable", map[string]any{"expires_at": "soon"}, "-"},
		{"expired", stamp(-time.Hour), "expired"},
		{"days", stamp(72 * time.Hour), "3d"},
		{"hours", stamp(5 * time.Hour), "5h"},
		{"minutes", stamp(30 * time.Minute), "30m"},
		{"seconds", stamp(30 * time.Second), "<1m"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := credValidityLabel(tc.cred); got != tc.want {
				t.Errorf("credValidityLabel = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMatchInstance(t *testing.T) {
	instances := []remote.DiscoveredInstance{
		{Instance: remote.Instance{PID: 8085, Port: 9090, URL: "http://localhost:9090"}},
		{Instance: remote.Instance{PID: 4242, Port: 8085, URL: "http://localhost:8085"}},
	}

	got, err := matchInstance(instances, "8085")
	if err != nil {
		t.Fatalf("matchInstance(8085): %v", err)
	}
	if got.URL != "http://localhost:8085" {
		t.Fatalf("kill 8085 matched %q, want the server on port 8085", got.URL)
	}

	got, err = matchInstance(instances, "4242")
	if err != nil {
		t.Fatalf("matchInstance(4242): %v", err)
	}
	if got.PID != 4242 {
		t.Fatalf("kill 4242 matched pid %d, want 4242", got.PID)
	}

	got, err = matchInstance(instances, "localhost:9090")
	if err != nil {
		t.Fatalf("matchInstance(localhost:9090): %v", err)
	}
	if got.URL != "http://localhost:9090" {
		t.Fatalf("matched %q, want http://localhost:9090", got.URL)
	}

	if _, err := matchInstance(instances, "12345"); err == nil {
		t.Fatal("expected no match for an unknown number")
	}
}

func TestMatchInstanceAmbiguousPort(t *testing.T) {
	instances := []remote.DiscoveredInstance{
		{Instance: remote.Instance{PID: 1, Port: 8085, URL: "http://localhost:8085"}},
		{Instance: remote.Instance{PID: 2, Port: 8085, URL: "http://host.docker.internal:8085"}},
	}
	if _, err := matchInstance(instances, "8085"); err == nil {
		t.Fatal("expected an ambiguity error when two instances share a port")
	}
}
