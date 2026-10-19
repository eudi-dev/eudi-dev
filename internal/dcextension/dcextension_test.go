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

package dcextension

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestManifestVersion(t *testing.T) {
	for version, want := range map[string]string{
		"v3.3.0":         "3.3.0",
		"3.3.0":          "3.3.0",
		"v3.3.0-beta.1":  "3.3.0",
		"v3.2.2+dirty":   "3.2.2",
		"dev":            "0.0.0",
		"":               "0.0.0",
		"v1.2.3.4.5":     "0.0.0",
		"(devel)":        "0.0.0",
		"v100000.0.0":    "0.0.0",
		"v3.3.0-rc.1+ab": "3.3.0",
	} {
		if got := manifestVersion(version); got != want {
			t.Errorf("manifestVersion(%q) = %q, want %q", version, got, want)
		}
	}
}

func TestTheZipCarriesTheWalletURLAndVersion(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteZip(&buf, Options{WalletURL: "http://localhost:8085/", Version: "v3.3.0"}); err != nil {
		t.Fatal(err)
	}
	archive, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) map[string]any {
		f, err := archive.Open(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		data, _ := io.ReadAll(f)
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return doc
	}
	if got := read("config.json")["wallet_url"]; got != "http://localhost:8085" {
		t.Errorf("wallet_url = %v, want http://localhost:8085", got)
	}
	manifest := read("manifest.json")
	if manifest["version"] != "3.3.0" || manifest["version_name"] != "v3.3.0" {
		t.Errorf("manifest version = %v (%v), want 3.3.0 (v3.3.0)", manifest["version"], manifest["version_name"])
	}
	for _, name := range []string{"page.js", "bridge.js", "background.js", "offscreen.html", "offscreen.js", "wallet-call.js", "popup.html", "popup.js", "icons/128.png"} {
		if _, err := archive.Open(name); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
}

func TestWriteDirMatchesTheZip(t *testing.T) {
	dir := t.TempDir()
	if err := WriteDir(dir, Options{WalletURL: "https://eudi-test.dev", Version: "dev"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"https://eudi-test.dev"`)) {
		t.Errorf("config.json = %s", data)
	}
	if _, err := os.Stat(filepath.Join(dir, "icons", "48.png")); err != nil {
		t.Errorf("icons not written: %v", err)
	}
}

func TestAWalletURLIsRequired(t *testing.T) {
	if err := WriteZip(io.Discard, Options{}); err == nil {
		t.Error("WriteZip without a wallet URL succeeded")
	}
}
