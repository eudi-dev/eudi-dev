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

// Package dcextension packages the browser extension that answers the W3C
// Digital Credentials API (navigator.credentials.get()) with an eudi-dev
// wallet.
package dcextension

import (
	"archive/zip"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed all:extension
var files embed.FS

// Options are the values written into the extension.
type Options struct {
	// WalletURL is the wallet the extension uses until the user sets another
	// one in its popup.
	WalletURL string
	// Version is the eudi-dev version, such as v3.3.0.
	Version string
}

// ZipName is the file name of the packaged extension.
const ZipName = "eudi-dev-dc-api-extension.zip"

// WriteZip writes the extension as a zip archive.
func WriteZip(w io.Writer, opts Options) error {
	zw := zip.NewWriter(w)
	err := walk(opts, func(name string, data []byte) error {
		f, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		return err
	})
	if err != nil {
		return err
	}
	return zw.Close()
}

// WriteDir writes the unpacked extension into dir, which Chrome loads with
// "Load unpacked".
func WriteDir(dir string, opts Options) error {
	return walk(opts, func(name string, data []byte) error {
		target := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

// walk calls write for each file, with the manifest version and config.json
// filled in.
func walk(opts Options, write func(name string, data []byte) error) error {
	walletURL := strings.TrimRight(strings.TrimSpace(opts.WalletURL), "/")
	if walletURL == "" {
		return fmt.Errorf("the extension needs a wallet URL")
	}
	config, err := json.MarshalIndent(map[string]string{"wallet_url": walletURL}, "", "  ")
	if err != nil {
		return err
	}
	if err := write("config.json", append(config, '\n')); err != nil {
		return err
	}
	return fs.WalkDir(files, "extension", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := files.ReadFile(name)
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(name, "extension/")
		if rel == "manifest.json" {
			if data, err = manifest(data, opts.Version); err != nil {
				return err
			}
		}
		return write(path.Clean(rel), data)
	})
}

func manifest(data []byte, version string) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("reading the extension manifest: %w", err)
	}
	m["version"] = manifestVersion(version)
	if version != "" {
		m["version_name"] = version
	}
	out, err := json.MarshalIndent(m, "", "  ")
	return append(out, '\n'), err
}

// Chrome's manifest version is one to four dot-separated integers.
var releaseVersion = regexp.MustCompile(`^v?(\d{1,5}(?:\.\d{1,5}){0,3})(?:[-+].*)?$`)

// manifestVersion turns v3.3.0-beta.1 into 3.3.0. A development build gets
// 0.0.0.
func manifestVersion(version string) string {
	if m := releaseVersion.FindStringSubmatch(strings.TrimSpace(version)); m != nil {
		return m[1]
	}
	return "0.0.0"
}
