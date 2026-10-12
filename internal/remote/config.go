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

package remote

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
)

var configBaseDir = config.BaseDir

type activeConfig struct {
	URL string `json:"url"`
}

func configPath() string {
	return filepath.Join(configBaseDir(), "remote.json")
}

func Active() string {
	data, err := os.ReadFile(configPath())
	if err != nil {
		return ""
	}
	var cfg activeConfig
	if json.Unmarshal(data, &cfg) != nil {
		return ""
	}
	return strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
}

// NormalizeURL validates and normalizes a remote wallet URL. A bare
// host:port or port gets an http scheme.
func NormalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("remote URL is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid remote URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid remote URL %q: expected http or https", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid remote URL %q: missing host", raw)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func SetActive(rawURL string) (string, error) {
	normalized, err := NormalizeURL(rawURL)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(configBaseDir(), 0o755); err != nil {
		return "", fmt.Errorf("creating config directory: %w", err)
	}
	data, err := json.MarshalIndent(activeConfig{URL: normalized}, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(configPath(), append(data, '\n'), 0o644); err != nil {
		return "", fmt.Errorf("writing remote config: %w", err)
	}
	return normalized, nil
}

func ClearActive() error {
	err := os.Remove(configPath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
