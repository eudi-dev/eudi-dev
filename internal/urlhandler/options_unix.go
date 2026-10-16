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

//go:build darwin || linux

package urlhandler

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
)

func saveOptions(opts Options) error {
	data, err := json.MarshalIndent(opts, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(config.BaseDir(), 0o755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	if err := os.WriteFile(optionsPath(), append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("writing handler options: %w", err)
	}
	return nil
}
