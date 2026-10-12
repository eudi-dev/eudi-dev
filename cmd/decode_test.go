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
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

// The text output reports the checks of the JSON output, such as a disclosure
// the credential does not reference.
func TestDecodeReportsTheValidationChecks(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://localhost:1",
		VCT:       "urn:test",
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "Erika"},
		Key:       key,
	})
	if err != nil {
		t.Fatal(err)
	}
	stray := base64.RawURLEncoding.EncodeToString([]byte(`["salt","role","admin"]`))
	credFile := filepath.Join(t.TempDir(), "cred.txt")
	if err := os.WriteFile(credFile, []byte(raw+stray+"~"), 0o644); err != nil {
		t.Fatal(err)
	}
	resetRemoteTestState(t)

	var runErr error
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"decode", credFile})
		runErr = rootCmd.Execute()
	})
	if runErr != nil {
		t.Fatalf("decode: %v", runErr)
	}
	if !strings.Contains(out, "✗ integrity:") || !strings.Contains(out, "not referenced") {
		t.Errorf("output lacks the failed integrity check:\n%s", out)
	}
}
