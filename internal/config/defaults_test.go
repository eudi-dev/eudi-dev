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

package config

import (
	"path/filepath"
	"testing"
)

func TestBaseDirResolution(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("EUDI_DEV_HOME", "")

	if got, want := BaseDir(), filepath.Join(home, ".eudi-dev"); got != want {
		t.Errorf("default: expected %s, got %s", want, got)
	}
	t.Setenv("EUDI_DEV_HOME", "/tmp/new-home")
	if got := BaseDir(); got != "/tmp/new-home" {
		t.Errorf("new env: expected /tmp/new-home, got %s", got)
	}
}
