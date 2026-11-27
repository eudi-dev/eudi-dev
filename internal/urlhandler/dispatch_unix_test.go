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

//go:build unix

package urlhandler

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The 'wallet accept' fallback runs the binary with the link and logs its
// output, since a clicked link has no terminal.
func TestTheFallbackRunsTheBinaryIntoTheLog(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "eudi")
	script := "#!/bin/sh\necho \"ran: $*\"\n[ \"$1\" = wallet ]\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	d := NewDispatcher(Options{}, binary, "1.2.3", "", nil, &log)

	if err := d.run([]string{"wallet", "accept", "--", "openid4vp://?a=b"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got, want := strings.TrimSpace(log.String()), "ran: wallet accept -- openid4vp://?a=b"; got != want {
		t.Errorf("log %q, want %q", got, want)
	}
	if err := d.run([]string{"other"}); err == nil {
		t.Error("a failing command returned no error")
	}
}
