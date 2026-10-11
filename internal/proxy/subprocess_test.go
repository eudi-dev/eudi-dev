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

package proxy

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// slowTerminal lets the child exit while lines still wait in its pipes.
type slowTerminal struct{ bytes.Buffer }

func (s *slowTerminal) Write(p []byte) (int, error) {
	time.Sleep(time.Millisecond)
	return s.Buffer.Write(p)
}

func runSubprocess(t *testing.T, script string) string {
	t.Helper()
	var out slowTerminal
	sub, err := StartSubprocess([]string{"sh", "-c", script}, NewOutputScanner(), &out)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-sub.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the subprocess did not finish")
	}
	if err := sub.Wait(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestSubprocessForwardsEveryLineBeforeItReportsTheExit(t *testing.T) {
	out := runSubprocess(t, `i=0; while [ $i -lt 300 ]; do echo "line $i"; i=$((i+1)); done; echo last >&2`)

	for _, want := range []string{"line 0\n", "line 299\n", "last\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output misses %q", want)
		}
	}
}

func TestSubprocessKeepsReadingAfterAVeryLongLine(t *testing.T) {
	out := runSubprocess(t, `head -c 3000000 /dev/zero | tr '\0' a; echo; echo after`)

	if got := strings.Count(out, "a"); got < 3000000 {
		t.Errorf("forwarded %d of 3000000 bytes of the long line", got)
	}
	if !strings.HasSuffix(out, "after\n") {
		t.Errorf("the output ends with %q", out[max(0, len(out)-40):])
	}
}
