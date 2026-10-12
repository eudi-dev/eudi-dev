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
	"fmt"
	"io"
	"os"

	"github.com/eudi-dev/eudi-dev/v3/internal/output"
)

// humanOut returns the writer for messages to a person. With --json that is
// stderr, because stdout carries only the JSON document (ADR 0020).
func humanOut() io.Writer {
	if jsonOutput {
		return os.Stderr
	}
	return os.Stdout
}

// printResult prints v as JSON with --json and calls text otherwise.
func printResult(v any, text func()) {
	if jsonOutput {
		output.PrintJSON(v)
		return
	}
	text()
}

// rejectJSON refuses --json for a command without a single result (ADR 0020).
func rejectJSON(reason string) error {
	if jsonOutput {
		return fmt.Errorf("--json does not work with this command: %s", reason)
	}
	return nil
}
