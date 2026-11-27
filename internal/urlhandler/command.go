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

package urlhandler

import (
	"fmt"
	"strings"
)

// handlerCommand is the shell\open\command of a Windows scheme key. Windows
// puts the clicked link in place of %1 as it is, so a link with a quotation
// mark can end the quoted argument. "--" keeps whatever follows from being
// read as flags, and 'wallet open-url' takes exactly one argument.
func handlerCommand(binary string) (string, error) {
	// CommandLineToArgvW would end the quoted path at a quotation mark. Windows
	// file names hold neither that nor control characters.
	if binary == "" || strings.ContainsAny(binary, "\"\r\n\t") {
		return "", fmt.Errorf("the path %q can't be quoted in a Windows command line", binary)
	}
	return `"` + binary + `" wallet open-url -- "%1"`, nil
}
