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

import "testing"

func TestHandlerCommand(t *testing.T) {
	tests := []struct {
		binary, want string
		wantErr      bool
	}{
		{binary: `C:\Users\me\go\bin\eudi.exe`, want: `"C:\Users\me\go\bin\eudi.exe" wallet open-url -- "%1"`},
		{binary: `C:\Program Files\eudi dev\eudi.exe`, want: `"C:\Program Files\eudi dev\eudi.exe" wallet open-url -- "%1"`},
		{binary: `C:\odd"name\eudi.exe`, wantErr: true},
		{binary: "C:\\bad\nname\\eudi.exe", wantErr: true},
		{binary: "", wantErr: true},
	}
	for _, tt := range tests {
		got, err := handlerCommand(tt.binary)
		if (err != nil) != tt.wantErr {
			t.Errorf("handlerCommand(%q) error %v, wantErr %t", tt.binary, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("handlerCommand(%q) = %q, want %q", tt.binary, got, tt.want)
		}
	}
}
