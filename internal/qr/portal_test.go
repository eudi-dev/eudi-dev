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

package qr

import (
	"errors"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

// org.freedesktop.portal.Request: the request path carries the caller's
// unique name without ':' and with '_' for '.'.
func TestPortalRequestPath(t *testing.T) {
	got := portalRequestPath(":1.42", "eudi_dev_ab")
	if want := dbus.ObjectPath("/org/freedesktop/portal/desktop/request/1_42/eudi_dev_ab"); got != want {
		t.Errorf("portalRequestPath = %q, want %q", got, want)
	}
}

func TestPortalScreenshotFile(t *testing.T) {
	results := func(uri string) map[string]dbus.Variant {
		return map[string]dbus.Variant{"uri": dbus.MakeVariant(uri)}
	}
	path, err := portalScreenshotFile([]any{uint32(0), results("file:///tmp/Screenshot%20from%20today.png")})
	if err != nil || path != "/tmp/Screenshot from today.png" {
		t.Errorf("success: path %q, error %v", path, err)
	}
	if _, err := portalScreenshotFile([]any{uint32(1), results("")}); !errors.Is(err, errCaptureCancelled) {
		t.Errorf("cancelled: error %v, want errCaptureCancelled", err)
	}
	if _, err := portalScreenshotFile([]any{uint32(2), results("")}); err == nil || !strings.Contains(err.Error(), "response 2") {
		t.Errorf("ended: error %v, want the response code", err)
	}
	if _, err := portalScreenshotFile([]any{uint32(0), results("https://example.com/shot.png")}); err == nil {
		t.Error("a non-file URI was accepted")
	}
	if _, err := portalScreenshotFile([]any{uint32(0)}); err == nil {
		t.Error("a response without results was accepted")
	}
}
