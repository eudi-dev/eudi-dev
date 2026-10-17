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
	"fmt"
	"net/url"
	"strings"

	"github.com/godbus/dbus/v5"
)

// The Screenshot portal of the XDG Desktop Portal
// (https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Screenshot.html).
// The desktop shows its own selection UI, under Wayland and X11.
const (
	portalService       = "org.freedesktop.portal.Desktop"
	portalPath          = dbus.ObjectPath("/org/freedesktop/portal/desktop")
	portalScreenshot    = "org.freedesktop.portal.Screenshot.Screenshot"
	portalRequest       = "org.freedesktop.portal.Request"
	portalResponse      = portalRequest + ".Response"
	portalResponseOK    = 0
	portalResponseAbort = 1
)

var errCaptureCancelled = errors.New("screen capture cancelled")

// portalRequestPath is the object path of the Request a portal call creates.
// org.freedesktop.portal.Request: "/org/freedesktop/portal/desktop/request/SENDER/TOKEN,
// where SENDER is the caller's unique name, with the initial ':' removed and
// all '.' replaced by '_'". Subscribing to it before the call avoids missing
// a fast response.
func portalRequestPath(uniqueName, token string) dbus.ObjectPath {
	sender := strings.ReplaceAll(strings.TrimPrefix(uniqueName, ":"), ".", "_")
	return dbus.ObjectPath("/org/freedesktop/portal/desktop/request/" + sender + "/" + token)
}

// portalScreenshotFile reads the Response signal of a Screenshot request: a
// response code and the results, whose "uri" is the file of the screenshot.
func portalScreenshotFile(body []any) (string, error) {
	if len(body) != 2 {
		return "", fmt.Errorf("the screenshot portal answered with %d values, want 2", len(body))
	}
	code, ok := body[0].(uint32)
	if !ok {
		return "", fmt.Errorf("the screenshot portal answered without a response code")
	}
	switch code {
	case portalResponseOK:
	case portalResponseAbort:
		return "", errCaptureCancelled
	default:
		return "", fmt.Errorf("the screenshot portal ended the request (response %d)", code)
	}
	results, _ := body[1].(map[string]dbus.Variant)
	raw, _ := results["uri"].Value().(string)
	uri, err := url.Parse(raw)
	if err != nil || uri.Scheme != "file" || uri.Path == "" {
		return "", fmt.Errorf("the screenshot portal returned no file URI (%q)", raw)
	}
	return uri.Path, nil
}
