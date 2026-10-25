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

package wallet

import (
	"net/http"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/defaults"
	"github.com/eudi-dev/eudi-dev/v3/internal/httpsec"
)

// TemplateImage returns the bytes of a bundled (embedded:<file>) or data URI
// template image. ok is false for an https image and for anything that is not
// an image.
func TemplateImage(ref string) (contentType string, data []byte, ok bool) {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, defaults.EmbeddedPrefix) {
		contentType, data, ok = defaults.Resolve(ref)
		if !ok || !strings.HasPrefix(contentType, "image/") {
			return "", nil, false
		}
		return contentType, data, true
	}
	data, contentType, ok = decodeImageDataURI(ref)
	return contentType, data, ok
}

// ServeTemplateImage serves the logo or background_image of a template
// display. A linked image has no copy to serve.
func ServeTemplateImage(w http.ResponseWriter, r *http.Request, d *credtemplate.TemplateDisplay, field string) {
	var ref string
	if d != nil {
		switch field {
		case "logo":
			ref = d.Logo
		case "background_image":
			ref = d.BackgroundImage
		}
	}
	contentType, data, ok := TemplateImage(ref)
	if !ok {
		http.NotFound(w, r)
		return
	}
	httpsec.ServeImage(w, r, contentType, data)
}
