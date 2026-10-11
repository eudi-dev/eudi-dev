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

package format

import "testing"

func TestImageMediaTypeByExtension(t *testing.T) {
	for name, want := range map[string]string{
		"logo.SVG":         "image/svg+xml",
		"card.png":         "image/png",
		"portraits/me.jpg": "image/jpeg",
		"me.jpeg":          "image/jpeg",
		"anim.gif":         "image/gif",
		"photo.webp":       "image/webp",
	} {
		if got, ok := ImageMediaType(name); !ok || got != want {
			t.Errorf("ImageMediaType(%q) = %q, %v, want %q", name, got, ok, want)
		}
	}
	if got, ok := ImageMediaType("data.json"); ok {
		t.Errorf("ImageMediaType(data.json) = %q, want no image", got)
	}
}
