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
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v2/internal/credtemplate"
)

func TestTemplateDisplay(t *testing.T) {
	w := generateTestWallet(t)

	if w.templateDisplay(nil) != nil {
		t.Error("a nil template display should resolve to nil")
	}
	if w.templateDisplay(&credtemplate.TemplateDisplay{}) != nil {
		t.Error("an empty template display should resolve to nil")
	}

	d := w.templateDisplay(&credtemplate.TemplateDisplay{
		Name:            "EUDI PID",
		BackgroundColor: "#3d59a1",
		TextColor:       "#ffffff",
		Logo:            "embedded:logo.svg",
		BackgroundImage: "embedded:german-id-specimen.jpg",
	})
	if d == nil {
		t.Fatal("a populated template display resolved to nil")
	}
	if d.Name != "EUDI PID" || d.BackgroundColor != "#3d59a1" || d.TextColor != "#ffffff" {
		t.Errorf("display fields not carried: %+v", d)
	}
	if !strings.HasPrefix(d.LogoURI, "data:image/svg+xml;base64,") {
		t.Errorf("embedded logo not resolved: %.40q", d.LogoURI)
	}
	if !strings.HasPrefix(d.BackgroundURI, "data:image/jpeg;base64,") {
		t.Errorf("embedded specimen not resolved: %.40q", d.BackgroundURI)
	}
}

// Embedded asset references must not escape the bundled asset directory.
func TestTemplateImage_EmbeddedIsSandboxed(t *testing.T) {
	w := generateTestWallet(t)
	if got := w.templateImage("embedded:../../go.mod", "logo"); got != "" {
		t.Errorf("a traversal reference resolved to %.30q", got)
	}
	if got := w.templateImage("embedded:not-a-real-asset.png", "logo"); got != "" {
		t.Errorf("an unknown asset resolved to %.30q", got)
	}
}

// The bundled PID templates supply the default cards' appearance.
func TestPredefinedTemplatesCarryDisplay(t *testing.T) {
	for _, tpl := range credtemplate.PredefinedTemplates() {
		if tpl.Display == nil {
			t.Errorf("template %q carries no display", tpl.Name)
			continue
		}
		if tpl.Display.Logo != "embedded:logo.svg" {
			t.Errorf("template %q logo = %q", tpl.Name, tpl.Display.Logo)
		}
		if strings.Contains(tpl.Name, "german") && tpl.Display.BackgroundImage == "" {
			t.Errorf("german template %q carries no specimen", tpl.Name)
		}
	}
}
