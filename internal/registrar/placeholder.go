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

package registrar

import (
	"bytes"
	"html/template"
	"net/http"
)

// placeholderPage is served at the default URLs. The registrar assigns them
// when a registration or a catalogue entry has no URL of its own. That way the
// links in registration certificates, in the consent dialog and in the
// catalogue work.
type placeholderPage struct {
	Kind, Title string
	Paragraphs  []string
}

var placeholderPages = map[string]placeholderPage{
	"/privacy-policy": {
		Kind:  "Relying party",
		Title: "Privacy policy",
		Paragraphs: []string{
			"A relying party registered without a privacy policy links to this page. The wallet shows the link in the consent dialog, so you can follow it while you test.",
			"A relying party that registers its own privacy policy links to that page instead.",
		},
	},
	"/support": {
		Kind:  "Relying party",
		Title: "Support",
		Paragraphs: []string{
			"A relying party registered without a support page links to this page. Its registration certificates carry the link as support_uri.",
			"A relying party that registers its own support page links to that page instead.",
		},
	},
	"/supervisory-authority": {
		Kind:  "Relying party",
		Title: "Supervisory authority",
		Paragraphs: []string{
			"A relying party registered without a contact form of its supervisory authority links to this page. A user would turn to that authority to report a relying party.",
			"A relying party that registers the form of its authority links to that page instead.",
		},
	},
	"/rulebook": {
		Kind:  "Attestation catalogue",
		Title: "Rulebook",
		Paragraphs: []string{
			"An attestation in the catalogue without its own rulebook links to this page. A rulebook describes an attestation type: its claims, who may issue it and how it is used.",
			"An attestation added with its own rulebook links to that page instead.",
		},
	},
}

var placeholderTemplate = template.Must(template.New("placeholder").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.Title}} · eudi-dev test registrar</title>
<style>
:root {
  --bg: #17191e; --surface: #21242a; --text: #eceef1; --dim: #a9afb9;
  --border: #2a2e35; --accent: #9dbcff; --warn-bg: #33291a; --warn-fg: #f3e3bd;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #f2f3f5; --surface: #ffffff; --text: #15171a; --dim: #5a606a;
    --border: #e4e6ea; --accent: #1f4fd1; --warn-bg: #fff3d6; --warn-fg: #4a3a10;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
  padding: 24px 16px; background: var(--bg); color: var(--text);
  font: 15px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif;
}
main {
  width: 100%; max-width: 560px; background: var(--surface); border: 1px solid var(--border);
  border-radius: 24px; padding: 32px;
}
.kind {
  margin: 0; font-size: 13px; font-weight: 600; color: var(--accent);
}
h1 { margin: 6px 0 16px; font-size: 26px; line-height: 1.25; }
.badge {
  display: inline-block; margin-bottom: 20px; padding: 1px 10px; background: var(--warn-bg);
  border-radius: 10px; color: var(--warn-fg); font-size: 12px; font-weight: 600;
}
p { margin: 0 0 12px; }
footer {
  margin-top: 24px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--dim); font-size: 13px;
}
@media (max-width: 480px) { main { padding: 24px 20px; } h1 { font-size: 22px; } }
</style>
</head>
<body>
<main>
<p class="kind">{{.Kind}}</p>
<h1>{{.Title}}</h1>
<span class="badge">Placeholder page</span>
{{range .Paragraphs}}<p>{{.}}</p>
{{end}}<footer>This page belongs to the eudi-dev test registrar. It holds test data only, and no real organization stands behind it.</footer>
</main>
</body>
</html>
`))

func (p placeholderPage) handler() http.HandlerFunc {
	var body bytes.Buffer
	if err := placeholderTemplate.Execute(&body, p); err != nil {
		panic(err)
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(body.Bytes())
	}
}
