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

// Package imprint wraps the operator's legal notice in a page served at /imprint by
// the wallet and decoder.
package imprint

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// disclaimer repeats the EU non-affiliation disclaimer from the README.
const disclaimer = `This site runs <a href="https://github.com/eudi-dev/eudi-dev">eudi-dev</a>, an independent open source project. It is <strong>not</strong> an official service of the European Commission or the European Union, has no affiliation with them, and is not endorsed by them. &ldquo;EUDI&rdquo; is used descriptively (a developer tool for the European Digital Identity ecosystem).`

// The server's script-src policy blocks inline scripts and javascript: links.
const pageTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Imprint</title>
<link rel="stylesheet" href="tokens.css">
<script src="theme.js"></script>
<style>
  body { font-family: var(--font-sans); line-height: 1.6; max-width: 42rem; margin: 2rem auto; padding: 0 1rem; background: var(--bg); color: var(--text); }
  a { color: var(--link); }
  hr { margin: 2rem 0; opacity: 0.4; }
  .disclaimer { font-size: 0.85rem; color: var(--text-dim); }
  .page-footer { margin: 2rem 0; }
</style>
</head>
<body>
<p><a href="./">&larr; Back</a></p>
%s
<hr>
<p class="disclaimer">%s</p>
<footer class="site-footer page-footer">
  <div class="footer-row">
    <span id="footer-version" class="footer-version"></span>
    <span id="footer-prerelease" class="footer-prerelease" hidden></span>
    <a href="https://github.com/sponsors/dominikschlosser" id="sponsor-link" class="footer-sponsor" target="_blank" rel="noopener" hidden><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.7l-1.1-1.1a5.5 5.5 0 0 0-7.8 7.8L12 21l8.8-8.6a5.5 5.5 0 0 0 0-7.8Z"/></svg>Sponsor</a>
  </div>
</footer>
<script src="footer.js" data-config="api/config api/meta"></script>
</body>
</html>
`

// Load reads the operator's imprint HTML snippet and wraps it in a page with
// the EU non-affiliation disclaimer. The snippet is trusted operator content
// and is embedded unescaped.
func Load(path string) ([]byte, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".html", ".htm":
	default:
		return nil, fmt.Errorf("imprint file %s must be an .html snippet", path)
	}
	snippet, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading imprint file: %w", err)
	}
	if strings.TrimSpace(string(snippet)) == "" {
		return nil, fmt.Errorf("imprint file %s is empty", path)
	}
	return []byte(fmt.Sprintf(pageTemplate, strings.TrimSpace(string(snippet)), disclaimer)), nil
}
