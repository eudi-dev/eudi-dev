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
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/image/draw"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/defaults"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/publicpath"
)

// Display text comes from issuer metadata, operator forms and templates, so
// its length is capped.
const (
	maxDisplayNameRunes        = 80
	maxDisplayDescriptionRunes = 500
	maxDisplayLocaleRunes      = 35
	maxDisplayAltTextRunes     = 120
)

func boundDisplayText(s string, maxRunes int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes])
}

// mergeCredentialDisplay lets each set field of over replace the one in base.
// Either display may be nil.
func mergeCredentialDisplay(base, over *oid4vc.CredentialDisplay) *oid4vc.CredentialDisplay {
	if base == nil {
		return over
	}
	if over == nil {
		return base
	}
	out := *base
	if over.Name != "" {
		out.Name = over.Name
	}
	if over.Description != "" {
		out.Description = over.Description
	}
	if over.BackgroundColor != "" {
		out.BackgroundColor = over.BackgroundColor
	}
	if over.TextColor != "" {
		out.TextColor = over.TextColor
	}
	// A new logo brings its own alt text, even an empty one. Alt text without a
	// logo describes the logo of the template.
	if over.LogoURI != "" {
		out.LogoURI = over.LogoURI
		out.LogoAltText = over.LogoAltText
	} else if over.LogoAltText != "" {
		out.LogoAltText = over.LogoAltText
	}
	if over.BackgroundURI != "" {
		out.BackgroundURI = over.BackgroundURI
	}
	return &out
}

const maxDisplayImageBytes = 256 << 10

// maxDisplayImageFetchBytes caps a download before it is shrunk to fit
// maxDisplayImageBytes.
const maxDisplayImageFetchBytes = 4 << 20

// displayImageMaxSide is the longest image side shown on a credential card.
const displayImageMaxSide = 1024

// maxDisplayImagePixels guards against decompression bombs. Decoding takes
// four bytes per pixel, so 32 megapixels caps the decode at about 128MB.
const maxDisplayImagePixels = 32 << 20

// cssColorValue follows OpenID4VCI §12.2.4 for the color fields:
// "numerical color values defined in CSS Color Module Level 3". Named colors
// are also accepted. Only a value of this shape reaches a style sheet.
var cssColorValue = regexp.MustCompile(`^(#[0-9a-fA-F]{3}|#[0-9a-fA-F]{6}|[a-zA-Z]{3,30}|(?:rgb|rgba|hsl|hsla)\([0-9,.%\s]{1,40}\))$`)

// displayForListing replaces stored images with URLs of the display endpoint,
// so a listing does not carry every card's images as base64.
func displayForListing(c StoredCredential) map[string]any {
	d := c.Display
	if d == nil {
		return nil
	}
	m := map[string]any{}
	addStringDetail(m, "name", d.Name)
	addStringDetail(m, "description", d.Description)
	addStringDetail(m, "locale", d.Locale)
	addStringDetail(m, "background_color", d.BackgroundColor)
	addStringDetail(m, "text_color", d.TextColor)
	addStringDetail(m, "logo_alt_text", d.LogoAltText)
	if d.LogoURI != "" {
		m["logo_uri"] = displayImageRef(c.ID, "logo", d.LogoURI)
	}
	if d.BackgroundURI != "" {
		m["background_uri"] = displayImageRef(c.ID, "background", d.BackgroundURI)
	}
	return m
}

// displayImageRef returns the endpoint URL for a stored image. An http(s) URL
// passes through. HTTP handlers add the path prefix with withPublicImagePaths.
func displayImageRef(id, kind, uri string) string {
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		return uri
	}
	return "/api/credentials/" + id + "/display/" + kind
}

func dataURIImage(uri string) (contentType string, data []byte, ok bool) {
	if !strings.HasPrefix(uri, "data:") {
		return "", nil, false
	}
	rest := uri[len("data:"):]
	comma := strings.IndexByte(rest, ',')
	if comma < 0 {
		return "", nil, false
	}
	meta, payload := rest[:comma], rest[comma+1:]
	if !strings.Contains(meta, "base64") {
		return "", nil, false
	}
	contentType = "application/octet-stream"
	if head, _, found := strings.Cut(meta, ";"); found && head != "" {
		contentType = head
	} else if meta != "" && !strings.Contains(meta, "=") {
		contentType = strings.TrimSuffix(meta, ";base64")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
	if err != nil {
		return "", nil, false
	}
	return contentType, decoded, true
}

// resolveCredentialDisplay uses the first §12.2.4 display entry of the
// configuration. A display problem is a warning in every mode.
func (w *Wallet) resolveCredentialDisplay(metadata map[string]any, configID string) *oid4vc.CredentialDisplay {
	configs, _ := metadata["credential_configurations_supported"].(map[string]any)
	config, _ := configs[configID].(map[string]any)
	credentialMetadata, _ := config["credential_metadata"].(map[string]any)
	entry, ok := firstDisplayEntry(credentialMetadata["display"])
	if !ok {
		return nil
	}
	d := &oid4vc.CredentialDisplay{}
	name, _ := entry["name"].(string)
	d.Name = boundDisplayText(name, maxDisplayNameRunes)
	description, _ := entry["description"].(string)
	d.Description = boundDisplayText(description, maxDisplayDescriptionRunes)
	locale, _ := entry["locale"].(string)
	d.Locale = boundDisplayText(locale, maxDisplayLocaleRunes)
	d.BackgroundColor = w.displayColor(entry, "background_color")
	d.TextColor = w.displayColor(entry, "text_color")
	if logo, ok := entry["logo"].(map[string]any); ok {
		uri, _ := logo["uri"].(string)
		d.LogoURI = w.cacheDisplayImage(uri, "logo")
		if d.LogoURI != "" {
			altText, _ := logo["alt_text"].(string)
			d.LogoAltText = boundDisplayText(altText, maxDisplayAltTextRunes)
		}
	}
	if background, ok := entry["background_image"].(map[string]any); ok {
		uri, _ := background["uri"].(string)
		d.BackgroundURI = w.cacheDisplayImage(uri, "background_image")
	}
	w.checkDisplayContrast(d)
	if *d == (oid4vc.CredentialDisplay{}) {
		return nil
	}
	return d
}

// checkDisplayContrast warns about a color pair below 3:1. Named colors and
// hsl() values are skipped because parseCSSColor does not read them.
func (w *Wallet) checkDisplayContrast(d *oid4vc.CredentialDisplay) {
	if d.BackgroundColor == "" || d.TextColor == "" {
		return
	}
	background, okBackground := parseCSSColor(d.BackgroundColor)
	text, okText := parseCSSColor(d.TextColor)
	if !okBackground || !okText {
		return
	}
	ratio := contrastRatio(background, text)
	if ratio >= 3 {
		return
	}
	w.addProtocolWarning("issuance", "credential_display_low_contrast",
		fmt.Sprintf("The credential display colors %s on %s have a contrast ratio of %.1f:1, below the 3:1 a readable card needs.",
			d.TextColor, d.BackgroundColor, ratio),
		map[string]any{
			"background_color": d.BackgroundColor,
			"text_color":       d.TextColor,
			"contrast_ratio":   ratio,
		})
}

func parseCSSColor(value string) ([3]float64, bool) {
	var rgb [3]float64
	value = strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(value, "#") && len(value) == 4:
		for i := 0; i < 3; i++ {
			n, err := strconv.ParseUint(strings.Repeat(value[i+1:i+2], 2), 16, 8)
			if err != nil {
				return rgb, false
			}
			rgb[i] = float64(n)
		}
		return rgb, true
	case strings.HasPrefix(value, "#") && len(value) == 7:
		for i := 0; i < 3; i++ {
			n, err := strconv.ParseUint(value[1+2*i:3+2*i], 16, 8)
			if err != nil {
				return rgb, false
			}
			rgb[i] = float64(n)
		}
		return rgb, true
	case strings.HasPrefix(value, "rgb(") || strings.HasPrefix(value, "rgba("):
		inner := value[strings.Index(value, "(")+1 : len(value)-1]
		parts := strings.Split(inner, ",")
		if len(parts) < 3 {
			return rgb, false
		}
		for i := 0; i < 3; i++ {
			part := strings.TrimSpace(parts[i])
			percent := strings.HasSuffix(part, "%")
			n, err := strconv.ParseFloat(strings.TrimSuffix(part, "%"), 64)
			if err != nil {
				return rgb, false
			}
			if percent {
				n = n * 255 / 100
			}
			rgb[i] = n
		}
		return rgb, true
	}
	return rgb, false
}

// contrastRatio is the WCAG 2 contrast ratio.
func contrastRatio(a, b [3]float64) float64 {
	la, lb := relativeLuminance(a), relativeLuminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

func relativeLuminance(rgb [3]float64) float64 {
	var channels [3]float64
	for i, c := range rgb {
		c /= 255
		if c <= 0.04045 {
			c /= 12.92
		} else {
			c = math.Pow((c+0.055)/1.055, 2.4)
		}
		channels[i] = c
	}
	return 0.2126*channels[0] + 0.7152*channels[1] + 0.0722*channels[2]
}

// templateDisplay validates colors like an issuer's display. An image
// "embedded:<file>" reads a bundled asset. Any other image goes through
// cacheDisplayImage. It returns nil for an empty template display.
func (w *Wallet) templateDisplay(td *credtemplate.TemplateDisplay) *oid4vc.CredentialDisplay {
	if td == nil {
		return nil
	}
	d := &oid4vc.CredentialDisplay{
		Name:            boundDisplayText(td.Name, maxDisplayNameRunes),
		Description:     boundDisplayText(td.Description, maxDisplayDescriptionRunes),
		Locale:          "en-US",
		BackgroundColor: w.displayColor(map[string]any{"background_color": td.BackgroundColor}, "background_color"),
		TextColor:       w.displayColor(map[string]any{"text_color": td.TextColor}, "text_color"),
		LogoURI:         w.templateImage(td.Logo, "logo"),
		LogoAltText:     boundDisplayText(td.LogoAltText, maxDisplayAltTextRunes),
		BackgroundURI:   w.templateImage(td.BackgroundImage, "background_image"),
	}
	if d.Name == "" && d.Description == "" && d.BackgroundColor == "" &&
		d.TextColor == "" && d.LogoURI == "" && d.BackgroundURI == "" {
		return nil
	}
	w.checkDisplayContrast(d)
	return d
}

// bundledImageDigests identifies the images bundled with the wallet. The demo
// issuer serves the art of its templates from them.
var bundledImageDigests = sync.OnceValue(func() map[[sha256.Size]byte]bool {
	digests := map[[sha256.Size]byte]bool{}
	entries, _ := defaults.ReadDir("images")
	for _, entry := range entries {
		if _, data, ok := TemplateImage(defaults.EmbeddedPrefix + "images/" + entry.Name()); ok {
			digests[sha256.Sum256(data)] = true
		}
	}
	return digests
})

// keepsTemplateImage reports whether a template image passes the visitor
// rules: bundled art, named or as a data URI.
func (w *Wallet) keepsTemplateImage(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" || !w.visitorRules().BundledImagesOnly {
		return true
	}
	_, data, ok := TemplateImage(ref)
	return ok && bundledImageDigests()[sha256.Sum256(data)]
}

func (w *Wallet) templateImage(ref, field string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if strings.HasPrefix(ref, defaults.EmbeddedPrefix) {
		contentType, data, ok := TemplateImage(ref)
		if !ok {
			w.rejectDisplayImage(field, ref, "not a bundled image")
			return ""
		}
		return "data:" + contentType + ";base64," + base64.StdEncoding.EncodeToString(data)
	}
	return w.cacheDisplayImage(ref, field)
}

// issuedDisplay validates operator input like an issuer's display. It
// returns nil when the input has no display.
func (w *Wallet) issuedDisplay(in IssueDisplay) *oid4vc.CredentialDisplay {
	d := &oid4vc.CredentialDisplay{
		Name:            boundDisplayText(in.Name, maxDisplayNameRunes),
		Description:     boundDisplayText(in.Description, maxDisplayDescriptionRunes),
		BackgroundColor: w.displayColor(map[string]any{"background_color": in.BackgroundColor}, "background_color"),
		TextColor:       w.displayColor(map[string]any{"text_color": in.TextColor}, "text_color"),
		LogoURI:         w.cacheDisplayImage(strings.TrimSpace(in.Logo), "logo"),
		LogoAltText:     boundDisplayText(in.LogoAltText, maxDisplayAltTextRunes),
		BackgroundURI:   w.cacheDisplayImage(strings.TrimSpace(in.BackgroundImage), "background_image"),
	}
	if d.Name == "" && d.Description == "" && d.BackgroundColor == "" &&
		d.TextColor == "" && d.LogoURI == "" && d.BackgroundURI == "" {
		return nil
	}
	w.checkDisplayContrast(d)
	return d
}

func (w *Wallet) displayColor(entry map[string]any, field string) string {
	value, _ := entry[field].(string)
	if value == "" {
		return ""
	}
	if cssColorValue.MatchString(value) {
		return value
	}
	w.addProtocolWarning("issuance", "credential_display_invalid",
		fmt.Sprintf("The credential display %s is %q, which is not a CSS Color Module Level 3 color (§12.2.4). It is ignored.", field, value),
		map[string]any{"field": field, "value": value})
	return ""
}

// cacheDisplayImage stores a §12.2.4 display image as a data URI. With
// --adhoc-display-images an https URL stays for the browser to fetch.
func (w *Wallet) cacheDisplayImage(uri, field string) string {
	if uri == "" {
		return ""
	}
	if strings.HasPrefix(uri, "data:") {
		body, mediaType, ok := decodeImageDataURI(uri)
		if !ok {
			w.rejectDisplayImage(field, uri, "a data URI must carry a base64 image")
			return ""
		}
		return w.encodeDisplayImage(body, mediaType, field, uri)
	}
	if w.AdhocDisplayImages && !w.visitorRules().BundledImagesOnly && strings.HasPrefix(uri, "https://") {
		// Browsers block http images on https pages, so only https URLs stay.
		// Each card view then reaches the issuer, so this mode is opt-in.
		return uri
	}
	return w.fetchAndEmbedDisplayImage(uri, field)
}

// embedDisplayImage ignores --adhoc-display-images. It is for the issuer
// logo, which consent shows once and the wallet never stores.
func (w *Wallet) embedDisplayImage(uri, field string) string {
	if uri == "" {
		return ""
	}
	if strings.HasPrefix(uri, "data:") {
		body, mediaType, ok := decodeImageDataURI(uri)
		if !ok {
			w.rejectDisplayImage(field, uri, "a data URI must carry a base64 image")
			return ""
		}
		return w.encodeDisplayImage(body, mediaType, field, uri)
	}
	return w.fetchAndEmbedDisplayImage(uri, field)
}

// Image URLs come from untrusted issuer metadata, so the fetch address
// policy blocks private destinations (ADR-0004).
func (w *Wallet) fetchAndEmbedDisplayImage(uri, field string) string {
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		w.rejectDisplayImage(field, uri, err.Error())
		return ""
	}
	resp, err := w.HTTPClient().Do(req)
	if err != nil {
		w.rejectDisplayImage(field, uri, err.Error())
		return ""
	}
	defer resp.Body.Close()
	contentType := resp.Header.Get("Content-Type")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(contentType, "image/") {
		w.rejectDisplayImage(field, uri, fmt.Sprintf("HTTP %d with content type %q, the card needs an image", resp.StatusCode, contentType))
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDisplayImageFetchBytes+1))
	if err != nil {
		w.rejectDisplayImage(field, uri, err.Error())
		return ""
	}
	if len(body) > maxDisplayImageFetchBytes {
		w.rejectDisplayImage(field, uri, fmt.Sprintf("larger than the %dMB download cap", maxDisplayImageFetchBytes>>20))
		return ""
	}
	mediaType, _, _ := strings.Cut(contentType, ";")
	return w.encodeDisplayImage(body, strings.TrimSpace(mediaType), field, uri)
}

// encodeDisplayImage keeps the bytes as served when they fit the cap and
// shrinks them to card size otherwise. Dimensions are checked first because
// a small file can declare huge dimensions.
func (w *Wallet) encodeDisplayImage(body []byte, mediaType, field, uri string) string {
	if w.visitorRules().BundledImagesOnly && !bundledImageDigests()[sha256.Sum256(body)] {
		w.rejectDisplayImage(field, uri, "the public demo shows only the art bundled with the wallet")
		return ""
	}
	if mediaType == "image/svg+xml" {
		return w.keepVectorImage(body, field, uri)
	}
	config, _, err := image.DecodeConfig(bytes.NewReader(body))
	if err != nil {
		w.rejectDisplayImage(field, uri, "not a raster image the wallet can read")
		return ""
	}
	if config.Width <= 0 || config.Height <= 0 || config.Width*config.Height > maxDisplayImagePixels {
		w.rejectDisplayImage(field, uri, fmt.Sprintf("%dx%d pixels, past the %d-megapixel cap", config.Width, config.Height, maxDisplayImagePixels>>20))
		return ""
	}
	if len(body) <= maxDisplayImageBytes {
		return "data:" + mediaType + ";base64," + base64.StdEncoding.EncodeToString(body)
	}
	shrunk, shrunkType, ok := shrinkDisplayImage(body)
	if !ok {
		w.rejectDisplayImage(field, uri, fmt.Sprintf("larger than the %dKB cap and not a raster image the wallet can shrink", maxDisplayImageBytes>>10))
		return ""
	}
	if len(shrunk) > maxDisplayImageBytes {
		w.rejectDisplayImage(field, uri, fmt.Sprintf("still larger than the %dKB cap at card size", maxDisplayImageBytes>>10))
		return ""
	}
	return "data:" + shrunkType + ";base64," + base64.StdEncoding.EncodeToString(shrunk)
}

// keepVectorImage stores an SVG as served. It has no pixel dimensions, so
// only the byte cap applies.
func (w *Wallet) keepVectorImage(body []byte, field, uri string) string {
	if len(body) > maxDisplayImageBytes {
		w.rejectDisplayImage(field, uri, fmt.Sprintf("larger than the %dKB cap", maxDisplayImageBytes>>10))
		return ""
	}
	// The SVG is only rendered through an <img> tag, which runs no scripts
	// and loads nothing external. Its endpoint also sends script-src 'self'.
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(body)
}

func decodeImageDataURI(uri string) ([]byte, string, bool) {
	rest, ok := strings.CutPrefix(uri, "data:")
	if !ok {
		return nil, "", false
	}
	meta, payload, ok := strings.Cut(rest, ",")
	if !ok || !strings.HasPrefix(meta, "image/") || !strings.HasSuffix(meta, ";base64") {
		return nil, "", false
	}
	body, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, "", false
	}
	return body, strings.TrimSuffix(meta, ";base64"), true
}

// shrinkDisplayImage writes an opaque image as JPEG to keep it small. A
// transparent image becomes PNG to keep its transparency.
func shrinkDisplayImage(body []byte) ([]byte, string, bool) {
	src, _, err := image.Decode(bytes.NewReader(body))
	if err != nil {
		return nil, "", false
	}
	bounds := src.Bounds()
	side := max(bounds.Dx(), bounds.Dy())
	scale := 1.0
	if side > displayImageMaxSide {
		scale = float64(displayImageMaxSide) / float64(side)
	}
	dst := image.NewRGBA(image.Rect(0, 0, max(1, int(float64(bounds.Dx())*scale)), max(1, int(float64(bounds.Dy())*scale))))
	draw.BiLinear.Scale(dst, dst.Bounds(), src, bounds, draw.Src, nil)

	var out bytes.Buffer
	if dst.Opaque() {
		if err := jpeg.Encode(&out, dst, &jpeg.Options{Quality: 80}); err != nil {
			return nil, "", false
		}
		return out.Bytes(), "image/jpeg", true
	}
	if err := png.Encode(&out, dst); err != nil {
		return nil, "", false
	}
	return out.Bytes(), "image/png", true
}

func (w *Wallet) rejectDisplayImage(field, uri, reason string) {
	w.addProtocolWarning("issuance", "credential_display_image_rejected",
		fmt.Sprintf("The credential display %s image was not kept: %s.", field, reason),
		map[string]any{"field": field, "uri": uri, "reason": reason})
}

// rememberDisplay updates both the stored credential and the caller's copy.
// The server may write that copy back after a reload during issuance.
func (w *Wallet) rememberDisplay(cred *StoredCredential, d *oid4vc.CredentialDisplay) {
	if w == nil || cred == nil || d == nil {
		return
	}
	cred.Display = d
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.Credentials {
		if w.Credentials[i].ID == cred.ID {
			w.Credentials[i].Display = d
			return
		}
	}
}

// withPublicImagePaths adds the request's path prefix to the display image
// URLs of a credential summary.
func withPublicImagePaths(r *http.Request, summary map[string]any) map[string]any {
	display, _ := summary["display"].(map[string]any)
	prefix := publicpath.Prefix(r)
	if display == nil || prefix == "" {
		return summary
	}
	for _, key := range []string{"logo_uri", "background_uri"} {
		if p, ok := display[key].(string); ok && strings.HasPrefix(p, "/api/") {
			display[key] = prefix + p
		}
	}
	return summary
}
