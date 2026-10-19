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
	"image"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// rasterize draws the modules of an SVG() result into a PNG file, with scale
// pixels per module.
func rasterize(t *testing.T, svg string, scale int) string {
	t.Helper()
	box := regexp.MustCompile(`viewBox="0 0 (\d+) (\d+)"`).FindStringSubmatch(svg)
	if box == nil {
		t.Fatalf("no viewBox in %q", svg)
	}
	width, _ := strconv.Atoi(box[1])
	height, _ := strconv.Atoi(box[2])
	img := image.NewGray(image.Rect(0, 0, width*scale, height*scale))
	draw.Draw(img, img.Bounds(), image.White, image.Point{}, draw.Src)
	for _, m := range regexp.MustCompile(`M(\d+) (\d+)h1v1h-1z`).FindAllStringSubmatch(svg, -1) {
		x, _ := strconv.Atoi(m[1])
		y, _ := strconv.Atoi(m[2])
		draw.Draw(img, image.Rect(x*scale, y*scale, (x+1)*scale, (y+1)*scale), image.Black, image.Point{}, draw.Src)
	}
	path := filepath.Join(t.TempDir(), "qr.png")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSVGRoundTrip(t *testing.T) {
	content := "openid4vp://?client_id=x509_hash%3Aabc&request_uri=https%3A%2F%2Fverifier.example%2Fverifier%2Frequest%2F" + strings.Repeat("a", 43)
	svg, err := SVG(content)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ScanFile(rasterize(t, svg, 8))
	if err != nil {
		t.Fatal(err)
	}
	if got != content {
		t.Errorf("decoded %q, want %q", got, content)
	}
}

// An unsigned request carries the whole query in the URI, so the QR code
// must hold a few kilobytes.
func TestSVGHoldsALongRequest(t *testing.T) {
	if _, err := SVG("openid4vp://?" + strings.Repeat("x", 2500)); err != nil {
		t.Fatal(err)
	}
}
