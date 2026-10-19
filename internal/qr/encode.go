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
	"fmt"
	"strings"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// SVG encodes content as a QR code and returns it as an SVG document. Error
// correction level L keeps long request URIs scannable.
func SVG(content string) (string, error) {
	hints := map[gozxing.EncodeHintType]any{
		gozxing.EncodeHintType_ERROR_CORRECTION: "L",
		gozxing.EncodeHintType_MARGIN:           2,
	}
	// Width and height 0 give one pixel per module.
	matrix, err := qrcode.NewQRCodeWriter().Encode(content, gozxing.BarcodeFormat_QR_CODE, 0, 0, hints)
	if err != nil {
		return "", fmt.Errorf("encoding the QR code: %w", err)
	}
	width, height := matrix.GetWidth(), matrix.GetHeight()
	var path strings.Builder
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			if matrix.Get(x, y) {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", x, y)
			}
		}
	}
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="100%%" height="100%%" fill="#fff"/><path fill="#000" d="%s"/></svg>`, width, height, path.String()), nil
}
