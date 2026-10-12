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

package web

import (
	"fmt"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
)

func Decode(input string) (map[string]any, error) {
	detected := format.DetectEncoding(input)

	switch detected {
	case format.FormatSDJWT:
		return Validate(input, ValidateOpts{})

	case format.FormatJWT:
		return Validate(input, ValidateOpts{})

	case format.FormatMDOC:
		return Validate(input, ValidateOpts{})

	default:
		return nil, fmt.Errorf("unable to auto-detect credential format (not JWT, SD-JWT, or mdoc)")
	}
}
