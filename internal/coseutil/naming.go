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

package coseutil

import (
	"encoding/base64"
	"strconv"

	"github.com/veraison/go-cose"
)

func coseInt(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case uint64:
		return int64(n)
	case int:
		return int64(n)
	}
	return 0
}

var coseHeaderLabels = map[int64]string{
	1: "alg", 2: "crit", 3: "content type", 4: "kid",
	32: "x5bag", 33: "x5chain", 34: "x5t", 35: "x5u",
}

// NameHeader replaces numeric COSE labels with registered names for display.
func NameHeader(header map[string]any) map[string]any {
	if len(header) == 0 {
		return nil
	}
	out := make(map[string]any, len(header))
	for key, value := range header {
		label := key
		if n, err := strconv.ParseInt(key, 10, 64); err == nil {
			if name, ok := coseHeaderLabels[n]; ok {
				label = name
			}
			if n == 1 {
				if alg, ok := coseAlgorithms[cose.Algorithm(coseInt(value))]; ok {
					value = alg.name
				}
			}
		}
		if label == "x5chain" || label == "x5bag" {
			value = encodeCertificates(value)
		}
		out[label] = value
	}
	return out
}

// encodeCertificates gives the DER certificates in the base64 form of an x5c
// entry (RFC 7515 §4.1.6). An mdoc x5chain then reads like a JWS x5c.
func encodeCertificates(value any) any {
	switch v := value.(type) {
	case []byte:
		return []any{base64.StdEncoding.EncodeToString(v)}
	case []any:
		out := make([]any, 0, len(v))
		for _, entry := range v {
			if der, ok := entry.([]byte); ok {
				out = append(out, base64.StdEncoding.EncodeToString(der))
			} else {
				out = append(out, entry)
			}
		}
		return out
	}
	return value
}

// NameKey replaces numeric COSE_Key labels with registered names for display.
func NameKey(key map[string]any) map[string]any {
	if len(key) == 0 {
		return nil
	}
	names := map[string]string{"1": "kty", "-1": "crv", "-2": "x", "-3": "y", "3": "alg", "2": "kid"}
	ktyNames := map[int64]string{1: "OKP", 2: "EC2", 3: "RSA", 4: "Symmetric"}
	crvNames := map[int64]string{1: "P-256", 2: "P-384", 3: "P-521", 6: "Ed25519"}
	out := make(map[string]any, len(key))
	for k, v := range key {
		name := k
		if named, ok := names[k]; ok {
			name = named
		}
		switch name {
		case "kty":
			if s, ok := ktyNames[coseInt(v)]; ok {
				v = s
			}
		case "crv":
			if s, ok := crvNames[coseInt(v)]; ok {
				v = s
			}
		case "x", "y":
			if b, ok := v.([]byte); ok {
				v = base64.RawURLEncoding.EncodeToString(b)
			}
		case "alg":
			if alg, ok := coseAlgorithms[cose.Algorithm(coseInt(v))]; ok {
				v = alg.name
			}
		}
		out[name] = v
	}
	return out
}
