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

// Package mdoctest builds unsigned mdoc documents for tests.
package mdoctest

import (
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/pkg/mdoc"
)

// WithHeader returns a document with this unprotected issuerAuth header.
func WithHeader(t testing.TB, unprotected map[any]any) *mdoc.Document {
	t.Helper()
	return &mdoc.Document{IssuerAuth: &mdoc.IssuerAuth{RawCOSE: sign1(t, unprotected, nil)}}
}

// WithMSO returns the document of an IssuerSigned structure with this MSO.
func WithMSO(t testing.TB, mso map[string]any) *mdoc.Document {
	t.Helper()
	payload := encode(t, cbor.Tag{Number: 24, Content: encode(t, mso)})
	issuerSigned := encode(t, map[string]any{
		"nameSpaces": map[string]any{},
		"issuerAuth": cbor.RawMessage(sign1(t, map[any]any{}, payload)),
	})
	doc, err := mdoc.ParseLenient(format.EncodeBase64URL(issuerSigned))
	if err != nil {
		t.Fatalf("parsing the test mdoc: %v", err)
	}
	return doc
}

func sign1(t testing.TB, unprotected map[any]any, payload []byte) []byte {
	t.Helper()
	return encode(t, cbor.Tag{Number: 18, Content: []any{
		[]byte{0xa1, 0x01, 0x26}, // {1: -7}, ES256
		unprotected,
		payload,
		make([]byte, 64),
	}})
}

func encode(t testing.TB, v any) []byte {
	t.Helper()
	data, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
