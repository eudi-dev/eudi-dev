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

package statuslist

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

// specVector is one entry of Appendix C, "Test vectors for Status List
// encoding", transcribed from the editor's copy of
// draft-ietf-oauth-status-list. Section 11.1: "Implementations SHOULD verify
// correctness using the test vectors given by this specification."
type specVector struct {
	Name string `json:"name"`
	Bits int    `json:"bits"`
	// LST is the base64url-encoded compressed byte array from the JSON
	// encoding of the vector (Section 4.2).
	LST string `json:"lst"`
	// CBOR is the hex of the CBOR encoding of the same list (Section 4.3).
	CBOR     string         `json:"cbor"`
	Statuses map[string]int `json:"statuses"`
}

func loadSpecVectors(t *testing.T) []specVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/spec_test_vectors.json")
	if err != nil {
		t.Fatalf("reading the specification's test vectors: %v", err)
	}
	var vectors []specVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parsing the specification's test vectors: %v", err)
	}
	if len(vectors) != 4 {
		t.Fatalf("expected the four appendix C vectors, got %d", len(vectors))
	}
	return vectors
}

// TestSpecTestVectors_JSONEncoding reads every index the appendix lists from
// the JSON encoding of each vector. Other indices must read as VALID ("All
// values that are not mentioned for the examples below can be assumed to be 0
// (VALID)").
func TestSpecTestVectors_JSONEncoding(t *testing.T) {
	for _, vector := range loadSpecVectors(t) {
		t.Run(vector.Name, func(t *testing.T) {
			compressed, err := format.DecodeBase64URL(vector.LST)
			if err != nil {
				t.Fatalf("decoding lst: %v", err)
			}
			bitstring, rawDeflate, err := zlibDecompress(compressed)
			if err != nil {
				t.Fatalf("decompressing lst: %v", err)
			}
			if rawDeflate {
				t.Error("the specification's own vectors carry the ZLIB header section 4.1 requires")
			}
			assertVectorStatuses(t, vector, bitstring)
		})
	}
}

// TestSpecTestVectors_CBOREncoding does the same through the CBOR encoding of
// Section 4.3. There bits is a CBOR unsigned integer and lst a CBOR byte string.
func TestSpecTestVectors_CBOREncoding(t *testing.T) {
	for _, vector := range loadSpecVectors(t) {
		t.Run(vector.Name, func(t *testing.T) {
			encoded, err := hex.DecodeString(vector.CBOR)
			if err != nil {
				t.Fatalf("decoding the CBOR vector: %v", err)
			}
			var statusList struct {
				Bits int    `cbor:"bits"`
				LST  []byte `cbor:"lst"`
			}
			if err := cbor.Unmarshal(encoded, &statusList); err != nil {
				t.Fatalf("parsing the CBOR StatusList: %v", err)
			}
			if statusList.Bits != vector.Bits {
				t.Fatalf("bits = %d, want %d", statusList.Bits, vector.Bits)
			}
			bitstring, _, err := zlibDecompress(statusList.LST)
			if err != nil {
				t.Fatalf("decompressing lst: %v", err)
			}
			assertVectorStatuses(t, vector, bitstring)
		})
	}
}

func assertVectorStatuses(t *testing.T, vector specVector, bitstring []byte) {
	t.Helper()

	named := make(map[int]bool, len(vector.Statuses))
	indices := make([]int, 0, len(vector.Statuses))
	for key := range vector.Statuses {
		idx, err := strconv.Atoi(key)
		if err != nil {
			t.Fatalf("test vector index %q is not a number", key)
		}
		indices = append(indices, idx)
		named[idx] = true
	}
	sort.Ints(indices)

	for _, idx := range indices {
		want := vector.Statuses[strconv.Itoa(idx)]
		got, err := extractStatus(bitstring, idx, vector.Bits)
		if err != nil {
			t.Fatalf("index %d: %v", idx, err)
		}
		if got != want {
			t.Errorf("index %d = %d, want %d", idx, got, want)
		}
	}

	// "All examples are initialized with a size of 2^20 entries."
	entries := len(bitstring) * 8 / vector.Bits
	if entries != 1<<20 {
		t.Errorf("the list holds %d entries, want 2^20", entries)
	}

	// Every other index is VALID. A sample catches an off-by-one in the packing.
	for _, idx := range []int{1, 2, 100, 4095, 65536, 500000, 1<<20 - 1} {
		if named[idx] {
			continue
		}
		got, err := extractStatus(bitstring, idx, vector.Bits)
		if err != nil {
			t.Fatalf("index %d: %v", idx, err)
		}
		if got != 0 {
			t.Errorf("unnamed index %d = %d, want 0 (VALID)", idx, got)
		}
	}

	// Section 8.3: "If the provided index is out of bounds of the Status List
	// ... the Referenced Token MUST be rejected".
	if _, err := extractStatus(bitstring, entries, vector.Bits); err == nil {
		t.Error("an index one past the end was accepted")
	}
}

// TestSpecTestVectors_ThroughTheChecker serves each appendix vector as a real
// Status List Token. The vectors then cover the fetch, verify and claim-check
// path.
func TestSpecTestVectors_ThroughTheChecker(t *testing.T) {
	key := mustGenerateKey(t)
	for _, vector := range loadSpecVectors(t) {
		t.Run(vector.Name, func(t *testing.T) {
			compressed, err := format.DecodeBase64URL(vector.LST)
			if err != nil {
				t.Fatalf("decoding lst: %v", err)
			}
			bitstring, _, err := zlibDecompress(compressed)
			if err != nil {
				t.Fatalf("decompressing lst: %v", err)
			}
			srv := jwtServer(t, key, vector.Bits, bitstring, nil)

			for key, want := range vector.Statuses {
				idx, _ := strconv.Atoi(key)
				result, err := Check(&StatusRef{URI: srv.URL, Idx: idx})
				if err != nil {
					t.Fatalf("index %d: %v", idx, err)
				}
				if result.Status != want {
					t.Errorf("index %d = %d, want %d", idx, result.Status, want)
				}
				if result.BitsPerEntry != vector.Bits {
					t.Errorf("index %d reported bits=%d, want %d", idx, result.BitsPerEntry, vector.Bits)
				}
				if result.IsValid != (want == 0) {
					t.Errorf("index %d reported valid=%v for status %d", idx, result.IsValid, want)
				}
			}
		})
	}
}
