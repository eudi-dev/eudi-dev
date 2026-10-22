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

package typemetadata

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
)

// parseDocument decodes a Type Metadata document. A malformed claims property
// makes claim metadata processing fail (§5.6), so it is a ProcessingError.
func parseDocument(body []byte) (Document, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil || object == nil {
		return Document{}, errors.New("the document is not a JSON object")
	}
	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		if _, hasClaims := object["claims"]; hasClaims && claimsMalformed(object["claims"]) {
			return Document{}, processingErrorf("SD-JWT VC §5.6: the claims of the Type Metadata are malformed: %v", err)
		}
		return Document{}, err
	}
	if doc.VCT == "" {
		return Document{}, errors.New("vct is missing")
	}
	for _, display := range doc.Display {
		if display.Locale == "" || display.Name == "" {
			return Document{}, errors.New("§5.5: every display entry needs a locale and a name")
		}
	}
	if err := checkClaims(doc); err != nil {
		return Document{}, processingErrorf("SD-JWT VC %v in the Type Metadata of %s", err, doc.VCT)
	}
	return doc, nil
}

func claimsMalformed(raw json.RawMessage) bool {
	var claims []Claim
	return json.Unmarshal(raw, &claims) != nil
}

var integrityHashes = []struct {
	name string
	new  func() hash.Hash
}{
	{"sha256", sha256.New},
	{"sha384", sha512.New384},
	{"sha512", sha512.New},
}

// VerifyIntegrity checks a document against integrity metadata (SD-JWT VC
// §6, with the syntax of W3C SRI §3). It uses the hash expressions of the
// strongest supported algorithm, and any of them may match.
func VerifyIntegrity(document []byte, metadata string) error {
	strongest := -1
	var digests [][]byte
	for _, expression := range strings.Fields(metadata) {
		name, value, ok := strings.Cut(expression, "-")
		if !ok {
			continue
		}
		value, _, _ = strings.Cut(value, "?")
		rank := -1
		for i, h := range integrityHashes {
			if h.name == name {
				rank = i
			}
		}
		if rank < 0 || rank < strongest {
			continue
		}
		if rank > strongest {
			strongest, digests = rank, nil
		}
		if digest, err := base64.StdEncoding.DecodeString(value); err == nil {
			digests = append(digests, digest)
		}
	}
	if strongest < 0 {
		return fmt.Errorf("the integrity metadata %q uses no supported hash algorithm (sha256, sha384, sha512)", metadata)
	}
	h := integrityHashes[strongest].new()
	h.Write(document)
	sum := h.Sum(nil)
	for _, digest := range digests {
		if bytes.Equal(digest, sum) {
			return nil
		}
	}
	return fmt.Errorf("the document does not match the integrity metadata %q", metadata)
}
