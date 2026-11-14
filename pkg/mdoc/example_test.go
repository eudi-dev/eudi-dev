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

package mdoc_test

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/pkg/mdoc"
)

func Example() {
	raw, _ := os.ReadFile("testdata/example.mdoc")
	keyPEM, _ := os.ReadFile("testdata/example-issuer.pem")
	block, _ := pem.Decode(keyPEM)
	issuerKey, _ := x509.ParsePKIXPublicKey(block.Bytes)

	doc, err := mdoc.Parse(string(raw))
	if err != nil {
		fmt.Println("not a valid mdoc:", err)
		return
	}
	if err := mdoc.Verify(doc, issuerKey); err != nil {
		fmt.Println(err)
		return
	}
	if err := mdoc.VerifyValueDigests(doc); err != nil {
		fmt.Println(err)
		return
	}
	for _, item := range doc.NameSpaces["org.example.member.1"] {
		if item.ElementIdentifier == "given_name" {
			fmt.Println(item.ElementValue)
		}
	}

	err = doc.ValidAt(time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC))
	fmt.Println(errors.Is(err, mdoc.ErrExpired))
	// Output:
	// Erika
	// true
}
