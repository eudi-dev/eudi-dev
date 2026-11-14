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

package sdjwt_test

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt"
)

func Example() {
	raw, _ := os.ReadFile("testdata/example.sd-jwt")
	keyPEM, _ := os.ReadFile("testdata/example-issuer.pem")
	block, _ := pem.Decode(keyPEM)
	issuerKey, _ := x509.ParsePKIXPublicKey(block.Bytes)

	token, err := sdjwt.Parse(string(raw))
	if err != nil {
		fmt.Println("not a valid SD-JWT:", err)
		return
	}
	if err := sdjwt.Verify(token, issuerKey); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(token.ResolvedClaims["given_name"])

	err = token.ValidAt(time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC))
	fmt.Println(errors.Is(err, sdjwt.ErrExpired))
	// Output:
	// Erika
	// true
}
