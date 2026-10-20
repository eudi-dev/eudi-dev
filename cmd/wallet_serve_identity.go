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

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v3/internal/demorp"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

// demoIdentityFlags are the files that replace the registered identity of the
// demo issuer or the demo verifier.
type demoIdentityFlags struct {
	SigningKey       string
	Info             string
	RegistrationCert string
}

func addDemoIdentityFlags(cmd *cobra.Command, flags *demoIdentityFlags, role, infoName, signs string) {
	cmd.Flags().StringVar(&flags.SigningKey, "demo-"+role+"-signing-key", "", fmt.Sprintf("PEM file with an EC private key and its access certificate chain, leaf first, for example from a member state sandbox. It signs the demo %s's %s instead of the access certificate from the wallet's registrar", role, signs))
	cmd.Flags().StringVar(&flags.Info, "demo-"+role+"-info", "", fmt.Sprintf("JSON file with the %s array for --demo-%s-signing-key", infoName, role))
	cmd.Flags().StringVar(&flags.RegistrationCert, "demo-"+role+"-registration-cert", "", fmt.Sprintf("File with a registration certificate (compact JWT) for --demo-%s-signing-key. It becomes the only entry of %s", role, infoName))
}

// load reads the files. Without a signing key it returns nil, and the demo
// keeps the identity the wallet's registrar issues. infoValue wraps a
// registration certificate as the issuer_info or verifier_info array.
func (f demoIdentityFlags) load(role string, infoValue func(string) (string, error)) (*demorp.ConfiguredIdentity, error) {
	keyFlag, infoFlag, certFlag := "--demo-"+role+"-signing-key", "--demo-"+role+"-info", "--demo-"+role+"-registration-cert"
	if f.SigningKey == "" {
		if f.Info != "" || f.RegistrationCert != "" {
			return nil, fmt.Errorf("%s and %s need %s", infoFlag, certFlag, keyFlag)
		}
		return nil, nil
	}
	if f.Info != "" && f.RegistrationCert != "" {
		return nil, fmt.Errorf("use either %s or %s", infoFlag, certFlag)
	}
	bundle, err := os.ReadFile(f.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", keyFlag, err)
	}
	var info []any
	switch {
	case f.Info != "":
		data, err := os.ReadFile(f.Info)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", infoFlag, err)
		}
		if err := json.Unmarshal(data, &info); err != nil {
			return nil, fmt.Errorf("%s: the file must hold a JSON array: %w", infoFlag, err)
		}
	case f.RegistrationCert != "":
		data, err := os.ReadFile(f.RegistrationCert)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", certFlag, err)
		}
		certificate := strings.TrimSpace(string(data))
		if !format.IsJWT(certificate) {
			return nil, fmt.Errorf("%s: the file must hold a registration certificate as a compact JWT", certFlag)
		}
		value, err := infoValue(certificate)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", certFlag, err)
		}
		if err := json.Unmarshal([]byte(value), &info); err != nil {
			return nil, fmt.Errorf("%s: %w", certFlag, err)
		}
	}
	identity, err := demorp.ParseConfiguredIdentity(string(bundle), info)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", keyFlag, err)
	}
	return identity, nil
}
