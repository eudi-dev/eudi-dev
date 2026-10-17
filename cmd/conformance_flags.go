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
	"encoding/base64"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/remote"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

const (
	haipFlagUsage                = "Enforce HAIP 1.0 on presentations (x509_hash, direct_post.jwt, DCQL, signed request object, P-256 response encryption) and on credential offers (https issuer, and authorization code offers also need PAR, PKCE S256, DPoP, client auth)"
	arfFlagUsage                 = "Check the access and registration certificates of verifiers and issuers against the ARF, including over-asking and revocation. Turns on --haip too, because the ARF builds on HAIP. With --mode strict the wallet refuses the request or the offer on any finding"
	relyingPartyCAFlagUsage      = "PEM file with CA certificates for relying party access and registration certificates. The wallet puts them on its access-ca and registrar lists (repeatable)"
	trustListCAFlagUsage         = "PEM file with CA certificates of trusted list operators. With --arf the wallet also accepts trusted lists signed under these CAs (repeatable)"
	trustedListFlagUsage         = "URL of an external list of trusted entities (ETSI TS 119 602) for the wallet's list of trusted lists. With --arf its providers anchor the checks of their list type (repeatable)"
	keyAttestationLevelFlagUsage = "What the key attestation claims as key_storage and user_authentication (OpenID4VCI Appendix D.2): whatever the issuer requires (default), 'none', or one of iso_18045_high, iso_18045_moderate, iso_18045_enhanced-basic, iso_18045_basic for both. The wallet holds its keys in software and can prove none of these levels"
)

// conformanceFlags are the flags that set what a wallet checks. The wallet
// --mode belongs to them too.
type conformanceFlags struct {
	cmd *cobra.Command
	// mode replaces the wallet --mode when set, such as by the demo profile.
	mode                string
	haip                bool
	arf                 bool
	encrypted           bool
	clientAttestation   bool
	vciVersion          string
	keyAttestationLevel string
	relyingPartyCAs     []string
	trustListCAs        []string
	trustedLists        []string
}

// addConformanceFlags registers the conformance flags of wallet serve,
// accept and scan.
func addConformanceFlags(cmd *cobra.Command) *conformanceFlags {
	f := &conformanceFlags{cmd: cmd}
	flags := cmd.Flags()
	flags.BoolVar(&f.haip, "haip", false, haipFlagUsage)
	flags.BoolVar(&f.arf, "arf", false, arfFlagUsage)
	flags.StringArrayVar(&f.relyingPartyCAs, "relying-party-ca", nil, relyingPartyCAFlagUsage)
	flags.StringArrayVar(&f.trustListCAs, "trusted-list-ca", nil, trustListCAFlagUsage)
	flags.StringArrayVar(&f.trustedLists, "trusted-list", nil, trustedListFlagUsage)
	flags.StringVar(&f.keyAttestationLevel, "key-attestation-level", "", keyAttestationLevelFlagUsage)
	flags.BoolVar(&f.encrypted, "require-encrypted-request", false, "Reject request objects that are not encrypted. The wallet always sends an encryption key in wallet_metadata, so this only requires the verifier to use it")
	flags.BoolVar(&f.clientAttestation, "client-attestation", false, "Send the wallet attestation on OID4VCI token requests even when the issuer does not advertise attest_jwt_client_auth (advertising it is only a SHOULD)")
	flags.StringVar(&f.vciVersion, "vci-version", string(wallet.VCIVersion10), "OpenID4VCI feature level the wallet uses as a client: '1.0' (the published version, the default) or '1.1' (also uses what the 1.1 draft adds, where an issuer offers it)")
	return f
}

// changed lists the conformance flags set on the command line.
func (f *conformanceFlags) changed() []string {
	var set []string
	if walletFlags.Changed("mode") {
		set = append(set, "--mode")
	}
	f.cmd.Flags().Visit(func(flag *pflag.Flag) {
		if slices.Contains(conformanceFlagNames, flag.Name) {
			set = append(set, "--"+flag.Name)
		}
	})
	return set
}

var conformanceFlagNames = []string{"haip", "arf", "relying-party-ca", "trusted-list-ca", "trusted-list", "key-attestation-level", "require-encrypted-request", "client-attestation", "vci-version"}

// walletConformance holds the values of the conformance flags: settings for
// every flow and trust inputs for the ARF checks.
type walletConformance struct {
	settings wallet.ConformanceSettings
	trust    trustedlists.Settings
}

func (f *conformanceFlags) resolve() (walletConformance, error) {
	rawMode := walletValidationMode
	if f.mode != "" {
		rawMode = f.mode
	}
	mode, err := wallet.ParseValidationMode(rawMode)
	if err != nil {
		return walletConformance{}, err
	}
	vciVersion, err := wallet.ParseVCIVersion(f.vciVersion)
	if err != nil {
		return walletConformance{}, fmt.Errorf("--vci-version: %w", err)
	}
	level, err := wallet.ParseKeyAttestationLevel(f.keyAttestationLevel)
	if err != nil {
		return walletConformance{}, fmt.Errorf("--key-attestation-level: %w", err)
	}
	for _, list := range f.trustedLists {
		if !format.IsWebURL(list) {
			return walletConformance{}, fmt.Errorf("--trusted-list %q is not an http or https URL", list)
		}
	}
	c := walletConformance{
		settings: wallet.ConformanceSettings{
			ValidationMode:          mode,
			RequireHAIP:             f.haip || f.arf && !f.cmd.Flags().Changed("haip"),
			RequireARF:              f.arf,
			RequireEncryptedRequest: f.encrypted,
			VCIVersion:              vciVersion,
			KeyAttestationLevel:     level,
			ForceClientAttestation:  f.clientAttestation,
		},
		trust: trustedlists.Settings{ConfiguredLists: f.trustedLists},
	}
	if c.trust.RelyingPartyCAPEM, err = loadPEMCertificates("relying-party-ca", f.relyingPartyCAs); err != nil {
		return walletConformance{}, err
	}
	if c.trust.ListCAPEM, err = loadPEMCertificates("trusted-list-ca", f.trustListCAs); err != nil {
		return walletConformance{}, err
	}
	return c, nil
}

func (c walletConformance) apply(w *wallet.Wallet) {
	w.SetConformance(c.settings)
	w.TrustSettings = c.trust
}

// checkRemoteSettings refuses the flags that would change a running wallet.
// A flag with the wallet's own value changes nothing.
func checkRemoteSettings(c *remote.Client, set []string, want walletConformance) error {
	outbound := changedOutboundFlags()
	if len(set) == 0 && len(outbound) == 0 {
		return nil
	}
	var cfg wallet.ConformanceDocument
	if err := c.Conformance(&cfg); err != nil {
		return fmt.Errorf("reading the running wallet's settings: %w", err)
	}
	var summary trustedlists.Summary
	if slices.ContainsFunc(set, func(flag string) bool {
		return flag == "--relying-party-ca" || flag == "--trusted-list-ca" || flag == "--trusted-list"
	}) {
		if err := c.TrustState(&summary); err != nil {
			return fmt.Errorf("reading the running wallet's trusted lists: %w", err)
		}
	}
	var differ []string
	for _, flag := range append(set, outbound...) {
		if difference := settingDifference(flag, want, cfg, summary); difference != "" {
			differ = append(differ, difference)
		}
	}
	if len(differ) == 0 {
		return nil
	}
	return fmt.Errorf("%s. A running wallet applies its settings to every step of a flow, so a command can't change them. Change them on 'wallet serve' or through PUT /api/config/conformance, and add CAs and lists with '%s trust'",
		strings.Join(differ, ", "), binaryName())
}

// settingDifference describes how the running wallet differs from flag. It
// is empty when the wallet already has the flag's value.
func settingDifference(flag string, want walletConformance, cfg wallet.ConformanceDocument, summary trustedlists.Summary) string {
	s := want.settings
	onOff := func(have, wanted bool) string {
		switch {
		case have == wanted:
			return ""
		case have:
			return flag + " is set on the running wallet"
		default:
			return flag + " is off on the running wallet"
		}
	}
	value := func(have, wanted string) string {
		if have == wanted {
			return ""
		}
		if have == "" {
			have = "unset"
		}
		return fmt.Sprintf("%s is %s on the running wallet", flag, have)
	}
	switch flag {
	case "--mode":
		return value(string(cfg.ValidationMode), string(s.ValidationMode))
	case "--haip":
		return onOff(cfg.RequireHAIP, s.RequireHAIP)
	case "--arf":
		return onOff(cfg.RequireARF, s.RequireARF)
	case "--require-encrypted-request":
		return onOff(cfg.RequireEncryptedRequest, s.RequireEncryptedRequest)
	case "--client-attestation":
		return onOff(cfg.ForceClientAttestation, s.ForceClientAttestation)
	case "--vci-version":
		return value(string(cfg.VCIVersion), string(s.VCIVersion))
	case "--key-attestation-level":
		return value(cfg.KeyAttestationLevel, s.KeyAttestationLevel)
	case "--tls-verify":
		return onOff(cfg.TLSVerification, walletTLSVerify)
	case "--relying-party-ca":
		trusted := slices.Clone(summary.RelyingPartyCAs)
		for _, entity := range summary.Entities {
			trusted = append(trusted, entity.Certificates...)
		}
		if missing := certificatesMissing(want.trust.RelyingPartyCAPEM, trusted); missing > 0 {
			return fmt.Sprintf("%s names %d CA certificates the running wallet does not trust", flag, missing)
		}
	case "--trusted-list-ca":
		if missing := certificatesMissing(want.trust.ListCAPEM, summary.TrustedListCAs); missing > 0 {
			return fmt.Sprintf("%s names %d CA certificates the running wallet does not trust", flag, missing)
		}
	case "--trusted-list":
		for _, url := range want.trust.ConfiguredLists {
			if !slices.ContainsFunc(summary.Lists, func(l trustedlists.Link) bool { return l.URL == url }) {
				return fmt.Sprintf("%s %s is not on the running wallet's list of trusted lists", flag, url)
			}
		}
	case "--tls-ca":
		// The running wallet does not report its CA bundle or its proxy, so
		// the CLI can't tell whether these match.
		return flag + " can't change the TLS settings of the running wallet"
	default:
		return flag + " can't change the proxy settings of the running wallet"
	}
	return ""
}

// certificatesMissing counts the certificates in bundle that are missing
// from trusted. trusted holds base64 DER certificates.
func certificatesMissing(bundle []byte, trusted []string) int {
	certs, err := keys.ParseCertificatesPEM(bundle)
	if err != nil {
		return 0
	}
	missing := 0
	for _, cert := range certs {
		if !slices.Contains(trusted, base64.StdEncoding.EncodeToString(cert.Raw)) {
			missing++
		}
	}
	return missing
}

// changedOutboundFlags lists the wallet's outbound HTTP flags set on the
// command line.
func changedOutboundFlags() []string {
	var set []string
	for _, name := range []string{"tls-verify", "tls-ca", "http-proxy", "https-proxy", "no-proxy"} {
		if walletFlags.Changed(name) {
			set = append(set, "--"+name)
		}
	}
	return set
}
