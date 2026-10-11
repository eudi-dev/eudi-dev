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
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
)

func registrarCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registrar",
		Short: "Register relying parties and issue their certificates",
		Long: `The wallet's registrar registers relying parties (TS05 v1.5) and issues their
access certificates (ETSI TS 119 411-8) and registration certificates (ETSI TS
119 475). The content of both certificates comes from the registration.

A verifier registers intended uses and gets a registration certificate for each.
An issuer registers as an attestation provider and lists its attestation types.
It gets one registration certificate for its service.`,
	}
	cmd.AddCommand(partiesCmd("verifiers"), partiesCmd("issuers"), accessCertCmd(), registrationCertCmd(), registrarStatusCmd(true), registrarStatusCmd(false))
	return cmd
}

// partyFlags hold the registration fields that verifiers and issuers share.
type partyFlags struct {
	rp                                registrar.WalletRelyingParty
	identifier, legalName, supportURI string
	serviceID                         string
}

func (f *partyFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.rp.TradeName, "name", "", "Trade name (required)")
	cmd.Flags().StringVar(&f.identifier, "identifier", "", "Identifier: an EUID, or the organizationIdentifier of a certificate such as LEIXG-529900T8BM49AURSDO55 (default: an assigned EUID)")
	cmd.Flags().StringVar(&f.legalName, "legal-name", "", "Legal name (default --name)")
	cmd.Flags().StringVar(&f.rp.Country, "country", "", "Country code (default the identifier's country)")
	cmd.Flags().StringVar(&f.supportURI, "support-uri", "", "Support contact: a web address or an email address (default a placeholder page on the wallet)")
	cmd.Flags().StringVar(&f.serviceID, "service-id", "", "Service identifier (the organizational unit in access certificates)")
}

// check requires --name for a new registration. --to adds to an existing
// registration, so the party flags don't apply then.
func (f *partyFlags) check(cmd *cobra.Command, to string) error {
	if to == "" {
		if f.rp.TradeName == "" {
			return fmt.Errorf(`required flag(s) "name" not set`)
		}
		return nil
	}
	for _, name := range []string{"name", "identifier", "legal-name", "country", "support-uri", "service-id"} {
		if cmd.Flags().Changed(name) {
			return fmt.Errorf("--to adds to an existing registration, so it takes no --%s", name)
		}
	}
	return nil
}

// registeredParty finds a registration by its identifier.
func registeredParty(svc walletService, identifier string) (registrar.WalletRelyingParty, error) {
	records, err := svc.RegistrarRecords()
	if err != nil {
		return registrar.WalletRelyingParty{}, err
	}
	for _, rp := range records {
		if registrar.HasIdentifier(rp, identifier) {
			return rp, nil
		}
	}
	return registrar.WalletRelyingParty{}, fmt.Errorf("relying party %s is not registered", identifier)
}

// extensionResult is the --json document of add --to.
type extensionResult struct {
	RelyingParty registrar.WalletRelyingParty             `json:"relyingParty"`
	IntendedUse  string                                   `json:"intendedUse,omitempty"`
	Registration *registrar.RegistrationCertificateResult `json:"registration"`
}

func (f *partyFlags) register(service registrar.WalletRelyingPartyService) (registrar.WalletRelyingParty, error) {
	rp := f.rp
	if f.identifier != "" {
		rp.Identifier = []registrar.Identifier{{Identifier: f.identifier}}
	}
	if f.legalName != "" {
		rp.LegalPerson.LegalName = []string{f.legalName}
	}
	service.ServiceIdentifier = f.serviceID
	service.SupportURI = f.supportURI
	rp.Services = []registrar.WalletRelyingPartyService{service}
	svc, err := managedWallet()
	if err != nil {
		return registrar.WalletRelyingParty{}, err
	}
	return svc.RegisterRelyingParty(rp)
}

func partiesCmd(role string) *cobra.Command {
	isIssuer := role == "issuers"
	short, add := "List, add and remove registered verifiers", verifiersAddCmd()
	if isIssuer {
		short, add = "List, add and remove registered issuers", issuersAddCmd()
	}
	cmd := &cobra.Command{
		Use:   role,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			records, err := svc.RegistrarRecords()
			if err != nil {
				return err
			}
			parties := slices.DeleteFunc(records, func(rp registrar.WalletRelyingParty) bool { return !hasRole(rp, role) })
			printResult(parties, func() {
				tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				if isIssuer {
					fmt.Fprintln(tw, "IDENTIFIER\tNAME\tATTESTATIONS")
				} else {
					fmt.Fprintln(tw, "IDENTIFIER\tNAME\tINTENDED USES")
				}
				for _, rp := range parties {
					var items []string
					for _, service := range rp.Services {
						if isIssuer {
							for _, a := range service.ProvidesAttestations {
								items = append(items, a.Format+":"+a.Type)
							}
							continue
						}
						for _, use := range service.IntendedUses {
							items = append(items, use.IntendedUseIdentifier)
						}
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\n", rp.Identifier[0].Identifier, rp.TradeName, strings.Join(items, " "))
				}
				_ = tw.Flush()
			})
			return nil
		},
	}
	cmd.AddCommand(add, partyRemoveCmd(role), listSubcommand(cmd, "List the registered "+role))
	return cmd
}

// hasRole reports whether a registration is one of the verifiers or issuers.
// A service provider counts as a verifier even before it has intended uses.
func hasRole(rp registrar.WalletRelyingParty, role string) bool {
	return slices.ContainsFunc(rp.Services, func(s registrar.WalletRelyingPartyService) bool {
		if role == "issuers" {
			return len(s.ProvidesAttestations) > 0
		}
		return len(s.IntendedUses) > 0 || slices.Contains(s.Entitlements, registrar.ServiceProviderEntitlement)
	})
}

// listSubcommand runs the parent's listing as "list", like wallet list and
// templates list.
func listSubcommand(parent *cobra.Command, short string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: short,
		Args:  cobra.NoArgs,
		RunE:  parent.RunE,
	}
}

func partyRemoveCmd(role string) *cobra.Command {
	singular := strings.TrimSuffix(role, "s")
	return &cobra.Command{
		Use:     "rm <identifier>",
		Aliases: []string{"remove", "delete"},
		Short:   "Remove a registered " + singular + " and revoke its registration certificates",
		Long: "Removes the registration of " + article(singular) + " " + singular + ` and revokes all its registration
certificates. A relying party that is a verifier and an issuer is removed in
both roles.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			records, err := svc.RegistrarRecords()
			if err != nil {
				return err
			}
			i := slices.IndexFunc(records, func(rp registrar.WalletRelyingParty) bool {
				return registrar.HasIdentifier(rp, args[0])
			})
			if i < 0 || !hasRole(records[i], role) {
				return fmt.Errorf("%s is not a registered %s", args[0], singular)
			}
			if err := svc.DeleteRelyingParty(args[0]); err != nil {
				return err
			}
			printResult(map[string]string{"removed": args[0]}, func() {
				fmt.Printf("Removed %s\n", args[0])
			})
			return nil
		},
	}
}

func verifiersAddCmd() *cobra.Command {
	var party partyFlags
	var purpose, privacy, dcqlIn, to string
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Register a verifier with an intended use",
		Long: `Registers a verifier with the wallet's registrar. The registrar assigns an
identifier when --identifier is empty.

The intended use lists the credentials and claims of a DCQL query. Requests
with that query then pass the over-asking check of --arf (ARF RPRC_21).
Run registration-cert to get its registration certificate.

--to adds the intended use to a registered relying party instead, such as an
issuer that asks for a PID before it issues. It stays one registration with
both roles. The command issues the verifier registration certificate and
prints its verifier_info. The service gets the Service_Provider entitlement,
so the registrar revokes the issuer registration certificate of the service.
Run registration-cert --provider for a new one.`,
		Example: `  eudi registrar verifiers add --name "Example Shop" --purpose "Age check" --dcql query.json
  eudi registrar verifiers add --to NLTEST.1A2B3C4D5E6F7A8B --purpose "Identity check before issuance" --dcql pid.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := party.check(cmd, to); err != nil {
				return err
			}
			use, err := intendedUseFromFlags(purpose, privacy, dcqlIn)
			if err != nil {
				return err
			}
			if to != "" {
				return addIntendedUse(cmd, to, use)
			}
			stored, err := party.register(registrar.WalletRelyingPartyService{IntendedUses: []registrar.IntendedUse{use}})
			if err != nil {
				return err
			}
			printResult(stored, func() {
				fmt.Printf("Registered %s as %s\n", stored.TradeName, stored.Identifier[0].Identifier)
				for _, use := range stored.Services[0].IntendedUses {
					fmt.Printf("Intended use: %s\n", use.IntendedUseIdentifier)
				}
			})
			return nil
		},
	}
	party.add(cmd)
	cmd.Flags().StringVar(&purpose, "purpose", "", "Purpose of the intended use (shown in the consent dialog, required)")
	cmd.Flags().StringVar(&dcqlIn, "dcql", "", "DCQL query with the credentials and claims to register (file, JSON or '-' for stdin, required)")
	cmd.Flags().StringVar(&privacy, "privacy-policy", "", "Privacy policy URL of the intended use (default a placeholder page on the wallet)")
	cmd.Flags().StringVar(&to, "to", "", "Identifier of a registered relying party to add the intended use to")
	_ = cmd.MarkFlagRequired("purpose")
	_ = cmd.MarkFlagRequired("dcql")
	_ = cmd.MarkFlagFilename("dcql", "json")
	return cmd
}

func issuersAddCmd() *cobra.Command {
	var party partyFlags
	var to string
	var categories []string
	var attestations []string
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Register an issuer and its attestation types",
		Long: `Registers an issuer as an attestation provider with the wallet's registrar. The
registrar assigns an identifier when --identifier is empty.

Each --attestation adds one attestation type (ARF RPRC_15). The registrar
gives the issuer the entitlement of each type's category in the catalogue
(ETSI TS 119 475 Annex A.2). --category sets the entitlements instead. Run
registration-cert to get the registration certificate. It comes inside an
issuer_info value for your issuer metadata.

--to adds the attestation types to a registered relying party instead. A
verifier issues as well and stays one registration with both roles. Its
service gets a provider entitlement, so the registrar revokes the verifier
registration certificates of the service. An issuer lists the new types next to
its others. The command issues the new issuer registration certificate, which
revokes the current one, and prints its issuer_info.`,
		Example: `  eudi registrar issuers add --name "Example University" --attestation dc+sd-jwt:urn:example:diploma:1
  eudi registrar issuers add --name "Example PID Provider" --attestation dc+sd-jwt:urn:eudi:pid:1 --attestation mso_mdoc:eu.europa.ec.eudi.pid.1
  eudi registrar issuers add --name "Example Bank" --category qeaa --attestation dc+sd-jwt:urn:example:account:1
  eudi registrar issuers add --to NLTEST.1A2B3C4D5E6F7A8B --attestation dc+sd-jwt:urn:example:ticket:1`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := party.check(cmd, to); err != nil {
				return err
			}
			var entitlements []string
			for _, category := range categories {
				if err := credtemplate.CheckCategory(category); err != nil || category == "" {
					return fmt.Errorf("--category takes %s, not %q", strings.Join(credtemplate.Categories, ", "), category)
				}
				entitlements = append(entitlements, registrar.CategoryOf(category).Entitlement)
			}
			provided, err := providedAttestations(attestations)
			if err != nil {
				return err
			}
			if to != "" {
				return addProvidedAttestations(cmd, to, entitlements, provided)
			}
			stored, err := party.register(registrar.WalletRelyingPartyService{Entitlements: entitlements, ProvidesAttestations: provided})
			if err != nil {
				return err
			}
			printResult(stored, func() {
				fmt.Printf("Registered %s as %s\n", stored.TradeName, stored.Identifier[0].Identifier)
				for _, attestation := range stored.Services[0].ProvidesAttestations {
					fmt.Printf("Attestation: %s %s\n", attestation.Format, attestation.Type)
				}
			})
			return nil
		},
	}
	party.add(cmd)
	cmd.Flags().StringArrayVar(&categories, "category", nil, "Credential category whose provider entitlement the issuer gets: pid, qeaa, pub-eaa or eaa (repeatable, default the categories of the attestation types in the catalogue)")
	cmd.Flags().StringArrayVar(&attestations, "attestation", nil, "Attestation type as format:type, such as dc+sd-jwt:urn:eudi:pid:1 or mso_mdoc:eu.europa.ec.eudi.pid.1 (repeatable, required)")
	cmd.Flags().StringVar(&to, "to", "", "Identifier of a registered relying party to add the attestation types to")
	_ = cmd.RegisterFlagCompletionFunc("category", staticCompletion(credtemplate.Categories...))
	_ = cmd.MarkFlagRequired("attestation")
	return cmd
}

// addIntendedUse adds an intended use to a registration and issues its
// verifier registration certificate.
func addIntendedUse(cmd *cobra.Command, identifier string, use registrar.IntendedUse) error {
	svc, err := managedWallet()
	if err != nil {
		return err
	}
	before, err := registeredParty(svc, identifier)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, service := range before.Services {
		for _, existing := range service.IntendedUses {
			known[existing.IntendedUseIdentifier] = true
		}
	}
	changed := cloneParty(before)
	changed.Services[0].IntendedUses = append(changed.Services[0].IntendedUses, use)
	enrolled, err := svc.Enrol(registrar.Enrolment{
		RelyingParty: changed,
		Registration: &registrar.EnrolmentRegistration{ServiceIdentifier: changed.Services[0].ServiceIdentifier},
	}, true)
	if err != nil {
		return err
	}
	stored, result := enrolled.RelyingParty, enrolled.Registration
	var added string
	for _, u := range stored.Services[0].IntendedUses {
		if !known[u.IntendedUseIdentifier] {
			added = u.IntendedUseIdentifier
		}
	}
	printResult(extensionResult{RelyingParty: stored, IntendedUse: added, Registration: result}, func() {
		fmt.Fprintf(cmd.ErrOrStderr(), "Added intended use %s to %s (%s)\n", added, stored.TradeName, identifier)
		fmt.Fprintln(cmd.OutOrStdout(), result.VerifierInfo)
	})
	return nil
}

// addProvidedAttestations makes a registered verifier an issuer as well and
// issues its issuer registration certificate.
func addProvidedAttestations(cmd *cobra.Command, identifier string, entitlements []string, provided []registrar.ProvidedAttestation) error {
	svc, err := managedWallet()
	if err != nil {
		return err
	}
	before, err := registeredParty(svc, identifier)
	if err != nil {
		return err
	}
	changed := cloneParty(before)
	// An issuer adds the types to the service it issues with already.
	i := max(0, slices.IndexFunc(changed.Services, func(s registrar.WalletRelyingPartyService) bool { return len(s.ProvidesAttestations) > 0 }))
	service := &changed.Services[i]
	added := 0
	for _, a := range provided {
		if !slices.Contains(service.ProvidesAttestations, a) {
			service.ProvidesAttestations = append(service.ProvidesAttestations, a)
			added++
		}
	}
	if added == 0 {
		return fmt.Errorf("%s already lists these attestation types", identifier)
	}
	// Without provider entitlements the registrar derives them from the
	// categories of all types, so the new types get matching entitlements.
	service.Entitlements = append(slices.DeleteFunc(service.Entitlements, isProviderEntitlement), entitlements...)
	enrolled, err := svc.Enrol(registrar.Enrolment{
		RelyingParty: changed,
		Registration: &registrar.EnrolmentRegistration{Provider: true, ServiceIdentifier: service.ServiceIdentifier},
	}, true)
	if err != nil {
		return err
	}
	stored, result := enrolled.RelyingParty, enrolled.Registration
	printResult(extensionResult{RelyingParty: stored, Registration: result}, func() {
		fmt.Fprintf(cmd.ErrOrStderr(), "Added the attestation types to %s (%s)\n", stored.TradeName, identifier)
		fmt.Fprintln(cmd.OutOrStdout(), result.IssuerInfo)
	})
	return nil
}

// isProviderEntitlement reports whether an entitlement is the provider
// entitlement of a credential category.
func isProviderEntitlement(entitlement string) bool {
	for _, category := range credtemplate.Categories {
		if category != "" && registrar.CategoryOf(category).Entitlement == entitlement {
			return true
		}
	}
	return false
}

// cloneParty copies a registration so a change leaves the original intact, and
// makes sure it has a service to change.
func cloneParty(rp registrar.WalletRelyingParty) registrar.WalletRelyingParty {
	var clone registrar.WalletRelyingParty
	raw, _ := json.Marshal(rp)
	_ = json.Unmarshal(raw, &clone)
	if len(clone.Services) == 0 {
		clone.Services = []registrar.WalletRelyingPartyService{{}}
	}
	return clone
}

// providedAttestations parses format:type values. The type of an SD-JWT VC is
// its vct and the type of an mdoc its doctype.
func providedAttestations(values []string) ([]registrar.ProvidedAttestation, error) {
	attestations := make([]registrar.ProvidedAttestation, 0, len(values))
	for _, value := range values {
		format, typ, ok := strings.Cut(strings.TrimSpace(value), ":")
		typ = strings.TrimSpace(typ)
		if !ok || typ == "" {
			return nil, fmt.Errorf("--attestation %q is not format:type, such as dc+sd-jwt:urn:eudi:pid:1", value)
		}
		if format != "dc+sd-jwt" && format != "mso_mdoc" {
			return nil, fmt.Errorf("--attestation %q has format %q, not dc+sd-jwt or mso_mdoc", value, format)
		}
		attestations = append(attestations, registrar.ProvidedAttestation{Format: format, Type: typ})
	}
	return attestations, nil
}

func intendedUseFromFlags(purpose, privacy, dcqlInput string) (registrar.IntendedUse, error) {
	use := registrar.IntendedUse{}
	if purpose != "" {
		use.Purpose = []registrar.MultiLangString{{Lang: "en", Content: purpose}}
	}
	if privacy != "" {
		use.PrivacyPolicy = []registrar.Policy{{PolicyURI: privacy}}
	}
	if dcqlInput == "" {
		return use, fmt.Errorf("an intended use needs --dcql with the credentials and claims to register")
	}
	raw, err := format.ReadInput(dcqlInput)
	if err != nil {
		return use, fmt.Errorf("reading the DCQL query: %w", err)
	}
	var query struct {
		Credentials []registrar.RegisteredCredential `json:"credentials"`
	}
	if err := json.Unmarshal([]byte(raw), &query); err != nil {
		return use, fmt.Errorf("parsing the DCQL query: %w", err)
	}
	use.Credentials = query.Credentials
	return use, nil
}

func accessCertCmd() *cobra.Command {
	var (
		req     registrar.AccessCertificateRequest
		csrPath string
	)
	cmd := &cobra.Command{
		Use:   "access-cert",
		Short: "Issue an access certificate for a CSR of a registered relying party",
		Long: `Signs an access certificate (ETSI TS 119 411-8) for the key of a certificate
signing request. The relying party keeps its private key. The public key comes
from the CSR and the subject from the registration, so the CSR subject can stay
empty.

It prints the PEM certificate. The client identifiers for it (x509_hash, and
x509_san_dns for every --dns name) go to stderr, or into the JSON output
with --json.`,
		Example: `  openssl ecparam -name prime256v1 -genkey -noout -out verifier.key
  openssl req -new -key verifier.key -subj "/" -out verifier.csr
  eudi registrar access-cert --identifier NLTEST.1A2B3C4D5E6F7A8B --csr verifier.csr > verifier.pem`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pemData, err := format.ReadInput(csrPath)
			if err != nil {
				return fmt.Errorf("reading the CSR: %w", err)
			}
			req.CSR = pemData
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			result, err := svc.AccessCertificate(req)
			if err != nil {
				return err
			}
			printResult(result, func() {
				for _, clientID := range result.ClientIDs {
					fmt.Fprintf(os.Stderr, "client_id: %s\n", clientID)
				}
				_, _ = fmt.Fprint(cmd.OutOrStdout(), result.Certificate)
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&req.Identifier, "identifier", "", "Identifier of the registered relying party (required)")
	cmd.Flags().StringVar(&req.ServiceIdentifier, "service-id", "", "Service the certificate is for (default the only service)")
	cmd.Flags().StringVar(&csrPath, "csr", "", "PEM certificate signing request (file or '-' for stdin, required)")
	cmd.Flags().StringSliceVar(&req.DNSNames, "dns", nil, "DNS name for the x509_san_dns client identifier (repeatable)")
	cmd.Flags().StringVar(&req.Validity, "validity", "", "Validity as a Go duration, at most 8760h (default 8760h)")
	_ = cmd.MarkFlagRequired("identifier")
	_ = cmd.MarkFlagRequired("csr")
	_ = cmd.MarkFlagFilename("csr", "csr", "pem")
	return cmd
}

func registrationCertCmd() *cobra.Command {
	var req registrar.RegistrationCertificateRequest
	var provider, renew, jwt bool
	cmd := &cobra.Command{
		Use:   "registration-cert",
		Short: "Print the registration certificate of an intended use or an issuer service",
		Long: `Prints the current registration certificate (ETSI TS 119 475, typ rc-wrp+jwt).
If there is none, or it has expired, the registrar issues one. --new issues a
new certificate and revokes the current one.

For a verifier it certifies an intended use and prints the certificate inside a
verifier_info value (OpenID4VP 1.0 §5.1). A verifier puts that value in its
requests, and the wallet shows the registered purpose. With --arf the wallet
also checks that a request asks only for registered credentials and claims
(ARF RPRC_21).

For an issuer it certifies the attestation provider service with the attestation
types (ARF RPRC_13) and prints an issuer_info value (ETSI TS 119 472-3
§4.2.3). An issuer puts that value in its Credential Issuer Metadata. With --arf
the wallet checks the value before requesting a credential.

Without --intended-use it uses the relying party's only intended use, or its
only provider service. --provider selects the provider service of
--service-id. --jwt prints the bare registration certificate instead, and
--json prints both.`,
		Example: `  eudi registrar registration-cert --identifier NLTEST.1A2B3C4D5E6F7A8B
  eudi registrar registration-cert --identifier NLTEST.1A2B3C4D5E6F7A8B --jwt | eudi decode
  eudi registrar registration-cert --identifier NLTEST.1A2B3C4D5E6F7A8B --intended-use 3f2a9c1e7b6d4a50 --json
  eudi registrar registration-cert --identifier NLTEST.1A2B3C4D5E6F7A8B --service-id diplomas --provider --new`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if provider && req.IntendedUseIdentifier != "" {
				return fmt.Errorf("--provider selects a service, so it takes no --intended-use")
			}
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			if req.IntendedUseIdentifier == "" && !provider {
				if req.IntendedUseIdentifier, err = onlyCertificateTarget(svc, req.Identifier, req.ServiceIdentifier); err != nil {
					return err
				}
			}
			var result *registrar.RegistrationCertificateResult
			if !renew {
				if result, err = currentRegistrationCertificate(cmd, svc, req); err != nil {
					return err
				}
				if result != nil && req.Validity != "" {
					return fmt.Errorf("--validity applies to a new certificate, so add --new")
				}
			}
			if result == nil {
				if result, err = svc.RegistrationCertificate(req); err != nil {
					return err
				}
			}
			printResult(result, func() {
				switch {
				case jwt:
					fmt.Fprintln(cmd.OutOrStdout(), result.RegistrationCertificate)
				case result.IssuerInfo != "":
					fmt.Fprintln(cmd.OutOrStdout(), result.IssuerInfo)
				default:
					fmt.Fprintln(cmd.OutOrStdout(), result.VerifierInfo)
				}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&req.Identifier, "identifier", "", "Identifier of the registered relying party (required)")
	cmd.Flags().StringVar(&req.ServiceIdentifier, "service-id", "", "Service of the intended use, or the issuer service (default any service)")
	cmd.Flags().StringVar(&req.IntendedUseIdentifier, "intended-use", "", "Intended use of the certificate (default the only one)")
	cmd.Flags().BoolVar(&provider, "provider", false, "Use the attestation provider service instead of an intended use")
	cmd.Flags().BoolVar(&renew, "new", false, "Issue a new certificate and revoke the current one")
	cmd.Flags().BoolVar(&jwt, "jwt", false, "Print the bare registration certificate instead of verifier_info or issuer_info")
	cmd.Flags().StringVar(&req.Validity, "validity", "", "Validity of a new certificate as a Go duration, at most 8760h (default 4320h)")
	_ = cmd.MarkFlagRequired("identifier")
	return cmd
}

// currentRegistrationCertificate returns the stored certificate of an intended
// use or, without one, of the provider service. It returns nil when there is
// no valid one.
func currentRegistrationCertificate(cmd *cobra.Command, svc walletService, req registrar.RegistrationCertificateRequest) (*registrar.RegistrationCertificateResult, error) {
	views, err := svc.RegistrationCertificateViews(req.Identifier)
	if err != nil {
		return nil, err
	}
	var found *registrar.RegistrationStatusView
	for i, v := range views {
		matches := v.IntendedUse == req.IntendedUseIdentifier
		if req.IntendedUseIdentifier == "" {
			matches = v.IntendedUse == "" && (req.ServiceIdentifier == "" || v.Service == req.ServiceIdentifier)
		}
		if matches && !v.Superseded && v.Certificate != "" && v.Expires > time.Now().Unix() {
			found = &views[i]
		}
	}
	if found == nil {
		return nil, nil
	}
	if found.Revoked {
		fmt.Fprintln(cmd.ErrOrStderr(), "The certificate is revoked. Run activate to make it valid again, or --new for a new one.")
	}
	return &registrar.RegistrationCertificateResult{RegistrationCertificate: found.Certificate, VerifierInfo: found.VerifierInfo, IssuerInfo: found.IssuerInfo}, nil
}

// onlyCertificateTarget returns the only intended use of the relying party, or
// an empty string when its only certificate target is a provider service.
func onlyCertificateTarget(svc walletService, identifier, serviceIdentifier string) (string, error) {
	records, err := svc.RegistrarRecords()
	if err != nil {
		return "", err
	}
	i := slices.IndexFunc(records, func(rp registrar.WalletRelyingParty) bool {
		return registrar.HasIdentifier(rp, identifier)
	})
	if i < 0 {
		return "", fmt.Errorf("relying party %s is not registered", identifier)
	}
	var uses, providers []string
	for _, service := range records[i].Services {
		if serviceIdentifier != "" && service.ServiceIdentifier != serviceIdentifier {
			continue
		}
		for _, use := range service.IntendedUses {
			uses = append(uses, use.IntendedUseIdentifier)
		}
		if len(service.ProvidesAttestations) > 0 {
			name := service.ServiceIdentifier
			if name == "" {
				name = "(no service identifier)"
			}
			providers = append(providers, name)
		}
	}
	switch {
	case len(uses) == 1 && len(providers) == 0:
		return uses[0], nil
	case len(uses) == 0 && len(providers) == 1:
		return "", nil
	case len(providers) == 0:
		return "", fmt.Errorf("relying party %s has %d intended uses, so pass --intended-use (%s)", identifier, len(uses), strings.Join(uses, ", "))
	default:
		return "", fmt.Errorf("relying party %s has intended uses (%s) and provider services (%s), so pass --intended-use, or --service-id with --provider", identifier, strings.Join(uses, ", "), strings.Join(providers, ", "))
	}
}

// registrarStatusCmd revokes or activates registration certificates.
func registrarStatusCmd(revoke bool) *cobra.Command {
	var identifier string
	var scope registrar.RegistrationScope
	use, verb, done := "activate", "Activate", "Activated"
	if revoke {
		use, verb, done = "revoke", "Revoke", "Revoked"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: verb + " the registration certificates of a relying party",
		Long: verb + ` the registration certificates issued for an intended use with
--intended-use, for a service with --service-id, or for the whole relying party.
A service's certificates are its provider certificate and those of its intended
uses. The change shows in the registrar's status list, and the registration
itself is kept.

Certificates revoked by the registrar itself stay revoked. That happens when a
newer certificate replaces one, or when an update changes or removes what it
certifies.`,
		Example: "  eudi registrar " + use + " --identifier NLTEST.1A2B3C4D5E6F7A8B\n  eudi registrar " + use + " --identifier NLTEST.1A2B3C4D5E6F7A8B --intended-use 3f2a9c1e7b6d4a50\n  eudi registrar " + use + " --identifier NLTEST.1A2B3C4D5E6F7A8B --service-id diplomas",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := managedWallet()
			if err != nil {
				return err
			}
			changed, err := svc.SetRegistrationCertificatesRevoked(identifier, scope, revoke)
			if err != nil {
				return err
			}
			printResult(map[string]int{"changed": changed}, func() {
				fmt.Printf("%s %d registration certificate(s)\n", done, changed)
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&identifier, "identifier", "", "Identifier of the registered relying party (required)")
	cmd.Flags().StringVar(&scope.IntendedUseIdentifier, "intended-use", "", "Only change the certificates of this intended use (default all)")
	cmd.Flags().StringVar(&scope.ServiceIdentifier, "service-id", "", "Only change the certificates of this service (default all)")
	_ = cmd.MarkFlagRequired("identifier")
	return cmd
}

// article is the indefinite article of an English word.
func article(word string) string {
	if strings.ContainsRune("aeiou", rune(strings.ToLower(word + " ")[0])) {
		return "an"
	}
	return "a"
}
