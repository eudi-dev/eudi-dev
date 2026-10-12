# eudi-dev documentation

Guides for using eudi-dev as a wallet, issuer, verifier and CA.

## First steps

- [What's new in 3.0.0](whats-new-3.0.md): the highlights of 3.0.0
- [Upgrading from 2.x](upgrading.md): changes that can break a 2.x setup
- [Examples](examples.md): end-to-end recipes that issue, present, and validate credentials

## Wallet

- [Wallet](wallet.md): overview, subcommands, quick start, storage, and credential type inheritance
- [Wallet server](wallet/serve.md): `wallet serve`, endpoints, trusted lists and `trust`, certificate export, and every serve flag
- [Presentation from the wallet](wallet/presenting.md): `wallet accept`, `wallet scan`, invoking by URL, HAIP enforcement
- [Issuance into the wallet](wallet/issuing.md): sign-in, deferred issuance, renewing, VCI feature level, wallet attestation, interactive authorization
- [Wallet HTTP API](wallet/http-api.md): the full REST API and remote control
- [Registrar](wallet/registrar.md): register verifiers and issuers, issue their certificates, keep a catalogue of attestations, and see what the wallet checks
- [Registrar API walkthrough](wallet/registrar-api.md): register a verifier and an issuer with curl and use their certificates against the wallet
- [UI automation](ui-automation.md): drive the wallet UI, the demo issuer and the demo verifier from Playwright or Selenium

## Issuance

- [Issue](issue.md): the `issue` command, flags, and round-trip examples
- [Credential templates](templates.md): named claim sets, card appearance (display), and the `templates` commands

## Presentation and validation

- [Validate](validate.md): verify a presentation or a credential from the CLI
- [Decode](decode.md): inspect credentials, requests, offers and trusted lists
- [Decoder](decoder.md): the web UI for decoding and validating credentials
- [DCQL](dcql.md): generate a DCQL query from a credential

## Deployment

- [Docker](docker.md): run the wallet, issuer, and verifier in containers
- [Helm chart](https://github.com/dominikschlosser/eudi-dev-helm): deploy the wallet on Kubernetes
- [Public demo hosting](public-demo.md): the hardened `--demo` profile for an internet-facing instance
- [Reverse proxy setup](reverse-proxy.md): serve the wallet on its own host or under a path prefix, with Istio and nginx examples
- [Debug proxy](proxy.md): record and decode OID4VP/OID4VCI traffic

## Conformance

- [Conformance](conformance.md): testing against the OpenID Foundation test suites
- [Conformance run](conformance-run.md): the harness that drives a wallet conformance run
- [Demo issuer and verifier conformance run](conformance-run-demorp.md): the harness that tests the demo issuer and verifier
- [Conformance results](conformance-results.md): the recorded suite results
- [Spec compliance](spec-compliance.md): the per-feature compliance matrix
- [Test certificates](test-certificates.md): EUDI specification versions, signing roles, certificate retrieval and test limits

## Reference

- [Diagrams](diagrams/README.md): interaction diagrams for the implemented OID4VP and OID4VCI flows
- [Architecture decision records](adr/): the decisions behind the design
- [Agent notes](agents/): domain, issue-tracker, and review conventions
