# Architecture

Terms are defined in [CONTEXT.md](CONTEXT.md).

## Layout

```
main.go        Entry point
cmd/           CLI commands (Cobra), one file per command or command group
internal/      Everything else (ADR-0007)
e2e/           Playwright tests against a running wallet server
examples/      Keycloak and web-wallet integration examples
```

### Packages

| Package | Responsibility |
|---|---|
| `certchain` | Certificate chains of JOSE (x5c) and COSE (x5chain) messages and their verification against trust anchors |
| `config` | Defaults (ports, timeouts) |
| `consent` | Consent requests, the credential options of a presentation, the selection logic and the in-memory runtime of pending requests (ADR-0011) |
| `credtemplate` | Credential templates, predefined and user-supplied |
| `credtype` | The EUDI credential type identifiers and which type extends which |
| `dcql` | DCQL query parsing, evaluation, generation |
| `demorp` | Demo issuer and verifier hosted by the wallet |
| `format` | Format detection, base64url, and the outbound fetch policy (ADR-0004) |
| `httpsec` | Browser security headers and the cross-origin guard (ADR-0002) |
| `imprint` | Operator-supplied legal notice page |
| `jsonutil` | Type-safe accessors for `map[string]any` and JSON values |
| `jwe` | Compact JWE decryption (ECDH-ES, Concat KDF, AES-GCM) |
| `jws` | JWS signing (ES256) and verification (ES, RS and PS families), shared by signer and verifier (ADR-0008) |
| `keys` | PEM and JWK key loading and conversion |
| `lote` | Lists of trusted entities (ETSI TS 119 602): parsing, signing and the certificates of their services |
| `mdoc` | mdoc parsing (CBOR) and COSE_Sign1 verification |
| `mock` | Test credential generators |
| `oid4vc` | OID4VP and OID4VCI request and offer parsing |
| `oid4vp` | The wallet side of OpenID4VP 1.0: request checks (client identifier, client metadata, verifier_info, HAIP), browser API requests and response delivery |
| `output` | Terminal output formatting |
| `provider` | The wallet's provider keys and certificates: the trusted list profile of each credential category, the signing key and CA of each profile, the access and registrar CAs, and the sequenced lists they sign |
| `proxy` | Reverse proxy, traffic classifier, dashboard |
| `publicpath` | The path prefix of the base URL behind a reverse proxy (ADR-0019) |
| `qr` | QR scanning from file or screen |
| `regcert` | Checks of registration certificates (ETSI TS 119 475) and their binding to access certificates, for the verifiers and issuers the wallet talks to |
| `registrar` | Relying party registrar (TS05 v1.5): registrations, access certificates (ETSI TS 119 411-8), registration certificates (ETSI TS 119 475), their status list, and the catalogue of attestations (EC TS11) |
| `remote` | Remote wallet control (REST client, instance discovery) |
| `sdjwt` | SD-JWT parsing, disclosure resolution, verification |
| `serverlog` | Console output as JSON log records |
| `statuslist` | Token Status List encoding and decoding, in JWT and CWT form |
| `storage` | Blob storage backed by files, memory or Postgres (ADR-0016) |
| `trustedlists` | The wallet's set of trusted lists (ADR-0022, ADR-0023): its own list per credential category, the providers and lists users add, the external lists it reads and the anchors they give |
| `urlhandler` | Registration of the wallet as the operating system handler for OID4VP and OID4VCI URL schemes |
| `validate` | The credential checks shared by `validate` and the web decoder: type, validity, digests, signature, catalogue trust, revocation and HAIP |
| `validity` | Time claims against the current time, with one clock skew rule |
| `wallet` | Wallet state (persisted through `storage`), HTTP server, presentation and issuance flows, the issuer role and the ARF checks of issuers and credentials |
| `web` | Decoder and validator web UI |

## Flows

**Decode and validate.** The tool accepts a file, URL, stdin or QR scan. It detects the format and parses the input. It then displays the result or checks its signature, validity period and revocation status.

**Presentation (OID4VP).** The wallet receives an authorization request through a URI, HTTP endpoint or browser API. It fetches and decrypts a request object when needed. Parameters in the request object override the outer parameters.

The wallet checks the client identifier, signature and required parameters. Debug mode reports findings and continues. Strict mode stops on findings. `--haip` adds the profile checks. DCQL selects the matching credentials. A credential also matches when its type extends the requested type.

After consent or automatic approval, the wallet creates an SD-JWT with a key binding JWT or an mdoc DeviceResponse. It sends the VP token to the verifier. It encrypts the token when the response mode requires it.

**Issuance (OID4VCI).** The wallet resolves a credential offer and fetches issuer and authorization server metadata. It follows the pre-authorized code flow or authorization code flow, using PAR, PKCE, DPoP and client attestation as required.

At feature level 1.1, the wallet uses the interactive flow when the issuer advertises an authorization challenge endpoint. The wallet answers with an OpenID4VP presentation or opens browser authentication through `auth_via_web`. It then exchanges the authorization code.

The wallet proves possession of its holder key, receives the credential and imports it. If the issuer defers issuance, the wallet stores the transaction ID and collects the credential later.

**Proxy.** The wallet connects to a verifier or issuer through the proxy. The proxy classifies each exchange as an OID4VP or OID4VCI step and shows it on a dashboard.

## Decisions

| ADR | Decision |
|---|---|
| [0001](docs/adr/0001-debug-by-default-validation-with-opt-in-strict-mode.md) | Debug-by-default validation with an opt-in strict mode |
| [0002](docs/adr/0002-the-wallet-http-api-is-unauthenticated.md) | The wallet HTTP API is unauthenticated |
| [0003](docs/adr/0003-keys-and-credentials-are-stored-unencrypted.md) | Keys and credentials are stored unencrypted |
| [0004](docs/adr/0004-outbound-fetches-are-policed-at-dial-time.md) | Outbound fetches are policed at dial time |
| [0005](docs/adr/0005-the-server-reloads-its-store-on-every-request.md) | The server reloads its store on every request |
| [0006](docs/adr/0006-one-binary-plays-wallet-issuer-verifier-and-ca.md) | One binary plays wallet, issuer, verifier and CA |
| [0007](docs/adr/0007-everything-lives-under-internal.md) | Everything lives under `internal/` |
| [0008](docs/adr/0008-jws-verification-uses-go-jose-jwe-stays-hand-written.md) | JWS verification uses go-jose, JWE stays hand-written |
| [0009](docs/adr/0009-signatures-are-verified-but-not-anchored-to-a-pre-registered-trust-list.md) | Signature checks have no configured trust anchors |
| [0010](docs/adr/0010-spec-conformance-is-checked-before-and-after-every-change.md) | Spec conformance is checked before and after every change |
| [0011](docs/adr/0011-a-flow-belongs-to-the-browser-that-started-it.md) | A flow belongs to the browser that started it |
| [0012](docs/adr/0012-every-entry-point-runs-the-same-flow.md) | Every entry point runs the same flow |
| [0013](docs/adr/0013-only-the-eudi-stack-is-supported.md) | Only what the EUDI stack references is supported |
| [0014](docs/adr/0014-pinned-draft-versions-stay-supported-alongside-the-latest.md) | Pinned draft versions stay supported alongside the latest |
| [0015](docs/adr/0015-the-web-ui-lays-out-at-phone-width.md) | The web UI lays out at phone width |
| [0016](docs/adr/0016-state-goes-through-one-storage-layer.md) | State goes through one storage layer |
| [0017](docs/adr/0017-generated-keys-can-derive-from-a-seed.md) | Generated keys can derive from a seed |
| [0018](docs/adr/0018-postgres-stores-wallet-entities-as-keyed-blobs.md) | Postgres stores wallet entities as keyed blobs |
| [0019](docs/adr/0019-the-base-url-is-the-public-identity.md) | The base URL is the public identity |
| [0020](docs/adr/0020-cli-output-can-be-automated.md) | CLI output can be automated |
| [0021](docs/adr/0021-arf-checks-are-a-separate-profile.md) | ARF checks are a separate profile |
| [0022](docs/adr/0022-one-trusted-list-per-credential-category.md) | One trusted list per credential category |
| [0023](docs/adr/0023-trust-anchors-come-from-trusted-lists.md) | Trust anchors come from trusted lists |

## Related

- [CONTEXT.md](CONTEXT.md) glossary
- [docs/spec-compliance.md](docs/spec-compliance.md) feature-by-feature status against the specifications
- [SECURITY.md](SECURITY.md) scope and threat model
