[← Wallet](../wallet.md)

# Presentation from the wallet

The wallet answers an OID4VP presentation request from the CLI (`wallet accept`), from a scanned QR (`wallet scan`), or at its own `/authorize` URL. `wallet accept` also handles credential offers (see [issuance into the wallet](issuing.md)).

## `wallet accept <uri>`

Detects the URI type and starts the matching flow:

- `openid4vp://`, `haip-vp://`, `eudi-openid4vp://`, `eu-eaap://`: OID4VP presentation (evaluates DCQL, shows the consent UI, submits the VP token)
  - Supports `response_type=vp_token id_token` (SIOPv2 + OID4VP combined flow). Generates a self-issued ID token alongside the VP token
  - Supports `response_type=id_token` (SIOPv2 only). Generates a self-issued ID token without VP token
- `openid-credential-offer://`, `haip-vci://`, `eu-eaa-offer://`: OID4VCI credential issuance (fetches the credential from the issuer)

EUDI issuance uses `eu-eaa-offer://` under [ETSI TS 119 472-3 V1.1.1](https://www.etsi.org/deliver/etsi_ts/119400_119499/11947203/01.01.01_60/ts_11947203v010101p.pdf), requirement GEN-REQ-4.1-06. All 3 offer schemes accept `credential_offer` and `credential_offer_uri` parameters.

In interactive mode (the default), OID4VP requests start a temporary consent UI server and open it in the browser. With `--auto-accept`, the wallet submits one credential per credential query (the most recently issued match), or all matching ones when the query sets `multiple: true`.

When a verifier responds to a presentation with a `redirect_uri`, the wallet prints the URL and opens it in a browser. A scripted run, or a host without a desktop, only prints it. `--no-open` disables opening.

`debug` mode matches DCQL queries loosely to help troubleshoot verifier queries. A credential that matches the requested format and metadata and at least one requested claim counts as a match with a warning, even when other required claim paths are missing. `strict` mode requires every claim path.

An `etsi_tl` entry in `trusted_authorities` identifies a trusted list. The wallet reads it like its own trusted lists. The list must be current and signed by a trusted list operator. The list's issuance services are the trust anchors for the credential. If the wallet can't read or verify the list, it logs a warning and the list matches no credential. The other entries still count. `debug` mode offers an unmatched credential as untrusted.

The wallet presents a `jwt_vc_json` credential without a Verifiable Presentation, so it can't prove holder binding. Such a credential answers only a query with `require_cryptographic_holder_binding: false` (OpenID4VP 1.0 Appendix B.1).

```bash
eudi wallet accept 'openid4vp://authorize?...' --auto-accept
eudi wallet accept 'eu-eaa-offer://?credential_offer_uri=...'
eudi wallet accept 'openid-credential-offer://...'
eudi wallet accept 'openid-credential-offer://...' --tx-code 123456
```

| Flag                    | Default  | Description                                      |
|-------------------------|----------|--------------------------------------------------|
| `--port`                | `8085`   | Server port for OID4VP                           |
| `--auto-accept`         | `false`  | Approve presentations without asking             |
| `--tls-verify` | mode default | Verify all outbound HTTPS certificates (`true` in strict mode, `false` in debug mode) |
| `--tls-ca` | None | Add PEM CA certificates to the system TLS trust store |
| `--http-proxy`, `--https-proxy`, `--no-proxy` | Environment | Forward proxy settings. See [outbound proxy](serve.md#outbound-proxy) |
| `--mode`                | `debug`  | Validation mode: `debug` or `strict`             |
| `--session-transcript`  | `oid4vp` | mdoc session transcript mode: `oid4vp` or `iso`  |
| `--tx-code`             | None     | Transaction code for OID4VCI pre-authorized code flow |
| `--docker`              | `false`  | Serve the trust and status lists under `host.docker.internal` for verifiers in a container. The server then binds `0.0.0.0` unless `--listen` sets another address |
| `--listen`              | `$EUDI_DEV_LISTEN`, else `127.0.0.1` | IP address the local server binds (see [listen address](serve.md#listen-address)) |
| `--key-attestation-level` | Issuer requirements | Test claims for key storage and user authentication: issuer requirements (default), `none`, or a level such as `iso_18045_high`. See [key attestation claims](serve.md#key-attestation-claims) |
| `--haip`                | `false`  | Check incoming presentations and credential offers against HAIP 1.0. `--mode` sets how violations are handled: strict refuses the flow, debug reports them and continues |
| `--arf`                 | `false`  | Check the access and registration certificates of verifiers and issuers against the ARF (see [ARF checks](#arf-checks) and [issuers](issuing.md#arf-checks)). With `--mode strict` the wallet refuses the request or the offer on any finding |
| `--relying-party-ca`    | None     | PEM file with CA certificates that issue relying party access and registration certificates. The wallet puts them on its `access-ca` and `registrar` lists (repeatable) |
| `--trusted-list-ca`       | None     | PEM file with CA certificates of trusted list operators. With `--arf` the wallet also accepts trusted lists signed under these CAs (repeatable) |
| `--trusted-list`        | None     | URL of an external list of trusted entities (ETSI TS 119 602) for the wallet's list of trusted lists (repeatable). Only `wallet serve` takes a list file or directory. See [trusted lists](serve.md#trusted-lists) |
| `--require-encrypted-request` | `false` | Reject a request object that the verifier did not encrypt |
| `--client-attestation`  | `false`  | Send the wallet attestation on OID4VCI token requests even when the issuer does not advertise `attest_jwt_client_auth` |
| `--key-attestation-proof-key` | `kid` | How a jwt proof with a key attestation names its signing key: `kid` `"0"`, `jwk` or `none` |
| `--vci-version`         | `1.0`    | OpenID4VCI feature level as a client: `1.0` or `1.1` |
| `--transaction-data`    | `false`  | Accept `transaction_data` in presentation requests (see [transaction data](#transaction-data)) |
| `--transaction-data-type` | None   | Accept another transaction data type besides the TS12 types. Takes effect only with `--transaction-data` (repeatable) |

Pre-authorized code offers work directly with `wallet accept`. Authorization code offers require a running `wallet serve` instance. Flows with attestation-based client authentication use a client ID derived from the wallet provider key, and other flows use the wallet origin. The redirect URI defaults to the `/callback` endpoint of the wallet origin. Set fixed values with `--vci-client-id` and `--vci-redirect-uri`. The wallet uses PAR and DPoP when advertised by the issuer.

For sign-in, `wallet accept` prints the authorization URL. It opens the URL only when no wallet page is already handling the flow, because the request can be used once (RFC 9126 §4). After the issuer redirects back, the wallet exchanges the code. The CLI waits for the credential or an error. A remote wallet follows the same process. See [sign-in during issuance](issuing.md#sign-in-during-issuance).

Strict mode verifies HTTPS certificates. Debug mode skips verification by default. For local flows, `--tls-verify=true|false` overrides either default and `--tls-ca dev-ca.pem` adds trusted CA certificates. See [HTTPS certificate verification](serve.md#https-certificate-verification).

When `accept` or `scan` forwards a flow to a running wallet, that wallet uses its own settings for every step of the flow. A conformance flag set to the running wallet's value has no effect. The same applies to a CA or list that the wallet already trusts. A flag with a different value fails and shows the wallet's value. The TLS CA and proxy flags always return an error, because the wallet doesn't report them. Set the settings on `wallet serve`, change them in its Settings dialog, or put CAs and lists on its trusted lists with [`trust`](serve.md#trusted-lists).

## `wallet scan`

Scans a QR code from an image file or screen capture and detects the content:

- `openid4vp://`, `haip-vp://`, `eudi-openid4vp://`, `eu-eaap://`: delegates to `accept` (OID4VP presentation)
- `openid-credential-offer://`, `haip-vci://`, `eu-eaa-offer://`: delegates to `accept` (OID4VCI issuance)
- SD-JWT / mdoc raw credential: delegates to `import`

```bash
eudi wallet scan qr-image.png
eudi wallet scan --screen              # interactive screen capture (macOS and Linux)
eudi wallet scan --screen --auto-accept # approves a presentation without asking
```

`wallet scan` reads the QR code, then runs the same flow as `wallet accept`. If a remote target is configured or a wallet server runs for the same wallet directory, it sends the request to that wallet and opens its consent UI. Otherwise it handles the request locally. See [automatic routing](http-api.md#automatic-routing-single-writer).

The wallet handling the flow fetches the offer and prompts for a transaction code when one is required. For a local flow, the CLI prompts when stdin is a terminal and `--tx-code` was not given. See [ADR-0012](../adr/0012-every-entry-point-runs-the-same-flow.md).

`wallet scan` uses the persistent `wallet --mode` setting and accepts the same `--auto-accept`, `--tx-code`, `--haip`, `--arf`, `--relying-party-ca`, `--trusted-list-ca` and `--trusted-list` flags as `accept`.

## Wallet invocation by URL

Both wallet flows also run at the wallet's own URL, wherever a verifier or issuer would use a custom-scheme link. Custom schemes are registered on macOS and Linux.

| Custom scheme | Wallet URL |
|---------------|------------|
| `openid4vp://?<params>` or `openid4vp://authorize?<params>` | `http://localhost:8085/authorize?<params>` |
| `openid-credential-offer://?<params>`, `haip-vci://?<params>` or `eu-eaa-offer://?<params>` | `http://localhost:8085/credential-offer?<params>` |

To convert a link, replace everything before the `?` with the wallet endpoint URL and keep the query string unchanged.

In a custom-scheme URI the part between `://` and `?` has no meaning, so `openid4vp://?...` and `openid4vp://authorize?...` are the same request.

```bash
# Presentation request: standard OID4VP authorization request parameters
curl 'http://localhost:8085/authorize?client_id=...&request_uri=...'

# Credential offer by reference
curl 'http://localhost:8085/credential-offer?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F123'

# Credential offer by value (url-encoded offer JSON), with a transaction code
curl 'http://localhost:8085/credential-offer?credential_offer=%7B...%7D&tx_code=1234'
```

`/credential-offer` accepts `credential_offer` or `credential_offer_uri`, plus an optional `tx_code` for the pre-authorized code flow.

Browser navigations are GET requests that accept HTML, such as clicked links. After a presentation, the browser goes to the verifier's `redirect_uri`, or to the wallet UI if none was returned. The same applies after a refusal (a denied request or no matching credential), because the verifier can return a `redirect_uri` for an error response too (OpenID4VP 1.0 §8.2). After an offer import, the browser goes to the wallet UI.

Other callers, including curl and test harnesses, receive the same JSON responses as `POST /api/presentations` and `POST /api/offers`. `keycloak-extension-oid4vp` can set `walletScheme` to the wallet's `/authorize` URL.

In interactive mode (no `--auto-accept`) the 2 caller types also behave differently before consent. A browser navigation redirects to the wallet UI for consent and then to the verifier's `redirect_uri`. An API call blocks until the request is approved or denied, in the UI or via `POST /api/requests/{id}/approve` or `/deny`. Both responses carry the verifier's `redirect_uri` when it returned one.

## Digital Credentials API

A verifier page can ask for a presentation with the W3C Digital Credentials API (`navigator.credentials.get()`). The eudi-dev browser extension answers these calls with an eudi-dev wallet, so you can test a verifier without a phone. `eudi wallet browser` opens Chrome with the extension loaded. The wallet answers the request at `POST /api/dc-api`. See [browser extension](browser-extension.md) for the installation, what a test with the extension covers and the interface for other test wallets.

## Transaction data

A verifier can ask the wallet to authorize a transaction, such as a payment, with the `transaction_data` request parameter (OpenID4VP 1.0 §5.1). The wallet accepts it only with `--transaction-data`. The Settings dialog and `PUT /api/config/conformance` (`transaction_data`) switch it at runtime. Without it, the wallet treats the parameter as unsupported (§5). Strict mode refuses the request and debug mode logs a warning.

The wallet knows the SCA transaction types of EUDI TS12 v1.0.1: `urn:eudi:sca:payment:1`, `urn:eudi:sca:login_risk_transaction:1`, `urn:eudi:sca:account_access:1` and `urn:eudi:sca:emandate:1`. `--transaction-data-type` adds more types, and `transaction_data_types` sets them at runtime.

The wallet checks each entry:

- it decodes to a JSON object with a known `type` and a non-empty `credential_ids` array (§5.1)
- each entry in `credential_ids` is the id of a credential query in the DCQL query
- the referenced queries ask for an SD-JWT VC with holder binding (§8.4, Appendix B.3.3). An mdoc query gets a finding, because no mdoc doctype defines transaction data yet (Appendix B.2.1)
- `transaction_data_hashes_alg` contains at least one of `sha-256`, `sha-384` and `sha-512` (Appendix B.3.3.1)
- a TS12 entry has `transaction_data_hashes_alg` and a `payload` object, and no other members (TS12 §4.2)
- a TS12 payload matches the JSON schema of its type (TS12 §3.2 and §4.3)

Strict mode refuses a request with such a finding. The error is `invalid_transaction_data`. Debug mode warns and still signs every entry that decodes, including one of an unknown type.

The consent dialog shows each transaction with its type and data. For the TS12 types it also sums up the payload in one sentence, such as "Pay €12.50 to Demo Shop". The data then stays folded until you open it. The wallet binds each entry to one presentation (§5.1). It takes the first query in `credential_ids` whose credential has a Key Binding JWT, else the first answered query. The Key Binding JWT of that presentation carries `transaction_data_hashes`, a hash of each entry as received. It also carries `transaction_data_hashes_alg` when the entry lists hash algorithms. The wallet picks the first of `sha-256`, `sha-384` and `sha-512` accepted by all entries of the presentation.

For a TS12 entry the Key Binding JWT also carries `jti`, `response_mode` and `amr` (TS12 §3.6). `jti` is new for each presentation. `response_mode` is the response mode of the answer. That is `direct_post` for a request without one. The wallet does not authenticate the user, so `amr` lists the factors of a typical wallet unit: `[{"knowledge":"pin_6_or_more_digits"},{"possession":"key_in_local_native_wscd"}]`.

The wallet checks that the credential is an SCA Attestation (TS12 §3.2 steps 1 and 2). Its Type Metadata needs the category `urn:eu:europa:ec:eudi:sua:sca` and must list the type in `transaction_data_types`. A failed check is a warning in the activity log, in strict mode too. You can still test a payment with any SD-JWT VC, such as the PID. The demo issuer's Demo Payment Account passes the check. The demo verifier asks for it with **Demo payment account**. Its `vct` is an HTTPS URL on the demo issuer. Its Type Metadata has the SCA category and lists the four TS12 types with their claims and UI labels (TS12 §4.1). The credential carries the document's hash in `vct#integrity`. With an HTTP base URL, the `vct` uses the self-signed HTTPS issuer URL on port+1. See [ADR 0031](../adr/0031-transaction-data-is-opt-in-and-binds-to-sd-jwt.md).

### Transaction templates

Transaction templates are named transaction data entries (OpenID4VP 1.0 §5.1) for any presentation request. The wallet comes with one example for each TS12 type: `payment`, `login`, `account-access` and `emandate`. Open them under **Templates > Transaction templates**. A template of your own replaces the predefined one with the same name. Deleting it brings the predefined one back.

**New transaction template** opens an editor with a name and a description. Its builder has a type, the hash algorithms, optional credential ids and a list of fields. For a TS12 type the fields form the `payload`, and the builder starts with the required fields of the TS12 schema. For any other type the fields sit next to `type`. A value is text or JSON, so `5` is a number and `{"name": "Demo Shop"}` is an object. **JSON** shows the whole entry. Some templates don't fit the builder and open in JSON, such as one with members next to a TS12 `payload`.

The editor's command panel shows the template as a curl call, as an `eudi templates transactions import` command and as a YAML file for `--transaction-templates`. See [configuration files](config-files.md).

The CLI manages the same templates:

```bash
eudi templates transactions list
eudi templates transactions show payment
eudi templates transactions import refund.yaml --name refund
eudi templates transactions delete refund
```

A template needs a `type`. The wallet checks a TS12 template against the TS12 rules for an entry (TS12 §4.2 and §4.3) and shows the findings as warnings. It still saves the template. A broken entry tests how a wallet refuses it.

`eudi templates transactions show` prints a template as JSON. Its `transaction_data` member is the entry. Encode it as base64url and add it to the `transaction_data` array of a request. On the demo verifier, check **Transaction data** and pick a template. A form shows the fields of its payload, and **JSON** shows the whole entry. An entry without `credential_ids` gets the query ids of the request. A TS12 entry gets a fresh `transaction_id` and the current time in `date_time`. [Demo issuer and verifier](../public-demo.md#demo-issuer-and-verifier) has the details, and [transaction templates](http-api.md#transaction-templates) has the API.

## HAIP 1.0 enforcement

`--haip` on `wallet serve` or `wallet accept` checks incoming requests and offers against [HAIP 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html). `--demo` turns it on by default (see [public demo](../public-demo.md)).

`--haip` adds the profile checks below. Strict mode rejects violations. Debug mode reports them and continues where possible. Advisory findings remain warnings in either mode.

For **presentations** (OID4VP `direct_post.jwt` and Digital Credentials API `dc_api.jwt`) the wallet checks every request against all of:

- `response_type` must be `vp_token` (§5)
- `response_mode` must be `direct_post.jwt` (§5.1) or `dc_api.jwt` (§5.2)
- A request object must use the `x509_hash:` Client Identifier Prefix (§5), and its Request Object signature must verify against a certificate whose SHA-256 is the prefix value
- The certificate signing the request must not be self-signed, and the trust anchor must not be included in the `x5c` header (§5)
- A request sent by redirect must carry a signed request object (JAR) delivered through `request_uri` (§5.1). An unsigned request is accepted only over the Digital Credentials API. §5.2 requires wallets to support it there
- The query must use DCQL (§5)
- The Verifier's client metadata must list both `A128GCM` and `A256GCM` in `encrypted_response_enc_values_supported` (§5)
- A signed Digital Credentials API request must list the caller origin in `expected_origins` (OpenID4VP Appendix A.2, incorporated by §5.2)
- The request object signing algorithm must be `ES256`

In `--mode strict` a non-compliant request is refused with HTTP 400. `POST /api/presentations` then returns `{"error": "<code>", "error_description": "<failed checks>"}`, with an OpenID4VP 1.0 §8.5 error code such as `invalid_request`. In `--mode debug` the same findings are logged as warnings and the flow continues.

For **issuance**, HAIP §6.1.1 checks every received credential. That covers every issuance flow and every copy of a batch. An SD-JWT VC must include its issuer signing certificate and chain in `x5c`, without the trust anchor. The signing certificate must not be self-signed.

The credential issuer must use HTTPS. Plain HTTP is allowed on a local host: `localhost`, any address in `127.0.0.0/8`, `::1` or `host.docker.internal`. Authorization code flows also require the authorization server to support that grant and offer PAR when using the authorization endpoint.

PKCE metadata is checked when present. A server advertising PKCE without `S256` violates the profile. The profile leaves the DPoP signing algorithms open, because §7 does not list DPoP proofs among the uses that require `ES256`. Omitted metadata is accepted because the referenced OAuth specifications make these fields optional and FAPI 2.0 constrains server behavior. Client authentication metadata is not checked.

For pre-authorized offers, only the HTTPS transport rule applies to this part of validation. HAIP §4 requires support for authorization code issuance but scopes PAR to use of the authorization endpoint.

§5 of the profile requires the `x509_hash` prefix for signed requests. With `--haip` an `x509_san_dns` client identifier is a finding.

An unsigned request arrives over the Digital Credentials API without a Request Object. Appendix A.2 of OpenID4VP says such a request carries no `client_id`, and a wallet ignores one that is present. The origin reported by the platform identifies the caller.

§7 requires at least ES256. The wallet advertises ES256 in `request_object_signing_alg_values_supported`.

As a client the wallet always follows the profile (PAR, PKCE S256, DPoP, wallet attestation when advertised, ES256 proofs, key attestation). `--haip` only changes how it validates issuers and verifiers.

```bash
eudi wallet serve --haip --auto-accept --pid
eudi wallet accept --haip 'openid4vp://authorize?...'
```

Every request to a given wallet uses the same validation mode, HAIP, ARF and encrypted-request settings.

## ARF checks

`--arf` on `wallet serve`, `wallet accept` or `wallet scan` checks the relying party's access and registration certificates in a presentation request against the ARF. It checks issuers too (see [issuing](issuing.md#arf-checks)). `--demo` turns it on by default. The Settings dialog and `PUT /api/config/conformance` (`require_arf`) switch it at runtime.

The wallet checks that:

- the request is signed with an access certificate in `x5c` (RPA_03)
- the access certificate chains to a trusted access certificate authority (RPA_04)
- no certificate on the path of the access certificate is revoked (RPA_06a, CIR (EU) 2024/2982 Article 3(1) and 5(2)). The wallet reads the CRL of every certificate with a CRL distribution point. A CRL is a finding too if it is unreadable, not signed by the certificate's issuer or past its next update
- the request carries at most one registration certificate in `verifier_info` (RPRC_19)
- the registration certificate is signed by a trusted registrar (RPRC_02a), identifies the relying party and the service of the access certificate (RPRC_17a), has a valid signature and `typ`, contains all claims required by ETSI TS 119 475 and is not expired (RPRC_17)
- the registrar has not revoked the registration certificate (RPRC_17). Its status list must be readable and chain to a trusted registrar (RPACANot_03b)
- the request asks only for credentials and claims registered in that certificate (RPRC_21)
- the response mode encrypts the presentation, so it is `direct_post.jwt`, `dc_api.jwt` or `ia_post.jwt` (OIA_09). With `--haip`, the HAIP check reports this instead.

A query for `urn:eudi:pid:1` without any domestic PID type gets a warning in every mode. Other wallets may not answer it with a domestic PID (see [credential type inheritance](../wallet.md#credential-type-inheritance)).

A request without a registration certificate gets a warning in every mode. So does a revoked registrar certificate, or one with an unreadable CRL (WRP-VALIDATION-02). Wallets must check registration certificates only from 11 August 2028 (CIR (EU) 2026/1731).

The ARF lets the Wallet Provider decide whether to refuse (RPA_06a). In `--mode debug` the wallet logs the findings as warnings and continues. `POST /api/presentations` returns them in `findings`. This works for requests by URL, over the Digital Credentials API and during [interactive authorization](issuing.md#interactive-authorization). Strict mode refuses.

How strict mode refuses depends on the verifier. When the request is signed with a trusted access certificate and its client identifier is valid, the wallet sends the verifier an error response (OpenID4VP 1.0 §8.5, RFC 6749 §4.1.2.1). When only ARF findings remain, the error is `access_denied`. Its `error_description` is "The request does not meet the ARF rules: " followed by the findings, for example `ARF RPRC_21: ...`. When the request also breaks OpenID4VP, the error is the §8.5 code of that problem, such as `invalid_request` or `invalid_transaction_data`, and the description lists all findings. `POST /api/presentations` answers with status `refused` and the same description. `wallet accept` and `wallet scan` send the same response. Over the Digital Credentials API, the error is in the API result (OpenID4VP 1.0 Appendix A). For any other strict refusal, the wallet sends nothing to the verifier. The caller gets HTTP 400 as described under [HAIP 1.0 Enforcement](#haip-10-enforcement).

The [registrar API walkthrough](registrar-api.md) shows both outcomes with real requests.

A request object is signed with an access certificate. Consent shows purposes and privacy policies only from registration certificates bound to that access certificate. A request without a request object shows none.

The wallet takes its trust anchors from [trusted lists](serve.md#trusted-lists) only. An access certificate must chain to a CA on an access certificate provider list (`access-ca`, ETSI TS 119 602 V1.1.1 Annex F). The wallet's own list contains the relying party access CA of its [registrar](registrar.md). The demo issuer and the demo verifier get their access certificates from that CA too. A registration certificate and its status list must chain to a CA on a registration certificate provider list (`registrar`, Annex G). The wallet's own list contains the registrar CA. The relying party access CA signs any visitor's CSR, so it is not on the `registrar` list.

For the CAs of another ecosystem, such as a member state's sandbox, use `trust add-ca --list access-ca` and `--list registrar`, or `--relying-party-ca` (it puts the CAs on both lists). An external list on the list of trusted lists works too. See [ADR 0023](../adr/0023-trust-anchors-come-from-trusted-lists.md).

