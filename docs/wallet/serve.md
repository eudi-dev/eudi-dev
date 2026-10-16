[← Wallet](../wallet.md)

# Wallet server

`wallet serve` runs the persistent wallet HTTP server (web UI, OID4VP and OID4VCI endpoints, trusted lists, optional URL scheme handling).

## `wallet serve`

It loads credentials from the selected storage backend, saves changes and logs requests. Interactive requests show a consent dialog.

The server exposes:

- Web UI for credential management and consent
- OID4VP authorization endpoint (`/authorize`)
- OID4VCI credential offer endpoint (`/credential-offer`). Accepts `credential_offer` / `credential_offer_uri` query parameters. Offer links can use the wallet URL in place of a custom scheme (see [Invoking the wallet by URL](presenting.md#wallet-invocation-by-url))
- Trusted list endpoint (`/api/trustlist`). It serves the PID list or the list for a `vct` or `doctype`. Use this URL as `--trusted-list` when validating PID credentials issued by the wallet
- Trusted list index endpoint (`/api/trustlists`) with one JWT endpoint per list
- HTTPS wallet endpoints on the wallet's effective issuer URL, including `/.well-known/jwt-vc-issuer`, `/.well-known/openid-credential-issuer`, `/api/trustlist`, `/api/trustlists`, `/api/statuslist`, and `/api/registrar/wrp`
- A management API mirroring the wallet CLI (list, show, import, remove and issue credentials, export certificates). It has no authentication (see [HTTP API](http-api.md))

For `credential_offer_uri`, the wallet fetches the offer for the dialog and again on approval (OpenID4VCI 1.0 §4.1.3). If the issuer serves the offer only once, issuance uses the copy shown in the dialog and logs the failed second fetch. If the first fetch fails, the dialog shows the issuer from the URI and approval retries the fetch.

If the offer requires a transaction code and none is given, issuance fails before the wallet uses the pre-authorized code. This applies to API callers and to `--auto-accept` too. The error gives the required code length and input mode.

After storing a credential, the wallet calls the issuer's Notification Endpoint if the issuer publishes one. The endpoint is optional (OpenID4VCI 1.0 §11). A rejected call logs a warning and the credential stays in the wallet. The warning quotes the response and compares it with §11.3 (an Authorization Error Response for a rejected token, a 400 for a bad `notification_id`).

The purpose and privacy policy in the presentation consent dialog come from the verifier's registration certificate. The certificate must belong to the access certificate that signed the request object (see [wallet checks](registrar.md#wallet-checks)). `--arf` checks the registration certificate (see [ARF checks](presenting.md#arf-checks)).

The presentation dialog starts with the wallet's automatic credential selection. The user can choose a credential-set option and a credential for each query. Auto-accept submits the automatic selection without a dialog.

If the verifier sets `multiple: true` on a query, all matching credentials are selected. At least one stays selected.

The dialog also offers non-matching credentials with the reasons (format, type, missing claims). In strict mode this includes credentials that fail a strict rule, such as a missing holder binding. They are never picked automatically. If you pick one, the wallet discloses every requested claim present in the credential. When nothing matches a request from a link, the UI, a DC API call or an issuer during issuance, the dialog opens, and **Approve** stays disabled until you pick a credential for every query. Auto-accept and API submissions get no dialog. The wallet answers them with `access_denied`.

When a query lists `claim_sets`, the wallet uses the first matching claim set (OpenID4VP 1.0 §6.4.1). The dialog says how many claim sets the verifier accepts and which one the wallet sends. The credential lists the claims of that set. **Show all claim sets** lists every matching claim set, and you can pick another one. The wallet then discloses the claims of the chosen set. The claim checkboxes still apply.

API clients receive the alternatives in `credential_options`. Each query also lists `non_matching` credentials with their `mismatches`. `unmatched` on a credential set lists the options without a matching credential. Send `picks` (query ID to credential ID, or to a list of credential IDs when the query has `"multiple": true`), `set_choices` (option index per set, or `-1` to skip an optional set), `claim_sets` (query ID to the index of a matching claim set) and `selected_claims` to `POST /api/requests/{id}/approve`. An invalid selection returns `400` and leaves the request pending.

![Consent dialog](../assets/wallet-consent-ui.png)

![Consent credential selection](../assets/wallet-consent-edit-ui.png)

A credential issued in the web UI can reference the wallet's own status list when configured, a custom URI and index, or no status list. The UI can revoke and activate credentials on the wallet's own status list. For an external status list it fetches the list on request.

The **</>** button beside a dialog's title shows the curl command for what the dialog does, with the dialog's current values. The panel can also show the matching CLI command. A second button switches the dialog between its normal size and almost full screen. See [dialog commands](../ui-automation.md#dialog-commands-and-size).

To drive the web UI from Playwright or Selenium, see [UI automation](../ui-automation.md).

![Issue credential dialog](../assets/wallet-issue-ui.png)

Only local wallets can change **Auto-accept** in the UI.

A fetched request object and its receipt share one activity entry. Deferred collection adds separate request and response entries, including pending replies and errors.

A batch import is one entry with the ID of every stored copy. Encrypted exchanges show the wire value first. Switching to the decrypted view changes only the log display.

Verifiers check wallet-issued credentials against the wallet CA. Issuers use it to check wallet and key attestations.

The default local issuer URL is `https://localhost:8086` (the wallet's HTTP port plus one). An HTTPS `--base-url`, such as `https://eudi-test.dev`, becomes the issuer URL. Issuer metadata, trusted lists and status lists are then served from the public origin behind an external TLS terminator (see [public demo hosting](../public-demo.md)).

To serve the wallet under a path prefix on a shared host, include the prefix in the base URL, such as `https://example.com/some/context`. See [reverse proxy setup](../reverse-proxy.md) for the proxy setup.

For a local https origin without an external TLS terminator, add `--serve-tls`. The wallet then also listens on the base URL's port with its own TLS certificate. The plain HTTP port stays open. `--serve-tls` requires an https `--base-url` with an explicit port. The [demo issuer and verifier conformance run](../conformance-run-demorp.md) needs it because the OIDF suite requires https endpoints.

The request objects of the demo verifier and the demo issuer carry `iat` in their JWS header, as ETSI TS 119 472-2 V1.3.1 OIDFVP-HAIP-REDIRECTS_RO-03 requires.

The demo verifier accepts a credential when its certificate chains to an issuance service on a credential provider list of the wallet's [list of trusted lists](#trusted-lists). That includes the wallet's own issuers, added providers and the providers on external lists. The status list of a credential chains to a revocation service of a credential provider list (ETSI TS 119 602 V1.1.1 Table D.3). With `--arf`, the catalogue entry of the requested type gives its category, and the credential and its status list must chain to a provider list of that category ([ADR 0022](../adr/0022-one-trusted-list-per-credential-category.md)). A PID needs a PID provider list (ARF OIA_12) and a PuB-EAA needs a PuB-EAA provider list (OIA_14). A type that the catalogue does not list, and whose name does not mark it as a PID, may chain to any provider list. `--demo-verifier-issuer-ca <pem>` (repeatable) adds more CAs directly (for example, the OIDF conformance suite signs its credentials under its own CAs).

The demo verifier checks a presented credential with the [checks of `validate`](../validate.md#checks), for SD-JWT VCs and mdocs alike. The signature must verify. A failed `type`, `expiry`, `integrity` or `status` check rejects the presentation. HAIP findings and an unanchored status list are warnings. The verifier then checks the key binding, the nonce, the audience and the requested claims. It fetches status lists and issuer metadata with the wallet's HTTP client, so `--tls-ca`, `--tls-verify` and the proxy flags apply.

### Trusted lists

The wallet publishes lists of trusted entities (ETSI TS 119 602). It takes every trust anchor from such lists ([ADR 0023](../adr/0023-trust-anchors-come-from-trusted-lists.md)). With `--arf`, the wallet checks received credentials against them. It also checks the access and registration certificates of verifiers and issuers. The demo issuer and the demo verifier use them too.

| List ID | Lists | LoTE type |
|---|---|---|
| `pid` | PID providers | `http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList` (Annex D) |
| `qeaa` | QEAA providers | `https://eudi-test.dev/LoTEType/QEAAProvidersList` |
| `pub-eaa` | PuB-EAA providers | `http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList` (Annex H) |
| `eaa` | Other EAA providers | `https://eudi-test.dev/LoTEType/EAAProvidersList` |
| `wallet-provider` | Wallet providers | `http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList` (Annex E) |
| `access-ca` | Providers of access certificates | `http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList` (Annex F) |
| `registrar` | Providers of registration certificates | `http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList` (Annex G) |

TS 119 602 registers no list type for QEAA or other EAA providers (QEAA providers are on TS 119 612 trusted lists). Annex C.1 lets a scheme operator create its own URIs, and §6.3.3 asks for one type per profile. So the `qeaa` and `eaa` lists have types of their own, with the service types `https://eudi-test.dev/SvcType/QEAA/Issuance`, `.../QEAA/Revocation`, `.../EAA/Issuance` and `.../EAA/Revocation`. These URIs identify the list profile. They are the same on every deployment, regardless of the base URL. A wallet state from eudi-dev 2 stores `http://uri.etsi.org/19602/LoTEType/local` for its EAA list, and the wallet reads that as the `eaa` list.

The `access-ca` list contains the relying party access CA of the [registrar](registrar.md). The `registrar` list contains the registrar CA. CAs from `--relying-party-ca` are on both lists.

#### Credential categories

Each credential category (`pid`, `qeaa`, `pub-eaa` and `eaa`) is a provider role with its own signing key and its own provider CA under the wallet CA. The category of a credential selects the signing key. The signing certificate is then on the list of that category.

The PID role signs with the wallet's issuer key (`issuer.pem`). The other roles have keys named `issuer-<role>` in the signing store, and the wallet provider has `wallet-provider`. `/.well-known/jwt-vc-issuer` lists one JWK per category list, per custom list and for unlisted credentials. The wallet serves each provider CA certificate at `/api/certificates/providers/{role}/{country}.der`.

A credential gets its category in this order:

- `--category` of `issue ... --wallet`, or `category` in the issue API
- the `category` of its [template](../templates.md)
- the category of its entry in the [attestation catalogue](registrar.md#attestation-catalogue)
- otherwise it is an EAA

The category `unlisted` keeps a credential off every list. Its signer has its own provider role (`unlisted`) and provider CA. Use it to test how a verifier handles an issuer without a trust anchor.

The wallet also keeps an issued-attestation registry. It lists the type of each credential issued by the wallet, with its category and trusted list data. The trusted lists include these types:

- `wallet serve --pid` registers the PID types
- `issue ... --wallet` registers the type of the issued credential

An imported credential and a credential signed with your own `--key` and `--cert` are on none of the wallet's lists, because the wallet did not sign them.

Each trusted list publishes its service's signing certificates, provider CAs and status signing certificates. With a configured root of path length zero, the list contains only the signing certificates. A separate list operator key under the wallet CA signs the list. An unchanged list keeps its signed instance until it expires. Changed content or expiry increments the sequence number. Previous instances are available at the list's `/history` endpoint. Every list except `pub-eaa` points to itself. Tables D.1 to G.1 require that for the lists of Annexes D to G, and Table H.1 forbids pointers. The `pub-eaa` list keeps its history. A removed service stays on it with the status withdrawn (Table H.3).

Wallet and key attestations use a separate wallet provider key. Their `x5c` contains the leaf and any intermediate certificates, with the self-signed root omitted. Issuers can pin the root from `/api/certificates/ca` or use `/api/trustlists/wallet-provider`.

#### Your providers and lists

To check the relying parties of another registrar, see [Use an external registrar](registrar.md#external-registrar).

`eudi trust` adds your own providers to the wallet's lists and external lists to the wallet's list of trusted lists:

```bash
eudi trust add-ca --list pid --name "Example PID Provider" --ca pid-ca.pem
eudi trust add-ca --list registrar --ca registrar-ca.pem
eudi trust add-ca --list trusted-list-ca --ca lists-ca.pem
eudi trust add-list https://lists.example/pid
eudi trust                       # or: eudi trust list
eudi trust rm-ca fc390242d2ad08ab
eudi trust rm-list https://lists.example/pid
```

`add-ca` takes a PEM file with CA certificates and one of the list IDs above. The wallet adds the CA to that list as a provider with an issuance and a revocation service, and signs the list. The CA is then a trust anchor for certificates issued under it and for their status lists. Adding the same certificates to the same list again replaces the earlier entry. The name defaults to the CA's common name. The wallet doesn't publish the `trusted-list-ca` list. Its CAs may sign trusted lists, like those from `--trusted-list-ca`, so the wallet accepts external lists signed under them.

`add-list` puts an external list of trusted entities on the list of trusted lists. With `--arf` the providers on the external list are trust anchors for the checks of its list type. For example, a PID provider list anchors the checks of received PIDs. The list signer must chain to the wallet CA, to a CA from `--trusted-list-ca` or to a CA added with `add-ca --list trusted-list-ca`. In `--mode strict` the wallet refuses an unreadable list. In `--mode debug` it adds the list and reports the reason. `wallet serve --trusted-list <url>` (repeatable) adds lists at startup. They can't be removed through the API. PID and PuB-EAA provider lists anchor their credentials directly. A list of another credential type anchors credentials only when the catalogue entry of the type links it (see [attestation catalogue](registrar.md#attestation-catalogue)).

`eudi trust` shows the wallet's lists, the added providers and the external lists:

```
LIST             DEFAULT  CATEGORY                    PATH
pid              yes      Credential providers        /api/trustlists/pid
...
registrar                 Relying party certificates  /api/trustlists/registrar

ID                LIST  NAME                CERTIFICATES
fc390242d2ad08ab  eaa   Example University  1

List of trusted lists: https://localhost:8086/api/trustlists/lists
```

The HTTP API:

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/trust` | `entities` (the added providers), `entity_lists` (the list IDs), `lists` (the external lists) and `lists_url` |
| `POST` | `/api/trust/entities` | Add a provider: `list`, `name` and `certificates` (PEM). Answers `201` with the entity and its `id` |
| `DELETE` | `/api/trust/entities/{id}` | Remove a provider |
| `POST` | `/api/trust/lists` | Add an external list: `url`. Answers `201` with the list |
| `DELETE` | `/api/trust/lists?url=<url>` | Remove an external list |

Each entry of `lists` has `url` and, where they apply, `configured` (from `--trusted-list`), `via` (the list of trusted lists that points to it) and `error` (why the wallet can't use it). A readable list also has its `type` (LoTEType). `direct` is `true` when the wallet uses lists of that type without a catalogue entry. For example:

```json
{
  "entities": [
    { "id": "fc390242d2ad08ab", "list": "eaa", "name": "Example University", "certificates": ["MIICCTCCAa+gAwIBAgIU..."] }
  ],
  "entity_lists": ["pid", "qeaa", "pub-eaa", "eaa", "wallet-provider", "access-ca", "registrar", "trusted-list-ca"],
  "lists": [
    {
      "url": "https://lists.example/pid",
      "error": "fetching the trusted list: fetching https://lists.example/pid: Get \"https://lists.example/pid\": dial tcp: lookup lists.example: no such host"
    }
  ],
  "lists_url": "https://localhost:8086/api/trustlists/lists"
}
```

The wallet keeps a fetched external list for 5 minutes, or until its `NextUpdate` if that comes first. A list past its `NextUpdate` is expired and anchors nothing (ETSI TS 119 602 V1.1.1 §6.3.15). A withdrawn service anchors nothing either. The public demo holds at most 20 added providers and 5 added lists.

#### List of trusted lists

`/api/trustlists/lists` is a list of trusted lists (ETSI TS 119 602 V1.1.1 §6.3.13). Its type is `https://eudi-test.dev/LoTEType/ListOfTrustedLists`. It points to every list of the wallet and to every readable external list. Each pointer has the list's location, the certificate of its signer, and the list type, scheme operator name, scheme territory and MIME type as qualifiers:

```json
{
  "LoTELocation": "https://localhost:8086/api/trustlists/pid",
  "ServiceDigitalIdentities": [{ "X509Certificates": [{ "val": "MIIC..." }] }],
  "LoTEQualifiers": [{
    "LoTEType": "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
    "SchemeOperatorName": [{ "lang": "en", "value": "EUDI Dev Wallet" }],
    "SchemeTerritory": "EU",
    "MimeType": "application/jwt"
  }]
}
```

The wallet follows the pointers of an external list of this type, one level deep. A pointed-to list must be signed by a certificate of its pointer (§6.3.13). `GET /api/trust` shows such a list with `via`. To trust all lists of another eudi-dev wallet at once, add its `/api/trustlists/lists`. That list is signed under the other wallet's CA. Start this wallet with `--trusted-list-ca` set to that CA.

`wallet serve` reuses persisted issuer and status list URLs unless `--base-url` or `--docker` overrides them. Credentials generated earlier then keep resolving against the same endpoints. Issuance with `issue ... --wallet` follows the same rule. Both print a note when no running server serves the embedded URLs.

The startup banner warns about a persisted Docker hostname outside Docker. It also warns about stored credentials whose issuer or status list URLs are not served by this server. Those credentials fail validation and status checks until they are issued again.

Each list is served at `/api/trustlists/{id}`:

- `pid`, `qeaa`, `pub-eaa` and `eaa` for the categories
- `wallet-provider` for the Wallet Provider list (issuers verify the wallet attestation against it)
- `access-ca` and `registrar` for the providers of relying party certificates
- `lists` for the list of trusted lists
- `tl-<8 hex digits>` for a credential type with its own trusted list fields, such as `--trusted-list-type`

`eudi trust list` shows these lists for the selected local or remote wallet:

```
LIST             DEFAULT  CATEGORY                    PATH
pid              yes      Credential providers        /api/trustlists/pid
qeaa                      Credential providers        /api/trustlists/qeaa
pub-eaa                   Credential providers        /api/trustlists/pub-eaa
eaa                       Credential providers        /api/trustlists/eaa
wallet-provider           Wallet providers            /api/trustlists/wallet-provider
access-ca                 Relying party certificates  /api/trustlists/access-ca
registrar                 Relying party certificates  /api/trustlists/registrar

List of trusted lists: https://localhost:8086/api/trustlists/lists
```

With `--json` it prints the `/api/trust` body with the `/api/trustlists` entries under `trust_lists`.

`/api/trustlists` lists them for API clients. Each entry includes:

- `id`, for example `pid` or `eaa`
- `path`, for example `/api/trustlists/pid`
- `advertised_url` when the wallet has an issuer URL configured, for example `https://localhost:8086/api/trustlists/pid`
- `url`, an alias for `advertised_url`

Clients that call the wallet through Docker port mappings, reverse proxies, or Testcontainers should resolve `path` against the URL of their `/api/trustlists` request. `advertised_url` is the configured publication URL of the wallet. It can differ from the request URL.

`/api/trustlist` selects a list by credential type:

- without parameters it returns the PID list
- `vct` and `doctype` select the list for a credential type

Examples:

- `/api/trustlists/pid`
- `/api/trustlists/eaa`
- `/api/trustlist?vct=urn:eudi:pid:1`
- `/api/trustlist?doctype=org.iso.23220.photoid.1`

Example discovery response:

```json
{
  "trust_lists": [
    {
      "id": "pid",
      "default": true,
      "path": "/api/trustlists/pid",
      "advertised_url": "https://localhost:8086/api/trustlists/pid",
      "url": "https://localhost:8086/api/trustlists/pid",
      "loTEType": "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList"
    },
    {
      "id": "eaa",
      "default": false,
      "path": "/api/trustlists/eaa",
      "advertised_url": "https://localhost:8086/api/trustlists/eaa",
      "url": "https://localhost:8086/api/trustlists/eaa",
      "loTEType": "https://eudi-test.dev/LoTEType/EAAProvidersList"
    },
    {
      "id": "wallet-provider",
      "default": false,
      "path": "/api/trustlists/wallet-provider",
      "advertised_url": "https://localhost:8086/api/trustlists/wallet-provider",
      "url": "https://localhost:8086/api/trustlists/wallet-provider",
      "loTEType": "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList"
    }
  ]
}
```

The example leaves out the `qeaa`, `pub-eaa`, `access-ca` and `registrar` entries.

`--register` also registers OS URL scheme handlers. `openid4vp://`, `eudi-openid4vp://`, `haip-vp://`, `eu-eaap://`, `openid-credential-offer://`, `haip-vci://` and `eu-eaa-offer://` links then open the wallet on macOS and Linux. On Windows, `--register` is a no-op.

```bash
eudi wallet serve
eudi wallet serve --port 9000 --auto-accept
eudi wallet serve --pid --credential extra.txt
eudi wallet serve --register           # also register URL scheme handlers using the current interactive/auto-accept mode
eudi wallet serve --register --port 9000
eudi wallet serve -d                   # run in the background (stop with `eudi wallet kill`)
EUDI_DEV_PORT=9000 EUDI_DEV_AUTO_ACCEPT=true eudi wallet serve
```

Every flag can also be set as `EUDI_DEV_<FLAG>`, with the flag name in upper case and underscores for dashes. A flag on the command line wins. A repeatable flag takes comma-separated values. An `EUDI_DEV_` variable that matches no flag stops the server at start (see [configuration by environment](../docker.md#configuration-by-environment)).

| Flag                    | Default  | Description                                      |
|-------------------------|----------|--------------------------------------------------|
| `--port`                | `8085`   | Server port                                      |
| `--listen`              | `$EUDI_DEV_LISTEN`, else `127.0.0.1` | IP address to bind. `0.0.0.0` opens the wallet to the network. See [listen address](#listen-address) |
| `--auto-accept`         | `false`  | Approve presentations and credential offers without asking. Without it, only interactive channels (web invocation URLs, scheme dispatches, browser DC-API) show the consent dialog. API submissions (`POST /api/offers`, `/api/presentations`) always auto-accept because the API call counts as consent (opt in per request with `"interactive": true`). With `--demo` only the flag turns it on (not `EUDI_DEV_AUTO_ACCEPT`) |
| `--credential`          | None     | Import credential from file (repeatable)         |
| `--credentials`         | None     | Credentials to add on every start, from a YAML or JSON file, a directory of such files, or stdin (`-`). See [startup credentials](#startup-credentials) |
| `--catalog`             | None     | Attestation types to pre-register in the catalogue on every start, from a YAML or JSON file, a directory of such files, or stdin (`-`). See [pre-registered catalogue entries](#pre-registered-catalogue-entries) |
| `--relying-parties`     | None     | Relying parties to register with the wallet's registrar on every start, from a YAML or JSON file, a directory of such files, or stdin (`-`). See [pre-registered relying parties](#pre-registered-relying-parties) |
| `--templates-dir`       | `<wallet-dir>/templates/` | Credential template directory. Template files are JSON or YAML. See [template files](../templates.md#template-files-and-storage) |
| `--pid`                 | `false`  | Generate default EUDI PID credentials on start   |
| `--key`                 | None     | Override holder key (PEM/JWK)                    |
| `--issuer-key`          | None     | Issuer key for generated PIDs (PEM/JWK)          |
| `--mode`                | `debug`  | Validation mode: `debug` or `strict`             |
| `--storage`             | `file`   | Storage backend: `file`, `memory`, `auto` or a `postgres://` URL. `$EUDI_DEV_STORAGE` when set (see [storage backends](../wallet.md#storage-backends)) |
| `--seed`                | None     | Derive the generated keys from this string. `auto` seeds the memory backend only. `$EUDI_DEV_SEED` when set (see [seeded keys](../wallet.md#seeded-keys)) |
| `--session-transcript`  | `oid4vp` | mdoc session transcript mode: `oid4vp` or `iso`  |
| `--register`            | `false`  | Register OS URL scheme handlers                  |
| `--no-register`         | `false`  | Skip URL scheme registration (overrides --register) |
| `--tls-verify` | mode default | Verify HTTPS certificates (`true` in strict mode, `false` in debug mode) |
| `--tls-ca` | None | PEM CA bundle added to system trust for outbound HTTPS |
| `--http-proxy` | `$HTTP_PROXY` | Forward proxy for outbound `http://` requests |
| `--https-proxy` | `$HTTPS_PROXY` | Forward proxy for outbound `https://` requests |
| `--no-proxy` | `$NO_PROXY` | Hosts, domains and CIDRs that bypass the proxy |
| `--allow-private-networks` | `$EUDI_DEV_ALLOW_PRIVATE_NETWORKS`, else `false` | Let outbound requests reach private networks. With `--demo` it also opens loopback. See [outbound address limits](#outbound-address-limits) |
| `--key-attestation-level` | Issuer requirements | Test claims for key storage and user authentication: issuer requirements (default), `none`, or a level such as `iso_18045_high`. Change it in the Conformance panel. See [key attestation claims](#key-attestation-claims) |
| `--preferred-format`    | None     | Preferred credential format when multiple match: `dc+sd-jwt`, `mso_mdoc`, or `jwt_vc_json`. Change it at runtime with `PUT /api/config/preferred-format` |
| `--status-list`         | `false`  | Embed status list references in generated credentials |
| `--base-url`            | None     | Public URL of the wallet, optionally with a path prefix (see [reverse proxy setup](../reverse-proxy.md)). An https base URL is used as the issuer URL (external TLS terminator). An http base URL derives a self-signed HTTPS issuer URL on port+1. Existing persisted issuer URLs are reused unless this flag is set |
| `--docker`              | `false`  | Use `host.docker.internal` instead of `localhost` when deriving new HTTP and HTTPS wallet endpoint URLs. The server then binds `0.0.0.0` unless `--listen` sets another address |
| `--vci-client-id`       | Wallet origin | Client ID for OID4VCI authorization code flows |
| `--vci-redirect-uri`    | Wallet origin + `/callback` | Redirect URI for OID4VCI authorization code flows |
| `--vci-version`         | `1.0`    | OpenID4VCI feature level of the wallet as a client: `1.0` (the published version) or `1.1` (also uses 1.1 draft features when the issuer supports them). See [OpenID4VCI feature level](issuing.md#openid4vci-feature-level) |
| `--haip`                | `false`  | Check incoming presentations and credential offers against HAIP 1.0. `--mode` sets how violations are handled. Strict aborts the flow. Debug reports the violation and continues |
| `--arf`                 | `false`  | Check the access and registration certificates of verifiers and issuers against the ARF (see [verifiers](presenting.md#arf-checks) and [issuers](issuing.md#arf-checks)). With `--mode strict` the wallet refuses the request or the offer on any finding |
| `--relying-party-ca`    | None     | PEM file with CA certificates that issue relying party access and registration certificates. The wallet puts them on its `access-ca` and `registrar` lists (repeatable) |
| `--trusted-list-ca`       | None     | PEM file with CA certificates of trusted list operators. With `--arf` the wallet also accepts trusted lists signed under these CAs (repeatable) |
| `--trusted-list`        | None     | URL of an external list of trusted entities for the [list of trusted lists](#list-of-trusted-lists) (repeatable) |
| `--client-attestation`  | `false`  | Send the wallet attestation on OID4VCI token requests even when the issuer does not advertise `attest_jwt_client_auth` (see [wallet attestation](issuing.md#wallet-attestation)) |
| `--adhoc-display-images` | `false` | Fetch HTTPS display images on demand instead of storing them. The issuer sees each render. See [display images](#display-images) |
| `--require-encrypted-request` | `false` | Refuse an unencrypted Request Object. The wallet always sends an encryption key in `wallet_metadata`, so this requires the Verifier to use it |
| `--demo`                | `false`  | Public demo profile: implies `--pid`, `--mode debug`, `--haip`, `--arf` and `--vci-version 1.1` (all overridable), disables process and filesystem endpoints, blocks fetches to loopback and private networks unless `--allow-private-networks` is given. Browser flows keep the consent dialog unless `--auto-accept` is on the command line. API flows auto-accept (see [public demo hosting](../public-demo.md)) |
| `--demo-issuer-client-auth` | `required` | Client authentication required by the authorization server of the built-in demo issuer at its PAR and token endpoints: `required` (HAIP 1.0 §4.4.1) or `optional` (also accepts wallets without a wallet attestation). See [public demo hosting](../public-demo.md) |
| `--demo-verifier-issuer-ca` | None | PEM file with extra issuer CA certificates for the demo verifier, in addition to the providers on the wallet's trusted lists. The flag is repeatable. Use it for credentials issued outside this wallet, such as in an OIDF conformance suite run |
| `--serve-tls`           | `false`  | Serve an https `--base-url` locally with the wallet's own TLS certificate instead of expecting an external TLS terminator. Requires an https base URL with an explicit port. The wallet also keeps listening on the HTTP port |
| `--demo-reset`          | `1h`     | Schedule for restoring the demo baseline: an interval (`24h`), a daily wall-clock time (`00:00`), or one with a timezone (`"00:00 Europe/Berlin"`). `0` disables. Requires `--demo` |
| `--imprint-file`        | None     | HTML snippet with the operator's legal notice, served at `/imprint` |
| `--log-format`          | `text`   | Console output format: `text` or `json` (one JSON record per line). See [JSON logs](#json-logs) |
| `--news-file`           | None     | HTML snippet with news for visitors, shown once in a popup and linked from the footer. Requires `--demo` |
| `--demo-consent-api`    | `false`  | Let API and CLI clients answer consent requests. By default only the web UI answers them, so a client doesn't answer another visitor's request by mistake. Requires `--demo` |
| `-d, --detached`        | `false`  | Run the server as a background process and return once it responds. Output goes to `<wallet-dir>/serve.log`. Stop it with `wallet kill` |

## Startup credentials

`--credentials` adds credentials on every start. It reads a YAML or JSON file, every `.yaml`, `.yml` and `.json` file of a directory (in name order), or stdin with `-`. An entry either issues a credential from a [template](../templates.md) or imports a finished one. A file can mix both.

```yaml
credentials:
  - id: employee-alice
    template: employee-card
    claims:
      employee_id: E-2
      department: Sales
  - id: erika
    template: german-pid-sdjwt
    claims:
      birthdate: 1970-01-31
    exp: 2160h
  - id: partner-ticket
    credential: eyJhbGciOiJFUzI1NiIs...~WyJ...~
```

`employee-card` is a user template saved beforehand (see [templates](../templates.md#cli)). `german-pid-sdjwt` is a built-in one.

| Field | Description |
|-------|-------------|
| `id` | Credential ID in the wallet, the API and the UI selectors. It starts with a letter or digit and holds letters, digits, `.`, `_` and `-`. Unique across all files |
| `template` | Template name or file path. The fields below override its defaults |
| `format` | `sdjwt`, `jwt` or `mdoc` (default the template's format) |
| `claims` | Claims merged over the template's claims |
| `always_disclosed` | Claims issued without selective disclosure, in addition to the template's list |
| `omit` | Top-level template claims to leave out |
| `exp` | Expiry as a Go duration (default the template's `exp`) |
| `display` | Card appearance, with the fields of the template's `display` |
| `protected` | `true` keeps visitors from deleting or revoking the credential. Default `true` with `--demo`, `false` otherwise |
| `credential` | A finished SD-JWT VC, JWT VC or mdoc to import instead of a template |

Every start adds the entries again. Template entries get fresh dates. A credential from an earlier start with the same `id` is replaced, so the wallet holds one copy of each entry. Its revocation status resets with each start.

Only one of `--credentials`, `--catalog` and `--relying-parties` can read stdin. A detached server (`-d`) can't read stdin.

With `--demo` the startup credentials are part of the baseline, so a demo reset restores them with the default PIDs. For a demo where visitors can delete every credential, set `protected: false` on the entries and turn off the default PIDs:

```bash
eudi wallet serve --demo --pid=false --credentials demo-credentials.yaml
```

## Pre-registered catalogue entries

`--catalog` adds attestation types to the [attestation catalogue](registrar.md#attestation-catalogue) on every start. It reads a YAML or JSON file, every `.yaml`, `.yml` and `.json` file of a directory (in name order), or stdin with `-`. A file holds one entry or a list of entries. An entry has the shape that `POST /api/catalog/attestations` takes.

```yaml
- name: University diploma
  category: qeaa
  credentials:
    - format: dc+sd-jwt
      type: urn:example:diploma:1
      claims: [[degree], [graduation_date]]
    - format: mso_mdoc
      type: org.example.diploma.1
      claims: [[org.example.diploma.1, degree]]
  schema:
    rulebookURI: https://university.example/rulebook
    attestationLoS: iso_18045_moderate
  issuerCA: university-ca.pem
- name: Library card
  credentials:
    - format: dc+sd-jwt
      type: urn:example:library:1
```

| Field | Description |
|-------|-------------|
| `name` | Name of the attestation type. Unique in the catalogue. The entry's id derives from it |
| `category` | `pid`, `qeaa`, `pub-eaa` or `eaa` (default `eaa`) |
| `credentials` | One `dc+sd-jwt` and one `mso_mdoc` format at most, each with its `type` (vct or doctype) and optional claim paths |
| `schema` | TS11 SchemaMeta fields: `rulebookURI`, `attestationLoS`, `bindingType`, `version` and `trustedAuthorities`. The defaults are those of `eudi catalog add` |
| `issuerCA` | PEM file with the CA of your issuer, relative to the catalogue file. The wallet puts it on the trusted list of the category, like `catalog add --issuer-ca`. It can't go with `trustedAuthorities` |

The wallet checks every entry before it starts. An invalid entry stops the start. So does an entry that reuses the name or a type of a template entry or of another entry in the files. The error message shows the file and the entry. An entry added through the UI, the API or `eudi catalog add` doesn't stop the start. The file's entry replaces it.

Each start loads the file again. An entry keeps its id, so a restart adds no duplicates. A changed entry is updated. An entry removed from the file leaves the catalogue at the next start. The wallet marks these entries as pre-registered and removes only those. Entries added through the UI, the API or `eudi catalog add` stay. The only exception is an entry with the name or a type of an entry in the file. The file's entry replaces it. A CA added through `issuerCA` stays on its list when you remove the entry. Remove it with `eudi trust rm-ca`.

Outside the demo you can change or delete a pre-registered entry. The next start restores it from the file. With `--demo` visitors can't change or delete these entries, and a demo reset restores them with their CAs.

## Pre-registered relying parties

`--relying-parties` registers verifiers and issuers with the wallet's [registrar](registrar.md) on every start. It reads files the same way as `--catalog`. A file holds one registration or a list. A registration has the shape that `POST /api/registrar/wrp` takes (see the [registrar API walkthrough](registrar-api.md)).

```yaml
identifier:
  - identifier: NLTEST.00000042
tradeName: Example Shop
legalPerson:
  legalName: ["Example Shop B.V."]
services:
  - serviceIdentifier: checkout
    intendedUses:
      - intendedUseIdentifier: age-check
        purpose:
          - lang: en
            content: Check that you are of age
        credentials:
          - format: dc+sd-jwt
            meta:
              vct_values: [urn:eudi:pid:1]
            claims:
              - path: [birthdate]
```

The file must set the `identifier` of each party and the `intendedUseIdentifier` of each intended use. The certificates contain them, so they have to stay the same on every start. The registrar fills in the other defaults, as for an API request. An invalid registration stops the start, and the error message shows the file.

Each start registers the parties again, also with memory storage. Each start also issues a registration certificate for every intended use and every issuer service. With file or Postgres storage, valid certificates are kept. The registration certificates show in the UI and in `GET /api/registrar/registration-certificates?identifier=<identifier>`. An access certificate needs the party's own key. Get it with **Issue access certificate** in the relying parties list or from the registrar API. With [seeded keys](../wallet.md#seeded-keys), certificates issued before a restart still verify.

When the stored registration differs from the file, the next start replaces it with the file's version. A service that lists attestation types without a provider entitlement gets the entitlement of each type's category. The category comes from `--catalog` and the templates. A type outside them counts as a PID when its name says so, and as an EAA otherwise. Catalogue entries added by visitors don't change these entitlements. A registration removed from the file stays registered. With `--demo` visitors can't change or delete these registrations, and a demo reset registers them again.

As with every flag, the environment variable is `EUDI_DEV_RELYING_PARTIES`.

## Key attestation claims

`--key-attestation-level` sets the test claims `key_storage` and `user_authentication` (OpenID4VCI Appendix D.2). By default they match the issuer's requirements. `none` omits both claims. A level such as `iso_18045_high` sets both explicitly. The Conformance panel can change this at runtime.

These claims describe simulated protection levels. Keys are stored unencrypted. See [SECURITY.md](../../SECURITY.md).

## Display images

By default, the wallet fetches display images once and stores them. `--adhoc-display-images` keeps HTTPS logo and background URLs from issuer metadata and fetches them on each card render. The wallet stores no HTTPS image.

Data URIs, template images and HTTP URLs are stored in both modes. Storing HTTP images avoids mixed content on an HTTPS page. `GET /api/config` reports the setting as `adhoc_display_images`. A public demo stores every image.

## `trust show`

Prints a trusted list of the wallet (ETSI TS 119 602) as a signed JWT. It contains the signing certificates, provider CAs and status signing certificates of the selected list. Verifiers use its provider CAs to validate the `x5c` or `x5chain` embedded in credentials. Issuer authorization data such as provider entitlements and `providesAttestations` comes from signed `/.well-known/openid-credential-issuer` metadata and `/api/registrar/wrp`. See [test certificates](../test-certificates.md).

Without arguments it prints the PID list, like `/api/trustlist`. A list ID, `--vct` or `--doctype` selects another list. The IDs are `pid`, `qeaa`, `pub-eaa`, `eaa`, `wallet-provider`, `access-ca`, `registrar` and the `tl-` IDs of custom lists. `trust list` shows all lists of the wallet. `trust show lists` prints the list of trusted lists (also at `/api/trustlists/lists`).

Pipe the output to a file or pass it to `validate --trusted-list`. `--url` prints only the URL for a running wallet server.

```bash
eudi trust show                          # Print the trusted list JWT
eudi trust show > trustlist.jwt          # Save to file
eudi trust show --url                    # http://localhost:8085/api/trustlist
eudi trust show pid --url                # http://localhost:8085/api/trustlists/pid
eudi trust show eaa --url                # http://localhost:8085/api/trustlists/eaa
eudi trust show --doctype org.iso.23220.photoid.1 --url
eudi trust show --url --port 9000        # http://localhost:9000/api/trustlist
eudi trust show --url --docker           # http://host.docker.internal:8085/api/trustlist
```

| Flag       | Default | Description                                        |
|------------|---------|----------------------------------------------------|
| `--url`    | `false` | Print only the trusted list URL (for a running server) |
| `--vct`    | None    | Select the trusted list covering this SD-JWT `vct`    |
| `--doctype`| None    | Select the trusted list covering this mdoc `docType`  |
| `--port`   | `8085`  | Wallet server port (used with --url)                |
| `--docker` | `false` | Use `host.docker.internal` instead of `localhost` (used with --url) |

## `trust ca-cert`

Loads or creates the shared root CA certificate and prints exactly one PEM certificate. Wallets under the same parent directory use this root for their signing and HTTPS certificate chains. Provider chains include an intermediate CA. Trusted lists publish the relevant service certificates and provider CAs.

`--jwks` exports the certificate as a JWKS document. It contains the certificate's public key as a JWK with `kid`, `alg`, `use`, the certificate chain in `x5c`, and the leaf hash in `x5t#S256`.

```bash
eudi trust ca-cert
eudi trust ca-cert --out wallet-ca-cert.pem
eudi trust ca-cert --jwks
```

On a running wallet server the same export is available as `GET /api/certificates/ca` (`?format=jwks` for JWKS). See [Certificate export](http-api.md#certificate-export).

| Flag     | Default | Description |
|----------|---------|-------------|
| `--out`  | None    | Write the shared wallet CA certificate to a file instead of stdout |
| `--pem`  | `false` | Output as PEM (the default when no format flag is set) |
| `--jwks` | `false` | Output as JWKS (public key with `x5c` chain) |

## Registrar

The wallet runs a relying party registrar. It registers relying parties and issues their access and registration certificates. See [registrar](registrar.md).

## `wallet tls-cert`

Loads or creates the HTTPS leaf certificate of the wallet's HTTPS endpoints and prints exactly one PEM certificate. To export the shared trust root, use `trust ca-cert`.

```bash
eudi wallet tls-cert
eudi wallet tls-cert --out wallet-tls-cert.pem
eudi wallet tls-cert --docker --out wallet-tls-cert.pem
eudi wallet tls-cert --base-url http://wallet:8085 --out wallet-tls-cert.pem
eudi wallet tls-cert --jwks
```

Pass the same `--port`, `--docker`, and `--base-url` flags as to `wallet serve`. The exported certificate then matches the certificate of the running wallet.

On a running wallet server the same export is available as `GET /api/certificates/tls` (`?format=jwks` for JWKS). It always matches the running server's HTTPS wallet host. See [Certificate export](http-api.md#certificate-export).

| Flag         | Default | Description |
|--------------|---------|-------------|
| `--out`      | None    | Write the certificate to a file instead of stdout |
| `--port`     | `8085`  | Wallet server port (certificate will match HTTPS wallet endpoints on `port+1`) |
| `--docker`   | `false` | Use `host.docker.internal` instead of `localhost` when deriving the HTTPS wallet host |
| `--base-url` | None    | Base URL used to derive the HTTPS wallet host |
| `--pem`      | `false` | Output as PEM (the default when no format flag is set) |
| `--jwks`     | `false` | Output as JWKS (public key with `x5c` chain) |

## `wallet register` / `wallet unregister`

Registers (or removes) OS-level URL scheme handlers for `openid4vp://`, `eudi-openid4vp://`, `haip-vp://`, `eu-eaap://`, `openid-credential-offer://`, `haip-vci://` and `eu-eaa-offer://` links.

The handler starts a local `wallet serve` instance when none is running and forwards the incoming URI to it. If a UI tab is open, the wallet notifies it over the event stream. Otherwise it opens the UI with the request ID in the URL, and that tab handles the request.

With `--auto-accept`, the handler processes URLs without opening the UI. It POSTs to a running `wallet serve` instance or runs `wallet accept` if that fails.

- **macOS**: Creates an AppleScript `.app` bundle in `~/Applications/` and registers via Launch Services
- **Linux**: Writes a hidden desktop entry, `~/.local/share/applications/dev.eudi.wallet.desktop`, and makes it the default handler of the schemes in `~/.config/mimeapps.list`. A clicked link runs `eudi wallet open-url <uri>`. This works with every desktop that follows the freedesktop.org standards, such as GNOME, KDE, XFCE, Cinnamon and MATE, and with `xdg-open` under a window manager. `register` warns when something is missing (see below)
- **Other platforms**: `register` / `unregister` are accepted as no-ops. Use `wallet accept <uri>` instead

```bash
eudi wallet register               # Register URL handlers and open the wallet UI by default
eudi wallet register --auto-accept # Keep URL handling silent / background-only
eudi wallet register --port 9000   # Use custom listener port
eudi wallet unregister             # Remove URL handlers
```

`wallet register` has no flags of its own. It takes `wallet serve` flags, stores them and replays them as `wallet serve ...` when a clicked link has to start the wallet. The handler also reads two of them:

| Flag            | Default | Effect on the handler                                                   |
|-----------------|---------|-------------------------------------------------------------------------|
| `--port`        | `8085`  | Port of the running wallet. The handler tries it first and then falls back to the CLI |
| `--auto-accept` | `false` | Handle incoming URLs without opening the wallet UI                      |

### URL scheme handlers on Linux

Browsers ask once before they open a link with a custom scheme. Firefox then asks the desktop for the default handler. Chrome and Chromium use the desktop portal or `xdg-open`. Snap browsers, the default on Ubuntu, may only open the scheme when `xdg-mime` names its default handler. Flatpak browsers go through the desktop portal.

`register` warns when:

- there is no graphical session (`DISPLAY` and `WAYLAND_DISPLAY` are unset). Nothing can click a link there.
- `xdg-open` or `xdg-mime` is missing. Install `xdg-utils` for Chrome, Chromium and snap browsers.
- `~/.config/mimeapps.list` is a link, for example from home-manager on NixOS. `register` leaves it alone and prints the lines to add to that configuration.
- the path of `eudi` contains spaces or special characters. `xdg-open` under a bare window manager can't run such a path.

A desktop-specific file such as `~/.config/kde-mimeapps.list` overrides `mimeapps.list`. If it names another handler for one of the schemes, `register` changes that entry too.

Without a desktop environment, `xdg-open` uses the scheme handlers only when `DISPLAY` or `WAYLAND_DISPLAY` is set. Under a window manager without the desktop portal, a Flatpak browser needs a portal backend such as `xdg-desktop-portal-gtk`.

The handler logs to `~/.eudi-dev/url-handler.log`. A wallet started by the handler logs to `~/.eudi-dev/url-handler-server.log`.

## HTTPS certificate verification

Strict mode verifies server certificates for every outbound HTTPS request. Debug mode skips verification by default. `--tls-verify=true` or `--tls-verify=false` overrides either default, including for local endpoints and redirects.

`--tls-ca dev-ca.pem` adds CA certificates to system trust. The wallet also trusts its own CA, which signs the certificate of its HTTPS listener. So the demo verifier can check the status lists of credentials issued by the wallet. Server certificates must also match the hostname and be within their validity dates. Credential and request object signatures are checked separately.

```bash
eudi wallet serve --mode strict --tls-ca dev-ca.pem
eudi wallet serve --mode strict --tls-verify=false
eudi wallet serve --mode debug --tls-verify=true
```

A running wallet uses its own TLS settings. Set them with its startup flags, in the Conformance panel, or through `PUT /api/config/conformance`.

## Outbound proxy

If issuers and verifiers are only accessible through a forward proxy, set the standard proxy environment variables or the matching flags:

```bash
HTTPS_PROXY=http://proxy.corp:3128 NO_PROXY=.corp.example eudi wallet serve
eudi wallet serve --https-proxy http://proxy.corp:3128 --no-proxy .corp.example
```

| Variable | Flag | Used for |
|----------|------|----------|
| `HTTPS_PROXY` | `--https-proxy` | Requests to `https://` URLs (almost all issuers and verifiers) |
| `HTTP_PROXY` | `--http-proxy` | Requests to `http://` URLs |
| `NO_PROXY` | `--no-proxy` | Hosts to connect to directly: a comma separated list of host names, domain suffixes such as `.corp.example`, IP addresses and CIDR ranges. `*` disables the proxy for all hosts |

A flag overrides the matching variable. Lowercase variable names work too. Proxy URLs can use `http`, `https`, `socks5` or `socks5h`. A URL without a scheme, such as `proxy.corp:3128`, uses `http`.

Requests to local hosts always bypass the proxy. A local host is `localhost`, any address in `127.0.0.0/8`, `::1` or `host.docker.internal`, in any letter case.

The wallet verifies the issuer or verifier certificate through the proxy too. If your proxy intercepts TLS traffic, add its CA with `--tls-ca` or disable verification with `--tls-verify=false`.

A running wallet uses its startup proxy settings. `wallet accept` and `wallet scan` therefore reject proxy flags when they forward a request to a running wallet. Set them on `wallet serve` instead.

## Listen address

The wallet, the decoder and the proxy have no authentication. So they bind `127.0.0.1` by default and only this machine reaches them. `--listen` picks another IP address. `0.0.0.0` binds every interface, IPv6 included where the system supports it. `::1` binds IPv6 loopback only. `localhost` stands for `127.0.0.1`.

```bash
eudi wallet serve --listen 0.0.0.0     # reachable from the network
EUDI_DEV_LISTEN=0.0.0.0 eudi decoder
```

The flag wins over `EUDI_DEV_LISTEN`. The [Docker image](../docker.md) sets the variable to `0.0.0.0`, so published ports reach every server in the container. `--docker` also binds `0.0.0.0` when neither the flag nor the variable is set. On Linux, `host.docker.internal` reaches the host on the Docker bridge, not on loopback. The wallet and the proxy print a note when they bind more than loopback.

The printed URLs stay on `localhost` for a loopback or wildcard address. A server bound to one other address prints that address. The wallet then needs a `--base-url` with that address too, because it builds its own URLs on `localhost` otherwise.

## Outbound address limits

Visitors give the wallet URLs (credential offers, request URIs and the URLs inside them). So the wallet connects only to public addresses and to loopback by default. Loopback covers the usual setup with wallet, issuer and verifier on one machine. The wallet refuses private (RFC 1918), link local, CGNAT, unique local, unspecified and multicast addresses. It also refuses the other special purpose ranges, such as reserved, documentation and benchmarking addresses, and the IPv6 ranges that embed an IPv4 address (NAT64, 6to4 and Teredo). Link local includes cloud metadata endpoints. The check runs on the resolved address of every connection, redirects included.

Some destinations come from the operator, so the wallet always reaches them at their exact address and port. These are the wallet's own origins, the `--trusted-list` URLs and the forward proxy.

Issuers and verifiers on a LAN, in Docker or in a cluster sit on private networks. Start the wallet with `--allow-private-networks` to reach them, or set `EUDI_DEV_ALLOW_PRIVATE_NETWORKS=true`. The flag wins over the variable. The [Docker image](../docker.md) sets the variable.

A proxied request connects only to the proxy. The proxy then connects to the destination. Only the proxy decides which addresses that request reaches.

`--demo` connects to public addresses and the operator's destinations only. `--allow-private-networks` or the variable lets a demo reach private networks and loopback too. The wallet then prints a warning at start, because any visitor can make it call local and internal services. An internet-facing demo sets `EUDI_DEV_ALLOW_PRIVATE_NETWORKS=false` (see [public demo hosting](../public-demo.md#outbound-connections)).

## JSON logs

`--log-format json` (or `EUDI_DEV_LOG_FORMAT=json`) prints every line of console output as one JSON record on stdout. This includes the startup summary, the request log and warnings:

```json
{"time":"2026-10-03T18:56:44.53+02:00","level":"WARN","msg":"OID4VP 1.0 §5.2: nonce is required"}
{"time":"2026-10-03T18:56:44.61+02:00","level":"INFO","msg":"Encrypting response: response_mode=direct_post.jwt","component":"VP"}
```

`level` is `WARN` or `ERROR` for warning and error lines and `INFO` otherwise. `component` identifies the part of the wallet that logged the line, such as `VCI`, `VP`, `DCQL` or `Demo issuer`. A multi-line entry, such as a token response, stays one record. The default `text` prints the colored console output.

## Conformance settings at runtime

**Local wallets** can change the validation mode, HTTPS certificate verification, the HAIP and ARF checks, whether request objects must be encrypted, the [OpenID4VCI version](issuing.md#openid4vci-feature-level) and the key attestation level (see [SECURITY.md](../../SECURITY.md)) at runtime. They do this in the **Conformance** panel or through `PUT /api/config/conformance`. The mdoc session transcript is set at startup. `PUT /api/config/preferred-format` changes the [preferred format](http-api.md#preferred-credential-format). Changes apply to every flow until the process restarts. `DELETE /api/config/conformance` restores startup settings.

**The public demo** runs the HAIP and ARF checks in debug mode. Violations are warnings and the flow continues. `PUT` and `DELETE /api/config/conformance` return `403`.

`eudi wallet config` (alias of `wallet info`) reports the active fields for a local or remote wallet.
