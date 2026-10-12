[← Wallet](../wallet.md)

# Serving the wallet

`wallet serve` runs the persistent wallet HTTP server (web UI, OID4VP and OID4VCI endpoints, trust lists, optional URL scheme handling). This page also covers the certificate exports (`ca-cert`, `tls-cert`), the `trust-list` command, URL scheme registration (`register`, `unregister`), and the runtime conformance settings.

## `wallet serve`

Starts the wallet HTTP server with a UI for managing credentials and running OID4VP/OID4VCI flows. It loads credentials from the selected storage backend, saves changes and logs requests. Interactive requests show a consent dialog.

The server exposes:

- Web UI for credential management and consent (list, show, import, remove, and issue credentials, with credential templates and CA and TLS certificate downloads)
- OID4VP authorization endpoint (`/authorize`)
- OID4VCI credential offer endpoint (`/credential-offer`). Accepts `credential_offer` / `credential_offer_uri` query parameters. Offer links can use the wallet URL in place of a custom scheme (see [Invoking the wallet by URL](presenting.md#invoking-the-wallet-by-url))
- Legacy ETSI trust list endpoint (`/api/trustlist`). Use this URL as `--trust-list` when validating PID credentials issued by the wallet
- Trust list index endpoint (`/api/trustlists`) with one JWT endpoint per trust list profile
- HTTPS wallet endpoints on the wallet's effective issuer URL, including `/.well-known/jwt-vc-issuer`, `/.well-known/openid-credential-issuer`, `/api/trustlist`, `/api/trustlists`, `/api/statuslist`, and `/api/registrar/wrp`
- A management API mirroring the wallet CLI (list, show, import, and remove credentials, issue credentials, generate PIDs, export certificates). It has no authentication (see [HTTP API](http-api.md))

The offer consent dialog shows the issuer, the issuance flow and any required transaction code. It also shows each credential's format, type, display name, description and claims if the issuer metadata has them.

For `credential_offer_uri`, the wallet fetches the offer for the dialog and again on approval (OpenID4VCI 1.0 §4.1.3). If the issuer serves the offer only once, issuance uses the copy shown in the dialog and logs the failed second fetch. If the first fetch fails, the dialog shows the issuer from the URI and approval retries the fetch.

If the offer requires a transaction code and none is given, issuance fails before the wallet uses the pre-authorized code. This applies to API callers and to `--auto-accept` too. The error gives the required code length and input mode.

After storing a credential, the wallet calls the issuer's Notification Endpoint if the issuer publishes one. The endpoint is optional (OpenID4VCI 1.0 §11). A rejected call logs a warning and the credential stays in the wallet. The warning quotes the response and compares it with §11.3 (an Authorization Error Response for a rejected token, a 400 for a bad `notification_id`).

The consent dialog for a presentation request also shows the purpose the verifier registered. The wallet reads it from the wallet-relying-party registration certificate (typ `rc-wrp+jwt`, in a `verifier_info` entry of format `registration_cert`) per OpenID4VP 1.0 §5.1. If the certificate signature does not verify against its own x5c leaf, the wallet skips the certificate and logs a warning in the activity log. The built-in demo verifier and demo issuer send a registration certificate with every request.

The presentation dialog starts with the wallet's automatic credential selection. If there are alternatives, **Edit** lets the user choose a credential-set option and a credential for each query. Changes apply immediately. **Done** returns to the summary, and **reset to auto** restores the automatic selection. Claim checkboxes apply to the selected credential. **Deny** and **Approve** apply to the whole presentation. Auto-accept submits the automatic selection without a dialog.

If the verifier sets `multiple: true` on a query, all matching credentials are selected. **Edit** can deselect them. At least one stays selected.

API clients receive the alternatives in `credential_options`. Send `picks` (query ID to credential ID, or to a list of credential IDs when the query has `"multiple": true`), `set_choices` (option index per set, or `-1` to skip an optional set) and `selected_claims` to `POST /api/requests/{id}/approve`. An invalid selection returns `400` and leaves the request pending.

![Consent dialog](../assets/wallet-consent-ui.png)

![Consent credential selection](../assets/wallet-consent-edit-ui.png)

A credential card uses the issuer's display name, logo, colors and background image. Without artwork, it shows a monogram or a generic icon. **About** opens the description.

Display names distinguish credentials of the same type, such as `EUDI PID` and `German PID`. The technical type and short ID appear below the name.

The Issue Credential dialog issues credentials from the web UI. It shows format-specific fields and has a claim builder next to a raw JSON editor. A credential template (for example `german-pid-sdjwt`) fills all fields for review before issuing. A status list selector controls the embedded status reference (the wallet's own list when configured, none, or a custom URI and index).

Credential cards show the revocation status when a credential has a status list reference. Credentials on the wallet's own status list show a live Active or Revoked badge and a Revoke or Activate button. Credentials with an external status list show a Check status action. It fetches the list and shows the current value.

UI controls have stable IDs and data attributes for browser automation. Credential cards expose `data-credential-id`, `data-format`, `data-vct`, `data-doctype` and `data-status`. For example, select a PID with `.credential-card[data-vct="urn:eudi:pid:1"]`.

| Control | ID or selector |
|---|---|
| Credential actions | `show-<id>`, `delete-<id>`, `revoke-<id>`, `status-check-<id>` |
| Template rows and actions | `template-row-<name>`, `template-edit-<name>`, `template-delete-<name>` |
| Consent actions | `consent-approve`, `consent-deny` |
| Consent credential | `consent-credential-<id>` |
| Claim checkboxes | `data-cred` and `data-claim` |
| Selection controls | `consent-edit-selection`, `consent-selection-done`, `consent-selection-reset` |
| Set options | `consent-set-<n>-option-<m>`, `consent-set-<n>-none` for optional sets |
| Query sections | `consent-query-<id>` |
| Candidate rows | `consent-candidate-<query>-<credential>`, with `data-query` and `data-cred` |
| Activity entries | `data-testid="log-entry"`, with `data-event` and `data-action` |
| Open or close an activity entry | `data-testid="log-entry-toggle"` |
| Switch encrypted or decrypted view | `data-testid="log-payload-toggle"` |
| Open a token in the decoder | `data-testid="log-decoder-link"` |
| Show an alternate wire value | `data-testid="log-wire-toggle"` |

Scope activity controls to their entry. Entries for a stored credential also have `data-credential-id`. Presentation decoder links have `data-query-id` and `data-token-index`. Credential response and batch import links have `data-credential-index`. Batch import links also have `data-credential-id` for each stored copy. Token indexes start at zero within each query. Credential indexes start at zero within the entry. The encryption toggle keeps the same selector in both views.

![Issue credential dialog](../assets/wallet-issue-ui.png)

The header links to GitHub and CLI installation instructions. Local wallets let users change **Auto-accept**. Demo wallets show the fixed setting.

An open activity entry shows its details and the request or response as formatted JSON. A fetched request object and its receipt share one entry, with the HTTP status and response. Deferred collection adds separate request and response entries, including pending replies and errors.

**Open in decoder** opens request JWTs and imported credentials. A batch is shown as one credential with multiple copies, such as **Imported credential (8 copies)**. The import entry includes the ID of every stored copy. Import and credential response entries have an **Open copy 1 in decoder** button for each copy. Sent presentations have one button per query, such as **Open 'pid' in decoder**.

Encrypted exchanges show the wire value first. **View decrypted** shows the plaintext. **View encrypted** switches back to the wire value. These buttons change the log display only.

**Trust & certificates** lists trust list URLs and offers CA, signing and HTTPS certificates. Verifiers use the CA for wallet-issued credentials. Issuers use it for wallet and key attestations.

The default local issuer URL is `https://localhost:8086`, on `<port+1>` relative to the wallet's HTTP port. An HTTPS `--base-url`, such as `https://eudi-test.dev`, becomes the issuer URL. Issuer metadata, trust lists and status lists are then served from the public origin behind an external TLS terminator (see [public demo hosting](../public-demo.md)). The [certificate examples](../test-certificates.md#retrieval-revocation-and-alternative-names) use the public demo origin and document localhost separately.

To serve the wallet under a path prefix on a shared host, include the prefix in the base URL, such as `https://example.com/some/context`. See [behind a reverse proxy](../reverse-proxy.md) for the proxy setup.

For a local https origin without an external TLS terminator, add `--serve-tls`. The wallet then also listens on the base URL's port with its own TLS certificate. The plain HTTP port stays open. `--serve-tls` requires an https `--base-url` with an explicit port. The [demo issuer and verifier conformance run](../conformance-run-demorp.md) uses this because the OIDF suite requires https endpoints.

The demo verifier accepts presented credentials whose issuer chains lead to the wallet's own CA. `--demo-verifier-trust-anchor <pem>` (repeatable) adds trust anchors for presentations issued outside this wallet (the OIDF conformance suite signs the credentials it presents under its own CAs).

`wallet ca-cert` exports the shared wallet CA for verifier trust stores or CI fixtures. `wallet tls-cert` exports the per-wallet HTTPS leaf certificate.

The wallet keeps an issued-attestation registry next to its credentials. Each credential type can register:

- its attestation identifier (`vct` or `docType`)
- its registrar entitlements
- its trust list profile data such as LoTE type, entity name, and issuance or revocation service type identifiers

Trust lists are created from that registry:

- `wallet generate-pid` and `wallet serve --pid` register PID attestation types with the PID trust list profile
- `issue ... --wallet` issues with the wallet issuer, stores the credential, and registers one issued-attestation entry for its credential type
- `wallet import` registers a default issued-attestation entry for the imported credential type
- credentials with identical trust list profile fields share one trust list

Each trust list publishes its service's signing certificates, provider CAs and status signing certificates. A separate list operator key signs the list. An unchanged list keeps its signed instance until it expires. Changed content or expiry increments the sequence number. Previous instances are available at the list's `/history` endpoint.

Wallet and key attestations use a separate wallet provider key. Their `x5c` contains the leaf and any intermediate certificates, with the self-signed root omitted. Issuers can pin the root from `/api/certificates/ca` or use `/api/trustlists/wallet-provider`.

`wallet serve` reuses persisted issuer and status list URLs unless `--base-url` or `--docker` overrides them. Credentials generated earlier then keep resolving against the same endpoints. Issuance commands (`issue ... --wallet`, `wallet generate-pid`) follow the same rule. They print a note when no server serves the embedded URLs.

The startup banner warns about a persisted Docker hostname outside Docker. It also warns about stored credentials with issuer or status list URLs that this server does not serve. Those credentials fail validation and status checks until they are issued again.

Each profile describes a role through its LoTE type, entity name and service types. It is served at `/api/trustlists/{id}` with a stable ID:

- `pid` for the built-in PID profile
- `wallet-provider` for the Wallet Provider profile (always present, used by issuers to verify the wallet attestation)
- `local` for the built-in local ETSI-shaped profile
- `tl-<hash>` for any additional custom profile

`eudi wallet trust-list --list` lists these profiles for the selected local or remote wallet:

```
ID               DEFAULT  CATEGORY              PATH
pid              yes      Credential providers  /api/trustlists/pid
wallet-provider           Wallet providers      /api/trustlists/wallet-provider
```

With `--json` it prints the `/api/trustlists` body unchanged.

`/api/trustlists` lists the profiles for API clients. Each entry includes:

- `id`, for example `pid` or `local`
- `path`, for example `/api/trustlists/pid`
- `advertised_url` when the wallet has an issuer URL configured, for example `https://localhost:8086/api/trustlists/pid`
- `url`, an alias for `advertised_url`

Clients that call the wallet through Docker port mappings, reverse proxies, or Testcontainers should resolve `path` against the URL they used for `/api/trustlists`. `advertised_url` is the configured publication URL of the wallet. It can differ from the URL the caller used.

`/api/trustlist` is the legacy endpoint. Its selection rules are:

- if a PID trust list profile exists, `/api/trustlist` returns that PID trust list
- if no PID profile exists, `/api/trustlist` returns the first available profile
- `vct` and `doctype` query parameters select the trust list for a specific credential type

Examples:

- `/api/trustlists/pid`
- `/api/trustlists/local`
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
      "id": "wallet-provider",
      "default": false,
      "path": "/api/trustlists/wallet-provider",
      "advertised_url": "https://localhost:8086/api/trustlists/wallet-provider",
      "url": "https://localhost:8086/api/trustlists/wallet-provider",
      "loTEType": "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList"
    },
    {
      "id": "local",
      "default": false,
      "path": "/api/trustlists/local",
      "advertised_url": "https://localhost:8086/api/trustlists/local",
      "url": "https://localhost:8086/api/trustlists/local",
      "loTEType": "http://uri.etsi.org/19602/LoTEType/local"
    }
  ]
}
```

When the wallet needs a local default profile, it uses:
- `LoTEType = http://uri.etsi.org/19602/LoTEType/local`
- `SvcType/Issuance`
- `SvcType/Revocation`

`--register` also registers OS URL scheme handlers. `openid4vp://`, `eudi-openid4vp://`, `haip-vp://`, `openid-credential-offer://`, `haip-vci://` and `eu-eaa-offer://` links then open the wallet on macOS. On Linux and Windows, `--register` is a no-op.

```bash
eudi wallet serve
eudi wallet serve --port 9000 --auto-accept
eudi wallet serve --pid --credential extra.txt
eudi wallet serve --register           # also register URL scheme handlers using the current interactive/auto-accept mode
eudi wallet serve --register --port 9000
eudi wallet serve -d                   # run in the background (stop with `eudi wallet kill`)
EUDI_DEV_PORT=9000 EUDI_DEV_AUTO_ACCEPT=true eudi wallet serve
```

Every flag can also be set as `EUDI_DEV_<FLAG>`, with the flag name in upper case and underscores for dashes. A flag on the command line wins. A repeatable flag takes comma-separated values. An `EUDI_DEV_` variable that names no flag stops the server at start (see [configuration by environment](../docker.md#configuration-by-environment)).

| Flag                    | Default  | Description                                      |
|-------------------------|----------|--------------------------------------------------|
| `--port`                | `8085`   | Server port                                      |
| `--auto-accept`         | `false`  | Auto-approve everything. Without it, only interactive channels (web invocation URLs, scheme dispatches, browser DC-API) show the consent dialog. API submissions (`POST /api/offers`, `/api/presentations`) always auto-accept because the API call counts as consent (opt in per request with `"interactive": true`) |
| `--credential`          | None     | Import credential from file (repeatable)         |
| `--pid`                 | `false`  | Generate default EUDI PID credentials on start   |
| `--key`                 | None     | Override holder key (PEM/JWK)                    |
| `--issuer-key`          | None     | Override issuer key (PEM/JWK)                    |
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
| `--key-attestation-level` | Issuer requirements | Test claims for key storage and user authentication: issuer requirements (default), `none`, or a level such as `iso_18045_high`. Change it in the Conformance panel. See [key attestation claims](#key-attestation-claims) |
| `--preferred-format`    | None     | Preferred credential format when multiple match: `dc+sd-jwt`, `mso_mdoc`, or `jwt_vc_json` |
| `--status-list`         | `false`  | Embed status list references in generated credentials |
| `--base-url`            | None     | Public URL of the wallet, optionally with a path prefix (see [behind a reverse proxy](../reverse-proxy.md)). An https base URL is used as the issuer URL (external TLS terminator). An http base URL derives a self-signed HTTPS issuer URL on port+1. Existing persisted issuer URLs are reused unless this flag is set |
| `--docker`              | `false`  | Use `host.docker.internal` instead of `localhost` when deriving new HTTP and HTTPS wallet endpoint URLs |
| `--vci-client-id`       | Wallet origin | Client ID for OID4VCI authorization code flows |
| `--vci-redirect-uri`    | Wallet origin + `/callback` | Redirect URI for OID4VCI authorization code flows |
| `--vci-version`         | `1.0`    | OpenID4VCI feature level the wallet uses as a client: `1.0` (the published version) or `1.1` (also uses 1.1 draft features the issuer supports). See [OpenID4VCI feature level](issuing.md#openid4vci-feature-level) |
| `--haip`                | `false`  | Check incoming presentations and credential offers against HAIP 1.0. `--mode` sets how violations are handled. Strict aborts the flow. Debug reports the violation and continues |
| `--client-attestation`  | `false`  | Send the wallet attestation on OID4VCI token requests even when the issuer does not advertise `attest_jwt_client_auth` (see [wallet attestation](issuing.md#wallet-attestation)) |
| `--adhoc-display-images` | `false` | Fetch HTTPS display images on demand instead of storing them. The issuer sees each render. See [display images](#display-images) |
| `--require-encrypted-request` | `false` | Refuse an unencrypted Request Object. The wallet always sends an encryption key in `wallet_metadata`, so this requires the Verifier to use it |
| `--demo`                | `false`  | Public demo profile: implies `--pid`, `--mode debug`, `--haip` and `--vci-version 1.1` (all overridable), disables process and filesystem endpoints, blocks fetches to internal networks. Browser flows keep the consent dialog, API flows auto-accept (see [public demo hosting](../public-demo.md)) |
| `--allow-private-networks` | `false` | Let `--demo` reach private networks and loopback, for a demo on a local machine or a test network. `wallet serve` then warns at start. Without `--demo` the wallet reaches every address, so the flag changes nothing (see [outbound connections](../public-demo.md#outbound-connections)) |
| `--demo-issuer-client-auth` | `required` | Client authentication the built-in demo issuer's authorization server requires at its PAR and token endpoints: `required` (HAIP 1.0 §4.4.1) or `optional`, which also accepts wallets that send no wallet attestation (see [public demo hosting](../public-demo.md)) |
| `--demo-verifier-trust-anchor` | None | CA certificate PEM file the demo verifier trusts for issuer chains, in addition to the wallet's own CA (repeatable). For presentations issued outside this wallet, such as an OIDF conformance suite run |
| `--serve-tls`           | `false`  | Serve an https `--base-url` locally with the wallet's own TLS certificate instead of expecting an external TLS terminator. Requires an https base URL with an explicit port. The wallet also keeps listening on the HTTP port |
| `--demo-reset`          | `1h`     | Schedule for restoring the demo baseline: an interval (`24h`), a daily wall-clock time (`00:00`), or one with a timezone (`"00:00 Europe/Berlin"`). `0` disables. Requires `--demo` |
| `--imprint-file`        | None     | HTML snippet with the operator's legal notice, served at `/imprint` |
| `--news-file`           | None     | HTML snippet with news for visitors, shown once in a popup and linked from the footer. Requires `--demo` |
| `-d, --detached`        | `false`  | Run the server as a background process and return once it responds. Output goes to `<wallet-dir>/serve.log`. Stop it with `wallet kill` |

## Key attestation claims

`--key-attestation-level` sets the test claims `key_storage` and `user_authentication` (OpenID4VCI Appendix D.2). By default they match the issuer's requirements. `none` omits both claims. A level such as `iso_18045_high` sets both explicitly. The Conformance panel can change this at runtime.

These claims describe simulated protection levels. Keys are stored unencrypted. See [SECURITY.md](../../SECURITY.md).

## Display images

By default, the wallet fetches display images once and stores them. `--adhoc-display-images` keeps HTTPS logo and background URLs from issuer metadata and fetches them on each card render. Each render contacts the issuer. The wallet stores no HTTPS image.

Data URIs, template images and HTTP URLs are stored in both modes. Storing HTTP images avoids mixed content on an HTTPS page. `GET /api/config` reports the setting as `adhoc_display_images`.

## `wallet trust-list`

Prints the ETSI trust list JWT containing the selected role's signing certificates, provider CAs and status signing certificates. Verifiers use its provider CAs to validate the `x5c` or `x5chain` embedded in credentials. Issuer authorization data such as provider entitlements and `providesAttestations` comes from signed `/.well-known/openid-credential-issuer` metadata and `/api/registrar/wrp`. See [test certificates](../test-certificates.md).

`wallet trust-list` prints the same trust list as the legacy `/api/trustlist` endpoint: the PID trust list when the wallet has a PID trust list profile, otherwise the first available profile.

`--id`, `--vct`, or `--doctype` selects a specific trust list profile. Typical profile IDs are `pid` and `local`.

Pipe the output to a file or pass it to `validate --trust-list`. `--url` prints only the URL for a running wallet server.

```bash
eudi wallet trust-list                          # Print the trust list JWT
eudi wallet trust-list > trustlist.jwt          # Save to file
eudi wallet trust-list --url                    # http://localhost:8085/api/trustlist
eudi wallet trust-list --id pid --url           # http://localhost:8085/api/trustlists/pid
eudi wallet trust-list --id local --url         # http://localhost:8085/api/trustlists/local
eudi wallet trust-list --doctype org.iso.23220.photoid.1 --url
eudi wallet trust-list --url --port 9000        # http://localhost:9000/api/trustlist
eudi wallet trust-list --url --docker           # http://host.docker.internal:8085/api/trustlist
```

| Flag       | Default | Description                                        |
|------------|---------|----------------------------------------------------|
| `--url`    | `false` | Print only the trust list URL (for a running server) |
| `--list`   | `false` | List the trust list profiles this wallet serves instead of printing one |
| `--id`     | None    | Select a trust list profile ID such as `pid` or `local` |
| `--vct`    | None    | Select the trust list covering this SD-JWT `vct`    |
| `--doctype`| None    | Select the trust list covering this mdoc `docType`  |
| `--port`   | `8085`  | Wallet server port (used with --url)                |
| `--docker` | `false` | Use `host.docker.internal` instead of `localhost` (used with --url) |

## `wallet ca-cert`

Loads or creates the shared root CA certificate and prints exactly one PEM certificate. Wallets under the same parent directory use this root for their signing and HTTPS certificate chains. New provider chains include an intermediate CA. Trust lists publish the relevant service certificates and provider CAs.

`--jwks` exports the certificate as a JWKS document. It contains the certificate's public key as a JWK with `kid`, `alg`, `use`, the certificate chain in `x5c`, and the leaf hash in `x5t#S256`. Use it for JWKS-based trust configuration.

```bash
eudi wallet ca-cert
eudi wallet ca-cert --out wallet-ca-cert.pem
eudi wallet ca-cert --jwks
```

On a running wallet server the same export is available as `GET /api/certificates/ca` (`?format=jwks` for JWKS). See [Certificate export](http-api.md#certificate-export).

| Flag     | Default | Description |
|----------|---------|-------------|
| `--out`  | None    | Write the shared wallet CA certificate to a file instead of stdout |
| `--pem`  | `false` | Output as PEM (the default when no format flag is set) |
| `--jwks` | `false` | Output as JWKS (public key with `x5c` chain) |

## `wallet tls-cert`

Loads or creates the HTTPS leaf certificate of the wallet's HTTPS endpoints and prints exactly one PEM certificate. `--out` writes it to a file for verifier trust stores in automated tests. To export the shared trust root, use `wallet ca-cert`.

```bash
eudi wallet tls-cert
eudi wallet tls-cert --out wallet-tls-cert.pem
eudi wallet tls-cert --docker --out wallet-tls-cert.pem
eudi wallet tls-cert --base-url http://wallet:8085 --out wallet-tls-cert.pem
eudi wallet tls-cert --jwks
```

Pass the same `--port`, `--docker`, and `--base-url` flags as to `wallet serve`. The exported certificate then matches the one the running wallet presents.

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

Registers (or removes) OS-level URL scheme handlers for `openid4vp://`, `eudi-openid4vp://`, `haip-vp://`, `openid-credential-offer://`, `haip-vci://` and `eu-eaa-offer://` links. These links then open the wallet.

The handler script starts a local `wallet serve` instance when none is running and forwards the incoming URI to it. If a UI tab is open, the wallet notifies it over the event stream. Otherwise it opens the UI with the request ID in the URL, and that tab handles the request.

With `--auto-accept`, the handler processes URLs without opening the UI. It POSTs to a running `wallet serve` instance or runs `wallet accept` if that fails.

- **macOS**: Creates an AppleScript `.app` bundle in `~/Applications/` and registers via Launch Services
- **Other platforms**: `register` / `unregister` are accepted as no-ops so scripts stay portable. Use `wallet accept <uri>` instead

```bash
eudi wallet register               # Register URL handlers and open the wallet UI by default
eudi wallet register --auto-accept # Keep URL handling silent / background-only
eudi wallet register --port 9000   # Use custom listener port
eudi wallet unregister             # Remove URL handlers
```

| Flag            | Default | Description                                                    |
|-----------------|---------|----------------------------------------------------------------|
| `--port`        | `8085`  | Listener port for handler script to try before falling back to CLI |
| `--auto-accept` | `false` | Handle incoming URLs silently without opening the wallet UI    |

## HTTPS certificate verification

Strict mode verifies server certificates for all HTTPS requests the wallet sends. Debug mode skips verification by default. `--tls-verify=true` or `--tls-verify=false` overrides either default, including for local endpoints and redirects.

`--tls-ca dev-ca.pem` adds CA certificates to system trust. Server certificates must also match the hostname and be within their validity dates. Credential and request object signatures are checked separately.

```bash
eudi wallet serve --mode strict --tls-ca dev-ca.pem
eudi wallet serve --mode strict --tls-verify=false
eudi wallet serve --mode debug --tls-verify=true
```

A running wallet uses its own TLS settings. Set them with its startup flags, in the Conformance panel, or through `PUT /api/config/conformance`.

## Outbound proxy

If issuers and verifiers are only accessible through a forward proxy (common in corporate networks), set the standard proxy environment variables or the matching flags:

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

Requests to `localhost`, `127.0.0.1`, `::1` and `host.docker.internal` always bypass the proxy.

The wallet verifies the issuer or verifier certificate through the proxy too (see above). If your proxy intercepts TLS traffic, add its CA with `--tls-ca` or disable verification with `--tls-verify=false`.

A running wallet uses the proxy settings it was started with. `wallet accept` and `wallet scan` therefore reject proxy flags when they forward a request to a running wallet. Set them on `wallet serve` instead.

## JSON logs

`--log-format json` (or `EUDI_DEV_LOG_FORMAT=json`) prints every line of console output as one JSON record on stdout, for log collectors such as Loki or Elasticsearch. This includes the startup summary, the request log and warnings:

```json
{"time":"2026-10-03T18:56:44.53+02:00","level":"WARN","msg":"OID4VP 1.0 §5.2: nonce is required"}
{"time":"2026-10-03T18:56:44.61+02:00","level":"INFO","msg":"Encrypting response: response_mode=direct_post.jwt","component":"VP"}
```

`level` is `WARN` or `ERROR` for warning and error lines and `INFO` otherwise. `component` identifies the part of the wallet that logged the line, such as `VCI`, `VP`, `DCQL` or `Demo issuer`. A multi-line entry, such as a token response, stays one record. The default `text` prints the colored console output.

## Changing the conformance settings

The **Conformance** panel in the wallet header controls validation mode, HTTPS certificate verification, HAIP, encrypted requests, the [OpenID4VCI feature level](issuing.md#openid4vci-feature-level), and the key attestation's storage claims (see [SECURITY.md](../../SECURITY.md)). HTTPS verification follows the mode default or is set to on or off.

**Local wallets** can change these settings in the panel or through `PUT /api/config/conformance`. Changes apply to every flow until the process restarts. `DELETE /api/config/conformance` restores startup settings.

**The public demo** shows read-only settings and runs HAIP in debug mode. Violations are warnings and the flow continues. `PUT` and `DELETE /api/config/conformance` return `403`. Run a local wallet to change the settings.

`eudi wallet config` (alias of `wallet info`) reports the active fields for a local or remote wallet.
