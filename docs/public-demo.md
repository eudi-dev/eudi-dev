# Public demo

Run a shared public wallet with the `--demo` profile, as at `https://eudi-test.dev`. Visitors can issue, present, decode and delete test credentials, and register and delete relying parties. Process controls and host filesystem endpoints are disabled. See [`examples/public-demo/`](../examples/public-demo/) for a deployment example.

## Demo profile

```bash
eudi wallet serve --demo --base-url https://eudi-test.dev \
  --vci-redirect-uri https://eudi-test.dev/callback \
  --status-list --imprint-file imprint.html
```

`--demo` turns on `--pid`, `--mode debug`, `--haip`, `--arf` and `--vci-version 1.1`. Explicit flags override them. For example, `--demo --vci-version 1.0` selects OpenID4VCI 1.0.

### Baseline and consent

The server starts without opening a browser and loads protected PID credentials from the bundled templates. User templates with the same names, including those in `--templates-dir`, override the baseline used at startup and reset.

Browser flows ask for consent. API submissions provide consent directly. A demo approves browser flows without asking only with `--auto-accept` on the command line. It ignores `EUDI_DEV_AUTO_ACCEPT` and warns at start when the flag is given. Each consent dialog appears in the browser session that started the flow. Requests without a browser ID appear in a shared banner where any visitor can answer them. Only the web UI answers consent requests, so an API or CLI client doesn't answer another visitor's request by mistake. A client can still name itself as the web UI, so this is no access control. `--demo-consent-api` (`EUDI_DEV_DEMO_CONSENT_API=true`) lets API and CLI clients answer consent requests too.

### Administrative operations

The public demo returns `403` for shutdown, error injection, log clearing and changes to format, consent or conformance settings. Visitors can save templates. They can't change or delete the predefined templates or the operator's templates (those present at startup). The demo issuer, the demo verifier and the parties from `--relying-parties` are protected. Visitors can't change these registrations. They can't issue or revoke their registration certificates either. Anyone can get an access certificate for these parties. Visitors can't delete the catalogue entries of the predefined templates. Linked images, from visitors or from issuer metadata, are fetched once and stored, so the cards show them without loading anything from elsewhere. The demo ignores `--adhoc-display-images`. A demo keeps at most 50 visitor templates, and a reset deletes them. Configuration responses omit host paths and the process ID.

### Outbound connections

Visitor URLs are restricted to public network addresses. The wallet checks resolved addresses when connecting and rejects loopback, private, link local, CGNAT and unique local ranges, including cloud metadata endpoints. It also rejects the reserved, documentation and benchmarking ranges and the IPv6 ranges that embed an IPv4 address (NAT64, 6to4 and Teredo). The operator's destinations are exempt at their exact address and port: the wallet's own advertised origins, the `--trusted-list` URLs and the forward proxy. The bundled issuer and verifier connect to the wallet through these origins.

A wallet without `--demo` also allows loopback. `--allow-private-networks` or `EUDI_DEV_ALLOW_PRIVATE_NETWORKS=true` lifts the limit, with and without `--demo` (see [outbound address limits](wallet/serve.md#outbound-address-limits)). A demo with the limit lifted reaches loopback and private networks. Any visitor could then use it to call services on the host or in its network. The wallet warns about this at start.

The Docker image sets `EUDI_DEV_ALLOW_PRIVATE_NETWORKS=true`. A public demo must set it to `false`, as the services `wallet` and `wallet-preview` in `examples/public-demo/docker-compose.yml` do.

### Validation

The public demo checks OpenID4VP and issuance against HAIP 1.0 and runs the [ARF checks](wallet/presenting.md#arf-checks). In debug mode, violations appear as warnings in the activity log and the flow continues.

Presentation checks cover request delivery, client identification, response encryption, credential formats and algorithms. Unsigned Digital Credentials API requests use the platform origin to identify the caller. Issuance checks cover the grant, PAR, PKCE, DPoP and client authentication. See [specification support](spec-compliance.md) for individual requirements.

Use `--mode strict` to reject violations, or `--haip=false` and `--arf=false` to turn the checks off. Some interoperability advisories remain warnings in strict mode.

### Periodic reset

Resets run every hour by default. `--demo-reset` accepts an interval such as `24h`, a daily time such as `00:00`, or a time with a zone such as `"00:00 Europe/Berlin"`. `0` disables resets. Daily schedules follow local time, including daylight saving changes, and retain their schedule across restarts.

A reset removes visitor credentials, registered relying parties and the providers and lists added to the trusted lists. It then registers the demo issuer, the demo verifier and the parties from `--relying-parties` again. It regenerates the protected PID baseline and clears the activity log. The CA, keys and URLs stay stable. The credential signing certificate is renewed.

## Browser hardening

Visitors share the wallet, so the UI escapes data from other visitors in both text and HTML attributes. This covers status list URIs, credential types, claim names and configuration IDs. The consent event stream accepts only same-origin requests.

Every response includes these headers:

| Header | Policy |
| --- | --- |
| `Content-Security-Policy` | Scripts from this origin only. Inline scripts, framing and `<base>` rewriting are blocked. |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |

## Cookies and browser storage

The demo uses the `eudi_session` cookie to associate consent requests with a browser. It is an opaque session value with `HttpOnly`, `SameSite=Lax` and, for HTTPS connections, `Secure`. The activity log remains shared.

Pages opened by the CLI or URL handler keep the supplied browser ID in `sessionStorage`. Theme preferences, dismissed banner state and the news a visitor has seen use `localStorage`. They store only UI state. There is no third-party tracking. Describe this storage in the deployment's privacy notice.

## robots.txt and security.txt

`/robots.txt` allows page indexing and excludes API and protocol endpoints. `/.well-known/security.txt` follows RFC 9116, lists the project contact and policy, and expires six months after the request. Every page has a meta description.

## Demo issuer and verifier

Every wallet server includes an issuer at `/issuer` and a verifier at `/verifier`. The issuer offers a Demo Event Ticket through pre-authorized and authorization code flows. The verifier requests the ticket or a PID through OpenID4VP.

The verifier signs requests delivered from `/verifier/request/{id}` with its access certificate, identifies itself with `x509_hash:` and receives encrypted `direct_post.jwt` responses. It is registered with the wallet's registrar for the credentials of the wallet's templates and sends its registration certificate with each request. A request can also go out without the registration certificate, or with your own key, access certificate and `verifier_info`. Each request has its own encryption key and accepts one verified response. A response that does not verify shows its failure and leaves the request open. An error response (for example after Deny) also leaves it open. The verifier answers it with a `redirect_uri` back to its page, and the page shows the error. Offers and requests expire after ten minutes and are kept only in memory.

By default, a PID request accepts either an SD-JWT VC or an mdoc. The ticket is always an SD-JWT VC. With **multiple**, the wallet may send several credentials for each query, such as two stored PIDs.

**Custom** builds your own request. In the builder you pick the credentials, claims, claim sets, credential sets and the client identifier prefix. An mdoc claim is an element name in the namespace of its doctype. Its **JSON** mode shows the DCQL query and lets you edit it, for example to add claim `values`. The request sends this query unchanged. The verifier checks the response against the query. Without `claim_sets`, the verifier needs every claim. With `claim_sets`, it needs one complete claim set. Each required credential set needs one of its options.

With the status list option, each ticket references a reserved index in the wallet's own status list. The wallet imports the ticket as revocable. After revocation, the demo verifier rejects the next presentation.

### PID credentials

The demo starts with four PID credentials: the country-independent EUDI PID (`urn:eudi:pid:1`) and the German PID that extends it (`urn:eudi:pid:de:1`), each as an SD-JWT VC and an mdoc. Each PID type has its own attributes, defined by its rulebook.

The PID request asks for `urn:eudi:pid:1`. Both credentials match it, and the wallet presents one of them. The German PID request asks for `urn:eudi:pid:de:1`. Only the German credential matches it. See [credential type inheritance](wallet.md#credential-type-inheritance).

`POST /verifier/api/requests` selects the PID type through `vct`. Any type under `urn:eudi:pid:` is accepted, including `urn:eudi:pid:fr:1`. National types request SD-JWT VC only. All PID mdocs use the doctype `eu.europa.ec.eudi.pid.1`. The doctype carries no country.

To include a ticket, set `ticket` in the same request:

| Value | DCQL query |
| --- | --- |
| `"combined"` | One credential set offers PID plus ticket or PID alone |
| `"optional"` | A second credential set requests the ticket with `required: false` |

### Shared state

All four baseline credentials are protected. The UI, the API and the CLI refuse to delete or revoke them. Visitor credentials can be deleted. Removing baseline protection requires direct access to `wallet.json`.

All visitors share credentials, registered relying parties, trusted lists and the activity log. Anyone can issue credentials, delete unprotected credentials, register, revoke and delete relying parties, and read the log. Anyone can also put providers and external lists on the wallet's [trusted lists](wallet/serve.md#trusted-lists). These entries then anchor the `--arf` checks for every visitor. The demo holds at most 20 added providers and 5 added lists. It keeps the newest 500 credentials and 100 deferred issuances, besides the protected PIDs. At most 30 consent dialogs and 30 sign-ins wait at once, and at most 3 of each per browser. Requests without a browser ID share one count of 3 (see [waiting flows](wallet/http-api.md#waiting-flows)). The demo refuses a credential larger than 512 KB. Errors from flows started in another browser are not shown. Use test data only.

## Rate limits

The compose example limits requests per client address in Caddy. The wallet only sees the proxy's address, so set rate limits in the proxy. Build Caddy with the supplied `Dockerfile` to include the rate-limit plugin.

Five zones return `429` with `Retry-After` when exceeded:

| Zone | Requests | What it covers |
|---|---|---|
| `flows_burst` | 120 per minute | Endpoints that fetch a visitor-supplied URL or add state that persists until the next reset: presentations, offers, issuance, imports, refreshes, deferred collection, demo issuer offers, verification requests |
| `flows_hour` | 2000 per hour | The same endpoints, to cap a long-running script between resets |
| `registrar_burst` | 60 per minute | Registrar changes: registrations, certificates and revocations (`POST`, `PUT` and `DELETE` under `/api/registrar/`) |
| `registrar_hour` | 600 per hour | The same registrar changes |
| `site` | 1200 per minute | All requests, including the UI and the stats report |

An idle page makes about 14 initial requests, then receives updates through an event stream. Clients behind the same public address share the limit. With another reverse proxy, set equivalent limits there.

## Base URL and issuer URL

With an HTTPS base URL, all advertised issuer, status list, metadata and trusted list URLs use that origin. The reverse proxy terminates TLS and the wallet serves HTTP behind it.

With an HTTP base URL, the wallet also starts its self-signed HTTPS listener on port+1.

## Client identity for authorization code issuance

The HAIP authorization code flow needs a client ID and redirect URI. Issuers in the EUDI ecosystem have no registered wallet clients. The wallet attestation identifies the wallet, so each authorization code flow with attestation-based client authentication uses a new random client ID. The redirect URI defaults to the `/callback` endpoint of the wallet origin (`--base-url`). The example deployment sets it explicitly:

```
--vci-redirect-uri https://eudi-test.dev/callback
```

An issuer that requires client registration needs a fixed client ID. Set it with `--vci-client-id` and register it together with the redirect URI. Flows without client attestation use the wallet origin as client ID. Pre-authorized code offers work without either flag (an attestation is still sent where the issuer's metadata asks for one).

## Demo issuer as an authorization server

The demo issuer is also its own authorization server. Its metadata at `/.well-known/oauth-authorization-server/issuer` advertises PAR, PKCE S256, DPoP and ABCA draft-10 methods `attest_jwt_client_auth` and `attest_jwt_client_auth_dpop`. Its endpoints are `/issuer/par`, `/issuer/authorize` and `/issuer/token`. With `--vci-version 1.1` (set by `--demo`), the metadata also advertises `POST /issuer/authorize-challenge`. It is the Authorization Challenge Endpoint of OpenID4VCI 1.1 §6 and runs [interactive authorization](wallet/issuing.md#interactive-authorization).

It accepts the attestation claims defined by ABCA draft-07, draft-08 and draft-10. A valid attestation for a supported draft other than the configured version produces a warning ([ADR-0014](adr/0014-pinned-draft-versions-stay-supported-alongside-the-latest.md)).

Client authentication is required on the token endpoint for both grants (HAIP 1.0 §4.4.1). `--demo-issuer-client-auth optional` also permits clients without an attestation. The authorization server then also advertises and accepts `none`. It still verifies any attestation that is sent.

The challenge for the key proof comes from the Nonce Endpoint defined in OpenID4VCI 1.0 §7. The issuer serves it at `POST /issuer/nonce` and advertises it as `nonce_endpoint` in its Credential Issuer metadata. If a proof uses a stale nonce, the issuer returns `invalid_nonce`. The wallet fetches a fresh nonce and retries.

The issuer offers the `jwt` and the `attestation` proof types (CIR (EU) 2024/2979 Annex Ib TR_KA-4). A wallet can send a key attestation in the `key_attestation` header of a jwt proof or as an attestation proof. The issuer then checks the attestation's signature with its `x5c` certificate, its expiry and its nonce. A jwt proof must be signed by the first attested key. The issuer binds one credential to each attested key, up to the `batch_size` of its metadata (ETSI TS 119 472-3 CRED-REQ-PROC-4.6.2.1-04). With `--arf`, a PID needs a key attestation whose `key_storage` is `iso_18045_high`, the level of a WSCD (TR_KA-8). The issuer treats a key attestation from an unknown wallet provider like a wallet attestation from that provider.

By default the jwt proof type works without a key attestation, so wallets without one can still collect credentials. `--demo-issuer-key-attestation required` puts `key_attestations_required` on the jwt proof type too and refuses a proof without a key attestation.

An offer set to "Deferred" on the issuer page, or created with `POST /issuer/api/offers?deferred=true`, is issued deferred. The credential endpoint answers `202` with a `transaction_id`. The wallet then collects the credentials at `POST /issuer/deferred_credential`. The Credential Issuer metadata advertises this endpoint as `deferred_credential_endpoint`. The credentials are ready after five seconds. Only the access token that started the issuance can collect them.

Sign in with **alice / alice**, the only account. The issuer stores no user data, and the session ends with the flow.

The user signs in when the wallet redeems the offer. The wallet runs the pushed authorization request, and the authorization endpoint asks the user to authenticate. The credential is bound to the account that completed that login.

The hosted wallet returns the authorization URL to the caller:

- The tab where you approved the offer receives an `authorize` event on `/api/requests/stream` and navigates to the issuer. Other open tabs stay where they are.
- An API caller receives `202 authorization_required`, the URL and an `offer_id`.

The flow waits for the issuer to redirect to `/callback`. The wallet then resumes issuance and returns the browser to the wallet UI.

The callback is matched by `state` alone, so the sign-in can happen in any browser with access to the wallet. `eudi wallet accept` can therefore complete an authorization code offer against the hosted demo. The CLI opens the URL locally and polls `GET /api/offers/{offer_id}` until it reports `completed` or `failed`.

By default, PAR and token requests both require a wallet attestation. The issuer verifies its signature and the possession proof, including `sub`, `aud` and expiry. It refuses a possession proof with a reused `jti`. It accepts either a separate `OAuth-Client-Attestation-PoP` JWT or a DPoP proof signed by the attested key (`attest_jwt_client_auth_dpop`).

A wallet attestation or a key attestation can reference a status list entry. It sits in `status` (OpenID4VCI 1.0 Appendix D.1 and E) or in `client_status.status` and `key_storage_status.status` (CIR (EU) 2024/2979 Annex Ib C_WIA-1 and C_KA-1). The issuer then fetches the status list. It refuses the attestation when the entry is anything other than valid, for example revoked (ARF WUA_25, WUA_11a). Sometimes the status cannot be established. The list host may be unreachable, the list may have expired or belong to another URI, or the index may be out of range. The issuer then accepts the attestation, marks it untrusted and logs the reason. Token Status List section 8.3 only says such an attestation SHOULD be rejected. The public demo cannot reach the status lists of a wallet on localhost.

Wallet attestations, key attestations, their possession proofs, DPoP proofs and key proofs can be signed with ES256, ES384 or ES512. CIR (EU) 2024/2979 Annex Ib SA-3 asks an issuer to support all three. The metadata lists them in `proof_signing_alg_values_supported` and `dpop_signing_alg_values_supported`.

The access token is bound to the DPoP key. The credential request must prove possession of that key again. The issuer publishes `credential_request_encryption` and `credential_response_encryption` with A128GCM and A256GCM (ETSI TS 119 472-3 CRYPTO-5-01). Both have `encryption_required: false`, so a wallet without encryption still gets plain JSON. A wallet that asks for an encrypted response must also encrypt its request (OpenID4VCI 1.0 §8.2). Otherwise the issuer answers `invalid_encryption_parameters`. The deferred credential endpoint works the same way. The ticket includes the signed-in account name, so a skipped login shows in the result.

### Wallets from other providers

The demo issuer trusts the wallet providers in the wallet's [list of trusted lists](wallet/serve.md#trusted-lists). These come from the wallet's own `wallet-provider` list at `/api/trustlists/wallet-provider`, from `trust add-ca --list wallet-provider`, and from external wallet provider lists. It also accepts attestations from other providers when their signature verifies against the included leaf certificate.

The ticket records the result in `wallet_attestation`: `trusted` for a chain to a trusted wallet provider, `untrusted` for another signer, or `none` when authentication was optional and omitted.

## Wallet attestation verification

The wallet authenticates PAR and token requests with a wallet attestation. With a separate possession proof, it sends both headers below. When the server advertises combined DPoP proof, the DPoP header replaces the separate attestation PoP header.

- `OAuth-Client-Attestation`, signed by the wallet provider key (`sub` is the client id, `cnf.jwk` is the wallet instance key for this authorization server, and `iss` is the wallet origin, as draft 10 permits). Its `x5c` header carries the wallet provider leaf and any intermediate certificates, without the self-signed root. It also carries the wallet instance claims described in [issuing](wallet/issuing.md#wallet-instance-and-key-attestation-claims).
- `OAuth-Client-Attestation-PoP`, signed by that wallet instance key. If the authorization server metadata advertises a `challenge_endpoint`, the wallet fetches a challenge first and includes it.

When the configuration requires key attestations, the credential proof includes `key-attestation+jwt`. It appears in the JWT proof header or as an attestation proof, depending on the offered format. The reported storage and user authentication levels and the certification are test claims. The wallet stores keys unencrypted ([SECURITY.md](../SECURITY.md)).

These endpoints publish the trust material:

| Source | URL |
| --- | --- |
| CA certificate (the anchor to pin) | `/api/certificates/ca`, JWKS form with `?format=jwks` |
| Wallet provider certificates | `/api/trustlists/wallet-provider` |
| Credential signing keys, one JWK per trusted list | `/.well-known/jwt-vc-issuer` |
| Trusted list index | `/api/trustlists` |
| List of trusted lists | `/api/trustlists/lists` |

Pin the CA through an out-of-band exchange. It is self-signed and persists across restarts and resets. Signing certificates can be renewed without changing that anchor.

Trusted lists are grouped by provider role. Each category has its own signing key and provider CA. The `pid`, `qeaa`, `pub-eaa` and `eaa` lists publish the credential signing certificates of their category and their provider CAs. The `wallet-provider` list publishes wallet provider certificates. The `access-ca` list contains the relying party access CA and the `registrar` list contains the registrar CA. A separate list operator signs the lists. Their sequence numbers and retained history let clients test trust updates.

The issuer metadata endpoints return JSON by default and a JWT signed with the access certificate key when the `Accept` header prefers `application/jwt`. They include a registration certificate from the registrar. Its identifier, legal name and country match the access certificate. The demo issuer and the demo verifier are registered with the registrar like any relying party. Visitors can't change these registrations. They can't issue or revoke their registration certificates either. Anyone can get an access certificate for them. See [test certificates](test-certificates.md) for the exact profiles and versions.

## Imprint

Pass `--imprint-file` with an HTML snippet containing the operator's name, address and contact details. The wallet serves it at `/imprint` and `/decoder/imprint`, and adds the EU non-affiliation notice. The standalone decoder accepts the same flag.

## News

Pass `--news-file` with an HTML snippet. The wallet opens it on a visitor's first visit and again after the file changes. It needs `--demo`.

An image next to the snippet, such as `<img src="overview.png">`, is embedded in the page, because the wallet loads images only from itself. Images can be PNG, JPEG, GIF, WebP or SVG, up to 2 MiB each. A paragraph with `class="lead"` stands out as the summary.

The example stack mounts the `news` folder, and `./deploy.sh push` copies it to the host. The header image is rendered from `3.source.html`.

## Deployment and updates

[`examples/public-demo/deploy.sh`](../examples/public-demo/deploy.sh) manages a host over ssh. Point `DEMO_HOST` at any ssh destination (a `~/.ssh/config` alias, `user@host`, or a bare host), optionally with `DEMO_DIR` and `DEMO_URL`. Put them in the environment or in a `deploy.env` next to the script (gitignored).

```bash
cd examples/public-demo
cat > deploy.env <<'ENV'
DEMO_HOST=root@demo.example
DEMO_URL=https://demo.example
ENV

./deploy.sh setup     # first deployment: Docker, stack, volume ownership, start
./deploy.sh push      # after editing Caddyfile, compose file or imprint
./deploy.sh update    # pull the released image and restart
./deploy.sh rollback  # restore the previous release
./deploy.sh status    # container status plus the version the site reports
./deploy.sh verify    # check that every public endpoint answers
./deploy.sh logs      # follow the wallet log
```

`push` and `update` record the previous release. `rollback` restores it. `rollback v2.0.0` selects a specific release. The selected tag is saved as `WALLET_TAG` in the host's `.env` and survives restarts.

The script pulls the image before switching, so an unpublished tag leaves the running demo unchanged. `update` clears the pin and installs the latest release.

`setup` also sets the owner of the wallet data volume. Docker creates named volumes owned by root, but the image runs as uid 1000. Without the change, the wallet crash-loops on a fresh host.

### Preview host

The preview host runs a second wallet with its own volume and release, behind the same Caddy at a separate subdomain. Point the subdomain at the same host and add its URL to `deploy.env`.

On eudi-test.dev the preview host is <https://preview.eudi-test.dev>.

```bash
# in deploy.env, alongside DEMO_HOST and DEMO_URL:
PREVIEW_URL=https://preview.demo.example

./deploy.sh preview          # run the newest release, betas included, on the preview host
./deploy.sh preview v2.1.0   # run a given release there instead
./deploy.sh verify           # checks the main site and the preview host
./deploy.sh promote          # move the main site to the release the preview runs
./deploy.sh logs preview     # follow the preview wallet log
```

`preview` copies the stack, prepares a separate data volume and saves `PREVIEW_TAG` in the host's `.env`. It starts the preview wallet and reloads Caddy without stopping the main site. Without a tag, it uses `beta`. That image tag always points to the newest release, betas included. Run `./deploy.sh preview` again after a new release to pull it.

`promote` reads the preview's reported version and deploys that exact image to the main site. It records the previous release for `rollback`.

### Strict conformance host

The strict conformance target runs as a third wallet on a separate subdomain, `strict.eudi-test.dev` in the example. It uses strict validation, HAIP, auto-accept and the default PID baseline.

Caddy permits only GET and HEAD from the public internet. This exposes protocol documents and GET `/authorize` requests. A GET `/authorize` request can start a presentation flow. The harness performs other management operations through an SSH tunnel to `127.0.0.1:18086` on the host.

`STRICT_TAG` pins its release independently. Its issuance redirect URI uses the `oid4vc-dev-vci-strict` alias on the production conformance service.

```bash
# in deploy.env, alongside DEMO_HOST and DEMO_URL:
STRICT_URL=https://strict.demo.example

./deploy.sh strict v2.3.0    # run v2.3.0 on the strict host, main site untouched
./deploy.sh logs strict      # follow the strict wallet log
```

[The conformance runbook](./conformance-run.md) describes the conformance run against this host.

## Usage statistics

The compose example includes an optional usage report at `/stats`, protected by basic auth. [GoAccess](https://goaccess.io) generates it from Caddy's access log every two minutes.

Caddy masks client addresses when writing the log: it zeroes the last IPv4 octet and the last 80 IPv6 bits in both `remote_ip` and `client_ip`. The report sets no cookies, adds no JavaScript to wallet pages and sends no data to third parties.

```bash
./deploy.sh stats-password   # writes stats.env with a bcrypt hash (gitignored)
./deploy.sh push             # applies it
./deploy.sh stats            # quick summary in the terminal
./deploy.sh stats-reset      # discard the log and start counting from zero
```

Then open `https://your-domain/stats/`. To turn it off, remove the `handle_path /stats*` block from the Caddyfile and the `stats` service. The anonymized log still counts as processed access data. Describe this logging in the imprint.

Your own tests appear in the statistics. One page load produces several requests for assets, wallet state and the event stream. `deploy.sh stats` separates page views from API calls and lists writes separately. Writes include issuance, presentation, imports and deletion from both people and automated tests.

Visitor counts are approximate because addresses are masked. Everyone sharing an IPv4 `/24` is counted together.

### Log bounds

- the access log rotates at 10 MiB, keeps three files and drops anything older than 30 days (about 40 MiB worst case)
- every container caps its own log at 10 MB with three files, through the `logging` anchor in the compose file (Docker's default is unlimited)
- the report only reads the current access log file, so the statistics only cover the period since the last rotation

## Deployment notes

- Terminate TLS in a reverse proxy (the example uses Caddy with automatic Let's Encrypt) and forward to the wallet's HTTP port. The wallet derives all advertised URLs from `--base-url`.
- Mount a volume at `/home/app/.eudi-dev` and set `EUDI_DEV_STORAGE=file` and `EUDI_DEV_SEED=`. This persists credentials, keys and the shared CA. Mount the parent of `wallet/` so the CA survives restarts and verifiers can reuse their trusted lists.
- Run one replica when using file storage.
- Keep the rate limiting in the proxy. The Caddyfile of the compose example enables the `rate_limit` zones described above.
- Leave `HTTP_PROXY` and `HTTPS_PROXY` unset in the container and do not pass `--http-proxy` or `--https-proxy`. With an outbound proxy, the connection-time address checks see only the proxy's address.
- Requests to the demo's own public URL, such as a pasted offer, resolve through public DNS. This works on cloud hosts that support hairpin NAT. A compose network alias for the public hostname would resolve to a private address and be blocked.

## CLI access to the demo

```bash
eudi wallet use https://eudi-test.dev
```

Management commands such as `list`, `issue` and `remove` then use the hosted wallet. `serve` and `register` run locally. `scan` captures locally and sends the detected flow to the selected wallet.
