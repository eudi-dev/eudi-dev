# Hosting a Public Demo

Run a shared public wallet with the `--demo` profile, as at `https://eudi-test.dev`. Visitors can issue, present, decode and delete test credentials. Process controls and host filesystem endpoints are disabled. See [`examples/public-demo/`](../examples/public-demo/) for a deployment example.

## Demo profile

```bash
eudi wallet serve --demo --base-url https://eudi-test.dev \
  --vci-client-id https://eudi-test.dev --vci-redirect-uri https://eudi-test.dev/callback \
  --status-list --imprint-file imprint.html
```

`--demo` starts with PID credentials, debug mode, HAIP checks and OpenID4VCI 1.1 support. Explicit flags override these defaults. For example, `--demo --vci-version 1.0` selects OpenID4VCI 1.0.

### Baseline and consent

The server starts without opening a browser and loads protected PID credentials from the bundled templates. User templates with the same names, including those in `--templates-dir`, override the baseline used at startup and reset.

Browser flows ask for consent. API submissions provide consent directly. Each consent dialog appears in the browser session that started the flow. Requests without a browser ID appear in a shared banner where any visitor can answer them.

The demo auto-accepts only with `--auto-accept` on the command line. It ignores `EUDI_DEV_AUTO_ACCEPT`, so the image default keeps the consent dialog. With `--auto-accept`, `wallet serve` warns at start and shows auto-accept in its Mode line.

### Administrative operations

Demo mode returns `403` for shutdown, template writes, error injection, log clearing and changes to format, consent or conformance settings. The issue endpoint also rejects template saving and visitor-supplied images. Template images still apply. Configuration responses omit host paths and the process ID.

### Outbound connections

Visitor URLs are restricted to public network addresses. The wallet checks resolved addresses when connecting and rejects loopback, private, link local, CGNAT and unique local ranges, including cloud metadata endpoints. Its own advertised origins are exempt at their exact address and port so the bundled issuer and verifier can communicate with the wallet.

`--allow-private-networks` (or `EUDI_DEV_ALLOW_PRIVATE_NETWORKS=true`) lifts this limit. The demo then reaches private networks and loopback, such as a verifier on your machine or in a test network. `wallet serve` warns at start that the demo can reach local and private addresses. A host that visitors on the internet use keeps the flag off, which is the default.

### Validation

Demo mode checks OpenID4VP and issuance against HAIP 1.0. In debug mode, violations appear as warnings in the activity log and the flow continues. The UI shows the active settings under **Conformance**.

Presentation checks cover request delivery, client identification, response encryption, credential formats and algorithms. Unsigned Digital Credentials API requests use the platform origin to identify the caller. Issuance checks cover the grant, PAR, PKCE, DPoP and client authentication. See [specification support](spec-compliance.md) for individual requirements.

Use `--mode strict` to reject violations or `--haip=false` to disable HAIP checks. Some interoperability advisories remain warnings in strict mode.

### Periodic reset

Resets run every hour by default. `--demo-reset` accepts an interval such as `24h`, a daily time such as `00:00`, or a time with a zone such as `"00:00 Europe/Berlin"`. `0` disables resets. Daily schedules follow local time, including daylight saving changes, and retain their schedule across restarts.

A reset removes visitor credentials, regenerates the protected PID baseline and clears the activity log. The CA, keys and URLs stay stable. The signing certificate is renewed. The footer shows the reset schedule.

## Browser hardening

Visitors share the wallet, so the UI escapes data from other visitors in both text and HTML attributes. This covers status list URIs, credential types, claim names and configuration IDs. The consent event stream accepts only same-origin requests.

Every response includes these headers:

| Header | Policy |
| --- | --- |
| `Content-Security-Policy` | Scripts from this origin only. Inline scripts, framing and `<base>` rewriting are blocked. |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |

## robots.txt and security.txt

`/robots.txt` allows page indexing and excludes API and protocol endpoints. `/.well-known/security.txt` follows RFC 9116, lists the project contact and policy, and expires six months after the request. Every page has a meta description.

## Demo issuer and verifier

Every wallet server includes an issuer at `/issuer` and a verifier at `/verifier`. The issuer offers a Demo Event Ticket through pre-authorized and authorization code flows. The verifier requests the ticket or a PID through OpenID4VP.

The verifier signs requests delivered from `/verifier/request/{id}` with its access certificate, identifies itself with `x509_hash:` and receives encrypted `direct_post.jwt` responses. A registrar-signed registration certificate identifies the same provider. Each request has its own encryption key and accepts one response. Offers and requests expire after ten minutes and are kept only in memory.

The verifier page has a PID format toggle. By default, a PID request accepts either an SD-JWT VC or an mdoc, and the wallet presents one it holds. Select a format to test whether the wallet can present it. The ticket is always an SD-JWT VC.

**Demo ticket + PID** asks for both in one request. **With the PID** offers the ticket together with the SD-JWT PID, or a PID alone. **Optional** asks for a PID and lets the wallet skip the ticket. Tick **multiple** to let the wallet send several credentials for each query, such as both PIDs a wallet holds.

The issuer page has a status list toggle. When enabled, each ticket references a reserved index in the wallet's own status list. The wallet imports the ticket as revocable. After revocation, the demo verifier rejects the next presentation.

### PID credentials

The demo starts with four PID credentials: the country-independent EUDI PID (`urn:eudi:pid:1`) and the German PID that extends it (`urn:eudi:pid:de:1`), each as an SD-JWT VC and an mdoc. Each PID type has its own attributes, defined by its rulebook.

The verifier page offers both through its credential toggle. The PID request asks for `urn:eudi:pid:1`. Both credentials match it, and the wallet presents one of them. The German PID request asks for `urn:eudi:pid:de:1`. Only the German credential matches it. See [credential type inheritance](wallet.md#credential-type-inheritance).

`POST /verifier/api/requests` selects the PID type through `vct`. Any type under `urn:eudi:pid:` is accepted, including `urn:eudi:pid:fr:1`. National types request SD-JWT VC only. All PID mdocs use the doctype `eu.europa.ec.eudi.pid.1`. The doctype carries no country.

To include a ticket, set `ticket` in the same request:

| Value | DCQL query |
| --- | --- |
| `"combined"` | One credential set offers PID plus ticket or PID alone |
| `"optional"` | A second credential set requests the ticket with `required: false` |

The consent dialog shows these choices.

### Shared state

All four baseline credentials are protected. The UI, the API and the CLI refuse to delete or revoke them. Visitor credentials can be deleted. Removing baseline protection requires direct access to `wallet.json`.

All visitors share credentials and the activity log. Anyone can issue credentials, delete unprotected credentials and read the log. Use test data only. The UI lists ten credentials per page, and the periodic reset clears visitor data.

## Rate limits

The compose example limits requests per client address in Caddy. The wallet only sees the proxy's address, so set rate limits in the proxy. Build Caddy with the supplied `Dockerfile` to include the rate-limit plugin.

Three zones return `429` with `Retry-After` when exceeded:

| Zone | Requests | What it covers |
|---|---|---|
| `flows_burst` | 120 per minute | Endpoints that fetch a visitor-supplied URL or add state that persists until the next reset: presentations, offers, issuance, imports, refreshes, deferred collection, demo issuer offers, verification requests |
| `flows_hour` | 2000 per hour | The same endpoints, to cap a long-running script between resets |
| `site` | 1200 per minute | All requests, including the UI and the stats report |

The limits allow interactive use and cap automated traffic. An idle page makes about 14 initial requests, then receives updates through an event stream. Clients behind the same public address share the limit. With another reverse proxy, set equivalent limits there.

## Base URL and issuer URL

With an HTTPS base URL, all advertised issuer, status list, metadata and trust list URLs use that origin. The reverse proxy terminates TLS and the wallet serves HTTP behind it.

With an HTTP base URL, the wallet also starts its self-signed HTTPS listener on port+1.

## Client identity for authorization code issuance

The HAIP authorization code flow needs a client ID and redirect URI. Both default to the wallet's own origin (`--base-url`) and its `/callback` endpoint. The example deployment sets them explicitly:

```
--vci-client-id https://eudi-test.dev --vci-redirect-uri https://eudi-test.dev/callback
```

If the issuer requires client registration, register those two values. Use different values if the issuer has already registered another client ID or redirect URI. Pre-authorized code offers work without either flag (an attestation is still sent where the issuer's metadata asks for one).

## The demo issuer as an authorization server

The demo issuer is also its own authorization server. Its metadata at `/.well-known/oauth-authorization-server/issuer` advertises PAR, PKCE S256, DPoP and ABCA draft-10 methods `attest_jwt_client_auth` and `attest_jwt_client_auth_dpop`. Its endpoints are `/issuer/par`, `/issuer/authorize` and `/issuer/token`.

It accepts the attestation claims defined by ABCA draft-07, draft-08 and draft-10. A valid attestation for a supported draft other than the configured version produces a warning ([ADR-0014](adr/0014-pinned-draft-versions-stay-supported-alongside-the-latest.md)).

Client authentication is required on the token endpoint for both grants (HAIP 1.0 §4.4.1). `--demo-issuer-client-auth optional` also permits clients without an attestation.

The challenge for the key proof comes from the Nonce Endpoint defined in OpenID4VCI 1.0 §7. The issuer serves it at `POST /issuer/nonce` and advertises it as `nonce_endpoint` in its Credential Issuer metadata. If a proof uses a stale nonce, the issuer returns `invalid_nonce`. The wallet fetches a fresh nonce and retries.

Sign in with **alice / alice**, also shown on the login page. This is the only account. The issuer stores no user data, and the session ends with the flow.

The user signs in while redeeming the offer. The **Authorization code offer** button creates an offer before sign-in. The wallet then runs the pushed authorization request, and the authorization endpoint asks the user to authenticate. The credential is bound to the account that completed that login.

The hosted wallet returns the authorization URL to the caller:

- The browser tab receives an `authorize` event on `/api/requests/stream` and navigates to the issuer.
- An API caller receives `202 authorization_required`, the URL and an `offer_id`.

The flow waits for the issuer to redirect to `/callback`. The wallet then resumes issuance and returns the browser to the wallet UI.

The callback is matched by `state` alone, so the sign-in can happen in any browser that can reach the wallet. This lets `eudi wallet accept` complete an authorization code offer against the hosted demo. The CLI opens the URL locally and polls `GET /api/offers/{offer_id}` until it reports `completed` or `failed`.

By default, PAR and token requests both require a wallet attestation. The issuer verifies its signature and the possession proof, including `sub`, `aud`, `jti` and expiry. It accepts either a separate `OAuth-Client-Attestation-PoP` JWT or a DPoP proof signed by the attested key (`attest_jwt_client_auth_dpop`).

The access token is bound to the DPoP key. The credential request must prove possession of that key again. The ticket includes the signed-in account name, so a skipped login shows in the result.

### Wallets from other providers

The demo issuer trusts the shared wallet CA. It also accepts attestations from other providers when their signature verifies against the included leaf certificate. The demo issuer can then test other wallets without trusting their provider.

The ticket records the result in `wallet_attestation`: `trusted` for a chain reaching the wallet CA, `untrusted` for another signer, or `none` when authentication was optional and omitted. The wallet provider's trust list is available at `/api/trustlists/wallet-provider`.

To test a wallet without attestation, use `--demo-issuer-client-auth optional`. The authorization server then also advertises and accepts `none`. It still verifies any attestation that is sent. The default is `required` (HAIP 1.0 §4.4.1).

## Verifying the wallet attestation

The wallet authenticates PAR and token requests with a wallet attestation. With a separate possession proof, it sends both headers below. When the server advertises combined DPoP proof, the DPoP header replaces the separate attestation PoP header.

- `OAuth-Client-Attestation`, signed by the wallet provider key (`sub` is the client id, `cnf.jwk` is the wallet's holder key, and `iss` is the wallet origin, as draft 10 permits). Its `x5c` header carries the wallet provider leaf and any intermediate certificates, without the self-signed root.
- `OAuth-Client-Attestation-PoP`, signed by that holder key. If the authorization server metadata advertises a `challenge_endpoint`, the wallet fetches a challenge first and includes it.

When the configuration requires key attestations, the credential proof includes `key-attestation+jwt`. It appears in the JWT proof header or as an attestation proof, depending on the offered format. The reported storage and user authentication levels are test claims. The wallet stores keys unencrypted ([SECURITY.md](../SECURITY.md)).

The certificate chain is included in the attestation. These endpoints publish the corresponding trust material:

| Source | URL |
| --- | --- |
| CA certificate (the anchor to pin) | `/api/certificates/ca`, JWKS form with `?format=jwks` |
| Wallet provider certificates | `/api/trustlists/wallet-provider` |
| Credential signing key by `kid` | `/.well-known/jwt-vc-issuer` |
| Trust list index | `/api/trustlists` |

Pin the CA through an out-of-band exchange. It is self-signed and persists across restarts and resets. Signing certificates can be renewed without changing that anchor.

Trust lists are grouped by role. The `pid` and `local` lists publish credential signing certificates and their provider CAs. The `wallet-provider` list publishes wallet provider certificates. A separate list operator signs the lists. Their sequence numbers and retained history let clients test trust updates.

The issuer metadata endpoints return JSON by default and an access-certificate-signed JWT when the request accepts only `application/jwt`. They include a registrar-signed registration certificate whose identifier, legal name and country match the access certificate. Registration status and revocation are not implemented. See [test certificates](test-certificates.md) for the exact profiles and versions.

## Imprint

Pass `--imprint-file` with an HTML snippet containing the operator's name, address and contact details. The wallet serves it at `/imprint` and `/decoder/imprint`, adds the EU non-affiliation notice and links it from the footer. The standalone decoder accepts the same flag.

## News

Pass `--news-file` with an HTML snippet to tell visitors about new features. The wallet opens it in a popup on the first visit and links it as **News** in the footer. A changed file opens once more. It needs `--demo`.

An image next to the snippet, such as `<img src="overview.png">`, is embedded in the page, because the wallet loads images only from itself. Images can be PNG, JPEG, GIF, WebP or SVG, up to 2 MiB each. A paragraph with `class="lead"` stands out as the summary.

The example stack mounts the `news` folder, and `./deploy.sh push` copies it to the host. On eudi-test.dev it points visitors to the beta on the preview host. `3.0.0-beta.source.html` is the page the overview image is rendered from.

The demo uses the `eudi_session` cookie to associate consent requests with a browser. It is an opaque session value with `HttpOnly`, `SameSite=Lax` and, for HTTPS connections, `Secure`. The activity log remains shared.

Pages opened by the CLI or URL handler keep the supplied browser ID in `sessionStorage`. Theme preferences, dismissed banner state and the news a visitor has seen use `localStorage`. They store only UI state. There is no third-party tracking. Describe this storage in the deployment's privacy notice.

## Deploying and updating

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
./deploy.sh rollback  # put the release that was live before that back
./deploy.sh status    # container status plus the version the site reports
./deploy.sh verify    # check that every public endpoint answers
./deploy.sh logs      # follow the wallet log
```

`push` and `update` record the previous release. `rollback` restores it. `rollback v2.0.0` selects a specific release. The selected tag is saved as `WALLET_TAG` in the host's `.env` and survives restarts.

The script pulls the image before switching, so an unpublished tag leaves the running demo unchanged. `update` clears the pin and installs the latest release.

`setup` also sets the owner of the wallet data volume. Docker creates named volumes owned by root, but the image runs as uid 1000. Without the change, the wallet crash-loops on a fresh host.

### Preview host

Use the preview host to try a release before deploying it to the main site. It runs a second wallet with its own volume and release, behind the same Caddy at a separate subdomain (`preview.eudi-test.dev` in the example). Point the subdomain at the same host and add its URL to `deploy.env`.

```bash
# in deploy.env, alongside DEMO_HOST and DEMO_URL:
PREVIEW_URL=https://preview.demo.example

./deploy.sh preview v2.1.0   # run v2.1.0 on the preview host, main site untouched
./deploy.sh verify           # checks the main site and the preview host
./deploy.sh promote          # move the main site to the release the preview runs
./deploy.sh logs preview     # follow the preview wallet log
```

`preview` copies the stack, prepares a separate data volume and saves `PREVIEW_TAG` in the host's `.env`. It starts the preview wallet and reloads Caddy without stopping the main site. Without a tag, it uses `latest`.

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

[The conformance runbook](./conformance-run.md) describes the run against it.

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
- Mount a volume at `/home/app/.eudi-dev` and set `EUDI_DEV_STORAGE=file` and `EUDI_DEV_SEED=`. This persists credentials, keys and the shared CA. Mount the parent of `wallet/` so the CA survives restarts and verifiers can reuse their trust lists.
- Run one replica when using file storage.
- Leave `HTTP_PROXY` and `HTTPS_PROXY` unset in the container and do not pass `--http-proxy` or `--https-proxy`. With an outbound proxy, the connection-time address checks see only the proxy's address.
- Requests to the demo's own public URL, such as a pasted offer, resolve through public DNS. This works on cloud hosts that support hairpin NAT. A compose network alias for the public hostname would resolve to a private address and be blocked.
- Keep the rate limiting in the proxy. The compose example's Caddyfile enables the `rate_limit` zones described above.

## Pointing the CLI at the demo

```bash
eudi wallet use https://eudi-test.dev
```

Management commands such as `list`, `issue` and `remove` then use the hosted wallet. `serve` and `register` run locally. `scan` captures locally and sends the detected flow to the selected wallet.
