[← Wallet](../wallet.md)

# Wallet HTTP API

A running `wallet serve` instance exposes this API. [Remote CLI commands](#remote-control) use it too.

## HTTP API

> **No authentication.** Anyone who can reach the port can control the wallet and read its credentials. Use it for local development and isolated test networks with test data. Public deployments should use [`--demo`](../public-demo.md), which disables administrative operations, restricts outbound connections and resets state periodically. The remaining data and endpoints are public.

> **Path prefix.** If `--base-url` includes a path prefix, such as `https://example.com/some/context`, prepend it to every path on this page (`/some/context/api/credentials`). Links in responses, such as credential image URLs, already include it. See [behind a reverse proxy](../reverse-proxy.md).

> **Browser origin checks.** Cross-origin API requests (by their `Origin` header) receive `403`. The Digital Credentials API endpoint is the exception because verifier pages call it from their own origins. CLI tools normally send no `Origin` header. The wallet accepts its own origin and the configured `--base-url`.

### Consent ownership

`GET /api/requests` and the event stream return the caller's own requests and unowned requests. This does not authenticate users.

A client that opens a wallet page supplies the same browser ID in the page's `owner` query parameter and the API's `X-Eudi-Owner` header. The CLI and remote URL handler do this automatically. Requests without a browser ID remain visible to all callers, including curl, CI jobs and commands using `--no-open`.

The `mine` field of a request document shows ownership. Bundled clients also send `X-Eudi-Client: <name>/<release>`. The server logs an upgrade notice once for interactive submissions that omit it.

`GET /api/error` and `DELETE /api/error` follow the same ownership rules. A caller can read and clear its own errors and unowned errors.

To approve or deny a request through `POST /api/requests/{id}/approve` or `/deny`, the caller must own it or pass `?request=<id>`. The wallet includes that ID in the browser redirect URL. Other callers receive `404`.

`GET /api/credentials` accepts optional `limit` and `offset` query parameters and reports the total number of stored credentials in the `X-Total-Count` response header. Without parameters it returns every credential. An offset past the end returns an empty array.

Protected baseline credentials cannot be deleted or revoked through the API. Individual operations return `403`. Deleting all credentials preserves protected entries and reports `kept_protected`. Demo mode marks its generated PIDs as protected. Changing the flag requires direct access to stored state, such as editing `wallet.json` on the file backend.

### Credential management

| Method   | Path                    | Body                  | Description                                        | CLI equivalent        |
|----------|-------------------------|-----------------------|----------------------------------------------------|-----------------------|
| `GET`    | `/api/credentials`      | None                  | List stored credentials                            | `wallet list --json`  |
| `GET`    | `/api/credentials/{id}` | None                  | Show one credential (id, format, claims, raw)      | `wallet show <id>`    |
| `POST`   | `/api/credentials`      | raw credential string | Import a credential (see [Credential import](#credential-import)) | `wallet import`       |
| `DELETE` | `/api/credentials/{id}` | None                  | Remove a credential by ID (`204` on success)       | `wallet remove <id>`  |
| `DELETE` | `/api/credentials`      | None                  | Remove all credentials (returns `{"deleted": n, "kept_protected": m}`)  | `wallet remove --all` |

```bash
# List credentials, pick one, inspect it, then delete it
curl http://localhost:8085/api/credentials
curl http://localhost:8085/api/credentials/<id>
curl -X DELETE http://localhost:8085/api/credentials/<id>

# Wipe the wallet
curl -X DELETE http://localhost:8085/api/credentials
```

### Issuing credentials

`POST /api/issue` issues a credential with the wallet's issuer key and certificate chain and imports it into the wallet. It is the HTTP equivalent of `issue sdjwt|jwt|mdoc --wallet`. All fields except `format` are optional:

| Field             | Type    | Description                                                                                  |
|-------------------|---------|----------------------------------------------------------------------------------------------|
| `format`          | string  | `sdjwt`, `jwt`, or `mdoc`. Required unless a `template` with a format is given               |
| `template`        | string  | Credential template name (see [templates](../templates.md)). Template claims become the base claim set and `claims` overrides individual claims |
| `claims`          | object  | Credential claims (default is a small test claim set, or the PID claim set with `pid`)       |
| `pid`             | bool    | Use the full EUDI PID Rulebook claims (like `--pid`)                                         |
| `omit`            | array   | Top-level claim names to drop from the claim set (like `--omit`)                             |
| `always_disclosed`| array   | Claims issued plainly instead of selectively disclosable, with dotted paths for nested claims (sdjwt only, like `--always-disclosed`) |
| `save_as_template`| string  | Save the resolved issuance parameters as a template with this name after issuing             |
| `catalog`         | object  | Add the saved template to the attestation catalogue with these fields (`name` and `schema`, see [templates](../templates.md#attestation-catalogue)). Needs `save_as_template` |
| `vct`             | string  | SD-JWT/JWT VC type (default is the default PID VCT)                                          |
| `doctype`         | string  | mdoc doc type (default `eu.europa.ec.eudi.pid.1`)                                            |
| `namespace`       | string  | Default namespace for mdoc claims (default is `doctype`). A claim key of the form `namespace:element` places that element in its own namespace instead |
| `exp`             | string  | Expiration duration such as `720h` or `24h` (default `720h`)                                 |
| `nbf`             | string  | Not-before as RFC3339 (`2025-01-15T00:00:00Z`) or relative duration (`-1h`)                  |
| `status_list_uri` | string  | Status list URI to embed. Default is the wallet's own status list when configured. `""` disables it |
| `status_list_idx` | int     | Status list index (default is the next free index on the wallet's status list)               |
| `category`        | string  | Credential category: `pid`, `qeaa`, `pub-eaa`, `eaa` or `unlisted`. Empty (default) takes the category of the template or the catalogue entry, else `eaa` |
| `trust`           | object  | Trust/registration metadata to persist with the credential type (same fields as the `issue` trust flags, e.g. `entitlements`, `trust_list_type`, `entity_name`) |
| `display`         | object  | Card appearance: `name`, `description`, `background_color`, `text_color`, `logo`, `logo_alt_text`, `background_image` (the `--display-*` flags). A public demo drops operator-supplied images |
| `display_template`| string  | Template that supplies the logo and background image of the credential (for a form with the template's claims flattened into `claims`) |
| `batch`           | int     | Issue this many copies with distinct holder keys. The wallet rotates between them (like `--batch`) |
| `unbound`         | bool    | Issue a bearer credential without a holder key (like `--unbound`). By default the credential is bound to the wallet. Only a query with `require_cryptographic_holder_binding: false` matches an unbound credential. In strict mode an unbound mdoc matches no query |
| `signing_key`     | string  | PEM or JWK private key that signs the credential instead of the wallet issuer key. Requires `signing_cert` (like `--key` with `--cert`). Refused on the public demo |
| `signing_cert`    | string  | PEM certificate chain, leaf first, embedded as the credential's x5c. The leaf must certify `signing_key` and the chain is embedded as given (a chain that includes its self-signed root produces a warning in debug mode and is refused in strict mode). The chain replaces the request's trust profile and registration metadata |

The response is `201` with the stored credential (`id`, `format`, `claims`, `raw`, `status_list_idx` when the credential was registered on the wallet's status list, and `template_path` when `save_as_template` was used).

```bash
# Issue an SD-JWT PID into the wallet
curl -X POST http://localhost:8085/api/issue \
  -H 'Content-Type: application/json' \
  -d '{"format": "sdjwt", "pid": true}'

# Issue an mdoc with custom claims that expires in 24 hours
curl -X POST http://localhost:8085/api/issue \
  -H 'Content-Type: application/json' \
  -d '{"format": "mdoc", "claims": {"given_name": "Erika"}, "exp": "24h"}'

# Issue an already-expired credential for negative tests
curl -X POST http://localhost:8085/api/issue \
  -H 'Content-Type: application/json' \
  -d '{"format": "sdjwt", "nbf": "-48h", "exp": "24h"}'
```

`POST /api/generate-pid` replaces default PIDs of the same type and returns `201` with the credential list. Like `wallet generate-pid`, this endpoint is deprecated. Use `POST /api/issue` with a PID template instead, for example `{"template": "pid-sdjwt"}`.

The optional body accepts `claims` overrides and a `vct`. The default uses `pid-sdjwt` and `pid-mdoc`. `urn:eudi:pid:de:1` selects `german-pid-sdjwt` and `german-pid-mdoc`. User template overrides apply.

```bash
curl -X POST http://localhost:8085/api/generate-pid \
  -H 'Content-Type: application/json' \
  -d '{"claims": {"given_name": "MAX", "family_name": "POWER"}}'
```

### Credential templates

The template endpoints use the same storage backend as the `templates` CLI commands. User templates live under the wallet's `templates/` prefix. See [templates](../templates.md) for the document format.

| Endpoint | Description |
|----------|-------------|
| `GET /api/templates` | List all templates (predefined and user), including claims |
| `GET /api/templates/{name}` | Get one template |
| `PUT /api/templates/{name}` | Create or replace a user template. The body is a full template document. This endpoint also imports shared templates. A `catalog` object also adds the template to the attestation catalogue (see [templates](../templates.md#attestation-catalogue)) |
| `DELETE /api/templates/{name}` | Delete a user template. Deleting an override of a predefined template restores the predefined version |

```bash
curl -X PUT http://localhost:8085/api/templates/employee-card \
  -H 'Content-Type: application/json' \
  -d '{"format": "sdjwt", "vct": "urn:example:employee", "claims": {"employee_id": "E-1"}, "always_disclosed": ["employee_id"]}'

curl -X POST http://localhost:8085/api/issue \
  -H 'Content-Type: application/json' \
  -d '{"template": "employee-card", "claims": {"employee_id": "E-42"}}'
```

### Certificate export

The CA and TLS endpoints return PEM by default. `?format=jwks` returns the public key and `x5c` chain as JWKS.

| Method | Path                            | Description                                              | CLI equivalent   |
|--------|---------------------------------|----------------------------------------------------------|------------------|
| `GET`  | `/api/certificates/ca`          | Shared wallet CA certificate (PEM)                       | `wallet ca-cert` |
| `GET`  | `/api/certificates/ca?format=jwks`  | Shared wallet CA certificate as JWKS                 | `wallet ca-cert --jwks` |
| `GET`  | `/api/certificates/tls`         | HTTPS leaf certificate for the wallet's issuer URL (PEM) | `wallet tls-cert` |
| `GET`  | `/api/certificates/tls?format=jwks` | HTTPS leaf certificate as JWKS                       | `wallet tls-cert --jwks` |
| `GET` | `/api/certificates/registrar` | Registrar signing certificate (PEM, `?format=jwks` for JWKS) | |
| `GET` | `/api/certificates/relying-party-access-ca` | Relying party access CA. It signs the access certificates of registered relying parties (PEM, `?format=jwks` for JWKS) | |
| `GET` | `/api/certificates/registrar-ca` | Registrar CA. It signs the registrar signing certificate (PEM) | |
| `GET` | `/api/certificates/ca.der` | Root CA certificate as DER | |
| `GET` | `/api/certificates/providers/{role}/{country}.der` | Provider CA certificate as DER | |
| `GET` | `/api/certificates/signers/{sha256}.pem` | Archived signing certificate as PEM | |
| `GET` | `/api/certificates/signers/{sha256}.der` | Archived signing certificate as DER | |

```bash
curl http://localhost:8085/api/certificates/ca > wallet-ca-cert.pem
curl 'http://localhost:8085/api/certificates/tls?format=jwks'
```

Provider roles are the credential categories `pid`, `qeaa`, `pub-eaa` and `eaa`, `wallet` for the wallet provider, `tl-<8 hex digits>` for a credential type with its own trusted list, and `unlisted` for unlisted credentials. Each role has its own provider CA. The country is two uppercase letters such as `NL`. Only existing providers can be retrieved. Signing certificate URLs use the SHA-256 fingerprint of the DER certificate and remain available after renewal. JOSE `x5u` uses PEM and COSE `x5u` uses DER. See [test certificates](../test-certificates.md) for the certificate profiles.

### Issuer metadata and trusted lists

These endpoints are available on both wallet ports.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/jwt-vc-issuer` | Public credential signing keys, one for each trusted list and one for unlisted credentials |
| `GET` | `/.well-known/openid-credential-issuer` | Wallet issuer metadata |
| `GET` | `/.well-known/openid-credential-issuer/issuer` | Demo issuer metadata, when the demo is enabled |
| `GET` | `/api/trustlist` | Default signed trusted list |
| `GET` | `/api/trustlists` | Available trusted lists and their URLs |
| `GET` | `/api/trustlists/{id}` | The signed trusted list `{id}` |
| `GET` | `/api/trustlist/history` | Sequence numbers and URLs of saved default trusted lists |
| `GET` | `/api/trustlist/history/{sequence}` | One saved default trusted list |
| `GET` | `/api/trustlists/{id}/history` | Sequence numbers and URLs of the saved instances of the list `{id}` |
| `GET` | `/api/trustlists/{id}/history/{sequence}` | One saved instance of the list `{id}` |
| `GET` | `/api/trustlists/lists` | The [list of trusted lists](serve.md#list-of-trusted-lists) |
| `GET` | `/api/trust` | Providers and external lists added to the trusted lists |
| `POST` | `/api/trust/entities` | Put a provider on one of the lists: `list`, `name` and `certificates` (PEM) |
| `DELETE` | `/api/trust/entities/{id}` | Take a provider off its list |
| `POST` | `/api/trust/lists` | Put an external list on the list of trusted lists: `url` |
| `DELETE` | `/api/trust/lists?url=<url>` | Take an external list off |

Issuer metadata is JSON by default. An `Accept` header that ranks `application/jwt` above `application/json` selects metadata signed with the access certificate key. Its `issuer_info` holds the registrar dataset and the registration certificate of the [demo issuer](registrar.md#the-demo-issuer-and-verifier). If you revoke that certificate in the registrar, the next metadata carries a new one.

Trusted lists contain service certificates and provider CAs. A separate list operator key signs them. History preserves each published JWT. Changed content or an expired instance advances the sequence number. See [trusted lists](serve.md#trusted-lists) for the list IDs, added providers and lists, and discovery.

### Registrar

*(new in 3.0.0)*

These endpoints are available on both wallet ports. Anyone with access to the wallet can register, change and delete relying parties, as with credentials. All `GET` endpoints under `/api/registrar/wrp` and `PUT /api/registrar/wrp` answer with a JWT signed by the registrar (`application/jwt`). Its payload has `iss`, `iat` and `data`. Send `Accept: application/json` without `application/jwt` to get the payload unsigned. See [registrar](registrar.md#registrar-api). The [registrar API walkthrough](registrar-api.md) registers a verifier and an issuer with curl and uses their certificates.

`PUT /api/registrar/wrp` and `PUT /api/catalog/schemas/{id}` have no CLI command.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/registrar/wrp` | Search relying party registrations (TS05 v1.5). With `serviceidentifier` and `isolateService=true` each record contains only that service |
| `GET` | `/api/registrar/wrp/{identifier}` | One registration |
| `GET` | `/api/registrar/wrp/{identifier}/services/{serviceidentifier}` | One service of a registration |
| `GET` | `/api/registrar/wrp/check-intended-use` | Check whether an intended use matches the given parameters, all optional, including `policyurl`. Answers `404` for an unknown `identifier` |
| `POST` | `/api/registrar/wrp` | Register a relying party |
| `PUT` | `/api/registrar/wrp` | Replace a registration and answer the stored registration in `data`. If an intended use or a service changes or is missing, its certificates are revoked |
| `DELETE` | `/api/registrar/wrp/{identifier}` | Delete a registration |
| `POST` | `/api/registrar/enrolments` | Register a relying party and issue its certificates in one step |
| `PUT` | `/api/registrar/enrolments` | Change a registration and issue its certificates in one step |
| `POST` | `/api/registrar/access-certificates` | Issue an access certificate for a CSR of a registered relying party |
| `POST` | `/api/registrar/registration-certificates` | Issue a registration certificate for a registered intended use (answers `verifierInfo`) or an issuer service (answers `issuerInfo`). Answers `409` if the registration changed in the meantime |
| `GET` | `/api/registrar/registration-certificates` | Status list entries of the issued registration certificates. A current certificate comes with its `verifierInfo` or `issuerInfo` value |
| `POST` | `/api/registrar/registration-certificates/status` | Revoke or activate registration certificates |
| `GET` | `/api/registrar/status-list` | Status list of the registration certificates |
| `GET` | `/api/catalog/schemas` | Catalogue of attestations (EC TS11 v1.0), signed and paged |
| `GET`, `PUT`, `DELETE` | `/api/catalog/schemas/{id}` | One attestation schema |
| `GET` | `/api/catalog/schemas/{id}/{format}` | The schema behind a schema URI |
| `GET`, `POST` | `/api/catalog/attestations` | List the catalogue with names, types and the `category` of each entry (`GET`) or add an entry (`POST`) |
| `GET` | `/api/catalog/categories` | The credential categories with their label, entitlement, trust rule and level of security |
| `GET` | `/privacy-policy`, `/support`, `/supervisory-authority`, `/rulebook` | Placeholder pages for the default privacy policy, support, supervisory authority and rulebook URLs |

### One-shot error override

Pre-program the wallet to return an error for the next presentation request, even in auto-accept mode. The override applies only to a request that passes validation, and only once.

**Set override:**

```bash
curl -X POST http://localhost:8085/api/next-error \
  -H 'Content-Type: application/json' \
  -d '{"error": "access_denied", "error_description": "User denied consent"}'
```

The next OID4VP authorization request returns the configured error:

```json
{
  "status": "error",
  "error": "access_denied",
  "error_description": "User denied consent"
}
```

Strict mode with `--arf` answers the same way when it refuses a request only because of ARF findings and the verifier signed the request with a trusted access certificate. The wallet sends the verifier `access_denied` (OpenID4VP 1.0 §8.5, RFC 6749 §4.1.2.1), and the API answers with `"status": "refused"`. The `error_description` starts with "The request does not meet the ARF registration rules" and names the findings. A request without an access certificate gets HTTP 400 like any invalid request, and the verifier gets no answer (see [presenting](presenting.md)).

**Clear override without consuming:**

```bash
curl -X DELETE http://localhost:8085/api/next-error
```

| Method   | Path              | Body                                                        | Description                |
|----------|-------------------|-------------------------------------------------------------|----------------------------|
| `POST`   | `/api/next-error` | `{"error": "...", "error_description": "..."}`              | Set one-shot error override |
| `DELETE` | `/api/next-error` | None                                                        | Clear override              |

### Preferred credential format

When a DCQL query matches both SD-JWT and mdoc credentials, the preferred format setting decides which format is presented.

**Set preference:**

```bash
curl -X PUT http://localhost:8085/api/config/preferred-format \
  -H 'Content-Type: application/json' \
  -d '{"format": "dc+sd-jwt"}'
```

**Clear preference:**

```bash
curl -X PUT http://localhost:8085/api/config/preferred-format \
  -H 'Content-Type: application/json' \
  -d '{"format": ""}'
```

| Method | Path                           | Body                    | Description                    |
|--------|--------------------------------|-------------------------|--------------------------------|
| `GET`  | `/api/config`                  | None                    | Full instance introspection document (see [Introspection](#introspection)) |
| `GET`  | `/api/news`                    | None                    | The news of a public demo as `{"id", "html"}`, 404 without `--news-file`. `/api/config` names its `news_id` |
| `PUT`  | `/api/config/preferred-format` | `{"format": "dc+sd-jwt"}`  | Prefer SD-JWT when multiple match |
| `PUT`  | `/api/config/preferred-format` | `{"format": "mso_mdoc"}`   | Prefer mdoc when multiple match   |
| `PUT`  | `/api/config/preferred-format` | `{"format": "jwt_vc_json"}` | Prefer JWT VC when multiple match |
| `PUT`  | `/api/config/preferred-format` | `{"format": ""}`            | Clear preference (default)        |
| `PUT`  | `/api/config/auto-accept`      | `{"enabled": true}`         | Approve every presentation and offer without a consent prompt, until the process restarts. `false` restores the consent prompt. Refused on the public demo |

The preference can also be set at startup via `--preferred-format`:

```bash
eudi wallet serve --auto-accept --pid --preferred-format dc+sd-jwt
```

### Credential import

Credentials can be imported at runtime via `POST /api/credentials`. The body is the raw credential string. Supported formats:

| Format | Detection | Stored as |
|--------|-----------|-----------|
| SD-JWT | Contains `~` separator | `dc+sd-jwt` |
| Plain JWT | 3-part JWT without `~` | `jwt_vc_json` |
| mdoc | CBOR-encoded | `mso_mdoc` |

Plain JWT VCs are presented without changes (no selective disclosure, no KB-JWT). Use `"format": "jwt_vc_json"` in DCQL queries to match them.

DID issuer keys cannot be resolved. Credentials whose `kid` or `iss` starts with `did:` are imported with an unverified issuer signature. Status list signatures using DID keys also remain unverified. Supported key sources are x5c chains and SD-JWT VC issuer metadata ([ADR-0013](../adr/0013-only-the-eudi-stack-is-supported.md)).

The DID appears in the activity log and the summary's `issuer_key_did` field. `eudi validate --haip` also reports it as a finding.

A credential bound to a holder key requires that private key for presentation. Importing a credential issued to another wallet does not transfer the key. The wallet reports the mismatch in its activity log, CLI warnings, the credential card and the summary's `key_binding_not_held` field.

```bash
# Import an SD-JWT
curl -X POST http://localhost:8085/api/credentials \
  -d 'eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ...~eyJhbGci...~'

# Import a plain JWT VC
curl -X POST http://localhost:8085/api/credentials \
  -d 'eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ...'
```

### Status list

PID credentials from `wallet generate-pid` or `wallet serve --pid` carry a `status.status_list` claim pointing to the wallet's HTTPS status list endpoint. `--status-list` enables this for other generated credentials. The URI in the credential is `https://<host>:<port+1>/api/statuslist`.

The default issuer URL is `https://localhost:<port+1>`. It serves `/.well-known/jwt-vc-issuer`, signed or unsigned `/.well-known/openid-credential-issuer` metadata, and `/api/registrar/wrp` registration data. Certificates use the shared wallet CA.

If the verifier runs in Docker (or anywhere else without access to `localhost`), use `--docker` (or `--base-url` for a custom URL) so the status list URL and the issuer metadata host are reachable:

```bash
# Verifier on the same host
eudi wallet serve --pid

# Verifier in Docker (shortcut for --base-url http://host.docker.internal:<port>)
eudi wallet serve --pid --docker

# Custom base URL
eudi wallet serve --pid --base-url http://my-host:8085
```

Change the status of a credential at runtime:

```bash
# Revoke a credential (status=1)
curl -X POST http://localhost:8085/api/credentials/<id>/status \
  -H 'Content-Type: application/json' \
  -d '{"status": 1}'

# Un-revoke (status=0)
curl -X POST http://localhost:8085/api/credentials/<id>/status \
  -H 'Content-Type: application/json' \
  -d '{"status": 0}'

# Resolve the current status (from the wallet's own list, or by fetching an
# external status list referenced by the credential)
curl http://localhost:8085/api/credentials/<id>/status
```

The endpoint accepts any Status Type from 0 to 255, for example SUSPENDED (`2`) or an application specific value. The published list carries the exact value. Its width is 1, 2, 4 or 8 bits, depending on the largest status in the list (the issuer's choice under section 7).

The GET response contains `status`, `managed`, `uri`, `idx`, and `source` (`wallet` for the wallet's own list, `remote` for a fetched external list). It returns 404 for credentials without any status list reference, 422 for a malformed reference, and 502 when an external status list cannot be fetched.

Credential listings (`GET /api/credentials` and `GET /api/credentials/{id}`) include a `status` object for credentials that carry a status list reference: `uri` and `idx` from the credential, `managed` (true when the entry is on this wallet's own status list), and the current `status` value for managed entries.

`GET /api/statuslist` serves the Status List Token on both wallet ports. `Accept: application/statuslist+cwt` selects CWT. Other requests receive JWT, including requests that prefer both formats equally. The endpoint enables CORS for browser clients (section 8.1). Historical queries with `time` return `501` because the wallet keeps no history (section 8.4).

```bash
curl -H 'Accept: application/statuslist+jwt' http://localhost:8085/api/statuslist
curl -H 'Accept: application/statuslist+cwt' http://localhost:8085/api/statuslist --output statuslist.cwt
```

The wallet and `eudi validate` read both forms. When they resolve a credential's status reference, they request both media types and parse the format the server returns.

`GET /api/crl` serves the root CA's DER certificate revocation list (`application/pkix-crl`). `GET /api/crl/providers/{role}/{country}` serves a provider CA's CRL. Generated signing certificates point to their provider's CRL. Certificates signed directly by the root, such as the status and trusted list signers, use `/api/crl`. These lists are empty and freshly signed with a week of validity. Credential revocation uses the status list.

### Deferred issuance

An issuer that cannot issue a credential immediately returns a transaction id. The wallet polls for the credential in the background. `wallet deferred` uses these endpoints:

| Method   | Path                          | Description                                                       | CLI equivalent              |
|----------|-------------------------------|-------------------------------------------------------------------|-----------------------------|
| `GET`    | `/api/deferred`               | List pending deferred credentials, with attempt counts           | `wallet deferred`           |
| `POST`   | `/api/deferred/{id}/collect`  | Poll the issuer now instead of waiting for the next attempt      | `wallet deferred check <id>`   |
| `DELETE` | `/api/deferred/{id}`          | Stop polling for one credential (returns the issuer and transaction id of the removed entry, `404` when the id is unknown) | `wallet deferred abandon <id>` |

```bash
curl http://localhost:8085/api/deferred
curl -X POST http://localhost:8085/api/deferred/<id>/collect
```

### Activity log

Each activity log entry has a timestamp, category (`presentation`, `issuance`, `management`), description, success flag and structured `details`.

`GET /api/log` returns the log format used by the CLI. The web UI uses `GET /api/log?view=activity` for the full protocol requests and responses. Encrypted exchanges include plaintext and the encrypted wire value. Summaries add context, such as selected disclosure paths.

| Method   | Path       | Description                                     | CLI equivalent |
|----------|------------|--------------------------------------------------|----------------|
| `GET`    | `/api/log` | The persisted activity log, newest last          | `wallet logs`  |
| `DELETE` | `/api/log` | Clear the log (`204`). Demo mode returns `403` | None           |

```bash
curl http://localhost:8085/api/log
curl -X DELETE http://localhost:8085/api/log
```

### Last error

The UI fetches this on page load, so it reports failures that occurred while no page was open. `GET` always returns `200`, with `null` when there is no error.

| Method   | Path         | Description                                        |
|----------|--------------|-----------------------------------------------------|
| `GET`    | `/api/error` | The last error (`message` and `detail`), or `null` |
| `DELETE` | `/api/error` | Clear it                                            |

### Health probes

Both endpoints answer `{"status": "ok"}` with `200`. They also answer under a [path prefix](../reverse-proxy.md).

| Method | Path       | Description                                                                                                  |
|--------|------------|--------------------------------------------------------------------------------------------------------------|
| `GET`  | `/healthz` | Liveness. Answers while the server runs, even when storage is down |
| `GET`  | `/readyz`  | Readiness. Reads from the storage backend and answers `503` with an `error` when that fails (for example an unreachable Postgres) |

### Encrypted request objects (`request_uri_method=post`)

OID4VP 1.0 §5.10 lets the wallet send its capabilities and a public encryption key to the verifier. The verifier can then encrypt the request object for that wallet.

When `request_uri_method=post`, the wallet sends two form parameters to `request_uri`:

- `wallet_metadata` describes supported credential formats, response types and modes, signing and encryption algorithms, and the public encryption key in `jwks`.
- `wallet_nonce` is a random nonce that the verifier can echo in its request object.

The wallet accepts a signed or unsecured request JWT, or decrypts a JWE using ECDH-ES with A128GCM or A256GCM. If the response contains `wallet_nonce`, it must match the sent value. An omitted nonce is accepted and logged because the parameter is optional.

`--require-encrypted-request` rejects request objects returned without encryption:

```bash
eudi wallet serve --auto-accept --pid --require-encrypted-request
```

### Example: E2E test flow

```bash
# 1. Start wallet in headless mode with both PID formats
eudi wallet serve --auto-accept --pid --preferred-format dc+sd-jwt &

# 2. Import an additional credential
curl -X POST http://localhost:8085/api/credentials -d @credential.txt

# 3. Run normal presentation (succeeds, uses SD-JWT)
curl -X POST http://localhost:8085/api/presentations \
  -H 'Content-Type: application/json' \
  -d '{"uri": "openid4vp://authorize?..."}'

# 4. Pre-program an error for the next request
curl -X POST http://localhost:8085/api/next-error \
  -H 'Content-Type: application/json' \
  -d '{"error": "access_denied", "error_description": "Simulated denial"}'

# 5. Next presentation returns the error (consumed after one use)
curl -X POST http://localhost:8085/api/presentations \
  -H 'Content-Type: application/json' \
  -d '{"uri": "openid4vp://authorize?..."}'

# 6. Switch to mdoc preference
curl -X PUT http://localhost:8085/api/config/preferred-format \
  -H 'Content-Type: application/json' \
  -d '{"format": "mso_mdoc"}'

# 7. Next presentation uses mdoc instead of SD-JWT
curl -X POST http://localhost:8085/api/presentations \
  -H 'Content-Type: application/json' \
  -d '{"uri": "openid4vp://authorize?..."}'
```

## Remote control

In remote mode, CLI commands use a running wallet's REST API. This covers credential management, issuance, renewal, deferred issuance, logs, presentations, trusted lists, certificate export, configuration and templates. `wallet logs --follow` remains local-only. `serve` and URL handler registration run locally. `scan` captures locally and sends the detected flow to the selected wallet.

```bash
# Switch management to a running instance (persisted until switched back)
eudi wallet use http://localhost:8085
eudi wallet list                     # lists the remote wallet's credentials
eudi issue sdjwt --wallet --template german-pid-sdjwt   # issues on the remote wallet
eudi wallet use local                # back to the local store

# One-off remote target without switching
eudi wallet list --remote http://localhost:8085

# Inspect the managed wallet (remote: the /api/config introspection document)
eudi wallet info
```

Remote commands print the same output as local ones. `eudi wallet use` (without arguments) or `eudi wallet info` shows which wallet is managed. In remote mode templates resolve against the remote instance's template directory. `wallet use <url>` verifies the target is reachable before persisting it (in `~/.eudi-dev/remote.json`, or `$EUDI_DEV_HOME/remote.json` when the environment variable is set).

#### Version compatibility

Every instance reports its release on `GET /api/version` (`version`, alongside `build_id`). `wallet use <url>` compares the CLI release with the instance release by semantic versioning:

- A differing major release is refused. `--force` selects it anyway.
- Minor and patch differences are accepted.
- A development build on either side, or an instance too old to report a version, skips the check.

The instance version is shown when a target is selected, in the `VERSION` column of `wallet ps` (and the `version` field of its `--json` output), and in the automatic routing notice below. `wallet ps` marks an incompatible instance with `(!)` and explains it on stderr.

### Automatic routing (single writer)

When a live instance serves the same wallet directory and no remote target is configured, the CLI routes commands through that instance's REST API. It prints `Routing through the running wallet instance <url>`, the release and the process ID to stderr. Version incompatibilities are reported there as well.

Use `--remote local` to bypass routing and access storage directly. While a server is running, prefer routing so the server sees each change immediately.

A running or remote wallet keeps its own store. A command that manages it refuses `--storage`, `--templates-dir` and `--seed`. A remote target from `--remote` or `wallet use` also refuses `--wallet-dir`. Add `--remote local` to use the local store with these flags.

A routed command uses the settings of the running wallet for every step of a flow, including a credential collected later. So it refuses a conformance flag whose value differs from the running wallet's, such as `--mode strict` on a wallet in debug mode. A flag with the wallet's own value passes. So does a `--relying-party-ca`, `--trusted-list-ca` or `--trusted-list` the wallet already trusts. Set the mode, HAIP, ARF and key attestation level on `wallet serve` or with `PUT /api/config/conformance`. Put CAs and lists on the wallet's trusted lists with `wallet trust`. `wallet trust add-ca --list trusted-list-ca` adds the CA of a list operator.

`wallet info` compares a running instance's configuration with the wallet file and warns when they differ (the file changed after the server started). Restarting `wallet serve` reloads the file.

### Instances

```bash
eudi wallet ps                       # list running instances (URL, version, pid, wallet dir)
eudi wallet use http://localhost:18924
eudi wallet kill 18924               # stop by port, pid, or URL
eudi wallet kill --all               # stop every running instance
```

`wallet instances list`, `wallet instances use`, and `wallet instances kill` are hidden deprecated aliases.

Each server registers in `~/.eudi-dev/instances/` and removes its entry on shutdown. Discovery removes an entry only when its process has exited. It asks each instance for its release and build ID through `GET /api/version`. An instance whose process runs but does not answer stays listed without a version, and commands for its wallet directory still route to it. `wallet kill` requests shutdown through the API and falls back to SIGTERM for unresponsive local processes.

Discovery includes local instances and the active remote target. A responding remote target appears with source `active`. The `ACTIVE` column marks the wallet currently managed by the CLI, including automatically routed local instances. JSON output uses the `active` field. An unreachable remote target produces a warning.

### Introspection

`GET /api/config` reports the instance version, build, serving URLs, wallet settings and credential count. It identifies the [storage backend](../wallet.md#storage-backends) and whether generated keys use a [seed](../wallet.md#seeded-keys).

The response includes `port`, `build_id`, `version`, `storage`, `seeded_keys`, `base_url`, `issuer_url`, `status_list_url`, `preferred_format`, `key_attestation_level`, `tls_verify`, `tls_verify_override`, `validation_mode`, `vci_version`, `auto_accept`, `session_transcript`, `require_haip`, `require_haip_issuance`, `require_arf`, `require_encrypted_request`, `force_client_attestation`, `adhoc_display_images`, `tls_listener`, `imprint` and `credential_count`.

Local instances also report `pid`, `wallet_dir` and `templates_dir`. Demo mode hides those fields and adds a `demo` object. `POST /api/shutdown` sends its response before stopping the instance.

`PUT /api/config/conformance` takes `mode`, `tls_verify`, `haip`, `arf`, `encrypted`, `vci_version` and `key_attestation_level`. It accepts these values for `tls_verify`:

| Value | HTTPS certificate verification |
|---|---|
| `true` | Verify certificates for every destination |
| `false` | Skip verification |
| `null` | Follow the mode default: strict verifies, debug skips |
| Omitted | Keep the current setting |

`GET /api/config` and the conformance response return the effective `tls_verify` value. They also return `tls_verify_override`, which is `null` when verification follows the mode default.

`DELETE /api/config/conformance` restores startup settings. Demo wallets reject changes. Add CA certificates at startup with `--tls-ca`.
