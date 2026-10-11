# Wallet

The wallet stores test credentials and presents them through OID4VP. It accepts OID4VCI offers from the CLI, QR codes and links. Credentials and keys are stored in `~/.eudi-dev/wallet/` by default. `--wallet-dir` selects another directory. [Memory and Postgres storage](#storage-backends) are also available.

The wallet has two validation modes. Both run the same checks. They differ in how they handle violations:

- `debug` (default) reports each finding and continues processing the request. In DCQL evaluation it keeps a credential match with a warning when some required claim paths are missing but other requested claims match
- `strict` treats violations as errors and rejects the request

Strict mode covers OpenID4VP 1.0, OpenID4VCI 1.0 and HAIP 1.0. Advisory findings are warnings in both modes. Two flags add more checks. `--haip` adds the HAIP 1.0 checks (see [HAIP 1.0 enforcement](wallet/presenting.md#haip-10-enforcement)). `--arf` adds the ARF checks of verifier and issuer certificates (see [ARF checks](wallet/presenting.md#arf-checks)). The mode decides what happens to their findings.

For OpenID Foundation conformance work, see [docs/conformance.md](./conformance.md).
For interaction diagrams of the implemented OID4VP and OID4VCI flows, see [docs/diagrams](./diagrams/README.md).

## Subcommands

| Subcommand   | Purpose |
|--------------|---------|
| `serve`      | Start the wallet server with its web UI |
| `list`       | List stored credentials |
| `show`       | Show a stored credential by ID (raw or decoded) |
| `import`     | Import an SD-JWT, JWT VC or mdoc credential from a file, stdin or a raw string |
| `remove`     | Remove a credential by its ID |
| `accept`     | Accept an OID4VP presentation request or OID4VCI credential offer (auto-detected) |
| `scan`       | Scan a QR code and accept or import its content |
| `refresh`    | Ask a credential's issuer for a fresh copy over the refresh token grant |
| `deferred`   | List deferred credentials (`check`, `abandon`) |
| `logs`       | Show the activity log (`clean` removes old entries) |
| `tls-cert`   | Print or export the wallet HTTPS leaf certificate |
| `ps`         | List running wallet instances |
| `use`        | Switch management to a remote instance (`use <url>`) or back to local (`use local`) |
| `kill`       | Stop a running wallet instance by pid, port or URL (`kill --all` stops all) |
| `info`       | Show the configuration of the managed wallet (local or remote) |
| `register`   | Register the OS URL scheme handlers on macOS (a no-op elsewhere) |
| `unregister` | Remove the OS URL scheme handlers on macOS (a no-op elsewhere) |

Three top-level commands also work on the active wallet and take the same wallet flags:

| Command     | Purpose |
|-------------|---------|
| `registrar` | Register verifiers and issuers, issue their access and registration certificates, and revoke or activate them (`verifiers`, `issuers`, `access-cert`, `registration-cert`, `revoke`, `activate`). See [registrar](wallet/registrar.md) |
| `catalog`   | List, add and remove attestation types in the [attestation catalogue](wallet/registrar.md#attestation-catalogue) (`list`, `add`, `rm`) |
| `trust`     | List the wallet's trusted lists (`list`), print one (`show`), export the wallet CA (`ca-cert`), and add or remove your CAs and external lists (`add-ca`, `rm-ca`, `add-list`, `rm-list`). See [trusted lists](wallet/serve.md#trusted-lists) |

## Quick start

```bash
# Issue PID credentials from the predefined templates and list them
eudi issue sdjwt --wallet --template pid-sdjwt
eudi issue mdoc --wallet --template pid-mdoc
eudi wallet list

# The German PID, which extends the country-independent one
eudi issue sdjwt --wallet --template german-pid-sdjwt
eudi issue mdoc --wallet --template german-pid-mdoc

# Show a credential (raw)
eudi wallet show <id>

# Show a credential (human-readable decoded)
eudi wallet show --decoded <id>

# Start the wallet web UI with stored credentials
eudi wallet serve

# Start the wallet and register URL scheme handlers
eudi wallet serve --register

# Export the shared wallet CA for verifier trust stores
eudi trust ca-cert --out wallet-ca-cert.pem

# Export the HTTPS wallet certificate for verifier trust stores
eudi wallet tls-cert --out wallet-tls-cert.pem

# Process an OID4VP request from the CLI
eudi wallet accept 'openid4vp://authorize?client_id=...'

# Accept a credential offer (auto-detected from URI)
eudi wallet accept 'openid-credential-offer://...'

# Scan a QR code from screen and auto-detect the flow
eudi wallet scan --screen

# Show wallet-side interactions
eudi wallet logs
eudi wallet logs -f

# Import a credential from a file
eudi wallet import credential.txt

# Register URL scheme handlers so openid4vp:// links open the wallet on macOS
eudi wallet register
```

On Linux and Windows, `wallet register` and `wallet unregister` are no-ops. Open copied protocol links with `eudi wallet accept '<uri>'`. Credential offers support `openid-credential-offer://`, `haip-vci://` and EUDI `eu-eaa-offer://`.

While `wallet use <url>` sets a remote target, the macOS URL handler sends clicked links to that instance. It opens the remote consent UI in the browser. `wallet use local` routes links back to the local wallet server.

## Credential type inheritance

A domestic PID extends the country-independent type, as required by ARF Annex 2 (v3.0.0), PID_14. For example, `urn:eudi:pid:de:1` includes the attributes defined by `urn:eudi:pid:1` and adds German attributes.

The wallet matches a DCQL `vct_values` entry against the credential's own type and every extended type. Any PID matches a request for `urn:eudi:pid:1`. A German PID matches a request for `urn:eudi:pid:de:1`. When a credential matches through an extended type, the `[DCQL]` server log records the requested type.

The wallet derives these relationships from two sources:

- the PID type itself. A country or region code after `urn:eudi:pid:` (`urn:eudi:pid:de:1`, `urn:eudi:pid:fr:1`) marks a domestic type. A domestic type extends `urn:eudi:pid:1`. A version number after `urn:eudi:pid:` (`urn:eudi:pid:1`, `urn:eudi:pid:2`) marks the country-independent type
- the `aka_vcts` claim ([SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) §2.2.2.2). It lists additional types of the credential and applies to every credential type. The German PID issued by eudi-dev carries it

Inheritance describes the credential type only. Signature and trusted list checks decide whether the issuer is authorized (§7.7: "Verifiers and Holders MUST NOT assume that any issuer who issues a credential extending a known type is authorized to do so").

In mdoc every PID has the doctype `eu.europa.ec.eudi.pid.1` (PID_04). National elements are in a domestic namespace. Its name is the doctype with the country or region code appended (`eu.europa.ec.eudi.pid.de.1`, PID_06). A `doctype_value` request therefore matches every PID. A claim query selects a national element by its namespace: `"path": ["eu.europa.ec.eudi.pid.de.1", "birth_name"]`.

## Storage

The wallet stores all data unencrypted. This includes private keys and any access or refresh tokens from issuers. Use it with test issuers only and treat the wallet directory as disposable.

All wallet state is stored in `~/.eudi-dev/wallet/` by default:

```
~/.eudi-dev/
├── wallet-ca-cert.pem  # Shared CA certificate used across wallet instances
├── wallet-ca-key.pem   # Shared CA private key
├── remote.json         # Active remote wallet target set by wallet use
├── instances/          # Registry of running wallet servers (one file per pid)
└── wallet/
    ├── wallet.json       # Credentials + metadata
    ├── holder.pem        # Holder EC private key (auto-generated on first use)
    ├── issuer.pem        # Issuer EC private key (signs PIDs)
    ├── wallet-log-cleaned-at # Timestamp marker written by wallet logs clean
    ├── wallet-tls-cert.pem # HTTPS certificate for wallet endpoints on port+1
    ├── wallet-tls-key.pem  # HTTPS private key for wallet endpoints on port+1
    ├── signing-keys/       # Keys for provider, access, registrar, status and list signatures
    ├── authorities/        # Self-signed relying party access CA and registrar CA
    ├── certificates/       # Current signing certificates and provider CAs
    ├── certificate-der/    # Published certificates retained by fingerprint
    ├── trustlists/         # Current signed trusted lists and their history
    ├── assets/             # Display images (card art) referenced from wallet.json
    └── templates/          # User credential templates (see templates.md)
```

Display images are stored once in `assets/`, named by a hash of their content. Credentials refer to them as `asset:<hash>.<ext>`. Embedded `data:` URIs are readable and move into asset storage on the next save.

On the file backend the activity log is the top-level `log` field of `wallet.json`. The other backends store each entry separately (see [Storage backends](#storage-backends)). `wallet logs clean` clears the entries and writes `wallet-log-cleaned-at`. When a running wallet server saves, it drops in-memory entries older than that marker. With `--wallet-dir`, both files are in that directory.

Keys are P-256 EC keys, generated on first use and reused across invocations. Wallets under the same parent directory share a persisted root CA. The generated root permits one intermediate CA. Credential and wallet provider certificates use provider intermediates for their role and country. A configured root with a path length of zero signs those leaves directly.

Generated credentials are signed with the key of their provider role. A PID uses the wallet's issuer key. The other categories, custom lists and unlisted credentials have their own keys in `signing-keys/` (see [trusted lists](wallet/serve.md#trusted-lists)). SD-JWT credentials carry a deterministic `kid` and a certificate chain in `x5c`, with the self-signed root omitted. The wallet's trusted lists publish the corresponding signing certificates and provider CAs. JWT VC issuer metadata lists one key per list.

Wallet attestations, access signatures, registrar responses, status lists and trusted lists use separate keys and certificates. File and Postgres storage keep signing certificates across restarts. Published certificate URLs stay available after renewal. See [test certificates](test-certificates.md) for the signing roles, EUDI specification versions and ISO certificate profile difference.

Generated credentials expire in **30 days** by default. Use `--exp` to override (e.g. `--exp 720h` for 30 days, `--exp 24h` for 1 day). Use `--nbf` to set a not-before time (RFC3339 or duration, e.g. `--nbf 2025-01-15T00:00:00Z` or `--nbf -1h`).

![Wallet UI](./assets/wallet-ui.png)

## `wallet show <id>`

Shows a stored credential by its ID (as printed by `wallet list`). An unambiguous ID prefix also works. By default it prints only the raw credential string, for piping. `--json` prints the stored credential with its metadata. `--decoded` prints human-readable output (the `--json` and `-v` global flags apply). Decoded output starts with a validity line.

The `VALID` column of `wallet list` shows the same information. It is the time left (`29d`, `5h`, `expired`), or `-` for a credential without an expiry.

```bash
eudi wallet show <id>                  # Raw credential string
eudi wallet show --json <id>           # Stored credential and metadata as JSON
eudi wallet show --decoded <id>        # Human-readable output
eudi wallet show --decoded --json <id> # JSON output
```

| Flag        | Default | Description                                          |
|-------------|---------|------------------------------------------------------|
| `--decoded` | `false` | Show human-readable decoded output instead of raw    |

## `wallet logs`

Shows saved OID4VP and OID4VCI activity, including requests, responses, credential imports, deferred issuance and notifications.

Each entry is one line with the event, direction, endpoint, status and other available request details. `-v` / `--verbose` expands the payloads, including DCQL queries, credential requests, presented claims and issuer or verifier responses.

`-f` / `--follow` prints new entries as they are saved.

```bash
eudi wallet logs              # One line per persisted wallet interaction
eudi wallet logs -v           # Expand request/response details
eudi wallet logs -f           # Print existing logs, then follow new entries
eudi wallet logs clean        # Remove old persisted wallet logs
eudi wallet logs --json       # JSON array of log entries
```

| Flag       | Default | Description                                      |
|------------|---------|--------------------------------------------------|
| `-f, --follow` | `false` | Keep running and print new entries as they appear. Local wallets only |
| `-v, --verbose` | `false` | Global flag. Expand structured log details        |
| `--json`   | `false` | Global flag. Output the persisted log entries as JSON. Cannot be combined with `--follow` |

## Wallet server

`wallet serve` runs the web UI, protocol endpoints, trusted lists and management API. It loads credentials from the selected storage backend and asks for consent on interactive requests. On macOS it can also register URL scheme handlers. The [activity log API](wallet/http-api.md#activity-log) describes the JSON format of the activity view.

```bash
eudi wallet serve                      # web UI on http://localhost:8085
eudi wallet serve --auto-accept --pid  # headless, with default PIDs, for tests
```

See [wallet server](wallet/serve.md) for the endpoints, trusted lists, certificate export, URL scheme registration, runtime conformance settings, and every `wallet serve` flag.

## Presentation

`wallet accept` answers an OID4VP presentation request or starts issuance for a credential offer. `wallet scan` does the same from a QR code. The wallet's `/authorize` and `/credential-offer` URLs run the same flows without a custom scheme.

```bash
eudi wallet accept 'openid4vp://authorize?...'   # evaluate DCQL, consent, submit
eudi wallet scan --screen                        # scan a QR and dispatch
```

See [presentation from the wallet](wallet/presenting.md) for the `wallet accept` and `wallet scan` flags, invoking the wallet by URL, HAIP 1.0 and ARF checks.

## Issuance

`wallet accept` accepts a credential offer. The UI, a scanned QR code and the `/credential-offer` URL do the same. The wallet handles sign-in at the issuer, deferred issuance, renewal, and interactive authorization (presentation during issuance).

```bash
eudi wallet accept 'openid-credential-offer://...'   # accept an offer
eudi wallet deferred                                 # what is still being collected
eudi wallet refresh <credential-id>                  # ask for a fresh copy
```

See [issuance into the wallet](wallet/issuing.md) for sign-in, renewal, deferred issuance, wallet attestation, the OpenID4VCI feature level (`--vci-version`), and interactive authorization.

## HTTP API

A running `wallet serve` exposes credential and template management, issuance, status changes, certificate exports and instance controls over HTTP. The API has no authentication by default. Use it for local development and isolated test networks only.

```bash
curl http://localhost:8085/api/credentials
curl -X POST http://localhost:8085/api/issue -d '{"format":"sdjwt","pid":true}'
```

See [the wallet HTTP API](wallet/http-api.md) for every endpoint and for remote control (driving another instance from the CLI).

## Shared flags

All wallet subcommands accept `--wallet-dir` to override the storage directory, `--templates-dir` to override the credential template directory (see [templates](templates.md)), `--storage` to choose the storage backend and `--seed` to derive the generated keys (see [seeded keys](#seeded-keys)). These flags shape the local store, so a command that manages a running or remote wallet refuses them (see [automatic routing](wallet/http-api.md#automatic-routing-single-writer)):

```bash
eudi wallet list --wallet-dir /tmp/test-wallet
eudi wallet serve --templates-dir ./my-templates
eudi wallet serve --storage memory
```

## Storage backends

`--storage` or `EUDI_DEV_STORAGE` selects where credentials, keys, certificates, assets, templates and the activity log are stored:

| Value | State lives in |
|-------|----------------|
| `file` (default) | The wallet directory described above. One wallet server per directory. CLI commands can run alongside it |
| `memory` | The process. One wallet server. It starts empty and loses all state on exit (the [Docker image](docker.md#storage) default) |
| `auto` | Files when `--wallet-dir` or `EUDI_DEV_HOME` is given or the state directory contains existing state, memory otherwise |
| `postgres://user:pass@host:5432/db` | Rows in `eudi_dev_state`. Servers using the same database and wallet prefix share persisted state |

The file backend stores wallet state in `wallet.json`. Memory and Postgres store entities separately. Postgres uses one table, `eudi_dev_state`, for entities, keys, certificates and revision markers, plus a sequence for write versions. See [the storage design](adr/0016-state-goes-through-one-storage-layer.md) for the schema and concurrency limits.

On every backend the CLI finds running wallets by their wallet directory. `GET /api/config` reports the backend as `storage`. The default wallet uses the database prefix `wallet`. Host processes and containers on the same database share its persisted state. Browser flows and demo requests stay local to each server.

The flag and environment variable also apply to `issue --wallet` and `templates`. [ADR-0018](adr/0018-postgres-stores-wallet-entities-as-keyed-blobs.md) explains why Postgres uses keyed blobs, with example keys and performance tradeoffs.

## Seeded keys

`--seed <string>` or `EUDI_DEV_SEED` derives holder, issuer, CA, TLS and role-specific signing keys from a string. With memory storage, the keys stay the same across restarts. Existing stored keys take precedence. A fresh memory store creates new certificates with unique serial numbers.

The [Docker image](docker.md#stateless-container) uses the public seed `eudi-dev`. The value `auto` uses that seed for memory storage and random keys for other backends. An empty value generates random keys. `GET /api/config` reports `seeded_keys`.
