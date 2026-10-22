# Postgres stores wallet entities as keyed blobs

## Decision

Postgres uses one table, `eudi_dev_state`. Each credential, status entry, log entry or other stored value has its own row and key. The wallet encodes these values as JSON, PEM or image bytes. The backend stores and retrieves the bytes through the same `storage.Store` interface used by files and memory.

[ADR-0016](0016-state-goes-through-one-storage-layer.md) describes the schema and how servers save and reload state.

## Rationale

The wallet validates credentials and matches DCQL queries in Go. It already needs parsed credentials in memory for these operations. Storage retrieves values by key or lists the values in a wallet section. The current operations do not use SQL joins or filter credential claims in the database.

One storage interface lets files, memory and Postgres share the wallet persistence code and backend tests. It also handles credentials, keys, certificates, images and templates without a different database schema for each kind of value. Adding an optional credential field does not require changing the SQL schema.

Memory and Postgres save each entity separately. Updating one credential leaves the other credential rows unchanged. Section revisions and row versions tell servers what to reload, so unchanged credentials keep their parsed form.

## Keys

The default wallet uses the prefix `wallet` on hosts and in containers. Custom wallet directories produce separate prefixes. Examples:

| Key | Contents |
|---|---|
| `wallet/state/credentials/<id>` | Credential JSON and display order |
| `wallet/state/status/<credential-id>` | Status list index and status |
| `wallet/state/log/<timestamp>-<hash>` | Activity log entry |
| `wallet/state/deferred/<id>` | Deferred issuance JSON and order |
| `wallet/state/revision/credentials` | Credential section revision marker |
| `wallet/state/status-counter/value` | Next status list index |
| `wallet/state/trust/lists` | Providers and external lists added to the trusted lists |
| `wallet/holder.pem`, `wallet/issuer.pem` | Private keys |
| `wallet/signing-keys/<name>.pem` | Provider and service signing keys |
| `wallet/certificates/<name>.pem` | Current provider and service certificates |
| `wallet/authorities/<name>.pem` | The relying party access CA and the registrar CA |
| `wallet/certificate-der/<sha256>.der` | Archived signing certificates |
| `wallet/trustlists/...` | Current trusted lists and signed history |
| `wallet-ca-key.pem`, `wallet-ca-cert.pem` | CA shared under the parent prefix |

## Consequences

The primary key supports direct lookups, and a `text_pattern_ops` index supports prefix queries. Saves compare wallet state in Go and write changed entities and revision markers in separate statements. Reloading a changed section first reads its row versions.

[The load test example](../../examples/load-test/README.md) exercises 2 servers sharing Postgres. The wallet microbenchmarks use memory, so they do not measure database latency.

Issuance can save a credential, its status entry, type registration and log. Batch issuance saves several credentials. A shared counter allocates distinct status indices using compare-and-swap. Interrupted issuance can leave unused indices. Logs are appended independently.

Each row write is atomic. A save across several rows can partially fail, and concurrent changes to the same entity can overwrite each other. The application checks relationships stored inside JSON.
