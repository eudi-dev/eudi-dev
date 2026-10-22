# The server reloads its store on every request

A running wallet must pick up changes made by CLI commands or another server. `withFreshStore` in `internal/wallet/server.go` checks storage before most request handlers run.

## Consequences

The file backend reloads `wallet.json` when its content hash changes. Modification times are too coarse on some filesystems to tell 2 writes apart. Memory and Postgres use section revisions and row versions to refresh changed state. Log views load the activity log on demand. See [ADR-0016](0016-state-goes-through-one-storage-layer.md) for the storage layout.

A reload during a flow overwrites unsaved state. For example, the UI polls while the user signs in at an issuer, and another server on the same database saves. A flow therefore changes the wallet state only in one step under the reload lock. `Wallet.saveChange` runs the change and the save together. The network calls of the flow run before that step. Issuance and renewal store a credential with all its batch copies this way.
