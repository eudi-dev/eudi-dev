# The CLI groups commands by role

The registrar, the attestation catalogue and the trusted lists started as subcommands of `wallet`. Verifiers and issuers use them as much as the wallet does, and developers did not look for them under `wallet`. The decoder ran as `serve`, which read like the wallet server.

## Decision

Each role has its own top-level command:

- `registrar` for relying party registrations and their certificates
- `catalog` for the attestation catalogue
- `trust` for the wallet's trusted lists, the CAs and lists a user adds, and the wallet CA
- `decoder` for the decoder web UI
- `wallet` for the holder: its credentials, its server and its flows

`trust show [list]` prints one trusted list. The list is a positional argument, and `lists` selects the list of trusted lists.

Each old command path stays as a hidden command in `cmd/moved.go`. It fails with a message that names the new path. Version 3.0.0 removes the deprecated commands (`wallet generate-pid`, `wallet instances`) without a pointer.

## Consequences

A script with an old path fails with a clear message and runs nothing. A moved path needs one line in `cmd/moved.go`.
