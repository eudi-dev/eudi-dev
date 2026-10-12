# The CLI groups commands by role

The registrar, the attestation catalogue and the trusted lists started as subcommands of `wallet`. Verifiers and issuers use them as much as the wallet does, and developers did not look for them under `wallet`. The decoder ran as `serve`. That name read like the wallet server.

## Decision

Each role has its own top-level command:

- `registrar` for relying party registrations and their certificates
- `catalog` for the attestation catalogue
- `trust` for the wallet's trusted lists, user-added CAs and lists, and the wallet CA
- `decoder` for the decoder web UI
- `wallet` for the holder: its credentials, its server and its flows

`trust show [list]` prints one trusted list. The list is a positional argument, and `lists` selects the list of trusted lists.

Each old command path stays as a hidden command in `cmd/moved.go`. It fails and tells you the new path. The removed commands `wallet generate-pid` and `wallet instances` get the same message. An old flag name, such as `validate --trust-list`, fails and tells you the new one. A command that groups subcommands prints its help when called alone and fails on an unknown subcommand.

## Consequences

A script with an old path fails with a clear message and runs nothing. A moved path needs one line in `cmd/moved.go`.
