# Security

## Scope

`eudi-dev` is a development and testing tool. Never use it with real credentials or real identity data.

## Key Considerations

- **Unencrypted storage**: Credentials and private keys are stored without encryption on every backend. File storage uses `~/.eudi-dev/wallet/` by default.
- **Seeded keys**: Anyone who knows or guesses `--seed` or `EUDI_DEV_SEED` can derive the generated keys. The Docker image uses the public seed `eudi-dev`. Set a different seed, or an empty value for random keys.
- **Shared CA**: File storage keeps the CA key at `~/.eudi-dev/wallet-ca-key.pem`. Postgres keeps it in the shared database. Wallets under the same parent directory share this CA. Anyone who can read the key can issue credentials accepted by verifiers that trust it.
- **Open HTTP API**: The wallet, decoder and proxy have no authentication. Keep them on localhost or an isolated network. For public hosting, use `--demo`. It disables process and filesystem controls, blocks requests to private networks and resets state periodically. All data and operations that remain are public. See [public demo hosting](docs/public-demo.md).
- **Browser access**: Web pages can send requests to localhost. The API rejects requests whose `Origin` belongs to another site. `/api/dc-api` is exempt because verifiers call it from their own pages. Protocol endpoints accept browser navigation. Requests without an `Origin` header (from CLI clients) are accepted.
- **Proxy logs**: The proxy records complete requests and responses, including tokens and credentials.
- **Supported trust mechanisms**: The wallet reports unsupported mechanisms (such as DID keys and OpenID Federation client identifiers) and does not resolve them. See [ADR-0013](docs/adr/0013-only-the-eudi-stack-is-supported.md).
- **Signature checks**: Request objects and signed issuer metadata are checked for valid signatures and consistent certificate chains. The wallet has no configured issuer or verifier trust anchors. A party with its own certificate and a matching `x509_hash` or `sub` passes these checks. A valid signature does not prove who the signer is.
- **Outbound HTTPS**: Strict mode verifies server certificates, including local endpoints and redirects. Debug mode skips verification by default. `--tls-verify=true|false` overrides either default for every destination. `--tls-ca` adds CA certificates to system trust. Credential and request object signatures are checked separately.
- **Test key attestations**: By default, key attestations claim the storage and authentication levels requested by the issuer, including `iso_18045_high`. The wallet does not provide those protections. Use `--key-attestation-level none` to omit the claims, or set a level to test that level. Local wallets can change this in the Conformance panel. The activity log records the claims.
- **Revocation**: The wallet can present revoked credentials. Its status display is for information only. The demo verifier checks status and rejects revoked credentials.

## Reporting

Report security issues at [github.com/eudi-dev/eudi-dev/issues](https://github.com/eudi-dev/eudi-dev/issues).
