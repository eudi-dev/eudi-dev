# Issue

Issue test SD-JWT, JWT, or mdoc credentials. By default, the output is signed with an ephemeral P-256 key and the public JWK is printed to stderr.

```bash
eudi issue sdjwt
eudi issue sdjwt --pid
eudi issue sdjwt --pid --omit place_of_birth,sex,personal_administrative_number
eudi issue sdjwt --pid --always-disclosed issuing_country,address.country
eudi issue sdjwt --template employee-card
eudi issue sdjwt --template employee-card --claims '{"employee_id": "E-42"}'
eudi issue sdjwt --claims '{"name":"Test","age":30}' --save-template my-test-cred
eudi issue sdjwt --claims '{"name":"Test","age":30}'
eudi issue sdjwt --iss https://my-issuer.example --vct my-type --exp 48h --nbf 2025-06-01T00:00:00Z
eudi issue sdjwt --key signing-key.pem
eudi issue sdjwt --wallet                # Issue and import into wallet
eudi issue sdjwt --wallet --vct urn:example:badge:1 --category eaa
eudi issue sdjwt --wallet --entitlement https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider --trusted-list-type http://example.com/LoTEType/Custom --issuance-service-type http://example.com/SvcType/Custom/Issuance --revocation-service-type http://example.com/SvcType/Custom/Revocation
eudi issue jwt                           # Plain JWT VC (no selective disclosure)
eudi issue jwt --pid
eudi issue jwt --claims '{"name":"Test","age":30}'
eudi issue mdoc
eudi issue mdoc --pid
eudi issue mdoc --claims '{"name":"Test"}' --doc-type com.example.test
eudi issue mdoc --pid --wallet           # Issue mdoc and import into wallet
```

Round-trip with decode:

```bash
eudi issue sdjwt | eudi decode
eudi issue jwt   | eudi decode
eudi issue mdoc  | eudi decode
```

## Flags

Flags marked "With `--wallet`" only work together with `--wallet`.

Flags shared by all three subcommands:

| Flag | Default | Description |
|------|---------|-------------|
| `--wallet-dir` | `~/.eudi-dev/wallet/` | Wallet storage directory used by `--wallet` |
| `--templates-dir` | `<wallet-dir>/templates/` | Credential template directory used by `--template` and `--save-template` |
| `--remote` | None | With `--wallet`: issue on the remote wallet server at this URL (`local` forces the local store) |
| `--storage` | `$EUDI_DEV_STORAGE` | With `--wallet`: storage backend (`file`, `memory`, `auto` or a `postgres://` URL, see [storage backends](wallet.md#storage-backends)) |
| `--seed` | `$EUDI_DEV_SEED` | With `--wallet`: derive the generated keys from this string (see [seeded keys](wallet.md#seeded-keys)) |

### `issue sdjwt`

| Flag       | Default                   | Description                                    |
|------------|---------------------------|------------------------------------------------|
| `--claims` | None                      | Claims as JSON string or `@filepath`           |
| `--key`    | None                      | Private key: a PEM or JWK file, or the PEM or JWK itself. Ephemeral if omitted |
| `--cert`   | None                      | Certificate chain (PEM, leaf first) embedded as x5c: a file or the PEM itself. Requires `--key` |
| `--iss`    | `https://issuer.example`  | Issuer URL                                     |
| `--vct`    | `urn:eudi:pid:1`       | Verifiable Credential Type                     |
| `--exp`    | `720h` (30 days)          | Expiration duration                            |
| `--nbf`    | None                      | Not-before time (RFC3339 or duration, e.g. `-1h`) |
| `--pid`    | `false`                   | Use full EUDI PID Rulebook claims              |
| `--omit`   | None                      | Comma-separated claim names to exclude         |
| `--template` | None                    | Credential template name or file (see [templates](templates.md)) |
| `--always-disclosed` | None            | Claims issued plainly instead of selectively disclosable (dotted paths for nested claims) |
| `--save-template` | None               | Save the issued claims, settings and card display as a template with this name |
| `--wallet` | `false`                   | Import the issued credential into the wallet   |
| `--batch`  | `0`                       | With `--wallet`: issue this many copies with separate holder keys, at most 8. The wallet presents an unused copy each time |
| `--unbound` | `false`                  | With `--wallet`: issue without a holder key (a bearer credential with no cnf). The default binds it to the wallet. Only a query with `require_cryptographic_holder_binding: false` matches it |
| `--status-list-uri` | None           | Status list URI to embed in credential         |
| `--status-list-idx` | `0`            | Status list index to embed in credential       |

### `issue jwt`

| Flag       | Default                   | Description                                    |
|------------|---------------------------|------------------------------------------------|
| `--claims` | None                      | Claims as JSON string or `@filepath`           |
| `--key`    | None                      | Private key: a PEM or JWK file, or the PEM or JWK itself. Ephemeral if omitted |
| `--cert`   | None                      | Certificate chain (PEM, leaf first) embedded as x5c: a file or the PEM itself. Requires `--key` |
| `--iss`    | `https://issuer.example`  | Issuer URL                                     |
| `--vct`    | `urn:eudi:pid:1`       | Verifiable Credential Type                     |
| `--exp`    | `720h` (30 days)          | Expiration duration                            |
| `--nbf`    | None                      | Not-before time (RFC3339 or duration, e.g. `-1h`) |
| `--pid`    | `false`                   | Use full EUDI PID Rulebook claims              |
| `--omit`   | None                      | Comma-separated claim names to exclude         |
| `--template` | None                    | Credential template name or file (see [templates](templates.md)) |
| `--save-template` | None               | Save the issued claims, settings and card display as a template with this name |
| `--wallet` | `false`                   | Import the issued credential into the wallet   |
| `--status-list-uri` | None           | Status list URI to embed in credential         |
| `--status-list-idx` | `0`            | Status list index to embed in credential       |

The JWT subcommand produces a standard JWT with all claims directly in the payload (no `_sd` or `_sd_alg` fields).

### `issue mdoc`

| Flag          | Default                        | Description                                    |
|---------------|--------------------------------|------------------------------------------------|
| `--claims`    | None                           | Claims as JSON string or `@filepath`           |
| `--key`       | None                           | Private key: a PEM or JWK file, or the PEM or JWK itself. Ephemeral if omitted |
| `--cert`      | None                           | Certificate chain (PEM, leaf first) embedded as x5chain: a file or the PEM itself. Requires `--key` |
| `--doc-type`  | `eu.europa.ec.eudi.pid.1`      | Document type                                  |
| `--namespace` | `eu.europa.ec.eudi.pid.1`      | Namespace                                      |
| `--exp`       | `720h` (30 days)               | Expiration duration                            |
| `--nbf`       | None                           | Not-before time (RFC3339 or duration, e.g. `-1h`) |
| `--pid`       | `false`                        | Use full EUDI PID Rulebook claims              |
| `--omit`      | None                           | Comma-separated claim names to exclude         |
| `--template`  | None                           | Credential template name or file (see [templates](templates.md)) |
| `--save-template` | None                       | Save the issued claims, settings and card display as a template with this name |
| `--wallet`    | `false`                        | Import the issued credential into the wallet   |
| `--batch`     | `0`                            | With `--wallet`: issue this many copies with separate holder keys, at most 8. The wallet presents an unused copy each time |
| `--unbound`   | `false`                        | With `--wallet`: issue without an MSO device key (a malformed mdoc for testing verifier rejection). The default binds it to the wallet. Only a query with `require_cryptographic_holder_binding: false` matches it. In strict mode no query matches it, but you can still pick it in the consent dialog |
| `--status-list-uri` | None                    | Status list URI to embed in credential         |
| `--status-list-idx` | `0`                     | Status list index to embed in credential       |

Without `--claims`, a minimal PID-like claim set is used (given_name, family_name, birthdate). `--pid` issues the full PID claim set. It has fifteen top-level SD-JWT claims (including the nested `address` and `place_of_birth` objects) or nineteen mdoc elements. The claims follow the [EUDI PID Rulebook v1.7](https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/6d8f7f8422e5bf6c48186005b6835c078f762a67/rulebooks/pid/pid-rulebook.md).

`issue jwt --pid` puts the same claim set in a plain JWT VC for verifier testing.

`--vct urn:eudi:pid:de:1` selects the German PID. It has fourteen top-level SD-JWT claims (including `aka_vcts` and the age thresholds) or twenty-three mdoc elements across two namespaces. `--vct urn:eudi:pid:it:1` and `--vct urn:eudi:pid:nl:1` select the Italian and Dutch PIDs. The claim sets come from the predefined `pid-*`, `german-pid-*`, `italian-pid-*` and `dutch-pid-*` templates. A user template with one of those names overrides the predefined claims for `--pid`.

`--template` supplies the claim set and defaults for type, namespace, and expiry. Explicit flags override the template. `--claims` overrides individual top level claims. `--omit` removes claims from the result. See [templates](templates.md) for the file format and the `templates` commands.

Every SD-JWT claim is selectively disclosable by default. `--always-disclosed` (or the template's `always_disclosed` list) embeds the listed claims plainly in the signed payload, so they cannot be withheld during presentation. Nested subclaims use dotted paths (`address.country`). `_sd`, `_sd_alg` and `...` are reserved by RFC 9901 and rejected as claim names. See [always disclosed claims](templates.md#always-disclosed-claims) for the registered claims that are always plain and for the mdoc and jwt behavior.

## Wallet registration metadata

With `--wallet`, the issuer key and certificate depend on the supplied flags:

- By default, the wallet uses the key and the certificate of the credential's category. A provider intermediate CA signs this certificate. If the configured root has a path length of zero, the root signs it directly.
- `--key` supplies another issuer key. The wallet creates a certificate for it under the shared CA. Only the local store does this. A running wallet server signs with its own issuer key and URL, so it refuses `--key` without `--cert` and `--iss`.
- `--key` with `--cert` uses the supplied key and chain. The category and the registration metadata flags are ignored. The wallet did not sign the credential, so its type is not on any wallet list.

A supplied chain that includes its self-signed root produces a warning in debug mode and is rejected in strict mode. Otherwise the wallet stores the credential and registers its type. That registration supplies metadata for:

- `/.well-known/openid-credential-issuer`
- `/api/trustlist`
- `/api/trustlists`

A type with a category is also in the registration of the demo issuer at `/api/registrar/wrp`.

Issued PID signatures include protected certificate URLs and SHA-256 fingerprints when the wallet has a certificate hosting URL. SD-JWT references PEM and mdoc references DER. Offline issuance has no hosting endpoint. See [test certificates](test-certificates.md) for certificate persistence, signing roles and the applicable EUDI versions.

Without explicit status list flags, `--wallet` registers the credential in the wallet's own status list.

If a wallet server is running for the same wallet directory, `--wallet` issues through its REST API (see [remote control](wallet/http-api.md#automatic-routing-single-writer)). Otherwise the command writes directly into the store. The embedded URLs resolve once `wallet serve` is running.

The wallet publishes one trusted list per credential category: `pid`, `qeaa`, `pub-eaa` and `eaa` (see [trusted lists](wallet/serve.md#trusted-lists)). The category of a credential decides the signer. The signer's certificate is on the list of that category. The category comes from `--category`, else from the template, else from the type's entry in the attestation catalogue. A credential with none of these is an EAA. `--category unlisted` keeps the credential off every list.

The category also sets the stored entitlement. PID gets `PID_Provider`, QEAA `QEAA_Provider`, PuB-EAA `PUB_EAA_Provider` and EAA `Non_Q_EAA_Provider`.

These flags set the stored trust and issuer metadata for the credential type:

| Flag | Default | Description |
|------|---------|-------------|
| `--category` | The template's or the catalogue entry's category, else `eaa` | Credential category: `pid`, `qeaa`, `pub-eaa`, `eaa` or `unlisted` |
| `--entitlement` | None | Registrar entitlement URI to store for the credential type. Repeatable |
| `--trusted-list-type` | None | LoTE type URI to store for the credential type |
| `--status-determination-approach` | None | Trusted list status determination approach URI to store |
| `--scheme-community-rule` | None | Trusted list scheme community rule URI to store |
| `--scheme-territory` | None | Trusted list scheme territory to store |
| `--trusted-entity-name` | None | Trusted list entity name to store |
| `--issuance-service-type` | None | Issuance service type identifier to store |
| `--revocation-service-type` | None | Revocation service type identifier to store |
| `--issuance-service-name` | None | Issuance service name to store |
| `--revocation-service-name` | None | Revocation service name to store |

### Display metadata

With `--wallet`, these flags set the card appearance of the imported credential on all three subcommands. Colors must conform to OpenID4VCI 1.0 §12.2.4. An invalid color is dropped with a warning. Images are subject to the same address policy and size limit as an issuer's display metadata. A public demo ignores the logo and background-image flags and keeps the template's images.

| Flag | Default | Description |
|------|---------|-------------|
| `--display-name` | None | The credential's display name |
| `--display-description` | None | The credential's display description |
| `--background-color` | None | The card background color, a CSS color (e.g. `#3d59a1`) |
| `--text-color` | None | The card text color, a CSS color |
| `--logo` | None | The card logo, a file path, a data URI, or an http(s) URL |
| `--logo-alt` | None | The logo's alt text |
| `--background-image` | None | The card background image, a file path, a data URI, or an http(s) URL |
| `--display-template` | None | Use the display of this template for any display value not set by the other display flags |
| `--catalog` | None | With `--save-template`: add the template to the attestation catalogue with this entry, as JSON like the `catalog` field of `POST /api/issue` (file, JSON or `-` for stdin) |
