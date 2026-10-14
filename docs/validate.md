# Validate

Check a credential's signature, expiry and revocation status.

```bash
# Full validation with signature verification
eudi validate --key issuer-key.pem credential.txt
eudi validate --trusted-list trusted-list.jwt credential.txt
eudi validate --key key.pem --allow-expired credential.txt
eudi validate --haip credential.txt

# Expiry + revocation check without signature verification
eudi validate credential.txt
```

## Checks

`validate`, the web decoder and the [demo verifier](wallet/serve.md#wallet-serve) run the same checks in this order:

| Check | What it checks |
|---|---|
| `type` | The `typ` header of an SD-JWT VC is `dc+sd-jwt` |
| `expiry` | `exp`, `nbf` and `iat` of a JWT, `validFrom` and `validUntil` of an mdoc. An mdoc without `validUntil` fails, because ISO 18013-5 requires it |
| `integrity` | The disclosure digests of an SD-JWT. Every disclosed element of an mdoc must match a value digest of the MSO. A DeviceResponse must report status 0 |
| `trusted list` | Entries of the supplied trusted list that could not be read (only when there are some) |
| `signature` | The issuer signature |
| `trust` | Whether a trusted list anchors the credential. An SD-JWT VC or an mdoc uses the list of its catalogue entry. A registration certificate uses the lists of registration certificate providers |
| `status` | The entry in the credential's status list |
| `status list signature` | Whether a trusted list anchors the status list |
| `haip` | The HAIP 1.0 rules for an SD-JWT VC (only with `--haip`) |

The validity check allows one minute of clock skew. A credential issued in the future gets a warning.

## Signature keys

Signature keys are resolved in this order:

1. The credential's x5c (SD-JWT/JWT) or x5chain (mdoc) certificate chain, validated against `--trusted-list` when given
2. An explicitly provided `--key`
3. The embedded leaf certificate alone, when neither a key nor a trusted list is given. This works offline. The output notes that the chain was not validated
4. JWT VC Issuer Metadata, for credentials without an embedded certificate

An mdoc carries its chain in the x5chain header (RFC 9360). The protected header counts first, then the unprotected one. A malformed certificate fails the signature check.

SD-JWT VC §4 inserts `/.well-known/jwt-vc-issuer` between the host and path of `iss`. For example, `https://example.com/tenant/1234` resolves to `https://example.com/.well-known/jwt-vc-issuer/tenant/1234`. The metadata's `issuer` must equal `iss`, and its keys must come from either `jwks` or `jwks_uri`.

A credential with its certificate chain validates without network access. Without a key or a certificate, the signature check is skipped and the other checks still run. A trusted list without an issuance service supplies no key, so the signature check fails.

## Flags

| Flag              | Description                                       |
|-------------------|---------------------------------------------------|
| `--key`           | Public key file (PEM or JWK), optional            |
| `--trusted-list`  | ETSI trusted list JWT (file path or URL), optional   |
| `--status-list`   | Check revocation via status list when the credential contains a status reference (enabled by default) |
| `--allow-expired` | Accept credentials outside their validity period   |
| `--haip` | Also check the credential against HAIP 1.0 and report violations |

## Revocation status

When a credential carries a status reference, `validate` fetches the Status List Token and reads the entry. It accepts both `application/statuslist+jwt` and `application/statuslist+cwt`.

The token's signature is always verified. If the check cannot complete, validation fails with an error. A status claim in another format, such as a W3C `StatusList2021Entry`, gets a warning and is not checked. The revocation services of a trusted list anchor the token (ETSI TS 119 602 V1.1.1 Table D.3). With `--trusted-list`, the token's chain must end in one of them. Without it, the list of the credential's catalogue entry anchors the token when its chain ends there. Otherwise the key comes from the token itself (`x5c` / `x5chain`, or a header `jwk`) and the output notes that the key is unanchored. The token's `sub` must equal the `uri` in the credential's status claim. `typ`, `iat` and `exp` are checked too.

The status is reported by name (VALID, INVALID, SUSPENDED, an application specific value, or unknown) with the raw value. For multi-bit lists, the full value is reported.

## Certificate chain validation

When a trusted list is given and the credential contains an x5c (SD-JWT/JWT) or x5chain (mdoc) chain, the chain is validated against the trusted list before the signature is verified:

1. The issuance services of the trusted list hold the **CA certificates** (trust anchors)
2. The credential's x5c/x5chain contains `[leaf, ...intermediates]`
3. The leaf certificate is verified to chain up to a trusted list CA via any intermediates
4. The leaf certificate's public key is used to verify the credential signature

Wallet-issued SD-JWT credentials follow the same model. The header contains a deterministic `kid` and an `x5c` chain with the leaf and any intermediate certificates (without the root). The wallet trusted list publishes signing certificates and their provider CAs. The wallet also publishes JWT VC issuer metadata at `/.well-known/jwt-vc-issuer`.

Without a key or a trusted list, `validate` and the web decoder use the trusted list of the credential's catalogue entry. Its issuance service anchors the credential, and its revocation service the status list.

A trusted list past its `NextUpdate` is expired (ETSI TS 119 602 V1.1.1 §6.3.15). `validate` rejects it, and the decoder fails the signature check. Entries that cannot be read are left out and reported in the `trusted list` check.

## Catalogue trust

When the wallet's attestation catalogue has an entry for the credential type, `validate` and the web decoder also check whether one of the entry's trusted lists anchors the credential. The check reads the lists linked in the entry. For a PID or a PuB-EAA it also reads the lists of that type from the wallet's list of trusted lists, like the wallet does on issuance. `validate` adds the result as `trust` to `--json`. If no list anchors the credential, the check gives a warning. It fails only in the decoder of a wallet that runs in strict mode with `--arf`, because only then does the wallet refuse the credential. The result doesn't change the exit code. A type without a catalogue entry gets no trust check.

A registration certificate (`typ` `rc-wrp+jwt`) has no catalogue entry. The wallet's lists of registration certificate providers anchor it instead, as they do for a presentation under `--arf`. The issuance service of such a list anchors the certificate, and its revocation service the status list.

`validate` and `eudi decoder` read the stored wallet when it exists. Neither creates one. The lists from `wallet serve --trusted-list` and the operators from `--trusted-list-ca` count only in the decoder of the running wallet. Fetches use the HTTP client of the wallet. In the decoder of the running wallet, that client follows `--tls-ca` and the proxy flags of `wallet serve`.

The decoder fetches the trusted lists, issuer metadata and status lists referenced in the input. So `eudi decoder` and the decoder of `wallet serve` reach public addresses and loopback only. Start the server with `--allow-private-networks`, or set `EUDI_DEV_ALLOW_PRIVATE_NETWORKS=true`, for issuers on a private network (see [outbound address limits](wallet/serve.md#outbound-address-limits)). The `validate` command has no limit.

Trusted list validation covers certificate trust and service listing. Provider class and attestation-type entitlement come from signed Credential Issuer metadata (`/.well-known/openid-credential-issuer`, `issuer_info`) and registrar data. A wallet keeps one trusted list per credential category. `/api/trustlist` serves the PID list and `/api/trustlists` lists every list. In containers, use the index entry's relative `path` instead of its advertised URL.

To let a verifier trust the wallet's local HTTPS endpoints, export the wallet CA with `eudi trust ca-cert --out wallet-ca-cert.pem` and add it to the verifier trust store. `wallet tls-cert` exports the per-wallet HTTPS leaf certificate as a single PEM instead.

```bash
# Validate a wallet-issued credential against the wallet's trusted list
eudi validate --trusted-list http://localhost:8085/api/trustlist credential.txt

# Validate against the German PID provider trusted list
eudi validate --trusted-list https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt credential.txt
```

## HAIP 1.0

`--haip` adds the [High Assurance Interoperability Profile](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html) rules to the checks of an SD-JWT VC. Section 6.1.1 requires the issuer's signing certificate and chain in the `x5c` header, without the trust anchor, and forbids a self-signed signing certificate. Section 6.1 requires a status claim to use `status_list`. HAIP sets no such rule for a plain JWT or an mdoc, so `--haip` adds nothing to their checks.

## Exit code

The exit code is non-zero when the `type`, `expiry`, `integrity`, `signature` or `status` check fails. `--allow-expired` ignores the `expiry` check. The catalogue trust and the HAIP findings don't change the exit code.

## JSON output

`--json` prints one JSON document. It holds the decoded credential, every check under `checks`, the signature verification under `verification`, the status list check under `status` and the HAIP findings under `haipFindings`. A check that didn't run is left out of `verification`, `status` and `haipFindings`. With `--haip`, `haipFindings` is an empty list when there are no findings.
