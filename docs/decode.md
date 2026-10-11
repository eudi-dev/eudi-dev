# Decode

Inspect credentials (SD-JWT, JWT VC, mdoc), OpenID4VCI/VP requests, and ETSI trusted lists. The format is detected from the input.

```bash
# Credentials
eudi decode credential.txt
eudi decode "eyJhbGci..."
eudi decode --json credential.txt
eudi decode -v credential.txt
cat credential.txt | eudi decode

# OpenID4VCI credential offers
eudi decode 'eu-eaa-offer://?credential_offer_uri=...'
eudi decode 'openid-credential-offer://?credential_offer_uri=...'
eudi decode 'https://issuer.example/offer?credential_offer=...'

# OpenID4VP authorization requests
eudi decode 'openid4vp://authorize?...'
eudi decode 'haip-vp://authorize?...'
eudi decode 'eudi-openid4vp://authorize?...'
eudi decode request.jwt
cat offer.json | eudi decode

# ETSI trusted lists
eudi decode trusted-list.jwt
eudi decode -f trusted-list https://example.com/trusted-list.jwt
```

## Auto-detection order

1. **URI schemes**: `openid-credential-offer://` / `haip-vci://` / `eu-eaa-offer://` (VCI), `openid4vp://` / `haip-vp://` / `eudi-openid4vp://` (VP)
2. **HTTP(S) URL with OID4 query params**: `credential_offer` / `credential_offer_uri` (VCI), `client_id` / `response_type` / `request_uri` (VP)
3. **SD-JWT**: contains `~` separator
4. **mdoc**: hex or base64url encoded CBOR
5. **JSON**: inspected for a trusted list `LoTE` object and for OID4 marker keys (`credential_issuer` → VCI, `client_id` → VP)
6. **JWT**: 3 dot-separated parts. Payload inspected for the same markers

## Format override

`--format` / `-f` sets the format when auto-detection picks the wrong one (for example a credential JWT whose payload contains `credential_issuer`):

```bash
eudi decode -f jwt "eyJhbGci..."
eudi decode -f sdjwt credential.txt
eudi decode -f mdoc credential.hex
eudi decode -f vci 'openid-credential-offer://...'
eudi decode -f vp request.jwt
```

Accepted values: `sdjwt` (or `sd-jwt`), `jwt`, `mdoc` (or `mso_mdoc`), `vci` (or `oid4vci`), `vp` (or `oid4vp`), `trusted-list` (or `trust`).

## QR code scanning

```bash
eudi decode --qr screenshot.png
eudi decode --screen
```

`--screen` runs the macOS `screencapture` tool in interactive selection mode. On other platforms, take a screenshot and pass it with `--qr`.

> **Note:** macOS grants screen capture permission to the terminal app (Terminal.app, iTerm2). If the permission is missing, System Settings opens at the Screen Recording pane. Grant it and run the command again.

## Flags

| Flag             | Description                                                  |
|------------------|--------------------------------------------------------------|
| `-f`, `--format` | Set the format: `sdjwt`, `jwt`, `mdoc`, `vci`, `vp`, `trusted-list` |
| `--qr`           | Decode QR from a PNG or JPEG image file                      |
| `--screen`       | Open interactive screen region selector and decode a QR code from the selection (macOS only) |

`--qr`, `--screen`, and positional input arguments are mutually exclusive.

## Example output

```
SD-JWT Credential
──────────────────────────────────────────────────

┌ Header
  alg: ES256
  typ: dc+sd-jwt

┌ Payload (signed claims)
  _sd: ["77ofip...", "EyNwlR...", "X3X1zI..."]
  _sd_alg: sha-256
  iss: https://issuer.example
  vct: urn:eudi:pid:1

┌ Disclosed Claims (3)
  [1] given_name: Jan Wijnand
  [2] family_name: 't Hart
  [3] birthdate: 1978-02-12
```

`decode` automatically verifies JWT and SD-JWT signatures. It uses the embedded `x5c` certificate when present, or issuer metadata resolved from `iss` and `kid`. Use `validate` to supply a key or trusted list and check revocation status.

An SD-JWT that violates an RFC 9901 §7.1 rejection rule (a disclosure that overwrites a signed claim, a duplicate digest, an unreferenced disclosure) is printed with the violated rule shown above the output. The wallet rejects such a credential on import.

Use `-v` for x5c chains, digest IDs, and device key info. Use `--json` for machine-readable output.
