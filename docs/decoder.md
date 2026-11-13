# Decoder

`eudi decoder` starts a web UI that decodes and validates SD-JWT VC, JWT VC and mdoc credentials. A running wallet serves the same decoder at `/decoder`.

```bash
eudi decoder                       # http://localhost:8080
eudi decoder credential.txt        # opens with the credential filled in
eudi decoder --port 9090
```

Paste a credential to see its header, claims and disclosures. The decoder runs the checks of [`validate`](validate.md) on it: signature, expiry, status and the trusted list of its [catalogue entry](validate.md#catalogue-trust). **Share** copies a link with the credential in the URL fragment, so the server never receives it. In the wallet, a link to a stored credential carries only its ID.

## Certificates

Paste an X.509 certificate to read its subject, issuer, validity, key, key usage, policies and extensions. The decoder reads these forms:

- one or more PEM certificates, also next to a private key
- an `x5c` array, as in a JWT header
- one `x5c` entry or DER in base64, base64url or hex

Each certificate shows its PEM, ready to copy.

A chain is leaf first, as in `x5c` (RFC 7515 §4.1.6). The decoder runs these checks:

- the validity period of each certificate
- whether each certificate is signed by the next
- revocation through the CRLs the certificates name, once the signatures verify

Without a CRL the revocation check is skipped. A single certificate that is not self-signed needs its issuer certificate in the input for the signature and revocation checks. The decoder does not anchor the chain in a trusted list.

In a credential, each entry of the `x5c` header or the mdoc `x5chain` shows the subject of its certificate. Click it to read the certificate in place. **Open in decoder** opens it on its own, with the checks of a pasted chain.

## Trust

The decoder reads the attestation catalogue of the stored wallet when one exists. It never creates a wallet. It anchors a credential in the trusted lists of its catalogue entry, as described in [catalogue trust](validate.md#catalogue-trust). A registration certificate has no catalogue entry. The decoder anchors it in the lists of registration certificate providers. A registration certificate copied from `verifier_info` is base64url encoded (ETSI TS 119 472-2 RO-16). The decoder, `eudi decode` and `eudi validate` decode it and read the JWT inside. The decoder of a running wallet also uses the lists from `--trusted-list` and the list operators from `--trusted-list-ca`.

The decoder fetches the trusted lists, issuer metadata and status lists referenced in the input. It only connects to public addresses and loopback. `--allow-private-networks` (or `EUDI_DEV_ALLOW_PRIVATE_NETWORKS=true`) lifts the limit for issuers on a private network (see [outbound address limits](wallet/serve.md#outbound-address-limits)).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8080` | Port to listen on |
| `--listen` | `$EUDI_DEV_LISTEN`, else `127.0.0.1` | IP address to bind. `0.0.0.0` opens the decoder to the network (see [listen address](wallet/serve.md#listen-address)) |
| `--imprint-file` | None | HTML snippet with the operator's legal notice, served at `/imprint` |
| `--allow-private-networks` | `$EUDI_DEV_ALLOW_PRIVATE_NETWORKS`, else `false` | Allow outbound requests to private networks |

## Validation API

`POST /api/validate` decodes and validates one credential. The decoder UI uses this call. A running wallet serves it at `/decoder/api/validate`. The body is JSON with these fields:

| Field | Type | Description |
|-------|------|-------------|
| `input` | string | The credential: an SD-JWT VC, a JWT, a base64url-encoded JWT, or an mdoc in base64url or hex. Required |
| `key` | string | Issuer public key (PEM or JWK) for the signature check |
| `trustListURL` | string | URL of a trusted list that anchors the issuer |
| `trustListRaw` | string | A trusted list JWT that anchors the issuer |
| `checkStatus` | bool | Fetch the status list of a credential with a status reference |
| `offline` | bool | Skip the checks that need the network. These checks return `skipped` with `needsNetwork: true` |

The response is the decoded credential with a `validation` object. Its `checks` array lists one entry per check with `name`, `status` (`pass`, `fail`, `warning` or `skipped`) and `detail`. A passing trust or status list check also returns its `anchor`: the `list_url` and `service` of the trusted list entry, and the catalogue `entry` that links the list.

```bash
curl -X POST http://localhost:8080/api/validate \
  -H 'Content-Type: application/json' \
  -d '{"input": "eyJhbGciOi...", "offline": true}'
```

```json
{
  "format": "dc+sd-jwt",
  "header": {"alg": "ES256", "typ": "dc+sd-jwt"},
  "payload": {"vct": "urn:eudi:pid:1"},
  "disclosures": [],
  "resolvedClaims": {},
  "validation": {
    "checks": [
      {"name": "expiry", "status": "pass", "detail": "expires in 29 days"},
      {"name": "signature", "status": "skipped", "detail": "Needs an issuer key that is only reachable over the network", "needsNetwork": true}
    ]
  }
}
```

A body without `input` returns `400`. Input that does not decode returns `422`. The API refuses requests with a foreign `Origin` header with `403`. Each error response is an [error object](wallet/http-api.md#errors) with `error` and `error_description`.
