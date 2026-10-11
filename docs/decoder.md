# Decoder

`eudi decoder` starts a web UI that decodes and validates SD-JWT VC, JWT VC and mdoc credentials. A running wallet serves the same decoder at `/decoder`.

```bash
eudi decoder                       # http://localhost:8080
eudi decoder credential.txt        # opens with the credential filled in
eudi decoder --port 9090
```

Paste a credential to see its header, claims and disclosures. The decoder runs the checks of [`validate`](validate.md) on it: signature, expiry, status and the trusted list of its [catalogue entry](validate.md#catalogue-trust). **Share** copies a link with the credential in the URL fragment, so the server never receives it. In the wallet, a link to a stored credential carries only its ID.

## Trust

The decoder reads the attestation catalogue of the stored wallet when one exists. It never creates a wallet. It anchors a credential in the trusted lists of its catalogue entry, as described in [catalogue trust](validate.md#catalogue-trust). The decoder of a running wallet also uses the lists from `--trusted-list` and the list operators from `--trusted-list-ca`.

The decoder fetches the trusted lists, issuer metadata and status lists named in the input. It reaches public addresses and loopback only. `--allow-private-networks` (or `EUDI_DEV_ALLOW_PRIVATE_NETWORKS=true`) lifts the limit for issuers on a private network (see [outbound address limits](wallet/serve.md#outbound-address-limits)).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8080` | Port to listen on |
| `--imprint-file` | None | HTML snippet with the operator's legal notice, served at `/imprint` |
| `--allow-private-networks` | `$EUDI_DEV_ALLOW_PRIVATE_NETWORKS`, else `false` | Let outbound requests reach private networks |
