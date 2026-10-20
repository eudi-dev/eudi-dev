# Demo issuer and verifier

`wallet serve` includes a demo issuer at `/issuer/` and a demo verifier at `/verifier/`. Their registrations and identities are described in [demo issuer and verifier](registrar.md#demo-issuer-and-verifier). How the issuer works as an authorization server is in [public demo hosting](../public-demo.md#demo-issuer-as-an-authorization-server).

## Your own access certificate

By default the demo issuer and the demo verifier sign with access certificates from the wallet's registrar. To test a wallet that trusts another ecosystem, such as a member state sandbox, start the server with that ecosystem's material:

```bash
eudi wallet serve --base-url https://wallet-test.ngrok.dev \
  --demo-issuer-signing-key sandbox.pem --demo-issuer-info sandbox-issuer-info.json \
  --demo-verifier-signing-key sandbox.pem --demo-verifier-registration-cert sandbox-rc.jwt
```

| Flag | Content |
|---|---|
| `--demo-issuer-signing-key`, `--demo-verifier-signing-key` | PEM file with an EC private key and its access certificate chain, leaf first |
| `--demo-issuer-info` | JSON file with the `issuer_info` array |
| `--demo-verifier-info` | JSON file with the `verifier_info` array |
| `--demo-issuer-registration-cert`, `--demo-verifier-registration-cert` | File with a registration certificate as a compact JWT. It becomes the only entry of `issuer_info` or `verifier_info` |

All flags are optional. An info file or a registration certificate needs the signing key of the same role. Use the info file or the registration certificate, not both. Without either, the metadata or the request carries no registration certificate.

The material replaces the **Registered** identity on the issuer and verifier pages. **Not registered** signs with the same key and leaves out the registration certificate. **Own certificates** still takes the key pasted on the page. The identity check during interactive authorization keeps the demo issuer's eudi-dev certificate.

## Offer options

Besides the identity, an offer sets how the issuer handles it:

- **Transaction code.** A pre-authorized offer set to "With", or created with `tx_code=true`, needs a six-digit transaction code (OpenID4VCI 1.0 §4.1.1). The issuer page shows the code below the offer, and the offer API returns it as `tx_code`. The token endpoint refuses a request without the code or with a wrong one, and the pre-authorized code is then used up.
- **Key proofs.** By default the metadata offers the `jwt` and the `attestation` proof types, and the wallet chooses. The `attestation` proof type needs a key attestation from the wallet provider. "jwt only", or `proof_types=jwt`, leaves it out.
- **Copies.** The number of credentials to issue, each bound to its own key.

The metadata comes from the issuer identifier, and one identifier serves the same metadata for every offer. So an offer with "jwt only" gets an identifier of its own under `/issuer/variant/`. It presents itself like the chosen identity. An identifier created for one offer advertises that offer's copies as `batch_size`. With a single copy it leaves out `batch_credential_issuance` and supports no batch issuance. See [ADR 0028](../adr/0028-each-demo-issuer-identity-is-its-own-issuer.md).

## Client attestation audience

The `aud` of the client attestation PoP must be the issuer identifier (ABCA draft-07 §5.2, draft-10 §5.1). The demo issuer also accepts the URL of the endpoint the wallet called, and logs a warning. A wallet with that mistake can then still finish the flow.
