# Each demo issuer identity is its own issuer

The demo issuer page lets you choose how the issuer identifies itself: registered, not registered, with unsigned metadata, or with your own access certificate and `issuer_info`. The signature and `issuer_info` both live in the Credential Issuer Metadata. A wallet fetches that metadata from the Credential Issuer Identifier, and the request does not say which offer it is for (OpenID4VCI 1.0 §12.2.2). The `credential_issuer` in the metadata must be identical to that identifier (§12.2.4). So one identifier can't serve different metadata per offer. A server-wide switch would change the issuer for every visitor of a shared demo.

## Decision

Each identity has its own Credential Issuer Identifier below `/issuer`:

- `/issuer` is the registered identity. It also serves the issuer page and its API.
- `/issuer/unregistered` publishes no `issuer_info`.
- `/issuer/unsigned` answers with plain JSON metadata without `issuer_info`, also when the wallet asks for signed metadata.
- `/issuer/own/{token}` is created for one offer. It signs with the visitor's key and access certificate chain and publishes the visitor's `issuer_info`. It ends 10 minutes after its last request.
- `/issuer/variant/{token}` is created for one offer whose options change the metadata, such as an offer for the `jwt` proof type alone. It presents itself like the chosen identity and ends like an own identity.

An identifier created for one offer also advertises the copies of that offer as its `batch_size`.

Every identifier serves the same protocol endpoints from the same state. The request path determines the identity. An offer records its identity. Its codes, tokens and authorization sessions work only at that identifier. The metadata, the DPoP `htu`, the key proof and attestation PoP `aud`, the `iss` of the authorization response and the `iss` of the issued credential all use the identifier in the request URL. The identity check during interactive authorization is a presentation request, so it is chosen separately from the issuer identity, like the identity of the demo verifier.

## Consequences

A wallet sees each identity as a separate issuer. A credential from an own identity keeps its issuer identifier after that identity expires, and the identifier then returns 404. The server root registers the well-known metadata of every identity, so a new identity needs no new route.
