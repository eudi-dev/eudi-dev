# Transaction data is opt-in and binds to SD-JWT VC

OpenID4VP 1.0 §5.1 defines `transaction_data`, and §5 requires a wallet without support to reject it. Appendix B.3.3.1 defines how an SD-JWT VC presentation carries it. Appendix B.2.1 leaves mdoc support to each doctype, and none defines it yet. EUDI TS12 v1.0.1 defines 4 SCA transaction types with JSON schemas.

## Decision

Support is off by default and turned on with `--transaction-data` or the `transaction_data` setting. A wallet without it keeps refusing the parameter. A verifier can test both cases. The TS12 types are always known. `--transaction-data-type` adds a verifier's own types.

Strict mode refuses a request with any of these findings. The error is `invalid_transaction_data` (§8.5). Debug mode warns and still binds every entry that decodes, including one of an unknown type. That lets a verifier test its hash checks with any type.

Only an SD-JWT VC with holder binding carries transaction data, in its Key Binding JWT. Each entry binds to one presentation, because §5.1 allows only one credential to authorize it. The wallet takes the first query in `credential_ids` whose credential has a Key Binding JWT, else the first answered query. The hash algorithm is the first of `sha-256`, `sha-384` and `sha-512` accepted by all entries of a presentation.

The wallet checks the members required by TS12 §4.2 (`transaction_data_hashes_alg` and `payload`). It validates the payload against the TS12 JSON schemas (§3.2 step 4). The schemas are bundled, so validation never fetches anything. A Key Binding JWT that authorizes a TS12 entry also carries the claims of TS12 §3.6: a fresh `jti`, the `response_mode` of the answer and `amr`. The wallet does not authenticate the user, so `amr` lists the factors of a typical wallet unit: `pin_6_or_more_digits` and `key_in_local_native_wscd`.

Steps 1 and 2 of TS12 §3.2 are warnings in strict and debug mode. The wallet warns when a TS12 entry binds to a credential whose Type Metadata lacks the category `urn:eu:europa:ec:eudi:sua:sca`. For an SCA Attestation it also warns when `transaction_data_types` does not list the type of the entry. TS12 tells the wallet to stop at either step. This wallet only warns, and a payment test works with any SD-JWT VC, such as the PID. Only a credential with an HTTPS `vct` has Type Metadata, so a URN type never counts as an SCA Attestation. The wallet validates the four TS12 types against its bundled schemas and does not read `schema` or `schema_uri` (step 3). So the wallet recognizes a TS12 payload only by its `type`. If Type Metadata maps another type to a TS12 schema, the wallet treats that type as a plain JSON object. Such a type needs `--transaction-data-type`, and its payload is not validated.

Transaction templates hold example entries, like credential templates hold example credentials. The wallet ships one for each TS12 type, and users add their own. A template never needs a schema of its own. The TS12 schemas check the TS12 types, and any other type is a plain JSON object.

## Consequences

The consent dialog shows the transaction data as JSON. For a TS12 type it also sums up the payload in one sentence. A verifier that sends transaction data for an mdoc query gets a refusal in strict mode and a presentation without transaction data in debug mode.
