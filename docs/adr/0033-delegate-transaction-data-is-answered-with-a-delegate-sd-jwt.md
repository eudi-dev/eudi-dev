# Delegate transaction data is answered with a Delegate SD-JWT

Delegate SD-JWT (draft-ietf-oauth-delegate-sd-jwt-00, 26 October 2026) lets the holder of an SD-JWT VC delegate it to another key. The holder signs a KB-SD-JWT over the credential. Its Delegate Payload holds the key of the Delegate Holder and limits the delegation. §7.1 defines the OpenID4VP transaction data type `delegate`. A verifier asks for a delegation with it, and the wallet answers with the chain. Section numbers without a document name refer to the draft.

The EUDI ARF does not reference this draft. [ADR-0013](0013-only-the-eudi-stack-is-supported.md) limits the toolkit to the specifications of the EUDI stack.

## Decision

The wallet supports the type `delegate` as an opt-in exception to ADR-0013. The exception has 3 reasons:

- The draft is a working group document of the IETF OAuth WG, like SD-JWT and SD-JWT VC.
- It builds on 3 mechanisms of the wallet: SD-JWT disclosures, the Key Binding JWT and OpenID4VP transaction data.
- Developers of agents and verifiers need a test wallet that produces the chain.

Support is experimental and off by default. It needs `--transaction-data` ([ADR-0031](0031-transaction-data-is-opt-in-and-binds-to-sd-jwt.md)) and `--delegate-sd-jwt`. `--experimental` turns on both. The Settings dialog and `PUT /api/config/conformance` (`delegate_sd_jwt`) change the switch at runtime. The flag help, a warning at startup, the documentation and the consent dialog say that the feature is experimental. Without the switch, `delegate` is an ordinary transaction data type. The wallet accepts it only when `--transaction-data-type` lists it, and then signs the entry's hash into the Key Binding JWT without the §7.1 checks. An unlisted `delegate` is an unknown type. Strict mode refuses the request, and debug mode signs the hash into a Key Binding JWT.

With the switch on, the wallet checks each `delegate` entry against §7.1:

- `format` is `dSD-JWT` or `dSD-JWT+KB`
- `delegate_payload_disclosure` decodes to `[salt, object]` (§5.1.3)
- every digest inside the Delegate Payload has its disclosure in `delegate_disclosures`
- every disclosure in `delegate_disclosures` matches a digest (RFC 9901 §7.1)
- the Delegate Payload of a `dSD-JWT+KB` entry has a `cnf` claim (§5.1.4)

Strict mode refuses a request with such a finding. The error is `invalid_transaction_data`. Debug mode warns and signs the KB-SD-JWT when the entry has a `delegate_payload_disclosure` string.

The answer is a dSD-JWT in compact serialization (§5.1.1). The wallet puts a KB-SD-JWT in the place of the Key Binding JWT and signs it with the `cnf` key of the credential:

```
<Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~~<KB-SD-JWT>~<delegate payload disclosure>~<delegate disclosure 1>~...~<delegate disclosure M>~
```

The KB-SD-JWT has these properties:

- `typ` is `kb-sd-jwt+kb` for the format `dSD-JWT+KB` and `kb+sd-jwt` for `dSD-JWT` (§5.1.4).
- `iat`, `aud`, `nonce` and `sd_hash` are those of a Key Binding JWT (RFC 9901 §4.3).
- `delegate_payload` is an array with the digest of each Delegate Payload disclosure.
- `_sd_alg` is the hash algorithm of `transaction_data_hashes`. §7.1 allows any hash algorithm that the transaction data accepts. The wallet tries `sha-256`, `sha-384` and `sha-512` in this order and uses the first one accepted by every entry of the presentation. An entry without `transaction_data_hashes_alg` accepts only `sha-256` (OpenID4VP 1.0 Appendix B.3.3.1).
- The wallet also adds `transaction_data_hashes` (OpenID4VP 1.0 Appendix B.3.3.1). That appendix is an optional profile for transaction data types, and the draft doesn't say whether `delegate` uses it. With the hashes, a verifier checks a `delegate` entry like every other transaction data entry, and the KB-SD-JWT is bound to the unchanged entry from the request.

The wallet copies `delegate_payload_disclosure` and `delegate_disclosures` into the answer unchanged. Several `delegate` entries bound to one presentation share one KB-SD-JWT (§7.1).

`pkg/sdjwt/delegate` builds and verifies the chain. `delegate.Verify` runs steps 1 to 5 of §6 for any number of KB-SD-JWTs and for the Key Binding JWT of the Delegate Holder in a dSD-JWT+KB. It verifies the Issuer-signed JWT with a key from the caller. The caller decides whether it trusts that key and whether the delegation fits its own policy. Step 5.1 rejects a dSD-JWT only when the caller requires Key Binding. `eudi decode`, `eudi validate` and the decoder show the components of a chain and add a `delegation` check.

The predefined transaction template `delegation` is listed while the feature is on. Each request needs a fresh salt, the key of the Delegate Holder and a current `exp`. The template therefore holds the Delegate Payload as the plain object `delegate_payload`. The demo verifier encodes it into `delegate_payload_disclosure` for each request. A payload without `cnf` gets the key of the demo verifier. A payload without `exp` gets an `exp` 1 hour ahead. The demo verifier verifies the chain of the answer. It also checks that the KB-SD-JWT carries the digest of each requested Delegate Payload.

For each Delegate SD-JWT, the wallet stores a delegation record with the credential. Every storage backend keeps these records. The draft defines no revocation of a single delegation, so the record is the only place where the user sees which delegations are still valid. It holds the requester, `aud`, `iat` (as `signed_at`), the format, the disclosed claim paths, each Delegate Payload with its `cnf` key and `exp`, and the dSD-JWT. A delegation is active until the `exp` of its Delegate Payload. The credential card counts the active ones, and a dialog lists all records. The wallet warns before it deletes or revokes a credential with active delegations. A deleted credential stays valid at the Delegate Holder. A revoked credential ends its delegations. A credential keeps up to 50 records.

The wallet implements the compact serialization for SD-JWT VC. The JSON serialization (§5.1.2) and mdoc are outside this decision.

## Consequences

The draft is at version 00, so its format can still change. The opt-in keeps a default wallet on the specifications of the EUDI stack. Follow the draft with each new version and state the version in findings and docs.

The consent dialog sums up a `delegate` entry in one sentence with the thumbprint of the `cnf` key and the `exp` of the Delegate Payload.
