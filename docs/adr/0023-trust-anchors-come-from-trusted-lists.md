# Trust anchors come from trusted lists

The ARF has the wallet accept a trust anchor because a trusted list operator signed the list containing that anchor (PPNot_05, TLPub_05, TLPub_07). The ARF keeps separate lists for PID providers, wallet providers, access certificate providers, registration certificate providers and PuB-EAA providers. RPACANot_05 and RPACANot_05a set up the lists of access certificate providers and registration certificate providers. ETSI TS 119 602 V1.1.1 defines these lists in Annexes D to H. A test wallet also needs a way to trust the issuers and registrars of a test setup without code changes.

## Decision

The wallet takes every trust anchor from lists of trusted entities. It signs these lists itself:

| List ID | Lists | Anchors |
|---|---|---|
| `pid`, `qeaa`, `pub-eaa`, `eaa` | Credential providers of each category ([ADR 0022](0022-one-trusted-list-per-credential-category.md)) | Received credentials (ISSU_07 to ISSU_10), and credentials and status lists at the demo verifier |
| `wallet-provider` | Wallet providers (Annex E) | Wallet and key attestations at the demo issuer |
| `access-ca` | Providers of access certificates (Annex F) | Access certificates of verifiers and issuers (RPA_04, ISSU_24, ISSU_34) |
| `registrar` | Providers of registration certificates (Annex G) | Registration certificates (RPRC_02a, ISSU_23c, ISSU_33a) and their status list (RPACANot_03b) |

An issuance service anchors issued certificates and credentials. A revocation service anchors status lists. A withdrawn service anchors nothing.

The registrar has two CAs of its own. Neither chains to the wallet CA:

- The relying party access CA signs every access certificate, including those of the demo issuer and the demo verifier. The `access-ca` list contains it.
- The registrar CA signs the registrar's signing certificate. The `registrar` list contains it. The relying party access CA is not on that list, because it signs any visitor's CSR.

The demo issuer and the demo verifier register with the registrar and get their certificates through the same code as any relying party. So a test against them exercises the same checks as a test against another party.

A list of trusted lists at `/api/trustlists/lists` points to all of these lists and to added external lists (§6.3.13). Each pointer gives the location and the signer certificate, with the list type, the scheme operator name, the scheme territory and the MIME type as qualifiers. The wallet follows the pointers of an external list of trusted lists one level deep. A pointed-to list must be signed by a certificate of its pointer.

The user adds trust in two ways, with `trust`, the trust API or the UI:

- A provider on one of the wallet's own lists. The wallet adds the provider's CA as an issuance and a revocation service and signs the list again.
- An external list on the list of trusted lists. Its signer must chain to a trusted list operator: the wallet CA, a CA from `--trusted-list-ca` or a CA added with `trust add-ca --list trusted-list-ca`.

`--relying-party-ca` puts its CAs on the `access-ca` and `registrar` lists. `--trusted-list` adds external lists at startup.

## Consequences

The wallet CA is no anchor for access or registration certificates. It anchors trusted lists as a list operator CA, and credentials through the provider CAs on its lists.

A test of another registrar or issuer needs one step: put its CA on the list of its role, or add its published list. The checks then run unchanged.

The wallet verifies the signature of every list on each check. External lists are cached for 5 minutes. A list past its next update anchors nothing (§6.3.15). In strict mode the wallet refuses to add an unreadable list. In debug mode it adds the list and reports why it can't use it.

On the public demo all visitors share the added providers and lists, so one visitor's CA anchors the checks of everyone until the next reset. The demo caps them at 20 providers and 5 lists.

Several servers on one database must use the same `--relying-party-ca` and `--trusted-list` flags ([ADR 0016](0016-state-goes-through-one-storage-layer.md)).
