# One trusted list per credential category

The ARF has the wallet check a received credential against the trusted list of its kind. A PID must chain to a PID Provider list (ISSU_07), a QEAA to a trusted list of QEAA Providers (ISSU_08) and a PuB-EAA to a list of PuB-EAA Providers (ISSU_09). Another EAA is checked whenever the wallet has the issuer's trust anchors (ISSU_10). A test wallet that issues all of these needs a trust anchor for each kind.

## Decision

Each credential type issued by the wallet has a credential category: `pid`, `qeaa`, `pub-eaa` or `eaa`. The predefined templates set it. A user template sets it or takes it from its catalogue entry. You set it in the registrar UI or with `catalog add --category`. `--category` sets it for a single credential. A credential without any of these is an EAA.

Each category has its own signing key, its own provider CA under the wallet CA and its own trusted list:

- `pid` uses the PID provider list type of ETSI TS 119 602 V1.1.1 Annex D
- `pub-eaa` uses the PuB-EAA provider list type of Annex H
- `qeaa` uses `https://eudi-test.dev/LoTEType/QEAAProvidersList` and `eaa` uses `https://eudi-test.dev/LoTEType/EAAProvidersList`. TS 119 602 has no list type for them. Annex C.1 lets a scheme operator create its own URIs, and §6.3.3 asks for one type per profile. The URIs identify the profile, so every deployment uses them. Real QEAA providers are on TS 119 612 trusted lists.

A list publishes its signers and their provider CA, so it anchors the credentials of its category and no others. A catalogue entry links the list of its category unless it links another one.

The category `unlisted` keeps a credential off every list. Its signer has its own key and provider CA, and no list contains them. It tests how a verifier handles an issuer without a trust anchor. An imported credential and a credential signed with your own key and chain are on no list either, because the wallet did not sign them.

The demo issuer and the demo verifier are ordinary registrations at the wallet's registrar. The demo issuer is registered for its credential types, except unlisted ones, with the entitlement of each category. The demo verifier has its own access certificate, so it is a separate relying party.

## Consequences

The list IDs are `pid`, `qeaa`, `pub-eaa` and `eaa`. Beside them the wallet publishes `wallet-provider`, `access-ca` and `registrar` ([ADR 0023](0023-trust-anchors-come-from-trusted-lists.md)).

A wallet state that stores `http://uri.etsi.org/19602/LoTEType/local` for a type reads it as the list of the type's category, or as `eaa`.

Every credential from a user template is on a list, so the demo issuer's registration covers its type from the first offer. A wallet with `--arf` reports only an unlisted type when the demo issuer offers one.
