# ARF checks are a separate profile

Strict mode covers OpenID4VP 1.0, OpenID4VCI 1.0 and HAIP 1.0. The ARF adds rules on how a relying party authenticates: an access certificate (RPA_03, RPA_04), a registration certificate (RPRC_02a, RPRC_17, RPRC_17a, RPRC_19) and the attributes it may ask for (RPRC_21). Issuers authenticate the same way before the wallet requests a credential. They sign their metadata with an access certificate (ISSU_22, ISSU_32). Their `issuer_info` holds a registration certificate. It lists which credential types the issuer may issue (RPRC_22a, RPRC_22b, RPRC_23, ISSU_24a, ISSU_24b, ISSU_34a, ISSU_34b). Most verifiers and issuers in tests do not follow these rules. OpenID4VP makes `verifier_info` optional. OpenID4VCI makes signed metadata optional.

## `--arf`

`--arf` runs the ARF checks, like `--haip` runs the HAIP checks. It is separate from the validation mode. The mode decides what happens to a finding. Without `--arf` the wallet does not check the ARF rules. With `--arf`, debug mode reports the findings in the consent dialog, the API response and the activity log. Strict mode refuses a presentation request, and it refuses an offer before the consent dialog. A verifier that signed its request with a trusted access certificate gets an `access_denied` error response (OpenID4VP 1.0 §8.5), so a test sees the refusal. The offer's consent dialog lists the findings about an issuer, because the ARF requires the wallet to warn the user. The ARF lets the Wallet Provider decide whether to refuse (RPA_06a, RPRC_17, RPRC_21), and strict mode refuses. If the wallet can't read a registration certificate's status list, that is a finding too, because it can't tell whether the certificate is revoked (ARF §6.6.3.3).

`--demo` turns `--arf` on, with debug mode.

## Trust anchors

Under RPA_04, ISSU_23, ISSU_33, RPRC_02a, ISSU_23c and ISSU_33a, the wallet trusts only notified access certificate authorities and registrars. The ARF keeps separate trusted lists for the two (RPACANot_05, RPACANot_05a), and so does the wallet. It takes every anchor from trusted lists ([ADR 0023](0023-trust-anchors-come-from-trusted-lists.md)):

- Access certificates (RPA_04, ISSU_24, ISSU_34) must chain to a CA on an access certificate provider list (`access-ca`, ETSI TS 119 602 V1.1.1 Annex F). The wallet's own list contains the relying party access CA. This CA signs every access certificate issued by the wallet's registrar.
- Registration certificates (RPRC_02a, ISSU_23c, ISSU_33a) must chain to a CA on a registration certificate provider list (`registrar`, Annex G). The wallet's own list contains the registrar CA. The status list of a registration certificate must chain to a revocation service on the same lists (RPACANot_03b).
- A trusted list must be signed by a trusted list operator: the wallet CA, a CA from `--trusted-list-ca` or a CA added with `trust add-ca --list trusted-list-ca`. The wallet accepts the provider trust anchors on a list because of that signature (PPNot_05, TLPub_05, TLPub_07).

The relying party access CA signs any visitor's CSR. If it were on the `registrar` list, anyone could sign their own registration certificate. `--relying-party-ca` puts its CAs on both lists, because one organization often runs both roles and a test setup then needs one file. `trust add-ca` puts a CA on one of them.

A catalogue entry links a trusted list, by default the wallet's list of its category ([ADR 0022](0022-one-trusted-list-per-credential-category.md)). A received credential must chain to that list. A PID or a PuB-EAA may also chain to a list of its type on the list of trusted lists. The category decides which rule applies: ISSU_07 for a PID, ISSU_08 for a QEAA, ISSU_09 for a PuB-EAA and ISSU_10 for another EAA. A PID, QEAA or PuB-EAA entry must link a readable trusted list. Otherwise that is a finding. For an EAA an unreadable list only gives a warning, because ISSU_10 applies only when the wallet has the anchors.

These are the only places where the wallet uses configured trust anchors. Without `--arf`, [ADR 0009](0009-signatures-are-verified-but-not-anchored-to-a-pre-registered-trust-list.md) applies.

If an issuer offers a type without a catalogue entry, the wallet warns in both modes. No specification requires this check.

## Consequences

A wallet with `--arf` and `--mode strict` refuses a verifier if it sends no registration certificate or several (RPRC_19), signs with an unknown access certificate, asks for more than it registered or uses a revoked registration certificate. It refuses an offer when the issuer metadata is unsigned. It also refuses the offer when the registration certificate is missing, revoked or doesn't list the offered type. It doesn't store a credential if the trusted list check fails (ISSU_11b). The ARF applies the registration certificate checks for issuers 24 months after the amended CIR 2024/2982 enters into force. Strict mode applies them already, because it tests the target state. Conformance runs use strict mode without `--arf`.
