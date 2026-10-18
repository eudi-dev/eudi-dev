# The current specification is definitive

The specifications of the EUDI stack change often. The ARF changes its requirements on its main branch between releases. ETSI and the OpenID Foundation publish new versions of documents that a profile references by an older version. An older text can require something that the current text has dropped. For example, ARF RPRC_18 had the wallet look up a relying party in the register when no registration certificate arrived. The current ARF has emptied RPRC_18, so the wallet does no such lookup.

## Decision

The current text of a specification decides what the toolkit checks and does:

- the ARF on its main branch, with its annexes
- the latest published version of an ETSI or OpenID document
- the latest published version of an EC technical specification (such as TS5, TS6 and TS11)

Where the ARF and ETSI TS 119 475 differ, the ARF wins. The ARF defines what an EUDI wallet must do, and TS 119 475 implements part of it.

[ADR-0014](0014-pinned-draft-versions-stay-supported-alongside-the-latest.md) is the exception. A draft that OpenID4VCI or HAIP pins stays supported next to the latest draft, because issuers and verifiers implement the pinned one.

## Consequences

Before a change, read the current text, even when the code cites an older version ([ADR-0010](0010-spec-conformance-is-checked-before-and-after-every-change.md)). A citation gives the current version, or the requirement identifier for the ARF. An ARF version such as "ARF v3.0.0" appears only where an older text is the reason for a behaviour.

When a specification drops a requirement, the toolkit removes its check. When it adds one, the check follows the requirement level of the current text.
