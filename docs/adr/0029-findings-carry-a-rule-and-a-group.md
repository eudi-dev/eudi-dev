# Findings carry a rule and a group

A finding used to be one sentence that started with its full citation, such as `ARF RPRC_22a and ETSI TS 119 472-3 V1.1.1 ISS-MDATA-REG_CERT-4.2.3-04 as adapted by CIR (EU) 2026/1731 Annex XI: the issuer metadata carries no registration certificate`. In the activity log these lines were too long to read. Findings about the registrar also looked the same as findings about protocol messages.

## Decision

A finding is a `findings.Finding` with 6 fields:

- `spec` is the specification, such as `ARF` or `OID4VP 1.0`.
- `rule` is the short identifier, such as `ARF RPRC_22a`.
- `citation` is the full reference when it says more than the rule, for example with the version of an ETSI specification.
- `url` opens the rule in the published specification. ETSI, ISO and the CIRs publish no anchors, so their findings have none.
- `text` is the finding itself.
- `group` is `registration` or `protocol`.

Each check builds its rule from a typed specification, such as `findings.ARF.Registration("RPRC_22a")`. The `registration` group covers registration with the registrar, access and registration certificates, entitlements and trusted lists. Everything else is `protocol`.

The JSON keeps every field it had. `findings` stays an array of sentences in API errors, consent requests, results and log details. The log `detail` line stays the same. A new `finding_details` array next to `findings` carries the structured form. A log entry also gets `finding_subject`. It names what the findings are about, such as `Request` or `Issuer`. Older CLI versions and API automations read the same fields as before.

## Consequences

The activity log shows the findings of an entry in a row per group, titled like "3 protocol findings about the request". A user who doesn't work with the registrar can leave the registration rows collapsed. A collapsed row names each specification once. The expanded row shows each finding with its rule below the text, linked to the specification. The UI shows the old text when `finding_details` is missing, for example in log entries of an older version. A finding without a citation shows its text only.
