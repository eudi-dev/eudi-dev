# What's new in 3.0

eudi-dev 3.0 lets you test the trust side of the EUDI Wallet ecosystem. Register your verifier or issuer, get real certificates for it and let the wallet check them the way the ARF describes. The [changelog](../CHANGELOG.md) lists every change, and [upgrading from 2.x](upgrading.md) lists what you have to change.

Want a quick look first? Open [eudi-test.dev](https://eudi-test.dev) and take the tour.

## Test your verifier with registered certificates

A wallet in the EUDI ecosystem only talks to registered relying parties. Register your verifier under **Registrar** › **Relying parties** and get an access certificate and a registration certificate. Sign your requests with the access certificate key and send the registration certificate in `verifier_info`.

With `--arf` (the public demo has it on) the wallet checks both certificates and their revocation. It also tells you when your request asks for more than you registered. The [registrar walkthrough](wallet/registrar-api.md) shows every step with curl.

## Test your issuer the same way

Register your issuer and its attestation types. Sign your issuer metadata with the access certificate key and publish the registration certificate in `issuer_info`. The wallet checks both before it accepts a credential.

## See why a flow failed

In debug mode the wallet still finishes a flow that breaks a rule, and it tells you what went wrong. The consent dialog and the API response list every failed check of the verifier or issuer. Switch to strict mode when your service should pass every check.

## Bring your own trust

Every trust anchor of the wallet comes from a trusted list (ETSI TS 119 602), with one list per credential category. Put the CA of your own issuer on a list with `eudi trust add-ca` or under **Trust & certificates**, or add your own list with `eudi trust add-list`.

## Browse attestation types

The registrar keeps a catalogue of attestation types, following the EC TS11 catalogue. Each entry has its formats, schemas, rulebook and trusted list. Load your own types on every start with `--catalog`.
