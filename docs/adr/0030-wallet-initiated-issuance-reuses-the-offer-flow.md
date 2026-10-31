# Wallet-initiated issuance reuses the offer flow

OpenID4VCI 1.0 §3.4 starts the Authorization Code Flow in the wallet, without an offer. Appendix H.4 does this during a presentation and H.6 after installation. H.6 names a Wallet Provider market place as one way to find issuers. The ARF ISSU_23 note also leaves the choice of issuers to the Wallet Provider.

## Decision

The wallet knows the demo issuer and each registered service or catalogue entry with a `credentialIssuer` URL. Visitors of a public demo share the registrar, so there it knows only the demo issuer and the operator's entries. `GET /api/issuance` matches the registrar catalogue against the metadata of these issuers. National PIDs share one mdoc doctype, so a format with several matching configurations keeps those with the display name of the catalogue entry.

`POST /api/issuance` builds an offer without `issuer_state` and runs the normal offer flow. All later steps are the same: metadata checks, PAR, sign-in and credential request. ARF ISSU_12a asks for all formats, so one authorization covers all configurations of the attestation. The user signs in once, and the wallet then sends one credential request per format with the same access token.

The click on **Request** is the consent to receive the credential, so no consent dialog follows. It doesn't cover disclosing a credential. If the issuer asks for a presentation, the user gets the normal prompt. The sign-in opens in a new tab with that click, because a browser blocks a tab opened later. The wallet closes the tab when the flow ends. The waiting status has a **Cancel** button, which calls `DELETE /api/offers/{id}`. The wallet doesn't watch for a closed tab, because `tab.closed` reads true for an issuer page with `Cross-Origin-Opener-Policy: same-origin` while the user signs in. A consent dialog of a running presentation stays open behind it.

When an issuance ends, the wallet matches open presentation dialogs again. A wallet with nothing to offer for a query still opens the dialog if the catalogue has the type, because the user can request it there. Strict mode and API callers without `interactive` get `no_match`. A dialog changes only when a query gets its first credential. It keeps the user's selection. The formats of one authorization share a refresh token, so a rotated token replaces it for all of them.

## Consequences

An issuer that refuses several configurations in one authorization fails the whole request. When a later format fails, the earlier credentials stay in the wallet and the result reports the failure. In strict mode a request without a matching credential is refused before the dialog, so the dialog offers no request.
