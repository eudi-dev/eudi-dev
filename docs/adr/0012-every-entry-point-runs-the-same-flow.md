# Every entry point runs the same flow

URL handlers, `wallet accept`, `wallet scan`, the web UI and the HTTP endpoints all call the same issuance or presentation flow. Entry points handle input and interaction. The shared flow handles the protocol.

## Entry point duties

Recognise the input and pass it to the flow. A scan also decodes an image into a URI, and a prompt may collect something the user has to type.

## Fetching offers and requests

The shared flow fetches `credential_offer_uri` and `request_uri`. Some issuers consume a credential offer on the first read, and RFC 9126 §4 says "the client MUST only use a `request_uri` value once". If an entry point fetches it first, the flow gets a 404.

An entry point that already holds a copy of the offer passes it on in `OfferOptions.ResolvedOffer`, so the flow works with an issuer that serves the offer once.

The flow decides which credentials match and whether consent is required. Entry points pass user settings such as `--haip`, validation mode and `--auto-accept` as options.

## Transaction code

A transaction code is delivered out of band, so the wallet has to ask the user for it. The consent dialog asks whenever an interactive wallet with a UI handles the offer. That covers the handler, a remote wallet, and a scan or a link routed to a running instance. For non-interactive issuance, including `--auto-accept` and API calls, the caller must supply the code. If the offer requires `tx_code` and none was supplied, the wallet rejects it before using the pre-authorized code. The error explains how to supply it.

The local headless flow (`eudi wallet accept` with no wallet server running) has no UI, so the CLI prompts for the code. This is the only exception to the rule above. The issuance reads the URI again to detect an offer that changed in the meantime. With an issuer that serves the offer once, that read fails and the issuance continues with the copy from the prompt, with `credential_offer_reread_failed` in the activity log.

## Consequences

The CLI has one entry point, `acceptOID4URI`. It decides between local and remote, and nothing before it reads the URI. The server has one per protocol (`POST /api/offers` and `POST /api/presentations`). The handler, the UI and scripts all call them. A new entry point calls one of them.

`TestRemoteAcceptLeavesTheOfferForTheWallet` checks that remote routing leaves the offer fetch to the wallet. Entry point tests cover routing and interaction. Shared flow tests cover protocol behavior.

Behaviour that differs between entry points is a defect unless it is the entry point's own job (a camera, a terminal prompt). Fix the difference instead of documenting it.
