# A flow belongs to the browser that started it

A shared wallet can serve several people at once. Each consent request, error report and issuer sign-in prompt records the browser that started its flow. Events with an owner go to that browser. Events without an owner follow the rules below.

The wallet identifies a browser through an opaque `eudi_session` cookie.

The CLI and remote URL handler can start a flow for a particular browser tab. They put the same owner value in the tab URL and the API request's `X-Eudi-Owner` header. The event stream uses a query parameter because `EventSource` cannot set custom headers.

For a local wallet, the URL handler leaves the owner unset. The wallet opens its UI with the request ID in the URL.

## Not a security boundary

The owner decides where UI events appear. It does not authenticate callers. Anyone can supply a cookie or header, and the API remains open ([ADR-0002](0002-the-wallet-http-api-is-unauthenticated.md)). The activity log is shared, so visitors can still read other flows there.

## Unowned flows stay answerable

Every caller can see and answer a flow without an owner. This keeps the CLI, curl, CI, Testcontainers, the conformance harness and every URL handler working. `TestBackwardsCompatibility_ClientsThatNameNoBrowser` and `TestUnownedRequestStaysAnswerable` cover it.

A sign-in prompt goes only to its owner because it navigates the browser. Clients without an owner receive the sign-in URL in the API response.

Errors follow the consent routing rules. Consent requests without an owner appear in the shared banner. A tab opened by a local wallet can answer its request directly using the request ID in its URL.

## The redirect carries the request id

When the wallet redirects a browser, the URL includes the request id. A call with that id can answer the request. This lets a browser without the cookie (inside a cross-site frame, or with cookies turned off) still complete its flow. The id is unguessable and the wallet sent it to that browser, so it works as a capability token.

## Consequences

Set the owner when creating an event and keep it immutable. Event streams can then read it without taking the registry lock.

The owner is never sent to a client. `consent.Request` is marshalled field by field (`marshal` in `internal/consent/request.go`), so a new field there must not expose the owner.

Use the same owner routing for local and shared wallets.
