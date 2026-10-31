# Browser extension for the Digital Credentials API

A verifier page can ask for a presentation with the [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/). The page calls `navigator.credentials.get()` with a `digital` request, and the browser passes the request to a wallet. Chrome asks a wallet on a phone, which needs Bluetooth for the proximity check. The eudi-dev browser extension answers the call with an eudi-dev wallet instead, so you can test a verifier without a phone.

The extension works in Chrome, Chromium, Edge and Brave on macOS, Linux and Windows.

## Installation

Install [eudi-dev Digital Credentials](https://chromewebstore.google.com/detail/nbddeclckpkklpejkmhchmhmajginnok) from the Chrome Web Store. It uses the public demo at https://eudi-test.dev. To use another wallet, such as a local one, set its URL in the extension's popup. In Chrome, Edge and Brave, the wallet's How to use dialog and the demo verifier show an install button until the extension is installed. A new release reaches the store after Google reviews it, so the store version can be a few days behind.

`wallet browser` opens the browser with the extension loaded:

```bash
eudi wallet browser                                  # opens the demo verifier of the wallet
eudi wallet browser https://verifier.example/login   # opens your verifier
```

The extension uses the wallet that the other wallet commands use: `--remote`, the target set with `wallet use`, or a running wallet server for the wallet directory. Without any of them it uses the public demo at https://eudi-test.dev. `--wallet-url` sets another wallet and `--browser-path` another browser. The command ends when you close the browser. It works on macOS and Linux.

The browser uses its own profile in the eudi-dev folder, separate from your everyday profile. Chrome 137 and later ignore `--load-extension`. `wallet browser` loads the extension with the Chrome DevTools Protocol command `Extensions.loadUnpacked`, which Chrome allows only in a separate profile.

To use the version of your eudi-dev release in your everyday profile, install it from a folder:

```bash
eudi wallet extension ~/eudi-dev-extension                                    # for the public demo at https://eudi-test.dev
eudi wallet extension ~/eudi-dev-extension --wallet-url http://localhost:8085
```

Every wallet server also offers the extension as a zip file at `/eudi-dev-dc-api-extension.zip`, set to that wallet, and the demo verifier links it. Unzip the file, open `chrome://extensions`, turn on Developer mode, choose Load unpacked and select the folder. Outside the Chrome Web Store, Chrome installs extensions only this way.

The extension's popup shows the wallet it uses and lets you set another one.

To test how a page behaves without the extension, clear **Answer Digital Credentials API calls** in the popup and reload the page. The extension then adds nothing to pages, so they get the browser's own API. The icon shows **OFF**.

## Use

The extension works with any verifier. A verifier page uses the standard API as it would with a phone wallet and needs no change. With the extension installed, every page gets the extension's `navigator.credentials.get()` for `digital` requests. Other calls, such as passkeys, still go to the browser.

The extension sends each request to the wallet and opens the wallet in a window, where you approve or deny the presentation. The window closes when the wallet answers. Closing it rejects the call with `NotAllowedError`, as closing the browser's own picker does. A wallet with `--auto-accept` answers at once, and no window opens.

The wallet binds the presentation to the origin of the calling page (OpenID4VP 1.0 Appendix A). The extension reads that origin from the browser, so a page can't claim another origin.

The extension answers presentation requests with the protocols `openid4vp-v1-unsigned`, `openid4vp-v1-signed` and `openid4vp-v1-multisigned`.

To try it, choose **Digital Credentials API** under Delivery on the demo verifier page. **Request** then chooses the protocol:

- **Signed** (`openid4vp-v1-signed`) signs the request with the verifier's access certificate and lists the page origin in `expected_origins`.
- **Unsigned** (`openid4vp-v1-unsigned`) has no signature and no `client_id`. The wallet identifies the verifier by the page origin, so the request carries no registration certificate.
- **Multisigned** (`openid4vp-v1-multisigned`) uses the JWS JSON serialization with 2 signatures. The first uses the verifier's access certificate. The second uses a new key that no registrar knows. Each signature has its `client_id` in its protected header (OpenID4VP 1.0 Appendix A.3.2). With it you test how a wallet handles a signer it can't trust.

The demo verifier always asks for an encrypted response (`dc_api.jwt`).

## Debugging a verifier

The page console and the wallet's activity log show what happened in a call.

- **Page console.** The extension logs each call to the page console: the request, then the result or the error. To turn this off, clear **Log calls to the page's console** in the popup.
- **All requests in the activity log.** The wallet logs each call with all its requests. It answers only the first request with a supported protocol. For each other request, the log gives the reason. A common mistake is the protocol `openid4vp` instead of `openid4vp-v1-signed` (OpenID4VP 1.0 Appendix A.1).
- **Refused calls.** Calls refused by the extension also appear in the activity log, for example a call without a user action. The same page and reason appear at most once a minute.
- **Unused parameters.** Parameters outside the list in OpenID4VP 1.0 Appendix A.2, such as `state` or `response_uri`, get a warning.
- **Response details.** The response entry shows the origin of the presentation and the `alg`, `enc` and `kid` of an encrypted response.
- **Cancelled calls.** The log gives the reason for a cancelled call: the page aborted it, or the user closed the wallet window.

## Test coverage

The extension takes the place of the browser's credential picker and the phone wallet. The verifier page and its backend run unchanged, so a test covers the verifier's side of the flow:

- the request: protocol, `expected_origins`, client identifier and signatures, DCQL query, `client_metadata` with the encryption key
- the call itself: the page calls the API after a user action, from a visible page with focus, one request at a time, and handles the errors
- the response: decryption of `dc_api.jwt`, the presentation audience `origin:<origin>` (OpenID4VP 1.0 §5.9.3), the mdoc session transcript with the DC API handover (Appendix B.2.6.2), error results such as `access_denied`

Before a request reaches the wallet, the extension runs the checks of W3C Digital Credentials §6.2 that a browser runs:

| Situation | Result |
|---|---|
| No request has a supported protocol | `TypeError` |
| The `data` of a request isn't an object | `TypeError` |
| The frame lacks the permissions policy `digital-credentials-get` | `NotAllowedError` |
| The page isn't visible or has no focus | `NotAllowedError` |
| No user action, such as a click, came shortly before the call | `NotAllowedError` |
| Another request of the page is still open | `NotAllowedError` |
| The page aborts the call with its `AbortSignal` | the abort reason |

A test with the extension doesn't cover:

- Chrome's own credential picker and the cross-device flow with QR code and Bluetooth
- deeper checks of the request data that a browser may make for each protocol. The wallet checks the request instead.
- the behavior of other wallets. A phone wallet may support fewer protocols, credential formats or DCQL features than the eudi-dev wallet.
- `org-iso-mdoc`, the protocol of Safari

Use the extension while you build a verifier and in its automated tests. Before a release, test with the phone wallets your users have.

## Wallet interface

The extension does the job of the operating system. A phone wallet gets requests through Credential Manager on Android or Identity Document Services on iOS. The extension sends them to the wallet over this HTTP interface instead. The eudi-dev wallet implements it, and other test wallets can too.

**Request.** The extension sends the argument of `navigator.credentials.get()` as JSON:

```http
POST <wallet URL>/api/dc-api
Content-Type: application/json
X-Eudi-Caller-Origin: https://verifier.example
X-Eudi-Owner: 2f6c1b9e-6a51-4d8e-9a43-0e1b8f0d2c77

{"digital": {"requests": [{"protocol": "openid4vp-v1-signed", "data": {"request": "eyJ..."}}]}}
```

- `X-Eudi-Caller-Origin` is the origin of the calling page, read from the browser. The request itself carries the extension's origin, such as `chrome-extension://<id>`, in `Origin`. A wallet must read `X-Eudi-Caller-Origin` only from requests whose `Origin` is an extension origin or missing. A web page can't send the header to the wallet, because the endpoint answers no CORS preflight.
- `X-Eudi-Owner` is a random ID that stays the same for an installed extension. It lets the wallet show the consent in the window that the extension opens.
- `X-Eudi-Call-Id` is a random ID of the call. The extension uses it to cancel the call.
- `requests` holds every request of the call. The wallet answers the first one with a supported protocol.

**Response.** The wallet answers when the user decides, at the latest after 5 minutes:

- `200` with `{"protocol": "...", "data": {...}}` resolves the call with a `DigitalCredential` of that protocol and data. A protocol error, such as `{"data": {"error": "access_denied"}}`, is a result too (OpenID4VP 1.0 Appendix A.4).
- Any other answer rejects the call with `NotAllowedError`. The message holds the `error_description` or `error` of a JSON error body.

**Consent window.** When the wallet hasn't answered after half a second, the extension opens `<wallet URL>/?focus=overview&owner=<X-Eudi-Owner>` in a window. It closes the window after the answer.

**Cancel.** When the user closes the window or the page aborts the call, the extension tells the wallet why and then cancels the HTTP request:

```http
POST <wallet URL>/api/dc-api/cancel
Content-Type: application/json
X-Eudi-Owner: 2f6c1b9e-6a51-4d8e-9a43-0e1b8f0d2c77

{"id": "<X-Eudi-Call-Id>", "reason": "The wallet window was closed"}
```

The wallet answers `204`, ends the call with `409` and the reason, and logs it. Only the extension with the same `X-Eudi-Owner` can cancel a call. An unknown call gets `404`.

**Refusals.** The extension also reports refused calls:

```http
POST <wallet URL>/api/dc-api/refusals
Content-Type: application/json
X-Eudi-Caller-Origin: https://verifier.example
X-Eudi-Owner: 2f6c1b9e-6a51-4d8e-9a43-0e1b8f0d2c77

{"name": "TypeError", "message": "No request uses a supported protocol", "request": {"digital": {"requests": [...]}}}
```

The wallet answers `204` and logs the refusal, at most once a minute for the same page, error and message.

**Older extensions.** Extensions before 3.5.0 send only requests with a supported protocol and no `X-Eudi-Call-Id`. They report no refusals and no cancel reasons. The wallet answers them as before. For a closed window, the log then says that the caller stopped waiting.

**Configuration.** `config.json` in the extension sets the default wallet URL in `wallet_url`. The popup overrides it.
