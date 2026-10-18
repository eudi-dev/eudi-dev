[← Documentation](README.md)

# UI automation

This guide is for tests that drive the wallet web UI from Playwright or Selenium. Your test plays the user. It receives credentials from your issuer, presents them to your verifier and reads what happened.

Each section covers one process. It lists the elements to use, the state to wait for and a short Playwright example in JavaScript. It also shows the faster API call and links the [end-to-end tests](../e2e/) of this repository for the same process.

The examples use `WALLET` for the wallet URL and Playwright's `page` and `expect`:

```js
const { test, expect } = require("@playwright/test");
const WALLET = "http://localhost:8085";
```

## Before you start

### A wallet for the tests

Start a wallet with the binary:

```bash
EUDI_DEV_STORAGE=memory eudi wallet serve --pid --port 8085
```

Or with the Docker image:

```bash
docker run -p 8085:8085 -p 8086:8086 -e EUDI_DEV_AUTO_ACCEPT=false ghcr.io/eudi-dev/eudi-dev
```

The wallet UI is at `http://localhost:8085/`. The demo issuer is at `/issuer/`, the demo verifier at `/verifier/` and the decoder at `/decoder/`. The HTTPS issuer endpoints of the wallet use the next port (8086).

| Setting | Effect |
|---|---|
| `--pid` | Loads an SD-JWT and an mdoc PID on start |
| `--storage memory` or `EUDI_DEV_STORAGE=memory` | Starts empty on every run. See [storage backends](wallet.md#storage-backends) |
| `EUDI_DEV_HOME` | Uses this directory instead of `~/.eudi-dev` |
| `--auto-accept` | Approves every offer and request without a consent dialog |
| `--demo` | The [public demo profile](public-demo.md). Each consent dialog opens only in the browser that started the flow. Settings are read-only |

The Docker image sets `EUDI_DEV_AUTO_ACCEPT=true`. Set `EUDI_DEV_AUTO_ACCEPT=false` when your test clicks through the consent dialogs. With auto-accept on, flows finish without a dialog and your test only reads the results. See [Docker](docker.md#configuration-by-environment) for the other variables.

### Consent dialog ownership

The wallet ties each consent request to a browser. A request opens as a dialog in the pages of that browser. Other browsers don't see it. A request without an owner shows in every browser as a banner with **Review** (`#pending-banner`, `#pending-review`). See [consent ownership](wallet/http-api.md#consent-ownership).

A request belongs to your test page when one of these holds:

- The flow started in the page: a click on **Process** or on a wallet link of an issuer or verifier, or an API call from the page itself.
- Your test sent the API call with Playwright's `page.request`. It shares the cookies of the page.
- Your test opened the wallet with `/?focus=overview&owner=<id>` and sent the API call with the header `X-Eudi-Owner: <id>`. Pick any unique ID per test. The page removes `owner` from its address bar and keeps it for reloads.

```js
const owner = "test-" + Date.now();
await page.goto(`${WALLET}/?focus=overview&owner=${owner}`);
// The call answers after the consent, so the test doesn't await it.
fetch(`${WALLET}/api/offers`, {
  method: "POST",
  headers: { "Content-Type": "application/json", "X-Eudi-Owner": owner },
  body: JSON.stringify({ uri: offerURI, interactive: true }),
});
await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
```

The page receives new requests over an event stream. Before you start a flow from outside the page, wait for `body[data-request-stream="open"]`. A request created earlier still opens, because the page loads pending requests when the stream connects.

`/?request=<id>` opens the dialog of one pending request. Take the ID from `GET /api/requests`.

E2E tests: [`demo.spec.js`](../e2e/demo.spec.js), tests *the tab the scheme handler opened takes the consent directly* and *another visitor's tab is not told about a pending request*. [`prefix.spec.js`](../e2e/prefix.spec.js), test *an open wallet page hears about new requests over its event stream*.

### Selectors

Every control has a stable `id`. In ids built from data, each character outside `A-Z`, `a-z`, `0-9`, `_` and `-` becomes `_`. Lists carry `data-*` attributes, and the activity log uses `data-testid`. Theme and screen width don't change ids. At phone width, header links move behind **☰ Menu** (`#header-menu-toggle`). Open it first in a narrow viewport.

All dialogs are `.consent-overlay` elements. An open dialog has the class `active`. Wait for it with `toHaveClass(/active/)` and for its end with `not.toHaveClass(/active/)`.

### Dialog commands and size

A dialog with a title has buttons beside it. This holds for the wallet and the decoder. `#<dialog id>-close` closes the dialog like its Close or Cancel button. A pending consent request has no close button, because you have to approve or deny it. `#<dialog id>-size` switches the dialog between its normal size and almost full screen. A maximized dialog has the class `dialog-maximized`. `#<dialog id>-command-toggle` opens the command panel `#<dialog id>-command`, where present. The panel shows the curl command for what the dialog does, with the dialog's current values (`#<dialog id>-command-text`). `#<dialog id>-command-cli` switches to the CLI command where one exists. A link to the matching docs follows in `#<dialog id>-command-docs-link`, where present. The dialogs with a command panel are:

| Dialog | Dialog id | CLI command |
|---|---|---|
| **Issue credential**, **New template**, **Edit template** | `issue-dialog` | `eudi issue`, `eudi templates import` |
| Register a verifier or issuer, add a use or service, issue an access certificate | `registrar-dialog` | `eudi registrar enrol`, `eudi registrar access-cert` |
| Add a catalogue entry | `registrar-catalog-add-dialog` | `eudi catalog add` |
| Consent dialog | `consent-dialog` | `eudi wallet requests approve`, `deny` |

The commands use the wallet URL of the page. A consent command answers the newest pending request of the same type. It looks the request up with `GET /api/requests` and `jq`. Set `REQUEST_ID` to answer a specific request. The command sees requests that came from API calls, the CLI and tests. Requests opened in a browser are visible only in that browser. On a public demo only the web UI answers consent requests, unless the operator starts it with `--demo-consent-api`. Without a CSR, the registrar command has a CSR placeholder. Its note shows how to create a CSR.

## Credential issuance

### Offer from your issuer

Paste the offer URI into the actions bar and click **Process**. The wallet then opens the consent dialog.

| Control | Selector |
|---|---|
| Offer or request input | `#offer-input` |
| **Process** | `#process-btn` |
| Consent dialog | `#consent-overlay`, content in `#consent-dialog` |
| Dialog title (**Credential offer** or **Presentation request**) | `#consent-title` |
| Issuer header | `#consent-who`, with `#consent-who-name`, `#consent-who-id`, `#consent-who-auth` |
| Issuer origin and offer facts | `#offer-issuer-origin`, `#offer-facts` |
| Findings about the issuer | `#consent-findings-summary` (collapsed), `#consent-findings-list` |
| Offered credential | `#offer-credential-<configuration id>` |
| **You will receive** claims | `#offer-credential-<configuration id>-claims`, rows `.consent-claim-name` and `.offer-claim-label` |
| Credential description and **More** | `#offer-description-<configuration id>`, `#offer-description-<configuration id>-toggle` |
| Transaction code | `#offer-tx-code-input`, `#offer-tx-code-description` |
| **Approve**, **Deny** | `#consent-approve`, `#consent-deny` |

An empty transaction code keeps the dialog open and marks the input with the class `input-error`.

```js
await page.goto(WALLET);
await page.locator("#offer-input").fill(offerURI);
await page.locator("#process-btn").click();
await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
await expect(page.locator("#consent-dialog")).toContainText("You will receive");
await page.locator("#consent-approve").click();
await expect(page.locator("#consent-overlay")).not.toHaveClass(/active/);
```

A link to the wallet works too. Point the browser at `/credential-offer?credential_offer_uri=...` on the wallet, and the dialog opens in that page.

API: `POST /api/offers` with `{"uri": "..."}` issues without a dialog. Add `"tx_code"` when the offer needs one. See [credential offers](wallet/http-api.md#credential-offers).

E2E tests: [`demo.spec.js`](../e2e/demo.spec.js), test *the issuance consent dialog says what is being issued*. [`wallet.spec.js`](../e2e/wallet.spec.js), tests *dialog asks for the code and blocks an empty approval* and *a long description opens behind More and a short one has no button*.

### Demo issuer

The demo issuer at `/issuer/` creates offers for the Demo Event Ticket and the wallet's templates. Choose the options, click **Create offer** and follow the wallet link.

| Control | Selector |
|---|---|
| Credential | `#credential-select` |
| Grant | `#grant-toggle [data-grant=""]` (pre-authorized code), `[data-grant="authorization_code"]` |
| Authorization (authorization code only) | `#authorization-toggle [data-authorization="browser"]`, `[data-authorization="presentation"]` |
| Status list, deferred, batch | `#status-toggle [data-status]`, `#deferred-toggle [data-deferred]`, `#batch-toggle [data-batch]` |
| Identity check (presentation during issuance only) | `#identity-check-toggle [data-identity-check="registered"]`, `"unregistered"`, `"own"` with `#identity-check-signing-key` and `#identity-check-verifier-info` |
| Issuer identity | `#identity-toggle [data-identity="registered"]`, `"unregistered"`, `"unsigned"`, `"own"` with `#signing-key` and `#issuer-info` |
| **Create offer** | `#create-btn` |
| Result | `#result`, with `#wallet-link`, `#scheme-uri`, `#offer-uri`, `#issuer-id` |
| Error | `#error` |

```js
await page.goto(`${WALLET}/issuer/`);
await page.locator("#create-btn").click();
await page.locator("#wallet-link").click();
await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
await page.locator("#consent-approve").click();
const ticket = page.locator('.credential-card[data-vct="urn:eudi-test:demo-ticket:1"]');
await expect(ticket.first()).toBeVisible();
```

API: `POST /issuer/api/offers` answers `wallet_url`, `scheme_uri`, `offer_uri` and `issuer`. `scheme_uri` uses `openid-credential-offer://`, which any OpenID4VCI wallet handles. The query parameters `grant`, `authorization`, `status`, `deferred`, `batch`, `credential`, `identity` and `identity_check` match the page options. Without `authorization_details` the token response has no credential identifiers. `credential_identifiers=always` adds them to every token response (OpenID4VCI 1.0 §6.2), as Keycloak does, and the wallet then has to request by `credential_identifier`. With `identity=own` the body carries `signing_key` and `issuer_info`, with `identity_check=own` an `identity_check` object with `signing_key` and `verifier_info` (see [demo issuer and verifier](wallet/registrar.md#demo-issuer-and-verifier)).

E2E tests: [`prefix.spec.js`](../e2e/prefix.spec.js), test *a demo issuer offer opened in the browser is issued*. [`demo.spec.js`](../e2e/demo.spec.js), test *a deferred offer is awaited and then collected*.

### Sign-in at the issuer

With an authorization code offer and **Browser sign-in**, the page leaves the wallet after **Approve**. The demo issuer shows a sign-in form with the account alice (password alice) filled in. After **Sign in** the browser returns to `/?focus=overview` and the credential arrives.

| Control | Selector |
|---|---|
| Username, password | `#username`, `#password` |
| **Sign in** | `#login-submit` |
| Sign-in error | `#login-error` |

```js
await page.goto(`${WALLET}/issuer/`);
await page.locator("#grant-authorization-code").click();
await page.locator("#authorization-browser").click();
await page.locator("#create-btn").click();
await page.locator("#wallet-link").click();
await page.locator("#consent-approve").click();
await page.locator("#login-submit").click();
await page.waitForURL(`${WALLET}/?focus=overview`);
```

API: `POST /api/offers` answers `202` with `authorization_url` and `offer_id`. Open the URL in the browser, sign in and poll `GET /api/offers/{offer_id}` until its `status` is `completed`. See [sign-in during issuance](wallet/issuing.md#sign-in-during-issuance).

E2E tests: [`demo.spec.js`](../e2e/demo.spec.js), test *the credential arrives once the user signs in at the issuer*. [`prefix.spec.js`](../e2e/prefix.spec.js), test *issuer sign-in returns to the wallet under the prefix*.

### Presentation during issuance

With **Presentation during issuance**, the issuer asks for a PID before it issues. After the first **Approve**, the same dialog shows **Presentation request**. Approve it as described under [credential presentation](#credential-presentation).

```js
await page.locator("#consent-approve").click();
await expect(page.locator("#consent-title")).toHaveText("Presentation request");
await page.locator("#consent-approve").click();
await expect(page.locator("#consent-overlay")).not.toHaveClass(/active/);
```

E2E tests: [`demo.spec.js`](../e2e/demo.spec.js), tests *the presentation is put only to the visitor whose issuance it is* and *an offer authorized by a presentation is redeemed without a browser*.

### Result on the credential list

Each stored credential is a `.credential-card` with the id `credential-<credential id>`.

| Attribute | Values |
|---|---|
| `data-credential-id` | The credential ID from `GET /api/credentials` |
| `data-format` | `sdjwt`, `jwt` or `mdoc` |
| `data-vct`, `data-doctype` | The type of the credential |
| `data-status` | `active`, `revoked`, `external` (status list of another issuer) or `none` |
| `data-expiry` | `valid`, `expiring`, `expired` or `not-yet-valid` |
| `data-protected` | `true` on the baseline PIDs of a demo |

The list shows ten cards per page. Use `#cred-prev` and `#cred-next` to page. `#cred-range` shows the range. `#deferred-section` lists deferred credentials while the wallet waits for them.

### Errors

A failed flow opens an error dialog in the page that started it.

| Control | Selector |
|---|---|
| Title and message | `#error-title`, `#error-message` |
| Findings of a refusal | `#error-findings`, one `#error-finding-<n>` each |
| **Technical details** | `#error-detail-more-toggle`, full text in `#error-detail` |
| **Dismiss** | `#error-dismiss` |
| Verifier answer after a presentation | `#result-title`, `#result-detail`, `#result-dismiss` |

An unusable input in **Process** opens the same error dialog. A failed import shows its reason in `#import-error` inside the **Import credential** dialog.

E2E tests: [`demo.spec.js`](../e2e/demo.spec.js), tests *the tab that started the failing flow does see the error* and *an error from someone else's flow stays out of uninvolved tabs*.

## Credential presentation

### Request from a verifier

Open the request in the wallet. Use the wallet link of your verifier, paste the request into `#offer-input` and click **Process**, or open `/authorize?client_id=...&request_uri=...` on the wallet. See [wallet invocation by URL](wallet/presenting.md#wallet-invocation-by-url).

The demo verifier at `/verifier/` builds requests for you:

| Control | Selector |
|---|---|
| Credential | `#credential-toggle [data-credential="pid"]`, `"ticket"`, `"pid-ticket"`, `"custom"`, and one button per national PID such as `"pid-de"` |
| PID format | `#format-toggle [data-format="both"]`, `"sd-jwt"`, `"mdoc"` |
| Ticket next to the PID | `#ticket-toggle [data-ticket="combined"]`, `"optional"` |
| **multiple** | `#request-multiple` |
| Client identifier prefix | `#scheme-toggle [data-scheme="x509_hash"]`, `"x509_san_dns"`, `"redirect_uri"`, `"pre-registered"` |
| Registration | `#identity-toggle [data-identity="registered"]`, `"unregistered"`, `"own"` with `#signing-key` and `#verifier-info` |
| Own query | `#custom-panel`, `#credentials-list`, `#add-credential` |
| **Create request** | `#create-request` |
| Request links | `#wallet-link`, `#scheme-uri` |

### Presentation consent

| Control | Selector |
|---|---|
| Verifier header and findings | `#consent-who`, `#consent-findings-summary`, `#consent-findings-list` |
| Registered purpose and privacy policy | `#consent-purpose-<n>`, `#consent-privacy-policy-<n>` |
| Selection summary | `#consent-selection-row` (**Auto-selected** or **Your selection**) |
| Credential to send | `#consent-credential-<credential id>`, a `.consent-credential` with `data-credential-id`, `data-vct`, `data-doctype` |
| Claim checkboxes | `.consent-claim input` with `data-cred` and `data-claim` |
| Note on a query with **multiple** | `#consent-multiple-<query id>` |
| Query without a matching credential (debug mode) | `#consent-unanswered-<query id>`. **Approve** stays disabled until you pick one |
| **Approve**, **Deny** | `#consent-approve`, `#consent-deny` |

Uncheck a claim to withhold it. The verifier then receives the presentation without that claim.

After **Approve** or **Deny**, the wallet follows the verifier's `redirect_uri`. Wait for the navigation. The demo verifier redirects to `/verifier/?response_code=...`. Without a redirect, the page stays in the wallet and shows the verifier's answer.

```js
await page.goto(`${WALLET}/verifier/`);
await page.locator('#credential-toggle [data-credential="pid"]').click();
await page.locator("#create-request").click();
await page.locator("#wallet-link").click();
await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
await page.locator("#consent-approve").click();
await page.waitForURL(/\/verifier\/\?response_code=/);
await expect(page.locator("#status")).toHaveAttribute("data-status", "verified");
```

API: `POST /api/presentations` with `{"uri": "..."}` presents the automatic selection without a dialog. With `"interactive": true` it waits for the dialog. See [presentation requests](wallet/http-api.md#presentation-requests).

E2E tests: [`prefix.spec.js`](../e2e/prefix.spec.js), test *a demo verifier request is answered and returns to the verifier*. [`demo.spec.js`](../e2e/demo.spec.js), tests *the registered demo verifier shows its purpose in the consent dialog*, *withholding a requested claim reaches the verifier as its absence* and *denying in the wallet returns to the verifier page, which shows the refusal*. [`wallet.spec.js`](../e2e/wallet.spec.js), tests *denying in the consent dialog continues at the verifier* and *denying stays in the wallet when the verifier sends no redirect_uri*.

### Selection

**Edit** opens the selection. **Done** returns to the summary. **Approve** also works from the edit screen.

| Control | Selector |
|---|---|
| **Edit**, **Done**, reset to the automatic selection | `#consent-edit-selection`, `#consent-selection-done`, `#consent-selection-reset` |
| Query section | `#consent-query-<query id>`, with `data-multiple="true"` for a query with **multiple** |
| Candidate | `#consent-candidate-<query id>-<credential id>`, a `.candidate` with `data-query` and `data-cred`. A picked one has the class `selected`. Under **multiple** it is a checkbox with `aria-checked` |
| Option of a credential set | `#consent-set-<n>-option-<m>` (radio) |
| Skip an optional set | `#consent-set-<n>-none` |
| Claim set | `#consent-claim-set-<query id>-current` says which claim set the wallet sends. `#consent-show-claim-sets-<query id>` opens the list `#consent-claim-set-<query id>`. Each set is the radio `#consent-claim-set-<query id>-<claim_sets index>` |
| Non-matching credentials | `#consent-show-nonmatching-<query id>` opens the list. Rows have `data-non-matching="true"`. Reasons are in `consent-mismatch-<query id>-<credential id>` |

Under **multiple**, the last selected credential stays selected. While a non-matching credential is picked or none matches, the list stays open under `#consent-nonmatching-label-<query id>`.

```js
await page.locator("#consent-edit-selection").click();
await page.locator("#consent-set-1-none").check();
await page.locator("#consent-query-pid .candidate:not(.selected)").first().click();
await page.locator("#consent-selection-done").click();
await page.locator("#consent-approve").click();
```

API: `POST /api/requests/{id}/approve` with `picks`, `set_choices`, `claim_sets` and `selected_claims`. See [consent requests](wallet/http-api.md#consent-requests).

E2E tests: [`demo.spec.js`](../e2e/demo.spec.js), tests *switching the set option presents the other format*, *edit, done and edit again keeps the selection, reset restores auto*, *an optional ticket set is answered by default and skippable* and *a multiple query lets the user withhold all but one credential*. [`wallet.spec.js`](../e2e/wallet.spec.js), tests *the chosen claim set reaches the verifier*, *a picked non-matching credential is sent with its reasons shown* and *a request nothing matches waits for a pick*.

### Verifier result

The demo verifier polls for the result and shows it on its page.

| Element | Selector |
|---|---|
| Status | `#status` with `data-status` set to `pending`, `verified`, `failed`, `declined` or `expired`. The text starts with `✓ Presentation verified`, `✗ Verification failed` or `✗ The wallet declined:` |
| Error of a failed or declined response | `#status-error` |
| Failed checks and warnings | `#checks .check-item` with the class `fail` or `warn` |
| Passed checks | `#checks-passed` (collapsed), opened with `#checks-passed-summary` |
| Check groups per credential | `.check-group`, headed with the query ID |
| Disclosed claims | `#claims` (table), rows `#claims-<n>-<claim>` |
| The presentation in the decoder | `#presentation-link` |

API: `GET /verifier/api/requests/{transaction id}` answers `status`, `checks` and `claims`. `POST /verifier/api/requests` with `{"type": "pid"}` creates a request and answers `transaction_id`, `wallet_url` and `scheme_uri`.

E2E tests: [`demo.spec.js`](../e2e/demo.spec.js), tests *a response with a ticket and a PID lists the checks of each credential* and *the redirect shows the requested credential and folds the passed checks*.

## Issue credential dialog

**Issue credential** issues a credential with the wallet's own issuer key. Choose a template or fill in the fields.

| Control | Selector |
|---|---|
| **Issue credential** | `#issue-btn` |
| Dialog | `#issue-overlay` |
| Format, template | `#issue-format` (`sdjwt`, `jwt`, `mdoc`), `#issue-template` |
| Type | `#issue-vct` or `#issue-doctype` |
| Claim rows | `#issue-claim-key-<n>`, `#issue-claim-value-<n>`, `#issue-claim-ns-<n>` (mdoc), `#issue-claim-sd-<n>` (selectively disclosable), `#issue-add-claim` |
| Claims as JSON | `#issue-claims-mode-json`, `#issue-claims`, back with `#issue-claims-mode-builder` |
| Status list, expiry, batch, binding | `#issue-status-list`, `#issue-exp`, `#issue-nbf`, `#issue-batch`, `#issue-binding` |
| Card appearance | `#issue-display-name`, `#issue-display-description`, `#issue-bg-color`, `#issue-text-color` |
| **Save as template** | `#issue-save-template` (name), `#issue-catalog` adds it to the attestation catalogue |
| **Issue**, cancel, error | `#issue-submit`, `#issue-cancel`, `#issue-error` |

```js
await page.goto(WALLET);
await page.locator("#issue-btn").click();
await page.locator("#issue-vct").fill("urn:example:member:1");
await page.locator("#issue-claim-key-0").fill("member_id");
await page.locator("#issue-claim-value-0").fill("M-1");
await page.locator("#issue-save-template").fill("member");
await page.locator("#issue-submit").click();
await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);
await expect(page.locator('.credential-card[data-vct="urn:example:member:1"]')).toBeVisible();
```

**Templates** (`#templates-link`) lists the templates. Rows are `template-row-<name>` with `template-edit-<name>` and `template-delete-<name>`. `#template-new` opens the same form with a name field (`#template-editor-name`).

API: `POST /api/issue` (see [credential issuance](wallet/http-api.md#credential-issuance)) and `PUT /api/templates/{name}` (see [credential templates](wallet/http-api.md#credential-templates)).

E2E tests: [`wallet.spec.js`](../e2e/wallet.spec.js), tests *issues an SD-JWT credential from the PID template with an added claim*, *issues an mdoc with a per-attribute namespace*, *saves the issue dialog contents as a template* and *manages templates and issues from one with a non-disclosable claim*.

## Activity, cards and decoder

### Activity log

Each exchange is an entry in **Activity**. Entries start collapsed. Scope the controls to their entry.

| Control | Selector |
|---|---|
| Entry | `data-testid="log-entry"`, with `data-event` (such as `presentation_response` or `credential_response`) and `data-action` (`presentation`, `issuance`, `management`) |
| Open or close an entry | `data-testid="log-entry-toggle"` |
| Switch encrypted or decrypted view | `data-testid="log-payload-toggle"` |
| Open a token in the decoder | `data-testid="log-decoder-link"` |
| Show an alternate wire value | `data-testid="log-wire-toggle"` |

Entries for a stored credential also have `data-credential-id`. Presentation decoder links have `data-query-id` and `data-token-index`. Credential response and batch import links have `data-credential-index`. Batch import links also have `data-credential-id` for each stored copy. Token indexes start at zero within each query. Credential indexes start at zero within the entry. The encryption toggle keeps the same selector in both views.

A fetched request object and its receipt share one entry. A batch import is one entry with the ID of every stored copy. Encrypted exchanges show the wire value first.

```js
const entry = page.locator('[data-testid="log-entry"][data-event="presentation_response"]').first();
await entry.getByTestId("log-entry-toggle").click();
const link = entry.locator('[data-testid="log-decoder-link"][data-query-id="pid"][data-token-index="0"]');
await expect(link).toHaveAttribute("href", /decoder\/#credential=/);
```

API: `GET /api/log` (see [activity log](wallet/http-api.md#activity-log)).

E2E tests: [`wallet.spec.js`](../e2e/wallet.spec.js), tests *activity starts collapsed and opens the sent presentation in the decoder*, *encrypted activity starts with the wire value and toggles plaintext at phone width* and *fetched request objects appear once with HTTP context and a decoder link*.

### Card actions

| Action | Selector |
|---|---|
| **Show** (opens the decoder in a new tab) | `#show-<credential id>` |
| **Delete** | `#delete-<credential id>` |
| **Revoke** or **Activate** on the wallet's status list | `#revoke-<credential id>` |
| **Check status** of an external status list | `#status-check-<credential id>` |
| Status badge | `#status-<credential id>` |
| **About** (description) | `#about-<credential id>` |

Protected credentials have no **Delete** or **Revoke**. After **Revoke**, the card has `data-status="revoked"`.

API: `DELETE /api/credentials/{id}` and `POST /api/credentials/{id}/status` with `{"status": 1}` (see [status list](wallet/http-api.md#status-list)).

E2E tests: [`wallet.spec.js`](../e2e/wallet.spec.js), tests *shows status badges and revokes and re-activates a credential* and *deletes the issued credential via its card button*. [`demo.spec.js`](../e2e/demo.spec.js), test *the seeded PIDs are marked and offer no destructive actions*.

### Decoder

The wallet serves the [decoder](decoder.md) at `/decoder/`. Open it with a token in the fragment (`/decoder/#credential=<token>`) or with a stored credential (`/decoder/?id=<credential id>`).

| Control | Selector |
|---|---|
| Input | `#input` |
| Format | `#format-badge` |
| Decoded sections | `#output .section[data-section="header"]`, `"payload"`, `"signature"`, `"kb-jwt"`, `"disc-<n>"` |
| Checks | `.validity-banner`, items `.vg-item` with `data-check` |
| Verify with a key or trusted list | `#output-verify-summary` opens it. `#output-verify-key`, `#output-verify-trusted-list`, `#output-verify-btn` |
| **Share**, **Clear** | `#share-btn` (copies a link), `#clear-btn` |

```js
await page.goto(`${WALLET}/decoder/?id=${credentialID}`);
await expect(page.locator("#format-badge")).toHaveText("SD-JWT");
await page.locator("#output-verify-summary").click();
await page.locator("#output-verify-trusted-list").fill(`${WALLET}/api/trustlists/pid`);
await page.locator("#output-verify-btn").click();
```

API: `POST /decoder/api/validate` (see [validation API](decoder.md#validation-api)).

E2E tests: [`ui.spec.js`](../e2e/ui.spec.js), tests *decodes and shows format badge, banner, and sections*, *verify form opens with key input and button* and *prefill via fragment*.

## Registrar and trust

### Register a verifier or issuer

Open **Registrar** (`#registrar-menu-toggle`), then **Relying parties** (`#registrar-parties-link`).

| Control | Selector |
|---|---|
| Register a verifier or issuer | `#registrar-parties-register`, `#registrar-parties-register-issuer` |
| Name, purpose, DNS name | `#registrar-name`, `#registrar-purpose`, `#registrar-dns` |
| Requested credentials (verifier) | `#registrar-credential-<n>-format`, `-type`, `-claims`, starting at 1. More with `#registrar-add-credential` |
| Attestations (issuer) | `#registrar-attestation-<n>-format`, `-type`, starting at 1. More with `#registrar-add-attestation` |
| Own CSR | `#registrar-csr`. `#registrar-csr-help-toggle` shows an OpenSSL command in `#registrar-csr-command` |
| **Register verifier** or **Register issuer**, error | `#registrar-submit`, `#registrar-error` |
| Result | `#registrar-result`, `#registrar-result-identifier`, `#registrar-client-id-<n>` |
| Key and certificate chain | `#registrar-pem`. Without a CSR it holds the private key too |
| `verifier_info` or `issuer_info` | `#registrar-verifier-info`, `#registrar-issuer-info` (JSON) |
| Relying parties list | `#registrar-search`, `#registrar-filter-verifiers`, `#registrar-filter-issuers`, entries `#registrar-party-<identifier>` |
| **Issue access certificate** of a service | `#registrar-party-<identifier>-service-<service>-access` (`default` without a service identifier) |

```js
await page.goto(WALLET);
await page.locator("#registrar-menu-toggle").click();
await page.locator("#registrar-parties-link").click();
await page.locator("#registrar-parties-register").click();
await page.locator("#registrar-submit").click();
await expect(page.locator("#registrar-result")).toBeVisible();
const clientID = await page.locator("#registrar-client-id-0").textContent();
const pem = await page.locator("#registrar-pem").inputValue();
const verifierInfo = JSON.parse(await page.locator("#registrar-verifier-info").inputValue());
```

API: `POST /api/registrar/enrolments` registers and issues the certificates in one call. See the [registrar API walkthrough](wallet/registrar-api.md).

E2E tests: [`wallet.spec.js`](../e2e/wallet.spec.js), tests *registering a verifier with the defaults issues both certificates*, *an own CSR keeps the key outside the wallet*, *registering an issuer issues its access certificate and issuer_info* and *a registration certificate shows its purpose in the consent dialog*.

### Attestation catalogue

Open **Registrar**, then **Attestation catalogue** (`#registrar-catalog-link`). The catalogue is `#registrar-catalog-overlay`. Entries are `#registrar-catalog-list .registrar-party`, with the name in `.registrar-party-name`.

| Control | Selector |
|---|---|
| Search | `#registrar-catalog-search` |
| Filters | `#registrar-catalog-filter-category-<category>`, `-los-<level>`, `-binding-<value>`, `-source-<source>` (with `aria-pressed`), `#registrar-catalog-filter-clear` |
| No match | `#registrar-catalog-empty` |
| Add an attestation | `#registrar-catalog-add`, form fields `#registrar-catalog-name`, `#registrar-catalog-category`, `#registrar-catalog-format-<n>-type`, `#registrar-catalog-save` |

API: `GET` and `POST /api/catalog/attestations` (see [registrar](wallet/http-api.md#registrar)).

E2E tests: [`wallet.spec.js`](../e2e/wallet.spec.js), tests *the attestation catalogue filters by category and security level* and *the attestation catalogue lists the PID types and adds an attestation*. [`catalog.spec.js`](../e2e/catalog.spec.js), test *the source filter and the search narrow the catalogue*.

### Trust & certificates

**Trust & certificates** (`#trust-link`) opens `#trust-overlay`.

| Control | Selector |
|---|---|
| **+ Add provider CA** | `#trust-add-provider`, then `#trust-entity-list`, `#trust-entity-name`, `#trust-entity-ca`, `#trust-entity-add` |
| Added providers of a list | `#trust-list-<list id>-added li` |
| **+ Add external list** | `#trust-add-list`, then `#trust-list-url`, `#trust-list-add` |
| External lists | `#trust-external-<n>-url`, `#trust-external-<n>-remove` |
| **Add that CA** in the external list popup | `#trust-external-add-operator` (opens the provider popup with `trusted-list-ca`) |
| Catalogue note of an external list | `#trust-external-<n>-catalogue-hint` |
| Certificate links | `#ca-cert-pem-link`, `#signing-jwks-link`, `#access-ca-cert-pem-link` |

API: `POST /api/trust/entities` and `POST /api/trust/lists` (see [issuer metadata and trusted lists](wallet/http-api.md#issuer-metadata-and-trusted-lists)).

E2E tests: [`wallet.spec.js`](../e2e/wallet.spec.js), test *trust dialog adds a provider CA and an external list in popups and shows them under their lists*. [`trust-dialogs.spec.js`](../e2e/trust-dialogs.spec.js), test *a refused CA keeps the provider popup open with the reason, and reopening clears it*.

## Settings

**Conformance** (`#conformance-link`) opens `#conformance-overlay`. A local wallet applies each change at once. A demo shows the settings read-only.

| Control | Selector |
|---|---|
| Validation mode | `#conf-mode-select` (`strict`, `debug`) |
| HTTPS certificates | `#conf-tls-select` (`auto`, `true`, `false`) |
| HAIP, ARF, encrypted request objects | `#conf-haip-input`, `#conf-arf-input`, `#conf-encrypted-input` |
| OpenID4VCI version, key attestation level | `#conf-vci-version-select`, `#conf-key-attestation-select` |
| **Reset to startup settings**, **Close** | `#conf-reset`, `#conformance-close` |

**Auto-accept** (`#auto-accept-toggle`) shows the state in `aria-pressed`. Only local wallets show it.

```js
await page.locator("#conformance-link").click();
await page.locator("#conf-mode-select").selectOption("strict");
await page.locator("#conf-arf-input").check();
await page.locator("#conformance-close").click();
```

API: `PUT /api/config/conformance` and `PUT /api/config/auto-accept` (see [introspection](wallet/http-api.md#introspection)).

E2E tests: [`wallet.spec.js`](../e2e/wallet.spec.js), tests *conformance panel changes the local wallet setting via the endpoint*, *strict mode with --arf refuses a request without an access certificate* and *names the mode and flips it at runtime*. [`demo.spec.js`](../e2e/demo.spec.js), test *the dialog reports what a demo instance checks*.

## API alternatives

Click through the UI only for the part your test is about. Prepare the rest with the API. The [HTTP API](wallet/http-api.md) has every endpoint.

| UI process | Endpoint |
|---|---|
| Accept an offer | `POST /api/offers` with `uri`, `tx_code` and `interactive` |
| Answer a presentation request | `POST /api/presentations` with `uri` and `interactive` |
| Answer a pending consent dialog | `GET /api/requests`, then `POST /api/requests/{id}/approve` or `/deny` |
| **Issue credential** | `POST /api/issue` |
| Credential list | `GET /api/credentials` |
| Activity | `GET /api/log` |
| Demo issuer offer | `POST /issuer/api/offers` |
| Demo verifier request and result | `POST /verifier/api/requests`, `GET /verifier/api/requests/{id}` |
| Register a relying party | `POST /api/registrar/enrolments` |
| Conformance settings | `PUT /api/config/conformance`, reset with `DELETE /api/config/conformance` |

Without `interactive`, the API call counts as consent and no dialog opens.

```bash
# Get a ticket into the wallet before the UI part of a test
offer=$(curl -s -X POST http://localhost:8085/issuer/api/offers | jq -r .scheme_uri)
curl -s -X POST http://localhost:8085/api/offers -H 'Content-Type: application/json' \
  -d "{\"uri\": \"$offer\"}"

# Switch the wallet to strict mode with ARF checks
curl -s -X PUT http://localhost:8085/api/config/conformance -H 'Content-Type: application/json' \
  -d '{"validation_mode": "strict", "require_arf": true}'
```

```js
const res = await fetch(`${WALLET}/verifier/api/requests`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ type: "pid" }),
});
const { transaction_id, wallet_url } = await res.json();
```

Errors of the wallet, registrar, catalogue and decoder API have one shape (see [errors](wallet/http-api.md#errors)):

```json
{"error": "invalid_request", "error_description": "invalid JSON body: invalid character 'n' looking for beginning of value"}
```
