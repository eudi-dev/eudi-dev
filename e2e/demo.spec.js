// @ts-check
// Demo requests belong to the browser that started them. A request without an owner
// stays available through the Review bar.
const { test, expect } = require("@playwright/test");
const { waitForServer } = require("./helpers");
const { execSync, spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const PORT = 18930;
const BASE = `http://localhost:${PORT}`;

let walletProcess;

test.describe.configure({ mode: "serial" });
test.setTimeout(60_000);

test.beforeAll(async () => {
  test.setTimeout(120_000);
  execSync("go build -o /tmp/eudi-demo-e2e ..", { cwd: __dirname });

  const walletDir = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-demo-e2e-"));
  // CI uploads the server log with the test results, so a failure shows wallet activity.
  const resultsDir = path.join(__dirname, "test-results");
  fs.mkdirSync(resultsDir, { recursive: true });
  const walletLogFd = fs.openSync(path.join(resultsDir, "demo-wallet.log"), "w");
  walletProcess = spawn(
    "/tmp/eudi-demo-e2e",
    [
      "wallet",
      "serve",
      "--demo",
      // Periodic resets would clear state during tests.
      "--demo-reset",
      "0",
      "--port",
      String(PORT),
      "--wallet-dir",
      walletDir,
      "--base-url",
      BASE,
    ],
    { stdio: ["ignore", walletLogFd, walletLogFd] }
  );
  await waitForServer(`${BASE}/api/version`, 30_000);
});

test.afterAll(() => {
  if (walletProcess) walletProcess.kill("SIGTERM");
});

async function postJSON(pathname, body) {
  const res = await fetch(BASE + pathname, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

async function verifierResult(id) {
  const res = await fetch(`${BASE}/verifier/api/requests/${id}`);
  return await res.json();
}

async function createVerifierRequest(page, credential) {
  await page.locator(`#credential-toggle [data-credential="${credential}"]`).click();
  await page.locator("#create-request").click();
}

// Only an authorization code offer lets the user choose between presentation and
// browser sign-in.
async function createIssuerOffer(page, { grant, authorization } = {}) {
  await page.goto(`${BASE}/issuer/`);
  if (grant) {
    await page.locator(`#grant-toggle [data-grant="${grant}"]`).click();
  }
  if (authorization) {
    await page.locator(`#authorization-toggle [data-authorization="${authorization}"]`).click();
  }
  await page.locator("#create-btn").click();
  await expect(page.locator("#result")).toBeVisible();
  return (await page.locator("#scheme-uri").textContent()) || "";
}

async function createVerificationRequest() {
  const { body } = await postJSON("/verifier/api/requests", { type: "pid" });
  return { id: body.transaction_id, walletURL: body.wallet_url, schemeURI: body.scheme_uri };
}

// The demo verifier answers a denial with a redirect_uri back to its page
// (OpenID4VP 1.0 §8.2), and the wallet tab follows it.
async function denyAtVerifier(page) {
  await page.locator("#consent-deny").click();
  await expect(page).toHaveURL(/\/verifier\/\?response_code=/, { timeout: 15_000 });
}

async function openAsSchemeHandler(page) {
  const owner = "test-owner-" + Math.random().toString(36).slice(2);
  await page.goto(`${BASE}/?focus=overview&owner=${owner}`);
  return owner;
}

// No owner emulates a URL handler that submits unowned requests. Submission errors
// are kept so waitForPending can report the cause of a timeout.
let lastSubmitError = null;

function submitAsSchemeHandler(pathname, uri, owner) {
  const headers = { "Content-Type": "application/json" };
  if (owner) {
    headers["X-Eudi-Client"] = "eudi-url-handler/test";
    headers["X-Eudi-Owner"] = owner;
  }
  lastSubmitError = null;
  // Interactive submissions wait for consent. Completed responses are drained to
  // release connections.
  fetch(BASE + pathname, {
    method: "POST",
    headers,
    body: JSON.stringify({ uri, interactive: true }),
  })
    .then(async (r) => {
      if (!r.ok) lastSubmitError = `${r.status} ${(await r.text()).slice(0, 300)}`;
      else if (r.body) await r.body.cancel();
    })
    .catch((e) => {
      lastSubmitError = String((e && e.message) || e);
    });
}

async function listPending(owner) {
  const headers = owner ? { "X-Eudi-Owner": owner } : {};
  const res = await fetch(`${BASE}/api/requests`, { headers });
  return await res.json();
}

async function pendingCount(owner) {
  return (await listPending(owner)).length;
}

async function waitForPending(expected, owner) {
  for (let i = 0; i < 50; i++) {
    if ((await pendingCount(owner)) === expected) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  const reason = lastSubmitError ? ` (last submission: ${lastSubmitError})` : "";
  throw new Error(`expected ${expected} pending request(s)${reason}`);
}

async function clearPending(owner) {
  const headers = owner ? { "X-Eudi-Owner": owner } : {};
  for (const req of await listPending(owner)) {
    await fetch(`${BASE}/api/requests/${req.id}/deny`, { method: "POST", headers });
  }
  await waitForPending(0, owner);
}

test.describe("Demo mode sponsor link", () => {
  for (const pagePath of ["/", "/issuer/", "/verifier/", "/decoder/"]) {
    test(`is shown on ${pagePath}`, async ({ page }) => {
      await page.goto(`${BASE}${pagePath}`);
      await expect(page.locator("#sponsor-link")).toBeVisible();
      await expect(page.locator("#sponsor-link")).toHaveAttribute(
        "href",
        "https://github.com/sponsors/dominikschlosser"
      );
    });
  }
});

test.describe("Demo mode conformance panel", () => {
  test("is read-only and cannot change the shared setting", async ({ page }) => {
    await page.goto(`${BASE}/?focus=overview`);
    const config = async () =>
      await page.evaluate(async () => await (await fetch("/api/config")).json());

    const before = await config();
    expect(before.validation_mode).toBe("debug");
    expect(before.require_haip).toBe(true);
    expect(before.require_arf).toBe(true);

    await page.click("#conformance-link");
    await expect(page.locator("#conf-mode-select")).toHaveValue("debug");
    await expect(page.locator("#conf-mode-select")).toBeDisabled();
    await expect(page.locator("#conf-haip-input")).toBeDisabled();
    await expect(page.locator("#conf-arf-input")).toBeDisabled();
    await expect(page.locator("#conf-encrypted-input")).toBeDisabled();
    await expect(page.locator("#conf-reset")).toBeHidden();
    await expect(page.locator("#conf-intro")).toHaveText("Fixed settings on the public demo.");

    expect(await page.evaluate(() => document.cookie)).not.toContain("eudi_conformance");
    const status = await page.evaluate(async () => {
      const r = await fetch("/api/config/conformance", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ validation_mode: "strict" }),
      });
      return r.status;
    });
    expect(status).toBe(403);
    expect((await config()).validation_mode).toBe("debug");
  });
});

test.describe("Demo mode consent visibility", () => {
  test.afterEach(async () => {
    await clearPending();
  });

  test("a request no client named a page for waits in the banner", async ({
    page,
  }) => {
    const req = await createVerificationRequest();
    submitAsSchemeHandler("/api/presentations", req.schemeURI);
    await waitForPending(1);

    await page.goto(`${BASE}/?focus=overview`);
    await expect(page.locator("#pending-banner")).toBeVisible();
    await expect(page.locator("#consent-overlay")).not.toHaveClass(/active/);

    await page.locator("#pending-review").click();
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
    await expect(page.locator("#consent-approve")).toBeVisible();
    await page.locator("#consent-deny").click();
  });

  test("the registered demo verifier shows its purpose in the consent dialog", async ({ page }) => {
    // The demo verifier sends its registration certificate in verifier_info
    // (OpenID4VP 1.0 §5.1).
    await page.goto(`${BASE}/verifier/`);
    await expect(page.locator("#identity-registered")).toHaveAttribute("aria-checked", "true");
    await page.locator('#credential-toggle [data-credential="pid"]').click();
    await page.locator("#create-request").click();
    await expect(page.locator("#scheme-uri")).toHaveAttribute("href", /^openid4vp:/);
    const schemeURI = await page.locator("#scheme-uri").getAttribute("href");
    submitAsSchemeHandler("/api/presentations", schemeURI);
    await waitForPending(1);

    await page.goto(`${BASE}/?focus=overview`);
    await page.locator("#pending-review").click();
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
    await expect(page.locator("#consent-purpose-0")).toContainText("Shows how a verifier requests and checks credentials");
    await expect(page.locator("#consent-privacy-policy-0")).toHaveAttribute("href", /\/privacy-policy$/);
    await page.locator("#consent-deny").click();
  });

  test("the consent dialog lists the findings about an unregistered verifier", async ({ page }) => {
    await page.goto(`${BASE}/verifier/`);
    await page.locator("#identity-unregistered").click();
    await page.locator('#credential-toggle [data-credential="pid"]').click();
    await page.locator("#create-request").click();
    await expect(page.locator("#scheme-uri")).toHaveAttribute("href", /^openid4vp:/);
    submitAsSchemeHandler("/api/presentations", await page.locator("#scheme-uri").getAttribute("href"));
    await waitForPending(1);

    await page.goto(`${BASE}/?focus=overview`);
    await page.locator("#pending-review").click();
    // Debug mode continues. The findings start as one collapsed line.
    const summary = page.locator("#consent-findings-summary");
    await expect(summary).toContainText("about this verifier");
    await expect(page.locator("#consent-findings-list")).toBeHidden();
    await summary.click();
    await expect(page.locator("#consent-findings-list")).toContainText("ARF RPRC_19");
    await expect(page.locator("#consent-findings-list")).toContainText("Wallets must check it from 11 August 2028");
    await page.locator("#consent-deny").click();
  });

  test("the issuance consent dialog says what is being issued", async ({ page }) => {
    const { body: offer } = await postJSON("/issuer/api/offers", {});
    const offerDoc = await (await fetch(offer.offer_uri)).json();
    const uri = "openid-credential-offer://?credential_offer=" + encodeURIComponent(JSON.stringify(offerDoc));

    const owner = await openAsSchemeHandler(page);
    submitAsSchemeHandler("/api/offers", uri, owner);
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);

    const dialog = page.locator("#consent-dialog");
    await expect(dialog).toContainText("EUDI Dev Demo Issuer");
    await expect(page.locator("#offer-issuer-origin")).toContainText(BASE);
    await expect(page.locator("#offer-facts")).toContainText("pre-authorized code");
    await expect(dialog).toContainText("Demo Event Ticket");
    await expect(dialog).toContainText("urn:eudi-test:demo-ticket:1");
    for (const claim of ["event", "tier", "seat", "given_name", "family_name"]) {
      await expect(dialog.locator(".consent-claim-name", { hasText: claim })).toHaveCount(1);
    }
    // Claims show the display names from the issuer metadata, with the path
    // next to them.
    const seat = dialog.locator(".consent-claim", { has: page.locator(".consent-claim-name", { hasText: /^seat$/ }) });
    await expect(seat.locator(".offer-claim-label")).toHaveText("Seat");
    const tier = dialog.locator(".consent-claim", { has: page.locator(".consent-claim-name", { hasText: /^tier$/ }) });
    await expect(tier.locator(".offer-claim-label")).toHaveText("Ticket tier");

    await page.locator("#consent-deny").click();
    await expect(page.locator("#consent-overlay")).not.toHaveClass(/active/);
  });

  test("a deferred offer is awaited and then collected", async ({ page }) => {
    const { body: offer } = await postJSON("/issuer/api/offers?deferred=true", {});
    const offerDoc = await (await fetch(offer.offer_uri)).json();
    const uri =
      "openid-credential-offer://?credential_offer=" +
      encodeURIComponent(JSON.stringify(offerDoc));

    const owner = await openAsSchemeHandler(page);
    submitAsSchemeHandler("/api/offers", uri, owner);
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
    await page.locator("#consent-approve").click();

    await expect(page.locator("#deferred-section")).toBeVisible({ timeout: 10_000 });
    await expect(
      page.locator("#credentials .credential-card", {
        hasText: "Demo Event Ticket",
      })
    ).toBeVisible({ timeout: 25_000 });

    await fetch(`${BASE}/api/credentials`, { method: "DELETE" });
  });

  // A failed flow without an owner doesn't open in a browser's next issuance.
  test("an earlier failure does not reopen on the next issuance", async ({ page }) => {
    const dead = "openid-credential-offer://?credential_offer=" + encodeURIComponent(JSON.stringify({
      credential_issuer: "https://issuer.invalid",
      credential_configuration_ids: ["nope"],
      grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "x" } },
    }));
    await postJSON("/api/offers", { uri: dead });
    await expect
      .poll(async () => JSON.stringify(await (await fetch(`${BASE}/api/log`)).json()))
      .toContain("issuer.invalid");

    const { body: offer } = await postJSON("/issuer/api/offers", {});
    const offerDoc = await (await fetch(offer.offer_uri)).json();
    const uri = "openid-credential-offer://?credential_offer=" + encodeURIComponent(JSON.stringify(offerDoc));

    // Dialogs are recorded from first paint. A retrying assertion could miss a brief stale
    // error. The page reads a stale error with a fetch, so the test waits until every
    // fetch of the page has finished.
    await page.addInitScript(() => {
      window.__fetches = 0;
      const original = window.fetch;
      window.fetch = (...args) => {
        window.__fetches++;
        return original(...args).finally(() => setTimeout(() => window.__fetches--, 0));
      };
      window.__dialogs = [];
      document.addEventListener("DOMContentLoaded", () => {
        const dialog = document.getElementById("consent-dialog");
        const overlay = document.getElementById("consent-overlay");
        if (!dialog || !overlay) return;
        new MutationObserver(() => {
          if (overlay.classList.contains("active") && dialog.textContent.trim()) {
            window.__dialogs.push(dialog.textContent.slice(0, 80));
          }
        }).observe(dialog, { childList: true, subtree: true, characterData: true });
      });
    });

    const owner = await openAsSchemeHandler(page);
    submitAsSchemeHandler("/api/offers", uri, owner);

    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
    await expect(page.locator("#consent-dialog")).toContainText("Demo Event Ticket");
    await page.waitForFunction(() => window.__fetches === 0);

    const shown = await page.evaluate(() => window.__dialogs);
    expect(shown.join(" | ")).not.toMatch(/Error/);
    await expect(page.locator(".consent-overlay.active")).toHaveCount(1);

    await page.locator("#consent-deny").click();
    await expect(page.locator("#consent-overlay")).not.toHaveClass(/active/);
  });

  test("an offer delivered by reference is described too", async ({ page }) => {
    const { body: offer } = await postJSON("/issuer/api/offers", {});
    const owner = await openAsSchemeHandler(page);
    submitAsSchemeHandler("/api/offers", offer.scheme_uri, owner);
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);

    const dialog = page.locator("#consent-dialog");
    await expect(dialog).toContainText("EUDI Dev Demo Issuer");
    await expect(dialog).toContainText("Demo Event Ticket");
    await expect(dialog.locator(".consent-claim-name", { hasText: "seat" })).toHaveCount(1);
    await page.locator("#consent-deny").click();
  });

  test("a scheme-dispatched credential offer is reachable the same way", async ({
    page,
  }) => {
    const { body: offer } = await postJSON("/issuer/api/offers", {});
    submitAsSchemeHandler("/api/offers", offer.scheme_uri);
    await waitForPending(1);

    await page.goto(`${BASE}/?focus=overview`);
    await page.locator("#pending-review").click();
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
    await expect(page.locator("#consent-dialog")).toContainText("Credential offer");
  });

  test("the tab the scheme handler opened takes the consent directly", async ({
    page,
  }) => {
    // The request may arrive before the handler tab finishes loading.
    const owner = "test-owner-" + Math.random().toString(36).slice(2);
    const req = await createVerificationRequest();
    submitAsSchemeHandler("/api/presentations", req.schemeURI, owner);
    await waitForPending(1, owner);

    await page.goto(`${BASE}/?focus=overview&owner=${owner}`);

    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
    await expect(page.locator("#consent-approve")).toBeVisible();
    await expect(page.locator("#pending-banner")).toBeHidden();
    await expect(page).not.toHaveURL(/owner=/);
  });

  // A proxy can hold back the event stream's response. The consent dialog of
  // a request opened in this tab must not wait for it.
  test("a request opened in this tab shows its dialog while the event stream hangs", async ({ page }) => {
    await page.route("**/api/requests/stream*", () => {});
    const req = await createVerificationRequest();
    const started = Date.now();
    await page.goto(req.walletURL);
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/, { timeout: 5000 });
    expect(Date.now() - started).toBeLessThan(5000);
    await expect(page.locator("body")).not.toHaveAttribute("data-request-stream", "open");
  });

  test("an error from someone else's flow stays out of uninvolved tabs", async ({
    browser,
  }) => {
    const context = await browser.newContext();
    const bystander = await context.newPage();
    await bystander.goto(`${BASE}/?focus=overview`);
    await expect(bystander.locator("#credentials")).toBeVisible();
    await expect(bystander.locator("#demo-note")).toBeVisible();
    await expect(bystander.locator("body")).toHaveAttribute("data-request-stream", "open");

    await fetch(`${BASE}/api/offers`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Eudi-Owner": "someone-else" },
      body: JSON.stringify({
        uri: "openid-credential-offer://?credential_offer_uri=http://127.0.0.1:1/gone",
      }),
    }).catch(() => {});

    // The stream delivers events in order. Once the later unowned request shows,
    // the error has had its chance to arrive.
    const unowned = await createVerificationRequest();
    submitAsSchemeHandler("/api/presentations", unowned.schemeURI);
    await expect(bystander.locator("#pending-banner")).toBeVisible();
    await expect(bystander.locator("#consent-overlay")).not.toHaveClass(/active/);
    await clearPending();
    await context.close();
  });

  test("the tab that started the failing flow does see the error", async ({
    page,
  }) => {
    await page.goto(`${BASE}/?focus=overview`);

    await page
      .locator("#offer-input")
      .fill("openid4vp://authorize?client_id=x509_hash:abc&request_uri=http://127.0.0.1:1/gone");
    await page.locator("#process-btn").click();

    await expect(page.locator("#consent-overlay")).toHaveClass(/active/, {
      timeout: 10_000,
    });
    await expect(page.locator("#consent-dialog")).toContainText("Error");
  });

  test("a request arriving after that tab opened reaches it too", async ({
    page,
  }) => {
    const owner = await openAsSchemeHandler(page);
    await expect(page.locator("#pending-banner")).toBeHidden();

    const first = await createVerificationRequest();
    submitAsSchemeHandler("/api/presentations", first.schemeURI, owner);
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);

    await denyAtVerifier(page);
    await page.goto(`${BASE}/?focus=overview&owner=${owner}`);

    const second = await createVerificationRequest();
    submitAsSchemeHandler("/api/presentations", second.schemeURI, "someone-else");
    await waitForPending(1, "someone-else");
    // The stream delivers events in order. The tab's own third request shows
    // after the tab has seen the other owner's request.
    const third = await createVerificationRequest();
    submitAsSchemeHandler("/api/presentations", third.schemeURI, owner);
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
    await denyAtVerifier(page);
    expect((await listPending("someone-else")).length, "the other owner's request stays pending").toBe(1);
    await clearPending("someone-else");
  });

  test("a request pushed off screen by a second one is offered in the banner", async ({
    page,
  }) => {
    const owner = await openAsSchemeHandler(page);

    const first = await createVerificationRequest();
    submitAsSchemeHandler("/api/presentations", first.schemeURI, owner);
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);

    // Only one dialog is visible. The banner must keep the replaced request accessible
    // after the current dialog closes. A denied offer leaves the user in the
    // wallet, so the banner shows in the same tab.
    const { body: offer } = await postJSON("/issuer/api/offers", {});
    submitAsSchemeHandler("/api/offers", offer.scheme_uri, owner);
    await waitForPending(2, owner);
    await expect(page.locator("#consent-dialog")).toContainText("Demo Event Ticket");

    await expect(page.locator("#pending-banner")).toBeHidden();
    await page.locator("#consent-deny").click();
    await expect(page.locator("#pending-banner")).toBeVisible();
    await expect(page.locator("#pending-text")).toHaveText(
      "A request is waiting for consent."
    );
    await page.locator("#pending-review").click();
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
    await expect(page.locator("#consent-approve")).toBeVisible();
    await denyAtVerifier(page);
    await waitForPending(0, owner);
  });

  // Any browser may answer an unowned request.
  test("a client that names no page leaves its request reachable", async ({
    browser,
  }) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    const req = await createVerificationRequest();
    submitAsSchemeHandler("/api/presentations", req.schemeURI);
    await waitForPending(1);

    await page.goto(`${BASE}/?focus=overview`);
    await expect(page.locator("#pending-banner")).toBeVisible();
    await page.locator("#pending-review").click();
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
    await expect(page.locator("#consent-approve")).toBeVisible();
    await page.locator("#consent-deny").click();
    await context.close();
  });

  test("a browser-initiated request opens its own dialog", async ({ page }) => {
    const req = await createVerificationRequest();

    await page.goto(req.walletURL);
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
    await expect(page.locator("#pending-banner")).toBeHidden();
    // The request ID grants access to consent, so it must leave the URL.
    await expect(page).not.toHaveURL(/request=/);
  });

  test("the Process button opens the consent dialog for a pasted request", async ({ page }) => {
    await page.goto(BASE);
    await expect(page.locator("#demo-note")).toBeVisible();

    const req = await createVerificationRequest();
    await page.locator("#offer-input").fill(req.schemeURI);
    await page.locator("#process-btn").click();
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
  });

  test("another visitor's tab is not told about a pending request", async ({
    browser,
  }) => {
    const starter = await browser.newPage();
    const bystander = await browser.newPage();
    await bystander.goto(BASE);
    // The page must load its configuration and enter demo mode before submission.
    await expect(bystander.locator("#demo-note")).toBeVisible();
    await expect(bystander.locator("body")).toHaveAttribute("data-request-stream", "open");

    const req = await createVerificationRequest();
    await starter.goto(req.walletURL);
    await expect(starter.locator("#consent-overlay")).toHaveClass(/active/);

    // The stream delivers events in order. The banner counts only the later
    // unowned request, so the starter's request never reached this tab.
    const unowned = await createVerificationRequest();
    submitAsSchemeHandler("/api/presentations", unowned.schemeURI);
    await expect(bystander.locator("#pending-text")).toHaveText("A request from outside this browser is waiting for consent.");
    await expect(bystander.locator("#consent-overlay")).not.toHaveClass(/active/);
    await clearPending();

    await starter.close();
    await bystander.close();
  });

  test("the banner disappears once nothing is pending", async ({ browser }) => {
    const page = await browser.newPage();
    const other = await browser.newPage();
    await page.goto(`${BASE}/?focus=overview`);
    await other.goto(`${BASE}/?focus=overview`);
    await expect(other.locator("#demo-note")).toBeVisible();

    const req = await createVerificationRequest();
    submitAsSchemeHandler("/api/presentations", req.schemeURI);
    await expect(page.locator("#pending-banner")).toBeVisible();

    await clearPending();
    await page.reload();
    await expect(page.locator("#pending-banner")).toBeHidden();

    await page.close();
    await other.close();
  });
});

// OpenID4VCI 1.1 §6 allows authorization through a presentation or browser sign-in.
test.describe("Demo issuer authorization choice", () => {
  test("the choice is offered for the grant that asks the user, and no other", async ({ page }) => {
    await page.goto(`${BASE}/issuer/`);

    // Pre-authorized offers have already been authorized (OpenID4VCI §3.5).
    await expect(page.locator("#authorization-row")).toBeHidden();

    await page.locator('#grant-toggle [data-grant="authorization_code"]').click();
    await expect(page.locator("#authorization-row")).toBeVisible();
    await expect(
      page.locator('#authorization-toggle [data-authorization="browser"]')
    ).toHaveClass(/selected/);

    await page.locator('#grant-toggle [data-grant=""]').click();
    await expect(page.locator("#authorization-row")).toBeHidden();
  });

  test("an offer authorized by a presentation is redeemed without a browser", async ({ page }) => {
    const uri = await createIssuerOffer(page, {
      grant: "authorization_code",
      authorization: "presentation",
    });
    expect(uri).toContain("openid-credential-offer://");

    const redeemed = await postJSON("/api/offers", { uri });
    expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);
    expect(redeemed.body.credential_id).toBeTruthy();

    const log = await (await fetch(`${BASE}/api/log`)).json();
    const events = log.map((entry) => (entry.details || {}).event);
    expect(events).toContain("authorization_challenge_request");
    expect(events).toContain("interactive_authorization_presentation");
  });

  // A presentation requested during issuance belongs to the browser that started that
  // issuance.
  test("the presentation is put only to the visitor whose issuance it is", async ({ browser }) => {
    const driverContext = await browser.newContext();
    const otherContext = await browser.newContext();
    const driver = await driverContext.newPage();
    const bystander = await otherContext.newPage();

    const { body: offer } = await postJSON(
      "/issuer/api/offers?grant=authorization_code&authorization=presentation",
      {}
    );
    await bystander.goto(`${BASE}/`);
    await driver.goto(`${BASE}/`);

    await driver.fill("#offer-input", offer.scheme_uri);
    await driver.locator("#process-btn").click();
    await driver.waitForSelector("#consent-overlay.active", { timeout: 15_000 });
    await driver.locator("#consent-approve").click();

    await expect(driver.locator("#consent-dialog")).toContainText(/Presentation request/i, {
      timeout: 15_000,
    });

    await expect(bystander.locator("#consent-overlay.active")).toHaveCount(0);
    await expect(bystander.locator("#pending-banner")).toBeHidden();

    await driverContext.close();
    await otherContext.close();
  });

  // A phone drops open requests when the user switches apps. The issuance goes on in
  // the wallet and waits for the presentation.
  test("a lost issuance request keeps the presentation dialog open", async ({ browser }) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    const { body: offer } = await postJSON(
      "/issuer/api/offers?grant=authorization_code&authorization=presentation",
      {}
    );
    await page.goto(`${BASE}/`);
    await page.evaluate(() => {
      const send = window.fetch;
      window.fetch = (url, opts) => {
        if (!String(url).endsWith("/approve") || window.dropApproval) return send(url, opts);
        send(url, opts).catch(() => {});
        return new Promise((_, reject) => {
          window.dropApproval = () => reject(new TypeError("Load failed"));
        });
      };
    });

    await page.fill("#offer-input", offer.scheme_uri);
    await page.locator("#process-btn").click();
    await page.waitForSelector("#consent-overlay.active", { timeout: 15_000 });
    await page.locator("#consent-approve").click();
    await expect(page.locator("#consent-dialog")).toContainText(/Presentation request/i, {
      timeout: 15_000,
    });

    await page.evaluate(() => window.dropApproval());
    await expect(page.locator("#error-title")).toHaveCount(0);
    await expect(page.locator("#consent-dialog")).toContainText(/Presentation request/i);

    await page.locator("#consent-approve").click();
    await expect(
      page.locator("#credentials .credential-card", { hasText: "Demo Event Ticket" })
    ).toBeVisible({ timeout: 15_000 });
    const pending = await page.evaluate(async () => (await fetch("api/requests")).json());
    expect(pending).toEqual([]);

    await context.close();
  });

  test("an offer authorized by a sign-in asks for the browser instead", async ({ page }) => {
    const uri = await createIssuerOffer(page, {
      grant: "authorization_code",
      authorization: "browser",
    });

    // This wallet serves http, and auth_via_web needs an https redirect URI
    // (OpenID4VCI 1.1 §6.2.1.2). The issuer sends it to the browser with
    // redirect_to_web, which returns a sign-in URL too.
    const redeemed = await postJSON("/api/offers", { uri });
    expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(202);
    expect(redeemed.body.status).toBe("authorization_required");
    expect(redeemed.body.authorization_url).toContain("/issuer/authorize");

    const log = await (await fetch(`${BASE}/api/log`)).json();
    const events = log.map((entry) => (entry.details || {}).event);
    expect(events).toContain("interactive_authorization_redirect_to_web");
  });

  // The pushed request_uri can be used once (RFC 9126 §4). Fetching it before browser
  // sign-in would consume it.
  test("the credential arrives once the user signs in at the issuer", async ({ page }) => {
    const uri = await createIssuerOffer(page, {
      grant: "authorization_code",
      authorization: "browser",
    });

    const redeemed = await postJSON("/api/offers", { uri });
    expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(202);
    const { authorization_url: authURL, offer_id: offerID } = redeemed.body;

    await page.goto(authURL);
    await expect(page.locator('input[name="username"]')).toHaveValue("alice");
    await page.locator('button[type="submit"]').click();

    await expect
      .poll(
        async () => (await (await fetch(`${BASE}/api/offers/${offerID}`)).json()).status,
        { timeout: 15_000 }
      )
      .toBe("completed");

    const status = await (await fetch(`${BASE}/api/offers/${offerID}`)).json();
    expect(status.result.credential_id).toBeTruthy();
  });
});

test.describe("Verifier request types", () => {
  test("the PID format toggle follows what is being requested", async ({ page }) => {
    await page.goto(`${BASE}/verifier/`);
    await expect(page.locator("#format-row")).toBeHidden();

    await page.locator('#credential-toggle [data-credential="pid"]').click();
    await expect(page.locator("#format-row")).toBeVisible();

    await page.locator('#credential-toggle [data-credential="pid-de"]').click();
    await expect(page.locator("#format-row")).toBeVisible();
  });

  test("asking for the German PID as an mdoc is refused with the reason", async ({ page }) => {
    await page.goto(`${BASE}/verifier/`);
    await page.locator('#credential-toggle [data-credential="pid-de"]').click();
    await page.locator('#format-toggle [data-format="mdoc"]').click();
    await page.locator("#create-request").click();

    await expect(page.locator("#status, #checks").first()).toContainText(/no mdoc form/i);
  });

  test("the German PID button is answered by the German PID", async ({ page }) => {
    await page.goto(`${BASE}/verifier/`);
    await createVerifierRequest(page, "pid-de");
    await expect(page.locator("#status")).toHaveText(/Waiting/);

    const uri = await page.locator("#scheme-uri").textContent();
    const answered = await postJSON("/api/presentations", { uri });
    expect(answered.status).toBe(200);

    await expect(page.locator("#status")).toHaveText(/verified/i, { timeout: 15000 });
    await expect(page.locator("#claims")).toContainText("urn:eudi:pid:de:1");
  });

  test("denying in the wallet returns to the verifier page, which shows the refusal", async ({ page }) => {
    await page.goto(`${BASE}/verifier/`);
    await createVerifierRequest(page, "pid");
    await expect(page.locator("#wallet-link")).toHaveAttribute("href", /request_uri=/);
    await page.goto(await page.locator("#wallet-link").getAttribute("href"));
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);

    await denyAtVerifier(page);
    await expect(page.locator("#status")).toHaveAttribute("data-status", "declined", { timeout: 15000 });
    await expect(page.locator("#status")).toHaveText(/^✗ The wallet declined: access_denied/);
    await expect(page.locator("#credential-pid")).toHaveAttribute("aria-checked", "true");
  });

  test("a response with a ticket and a PID lists the checks of each credential", async ({ page }) => {
    const offer = await postJSON("/issuer/api/offers", {});
    expect((await postJSON("/api/offers", { uri: offer.body.scheme_uri })).status).toBe(200);
    await page.goto(`${BASE}/verifier/`);
    await createVerifierRequest(page, "pid-ticket");
    await expect(page.locator("#status")).toHaveText(/Waiting/);
    const uri = await page.locator("#scheme-uri").textContent();
    expect((await postJSON("/api/presentations", { uri })).status).toBe(200);

    await expect(page.locator("#status")).toHaveAttribute("data-status", "verified", { timeout: 15000 });
    await page.locator("#checks-passed-summary").click();
    const groups = page.locator("#checks-passed .check-group");
    expect(await groups.count()).toBeGreaterThanOrEqual(3);
    await expect(groups.first()).toHaveText("Response");
    await expect(groups.filter({ hasText: /^ticket$/ })).toHaveCount(1);
    await expect(page.locator("#checks-passed .check-item", { hasText: /^. ticket: / })).toHaveCount(0);
    // Polling continues while the request is open. The passed checks stay open.
    await page.waitForTimeout(4000);
    await expect(page.locator("#checks-passed")).toHaveAttribute("open", "");
  });

  test("the redirect shows the requested credential and folds the passed checks", async ({ page }) => {
    await page.goto(`${BASE}/verifier/`);
    await createVerifierRequest(page, "pid-de");
    await expect(page.locator("#status")).toHaveText(/Waiting/);
    const uri = await page.locator("#scheme-uri").textContent();
    const answered = await postJSON("/api/presentations", { uri });
    expect(answered.body.redirect_uri).toContain("response_code=");

    await page.goto(answered.body.redirect_uri);
    await expect(page.locator("#status")).toHaveText(/^✓ Presentation verified, \d+ checks passed/, { timeout: 15000 });
    await expect(page.locator("#credential-pid-de")).toHaveAttribute("aria-checked", "true");
    await expect(page.locator("#format-row")).toBeVisible();
    await expect(page.locator("#checks-passed")).not.toHaveAttribute("open", "");
    await expect(page.locator("#checks-passed .check-item").first()).toBeHidden();
  });
});

test.describe("Protected baseline credentials", () => {
  // Earlier test credentials are removed, so the four protected PIDs fit on the first page.
  test.beforeEach(async () => {
    await fetch(`${BASE}/api/credentials`, { method: "DELETE" });
  });

  test("the seeded PIDs are marked and offer no destructive actions", async ({
    page,
  }) => {
    await page.goto(BASE);
    const cards = page.locator(".credential-card[data-protected='true']");
    await expect(cards).toHaveCount(4, { timeout: 5000 });

    const first = cards.first();
    await expect(first.locator(".status-protected")).toHaveText("Protected");
    await expect(first.locator(".status-protected")).toHaveAttribute(
      "title",
      /Can't be deleted or revoked/
    );
    await expect(first.locator("[data-delete]")).toHaveCount(0);
    await expect(first.locator("[data-revoke]")).toHaveCount(0);
  });

  test("the two mdoc PIDs are told apart by their short id", async ({
    page,
  }) => {
    await page.goto(BASE);
    const mdocCards = page.locator(".credential-card[data-format='mdoc']");
    await expect(mdocCards).toHaveCount(2, { timeout: 5000 });

    // Both mdoc PIDs have the same doctype. Their short IDs distinguish the cards.
    const firstId = await mdocCards.nth(0).locator(".cred-shortid").textContent();
    const secondId = await mdocCards.nth(1).locator(".cred-shortid").textContent();
    expect(firstId).toMatch(/^#[0-9a-f]{8}$/);
    expect(secondId).toMatch(/^#[0-9a-f]{8}$/);
    expect(firstId).not.toBe(secondId);
  });

  test("the API refuses to delete or revoke them", async () => {
    const res = await fetch(`${BASE}/api/credentials`);
    const creds = await res.json();
    const guarded = creds.find((c) => c.protected);
    expect(guarded, "expected a protected baseline credential").toBeTruthy();

    const del = await fetch(`${BASE}/api/credentials/${guarded.id}`, { method: "DELETE" });
    expect(del.status).toBe(403);

    const revoke = await fetch(`${BASE}/api/credentials/${guarded.id}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: 1 }),
    });
    expect(revoke.status).toBe(403);

    const after = await (await fetch(`${BASE}/api/credentials/${guarded.id}`)).json();
    expect(after.protected).toBe(true);
    expect(after.status.status).toBe(0);
  });

  test("issued credentials remain deletable and clearing keeps the baseline", async ({
    page,
  }) => {
    const issued = await postJSON("/api/issue", { format: "sdjwt", vct: "urn:example:e2e" });
    expect(issued.status).toBe(201);
    expect(issued.body.protected).toBeUndefined();

    await page.goto(BASE);
    const card = page.locator(`#credential-${issued.body.id}`);
    await expect(card).toBeVisible({ timeout: 5000 });
    await expect(card.locator("[data-delete]")).toHaveCount(1);

    const cleared = await fetch(`${BASE}/api/credentials`, { method: "DELETE" });
    expect((await cleared.json()).kept_protected).toBe(4);

    const remaining = await (await fetch(`${BASE}/api/credentials`)).json();
    expect(remaining).toHaveLength(4);
    expect(remaining.every((c) => c.protected)).toBe(true);
  });
});

test.describe("Credential paging", () => {
  test("pages through a long credential list", async ({ page }) => {
    await fetch(`${BASE}/api/credentials`, { method: "DELETE" });
    for (let i = 0; i < 21; i++) {
      await postJSON("/api/issue", { format: "sdjwt", vct: `urn:example:page-${i}` });
    }

    await page.goto(BASE);
    const range = page.locator("#cred-range");
    await expect(page.locator(".credential-card")).toHaveCount(10, { timeout: 5000 });
    await expect(range).toHaveText("1–10 of 25");
    await expect(page.locator("#cred-prev")).toBeDisabled();

    await page.locator("#cred-next").click();
    await expect(range).toHaveText("11–20 of 25");
    await expect(page.locator(".credential-card")).toHaveCount(10);

    await page.locator("#cred-next").click();
    await expect(range).toHaveText("21–25 of 25");
    await expect(page.locator(".credential-card")).toHaveCount(5);
    await expect(page.locator("#cred-next")).toBeDisabled();

    await page.locator("#cred-prev").click();
    await expect(range).toHaveText("11–20 of 25");

    await fetch(`${BASE}/api/credentials`, { method: "DELETE" });
  });

  test("the pager stays hidden when everything fits on one page", async ({ page }) => {
    await fetch(`${BASE}/api/credentials`, { method: "DELETE" });
    await page.goto(BASE);
    await expect(page.locator(".credential-card")).toHaveCount(4, { timeout: 5000 });
    await expect(page.locator("#cred-pager")).toBeHidden();
  });
});

test.describe("Consent credential selection", () => {
  test.beforeEach(async () => {
    await clearPending();
  });

  async function openConsent(page) {
    const req = await createVerificationRequest();
    const owner = await openAsSchemeHandler(page);
    submitAsSchemeHandler("/api/presentations", req.schemeURI, owner);
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
    return req;
  }

  async function verifierStatus(id) {
    return (await verifierResult(id)).status;
  }

  test("the main screen shows the auto-selection and announces the alternatives", async ({ page }) => {
    await openConsent(page);

    const row = page.locator("#consent-selection-row");
    await expect(row).toContainText("Auto-selected");
    await expect(page.locator("#consent-edit-selection")).toBeVisible();
    await expect(page.locator(".consent-credential")).toHaveCount(1);
    await expect(page.locator(".consent-claim input[type=checkbox]").first()).toBeChecked();

    await denyAtVerifier(page);
  });

  test("the edit screen offers the set options and the candidates per query", async ({ page }) => {
    await openConsent(page);
    await page.locator("#consent-edit-selection").click();

    const setOptions = page.locator(".consent-sets .consent-set-option");
    await expect(setOptions).toHaveCount(2);
    await expect(page.locator(".consent-sets .auto-chip")).toHaveCount(1);
    await expect(page.locator(".consent-credential[data-query-id] .candidate")).toHaveCount(2);
    await expect(page.locator("#consent-approve")).toBeVisible();

    await denyAtVerifier(page);
  });

  test("switching the set option presents the other format", async ({ page }) => {
    const req = await openConsent(page);
    await expect(page.locator(".consent-credential").first()).toHaveAttribute("data-vct", /./);

    await page.locator("#consent-edit-selection").click();
    await page.locator("#consent-set-0-option-1").check();
    await expect(page.locator(".consent-credential[data-query-id]").first()).toHaveAttribute("data-query-id", "pid_mdoc");
    await page.locator("#consent-selection-done").click();

    await expect(page.locator(".consent-credential").first()).toHaveAttribute("data-doctype", /./);
    await expect(page.locator("#consent-selection-row")).toContainText("Your selection");

    await page.locator("#consent-approve").click();
    // Verifier navigation confirms that approval completed.
    await expect(page).toHaveURL(/\/verifier\/\?response_code=/, { timeout: 15_000 });
    const result = await verifierResult(req.id);
    expect(result.status).toBe("verified");
    expect(result.checks.map((c) => c.name)).toContain("presentation parses as an mdoc DeviceResponse");
  });

  test("switching the credential presents the other PID", async ({ page }) => {
    const req = await openConsent(page);
    const before = await page.locator(".consent-credential").first().getAttribute("data-vct");

    await page.locator("#consent-edit-selection").click();
    await page.locator(".candidate:not(.selected)").first().click();
    await page.locator("#consent-selection-done").click();

    const after = await page.locator(".consent-credential").first().getAttribute("data-vct");
    expect(after).not.toBe(before);
    await expect(page.locator(".consent-claim input[type=checkbox]").first()).toBeChecked();

    await page.locator("#consent-approve").click();
    await expect(page).toHaveURL(/\/verifier\/\?response_code=/, { timeout: 15_000 });
    const result = await verifierResult(req.id);
    expect(result.status).toBe("verified");
    expect(result.claims.vct).toBe(after);
  });

  test("withholding a requested claim reaches the verifier as its absence", async ({ page }) => {
    const req = await openConsent(page);

    await page.locator('.consent-claim input[data-claim="given_name"]').uncheck();
    await page.locator("#consent-approve").click();
    await expect(page).toHaveURL(/\/verifier\/\?response_code=/, { timeout: 15_000 });

    const result = await verifierResult(req.id);
    expect(result.status).toBe("failed");
    expect((result.claims || {}).given_name).toBeFalsy();
    expect(result.checks.filter((c) => !c.ok).length).toBeGreaterThan(0);
  });

  test("edit, done and edit again keeps the selection, reset restores auto", async ({ page }) => {
    await openConsent(page);

    await page.locator("#consent-edit-selection").click();
    const alternate = page.locator(".candidate:not(.selected)").first();
    const alternateID = await alternate.getAttribute("data-cred");
    await alternate.click();
    await page.locator("#consent-selection-done").click();
    await page.locator("#consent-edit-selection").click();

    await expect(page.locator(`.candidate[data-cred="${alternateID}"]`)).toHaveClass(/selected/);

    await page.locator("#consent-selection-reset").click();
    await expect(page.locator(`.candidate[data-cred="${alternateID}"]`)).not.toHaveClass(/selected/);
    await expect(page.locator("#consent-selection-reset")).toHaveCount(0);

    await denyAtVerifier(page);
  });

  async function ensureTicket() {
    const creds = await (await fetch(`${BASE}/api/credentials`)).json();
    if (creds.some((c) => (c.claims || {}).vct === "urn:eudi-test:demo-ticket:1")) return;
    const { body: offer } = await postJSON("/issuer/api/offers", {});
    await postJSON("/api/offers", { uri: offer.scheme_uri });
  }

  async function openPreparedConsent(page, requestBody) {
    const { body } = await postJSON("/verifier/api/requests", requestBody);
    const owner = await openAsSchemeHandler(page);
    submitAsSchemeHandler("/api/presentations", body.scheme_uri, owner);
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
    return { id: body.transaction_id };
  }

  test("an optional ticket set is answered by default and skippable", async ({ page }) => {
    await ensureTicket();
    const req = await openPreparedConsent(page, { type: "pid", ticket: "optional" });

    await expect(page.locator(".consent-credential")).toHaveCount(2);
    await expect(page.locator('.consent-credential[data-vct="urn:eudi-test:demo-ticket:1"]')).toBeVisible();

    await page.locator("#consent-edit-selection").click();
    await expect(page.locator(".consent-sets")).toHaveCount(2);
    await page.locator("#consent-set-1-none").check();
    await expect(page.locator(".consent-credential[data-query-id]")).toHaveCount(1);
    await page.locator("#consent-selection-done").click();

    await expect(page.locator(".consent-credential")).toHaveCount(1);
    await page.locator("#consent-approve").click();
    await expect(page).toHaveURL(/\/verifier\/\?response_code=/, { timeout: 15_000 });
    const result = await verifierResult(req.id);
    expect(result.status).toBe("verified");
    expect((result.claims || {}).ticket).toBeFalsy();
    expect(result.checks.map((c) => c.name)).toContain("ticket: not presented (optional)");
  });

  test("the ticket travels next to the PID and verifies", async ({ page }) => {
    await ensureTicket();
    const req = await openPreparedConsent(page, { type: "pid", ticket: "optional" });

    await page.locator("#consent-approve").click();
    await expect(page).toHaveURL(/\/verifier\/\?response_code=/, { timeout: 15_000 });
    const result = await verifierResult(req.id);
    expect(result.status).toBe("verified");
    expect(result.claims.ticket.event).toBe("EUDI Interop Fest");
    expect(result.checks.map((c) => c.name)).toContain("ticket: signature");
  });

  test("a combined option presents PID and ticket together or the PID alone", async ({ page }) => {
    await ensureTicket();
    const req = await openPreparedConsent(page, { type: "pid", ticket: "combined" });

    await expect(page.locator(".consent-credential")).toHaveCount(2);

    await page.locator("#consent-edit-selection").click();
    await expect(page.locator(".consent-sets")).toHaveCount(1);
    await expect(page.locator(".consent-set-option").first()).toContainText("ticket");
    await page.locator("#consent-set-0-option-1").check();
    await page.locator("#consent-selection-done").click();

    await expect(page.locator(".consent-credential")).toHaveCount(1);
    await page.locator("#consent-approve").click();
    await expect(page).toHaveURL(/\/verifier\/\?response_code=/, { timeout: 15_000 });
    const result = await verifierResult(req.id);
    expect(result.status).toBe("verified");
    expect((result.claims || {}).ticket).toBeFalsy();
  });

  test("a multiple PID next to an optional ticket set sends every PID and can withhold both", async ({ page }) => {
    await ensureTicket();
    const req = await openPreparedConsent(page, { type: "pid", format: "sd-jwt", ticket: "optional", multiple: true });

    // The PIDs are not alternatives. Only the optional ticket set is.
    await expect(page.locator("#consent-selection-row")).toContainText("1 alternative");
    const note = page.locator("#consent-multiple-pid");
    await expect(note).toContainText(/The wallet sends (\d+) of \1 matching credentials/);
    const pidCards = page.locator('#consent-dialog .consent-credential[data-credential-id]:not([data-vct="urn:eudi-test:demo-ticket:1"])');
    const sentPIDs = await pidCards.count();
    expect(sentPIDs).toBeGreaterThanOrEqual(2);

    await page.locator("#consent-edit-selection").click();
    const candidates = page.locator('#consent-query-pid .candidate[role="checkbox"]');
    await expect(candidates).toHaveCount(sentPIDs);
    await expect(page.locator("#consent-query-pid .auto-chip")).toHaveCount(sentPIDs);
    for (let i = 1; i < sentPIDs; i++) await candidates.nth(i).click();
    await page.locator("#consent-set-1-none").check();
    await page.locator("#consent-selection-done").click();
    await expect(note).toContainText(`The wallet sends 1 of ${sentPIDs}`);

    await page.locator("#consent-approve").click();
    await expect(page).toHaveURL(/\/verifier\/\?response_code=/, { timeout: 15_000 });
    const result = await verifierResult(req.id);
    expect(result.status).toBe("verified");
    expect(result.claims.pid).toHaveLength(1);
    expect(result.claims.ticket).toBeFalsy();
  });

  test("a combined multiple request sends every PID together with the ticket", async ({ page }) => {
    await ensureTicket();
    const req = await openPreparedConsent(page, { type: "pid", format: "sd-jwt", ticket: "combined", multiple: true });
    const sent = await page.locator("#consent-dialog .consent-credential[data-credential-id]").count();

    await page.locator("#consent-approve").click();
    await expect(page).toHaveURL(/\/verifier\/\?response_code=/, { timeout: 15_000 });
    const result = await verifierResult(req.id);
    expect(result.status).toBe("verified");
    expect(result.claims.pid.length + result.claims.ticket.length).toBe(sent);
    expect(result.claims.pid.length).toBeGreaterThanOrEqual(2);
    expect(result.claims.ticket[0].event).toBe("EUDI Interop Fest");
  });

  // ADR-0015: the pages lay out at phone width. A multiple result lists several claim
  // sets. They must wrap inside the card.
  test("the verifier page and a multiple result fit at phone width", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 800 });
    const req = await openPreparedConsent(page, { type: "pid", format: "sd-jwt", multiple: true });
    await page.locator("#consent-approve").click();
    await expect(page).toHaveURL(/\/verifier\/\?response_code=/, { timeout: 15_000 });
    await expect(page.locator("#claims")).toBeVisible();
    expect((await verifierResult(req.id)).claims.pid.length).toBeGreaterThanOrEqual(2);

    const overflow = () => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(await overflow()).toBeLessThanOrEqual(0);
    await page.locator('#credential-toggle [data-credential="pid-ticket"]').click();
    expect(await overflow()).toBeLessThanOrEqual(0);
  });

  test("the verifier page asks for the ticket next to the PID and for multiple", async ({ page }) => {
    await page.goto(`${BASE}/verifier/`);
    await page.locator('#credential-toggle [data-credential="pid-ticket"]').click();
    await expect(page.locator("#ticket-row")).toBeVisible();
    await page.locator('#ticket-toggle [data-ticket="optional"]').click();
    await page.locator("#request-multiple").check();
    const [resp] = await Promise.all([
      page.waitForResponse((r) => r.url().endsWith("/verifier/api/requests") && r.request().method() === "POST"),
      page.locator("#create-request").click(),
    ]);
    expect(JSON.parse(resp.request().postData())).toMatchObject({ type: "pid", ticket: "optional", multiple: true });
    expect(resp.ok()).toBe(true);

    await page.locator('#credential-toggle [data-credential="custom"]').click();
    await expect(page.locator("#multiple-row")).toBeHidden();
  });

  test("approving straight from the edit screen submits the drafted selection", async ({ page }) => {
    const req = await openConsent(page);

    await page.locator("#consent-edit-selection").click();
    await page.locator(".candidate:not(.selected)").first().click();
    await page.locator("#consent-approve").click();
    // Reopening Edit during submission must not create another enabled Approve button.
    await page.locator("#consent-selection-done").click({ timeout: 2000 }).catch(() => {});

    await expect(page).toHaveURL(/\/verifier\/\?response_code=/, { timeout: 15_000 });
    expect(await verifierStatus(req.id)).toBe("verified");
  });
});

test.describe("Multi-tab dialogs", () => {
  test("a request answered in one tab closes its dialog in the other", async ({
    browser,
  }) => {
    const req = await createVerificationRequest();
    const owner = "multitab-" + Math.random().toString(36).slice(2);
    const ctx = await browser.newContext();
    try {
      const tab1 = await ctx.newPage();
      const tab2 = await ctx.newPage();
      await tab1.goto(`${BASE}/?focus=overview&owner=${owner}`);
      await tab2.goto(`${BASE}/?focus=overview&owner=${owner}`);
      // Both event streams must connect before the request arrives.
      for (const tab of [tab1, tab2]) {
        await expect(tab.locator("body")).toHaveAttribute("data-request-stream", "open");
      }
      submitAsSchemeHandler("/api/presentations", req.schemeURI, owner);
      await expect(tab1.locator("#consent-overlay")).toHaveClass(/active/);
      await expect(tab2.locator("#consent-overlay")).toHaveClass(/active/);

      await denyAtVerifier(tab1);
      await expect(tab2.locator("#consent-overlay")).not.toHaveClass(/active/);
    } finally {
      await ctx.close();
    }
  });

  // The submitting tab stays open until it receives the result. Other tabs close
  // their stale dialogs.
  test("approving in one tab completes while the other tab's dialog closes", async ({
    browser,
  }) => {
    const req = await createVerificationRequest();
    const owner = "multitab-approve-" + Math.random().toString(36).slice(2);
    const ctx = await browser.newContext();
    try {
      const acting = await ctx.newPage();
      const stale = await ctx.newPage();
      await acting.goto(`${BASE}/?focus=overview&owner=${owner}`);
      await stale.goto(`${BASE}/?focus=overview&owner=${owner}`);
      for (const tab of [acting, stale]) {
        await expect(tab.locator("body")).toHaveAttribute("data-request-stream", "open");
      }
      submitAsSchemeHandler("/api/presentations", req.schemeURI, owner);
      await expect(acting.locator("#consent-overlay")).toHaveClass(/active/);
      await expect(stale.locator("#consent-overlay")).toHaveClass(/active/);

      await acting.locator("#consent-approve").click();
      await expect(stale.locator("#consent-overlay")).not.toHaveClass(/active/);
      await expect
        .poll(async () => {
          const res = await fetch(`${BASE}/verifier/api/requests/${req.id}`);
          return (await res.json()).status;
        }, { timeout: 15_000 })
        .toBe("verified");
    } finally {
      await ctx.close();
    }
  });
});

// The page's clock is installed, so a test moves time forward instead of
// sleeping.
test.describe("Verifier polling", () => {
  test.beforeEach(async ({ page }) => {
    await page.clock.install();
  });

  function countPolls(page) {
    const open = new Set();
    const state = {
      n: 0,
      get open() {
        return open.size;
      },
    };
    page.on("request", (req) => {
      if (!req.url().includes("/verifier/api/requests/")) return;
      state.n++;
      open.add(req);
    });
    const done = (req) => open.delete(req);
    page.on("requestfinished", done);
    page.on("requestfailed", done);
    return state;
  }

  // advance moves the clock in steps and lets each poll finish, so the page
  // schedules the next poll from its answer as it does in real time.
  async function advance(page, polls, ms) {
    for (let elapsed = 0; elapsed < ms; elapsed += 250) {
      await page.clock.runFor(250);
      await expect.poll(() => polls.open).toBe(0);
    }
  }

  test("an unknown or expired request stops the polling", async ({ page }) => {
    await page.goto(`${BASE}/verifier/?response_code=00000000000000000000000000000000`);
    await expect(page.locator("#status")).toHaveText(/expired/, { timeout: 10_000 });

    const polls = countPolls(page);
    await advance(page, polls, 20_000);
    expect(polls.n, "no further polls after the request is gone").toBe(0);
  });

  test("a hidden tab does not poll", async ({ page }) => {
    await page.goto(`${BASE}/verifier/`);
    await createVerifierRequest(page, "pid");
    await expect(page.locator("#status")).toHaveText(/Waiting/);

    // Chromium cannot background a page on command, so the test fakes document visibility.
    await page.evaluate(() => {
      Object.defineProperty(document, "hidden", { get: () => true });
      document.dispatchEvent(new Event("visibilitychange"));
    });

    const polls = countPolls(page);
    await advance(page, polls, 20_000);
    expect(polls.n, "a hidden tab must not keep polling").toBe(0);
  });

  test("a late answer for an older request does not take over the polling", async ({ page }) => {
    await page.goto(`${BASE}/verifier/`);
    let releaseFirst;
    const firstHeld = new Promise((resolve) => (releaseFirst = resolve));
    let firstID = null;
    await page.route("**/verifier/api/requests/*", async (route) => {
      if (firstID === null) {
        firstID = route.request().url().split("/").pop();
        await firstHeld;
      }
      await route.continue();
    });
    await createVerifierRequest(page, "pid");
    await expect.poll(() => firstID).not.toBeNull();
    const secondPolled = page.waitForResponse(
      (resp) => resp.url().includes("/verifier/api/requests/") && !resp.url().endsWith("/" + firstID)
    );
    await createVerifierRequest(page, "pid");
    await secondPolled;

    const stalePolls = [];
    page.on("request", (req) => {
      if (req.url().endsWith("/verifier/api/requests/" + firstID)) stalePolls.push(req.url());
    });
    const firstAnswered = page.waitForResponse((resp) => resp.url().endsWith("/verifier/api/requests/" + firstID));
    releaseFirst();
    await firstAnswered;
    await advance(page, countPolls(page), 20_000);
    expect(stalePolls, "the older request must not be polled again").toEqual([]);
  });

  test("a visible tab backs off instead of hammering", async ({ page }) => {
    await page.goto(`${BASE}/verifier/`);
    const polls = countPolls(page);
    await createVerifierRequest(page, "pid");
    await expect(page.locator("#status")).toHaveText(/Waiting/);

    await advance(page, polls, 10_000);
    expect(polls.n, `polls in 10s: ${polls.n}`).toBeLessThanOrEqual(5);
    expect(polls.n, "but it must still be polling").toBeGreaterThan(0);
  });
});

test.describe("Conformance", () => {
  test("the dialog reports what a demo instance checks", async ({ page }) => {
    await page.goto(BASE);
    await page.locator("#conformance-link").click();
    await expect(page.locator("#conformance-overlay")).toHaveClass(/active/);

    await expect(page.locator("#conf-mode-select")).toHaveValue("debug");
    await expect(page.locator("#conf-haip-input")).toBeChecked();
    await expect(page.locator("#conf-arf-input")).toBeChecked();
    await expect(page.locator("#conf-encrypted-input")).not.toBeChecked();
    await expect(page.locator("#conf-transcript")).toHaveText("OpenID4VP");
    await expect(page.locator("#conf-mode-hint")).toHaveText("Warn and continue");

    await page.locator("#conformance-close").click();
    await expect(page.locator("#conformance-overlay")).not.toHaveClass(/active/);
  });

  // Go tests cover debug mode acceptance of HAIP violations.
});

test.describe("Demo mode hardening", () => {
  test("images, predefined templates and process control stay locked", async () => {
    const blocked = [
      ["PUT", "/api/templates/pid-sdjwt", { format: "sdjwt", claims: {} }],
      ["DELETE", "/api/templates/pid-sdjwt", null],
      ["PUT", "/api/templates/e2e-image", { format: "sdjwt", claims: {}, display: { logo: "data:image/png;base64,iVBORw0KGgo=" } }],
      ["POST", "/api/shutdown", null],
      ["POST", "/api/next-error", { error: "access_denied" }],
      ["PUT", "/api/config/preferred-format", { preferred_format: "dc+sd-jwt" }],
      ["PUT", "/api/config/conformance", { validation_mode: "debug" }],
      ["DELETE", "/api/config/conformance", null],
      ["POST", "/api/issue", { format: "sdjwt", vct: "urn:eudi:pid:1", status_list_uri: "", display: { background_image: "data:image/png;base64,iVBORw0KGgo=" } }],
      ["POST", "/api/issue", { format: "sdjwt", vct: "urn:eudi:pid:1", status_list_uri: "", display: { logo: "data:image/png;base64,iVBORw0KGgo=" } }],
    ];
    for (const [method, pathname, body] of blocked) {
      const res = await fetch(BASE + pathname, {
        method,
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
      expect(res.status, `${method} ${pathname}`).toBe(403);
    }
  });

  test("the UI hides what demo mode does not offer", async ({ page }) => {
    await page.goto(BASE);
    await expect(page.locator("#templates-link")).toBeVisible();
    await expect(page.locator("#tls-cert-pem-link")).toBeHidden();
    await expect(page.locator("#clear-log-btn")).toBeHidden();
    await expect(page.locator("#decoder-link")).toBeVisible();
    await expect(page.locator("#demo-banner")).toBeVisible();
    await expect(page.locator("#auto-accept-toggle")).toBeHidden();
    await page.locator("#issue-btn").click();
    await expect(page.locator("#issue-display-name")).toBeVisible();
    await expect(page.locator("#issue-logo")).toBeHidden();
    await expect(page.locator("#issue-bg-image")).toBeHidden();
    await expect(page.locator("#issue-save-template")).toBeVisible();
  });

  test("a visitor saves a template and adds it to the catalogue", async ({ page }) => {
    // Unique names keep a retry clear of the entries of an earlier attempt.
    const id = "e2e-visitor-" + Date.now();
    await page.goto(BASE);
    await page.locator("#templates-link").click();
    await expect(page.locator("#template-delete-pid-sdjwt")).toHaveCount(0);
    await page.locator("#template-new").click();
    await page.locator("#template-editor-name").fill(id);
    await page.locator("#issue-vct").fill(`urn:example:${id}:1`);
    await page.locator('#issue-claim-rows input[id^="issue-claim-key-"]').first().fill("level");
    await page.locator('#issue-claim-rows input[id^="issue-claim-value-"]').first().fill("gold");
    await expect(page.locator("#issue-batch")).toBeHidden();
    await page.locator("#issue-catalog").check();
    await page.locator("#issue-catalog-name").fill(`E2E visitor card ${id}`);
    await page.locator("#issue-catalog-rulebook").fill("not a url");
    await page.locator("#issue-submit").click();
    await expect(page.locator("#issue-error")).toContainText("http or https URL");
    await page.locator("#issue-catalog-rulebook").fill("");
    await page.locator("#issue-submit").click();
    await expect(page.locator(`#template-row-${id}`)).toBeVisible();
    await expect(page.locator(`#template-delete-${id}`)).toBeVisible();
    const entries = await (await fetch(BASE + "/api/catalog/attestations")).json();
    expect(entries.map((e) => e.name)).toContain(`E2E visitor card ${id}`);
    await page.locator(`#template-delete-${id}`).click();
    await expect(page.locator(`#template-row-${id}`)).toHaveCount(0);
  });

  test("visitors can't change the demo registrations or the predefined catalogue entries", async ({ page }) => {
    const name = "E2E visitor diploma " + Date.now();
    const added = await (await fetch(BASE + "/api/catalog/attestations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, credentials: [{ format: "dc+sd-jwt", type: `urn:example:${Date.now()}:1` }] }),
    })).json();
    expect(added.schema.id).toBeTruthy();
    await page.goto(BASE);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();
    await page.locator("#registrar-search").fill("EUDI Dev Demo Verifier");
    const card = "#registrar-party-NLTEST_00000001";
    await expect(page.locator(card + "-protected")).toHaveText("Protected");
    await expect(page.locator(card + "-delete")).toHaveCount(0);
    await expect(page.locator(card + "-add-use")).toHaveCount(0);
    await expect(page.locator(card + ' [id$="-summary-delete"]')).toHaveCount(0);
    await page.locator(card + ' [id$="-details"]').first().click();
    await expect(page.locator('#registrar-cert-body [id$="-verifier-info"]')).toHaveValue(/registration_cert/);
    await expect(page.locator("#registrar-cert-body button")).toHaveCount(1); // the copy button
    await page.locator("#registrar-cert-close").click();
    // Issuing an access certificate doesn't change the registration, so
    // visitors may get one.
    await page.locator(card + ' [id$="-access"]').first().click();
    await page.locator("#registrar-submit").click();
    await expect(page.locator("#registrar-submit")).toHaveText("✓ Issued");
    await expect(page.locator("#registrar-pem")).toHaveValue(/BEGIN CERTIFICATE/);
    await page.locator("#registrar-close").click();
    await page.locator("#registrar-parties-close").click();

    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-catalog-link").click();
    const entry = (n) => page.locator("#registrar-catalog-list .registrar-party").filter({ hasText: n });
    await expect(entry("EUDI PID").locator('[id$="-delete"]')).toHaveCount(0);
    await entry(name).locator('[id$="-delete"]').click();
    await expect(entry(name)).toHaveCount(0);
  });

  test("the decoder links back to the wallet it is mounted on", async ({ page }) => {
    await page.goto(BASE + "/decoder/");
    const walletLink = page.locator("#wallet-link");
    await expect(walletLink).toBeVisible();
    await expect(walletLink).toHaveText("Wallet");
    await walletLink.click();
    await expect(page.locator("#decoder-link")).toBeVisible();
  });
});

test.describe("Custom verifier request builder", () => {
  test.beforeEach(async () => {
    // Earlier tests leave a lot of wallet state. Presentation and redirect are slow on
    // loaded CI runners.
    test.setTimeout(180_000);
    await clearPending();
  });

  async function buildCustom(page, nationalitiesPath, { multiple = false } = {}) {
    await page.goto(`${BASE}/verifier/`);
    await page.locator('#credential-toggle [data-credential="custom"]').click();
    await expect(page.locator("#custom-panel")).toBeVisible();
    if (nationalitiesPath) {
      await page.locator(".claim-input").nth(1).fill(nationalitiesPath);
    }
    if (multiple) {
      await page.locator("#credentials-list .multiple-input").first().check();
    }
    const [resp] = await Promise.all([
      page.waitForResponse(
        (r) => r.url().endsWith("/verifier/api/requests") && r.request().method() === "POST"
      ),
      page.locator("#create-request").click(),
    ]);
    const body = await resp.json();
    const schemeURI = (await page.locator("#scheme-uri").textContent()) || "";
    return { id: body.transaction_id, walletURL: body.wallet_url, schemeURI };
  }

  async function present(page, schemeURI) {
    const owner = await openAsSchemeHandler(page);
    submitAsSchemeHandler("/api/presentations", schemeURI, owner);
    // The pending submission must reach the wallet before its dialog can open.
    await waitForPending(1, owner);
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/, { timeout: 45_000 });
  }

  test("a bare array path discloses an empty array and the consent warns", async ({ page }) => {
    const { id, schemeURI } = await buildCustom(page);

    await present(page, schemeURI);
    const natRow = page.locator("#consent-dialog .consent-claim", { hasText: "nationalities" });
    await expect(natRow.locator(".consent-claim-value")).toContainText("[]");
    await expect(natRow.locator(".consent-claim-hint")).toBeVisible();
    await expect(natRow.locator(".consent-claim-hint")).toContainText(/empty array/i);
    await expect(natRow.locator('input[type="checkbox"]')).toBeChecked();

    await page.locator("#consent-approve").click();
    await expect(page).toHaveURL(/\/verifier\/\?response_code=/, { timeout: 45_000 });

    const result = await verifierResult(id);
    expect(result.status).toBe("verified");
    expect(result.claims.cred_0.nationalities).toEqual([]);
  });

  // OpenID4VP 1.0 §6.4.1: the JSON editor sends claim_sets. The verifier accepts
  // the claim set the user picks in the wallet.
  test("a written query with claim sets accepts the claim set the user picks", async ({ page }) => {
    await page.goto(`${BASE}/verifier/`);
    await page.locator('#credential-toggle [data-credential="custom"]').click();
    await page.locator("#query-mode-json").click();
    const editor = page.locator("#dcql-json");
    await expect(editor).toHaveValue(/"cred_0"/);
    await expect(page.locator("#query-builder")).toBeHidden();
    await editor.fill(JSON.stringify({
      credentials: [{
        id: "pid",
        format: "dc+sd-jwt",
        meta: { vct_values: ["urn:eudi:pid:1"] },
        claims: [
          { id: "a", path: ["given_name"] },
          { id: "b", path: ["family_name"] },
          { id: "c", path: ["birthdate"] },
        ],
        claim_sets: [["a", "b"], ["a", "c"]],
      }],
    }));
    const [resp] = await Promise.all([
      page.waitForResponse((r) => r.url().endsWith("/verifier/api/requests") && r.request().method() === "POST"),
      page.locator("#create-request").click(),
    ]);
    const { transaction_id: id } = await resp.json();
    const schemeURI = (await page.locator("#scheme-uri").textContent()) || "";

    await present(page, schemeURI);
    await page.locator("#consent-show-claim-sets-pid").click();
    await page.locator("#consent-claim-set-pid-1").check();
    await page.locator("#consent-approve").click();
    await expect(page).toHaveURL(/\/verifier\/\?response_code=/, { timeout: 45_000 });

    const result = await verifierResult(id);
    expect(result.status).toBe("verified");
    expect(result.checks.map((c) => c.name)).toContain("pid: claim set 2 of 2 was disclosed (a, c)");
  });

  // The builder writes claim_sets and credential_sets, and the wallet answers
  // them.
  test("the builder sends claim sets and credential sets", async ({ page }) => {
    await page.goto(`${BASE}/verifier/`);
    await page.locator('#credential-toggle [data-credential="custom"]').click();
    const first = "#credentials-list-0";
    await page.locator(`${first}-claim-1-input`).fill("family_name");
    await page.locator(`${first}-add-claim`).click();
    await page.locator(`${first}-claim-2-input`).fill("birthdate");
    await page.locator(`${first}-add-claim-set`).click();
    await page.locator(`${first}-claim-set-0-${first.slice(1)}-claim-0`).check();
    await page.locator(`${first}-claim-set-0-${first.slice(1)}-claim-1`).check();
    await page.locator(`${first}-add-claim-set`).click();
    await page.locator(`${first}-claim-set-1-${first.slice(1)}-claim-0`).check();
    await page.locator(`${first}-claim-set-1-${first.slice(1)}-claim-2`).check();

    await page.locator("#add-credential").click();
    await page.locator("#credentials-list-1-format-mso-mdoc").click();
    await page.locator("#credentials-list-1-type").fill("eu.europa.ec.eudi.pid.1");
    await page.locator("#credentials-list-1-claim-0-input").fill("given_name");
    await page.locator("#add-credential-set").click();
    await page.locator("#credential-sets-0-option-0-credentials-list-0").check();
    await page.locator("#credential-sets-0-add-option").click();
    await page.locator("#credential-sets-0-option-1-credentials-list-1").check();

    await page.locator("#query-mode-json").click();
    const query = JSON.parse(await page.locator("#dcql-json").inputValue());
    expect(query.credentials[0].claim_sets).toEqual([["given_name", "family_name"], ["given_name", "birthdate"]]);
    expect(query.credential_sets).toEqual([{ options: [["cred_0"], ["cred_1"]] }]);
    expect(query.credentials[1].claims).toEqual([{ path: ["eu.europa.ec.eudi.pid.1", "given_name"] }]);
    await page.locator("#query-mode-builder").click();

    const [resp] = await Promise.all([
      page.waitForResponse((r) => r.url().endsWith("/verifier/api/requests") && r.request().method() === "POST"),
      page.locator("#create-request").click(),
    ]);
    const { transaction_id: id } = await resp.json();
    const schemeURI = (await page.locator("#scheme-uri").textContent()) || "";

    await present(page, schemeURI);
    await page.locator("#consent-approve").click();
    await expect(page).toHaveURL(/\/verifier\/\?response_code=/, { timeout: 45_000 });

    const result = await verifierResult(id);
    expect(result.status).toBe("verified");
    expect(result.checks.map((c) => c.name)).toContain("cred_0: claim set 1 of 2 was disclosed (given_name, family_name)");
  });

  test("ending the path with [*] discloses the array elements", async ({ page }) => {
    const { id, schemeURI } = await buildCustom(page, "nationalities[*]");

    await present(page, schemeURI);
    const credentials = await (await fetch(`${BASE}/api/credentials`)).json();
    const dutchPID = credentials.find(c => c.vct === "urn:eudi:pid:1" && c.format === "dc+sd-jwt");
    expect(dutchPID).toBeDefined();
    await page.locator("#consent-edit-selection").click();
    await page.locator(`#consent-candidate-cred_0-${dutchPID.id}`).click();
    await page.locator("#consent-selection-done").click();
    await expect(page.locator("#consent-dialog .consent-claim-warn")).toHaveCount(0);

    await page.locator("#consent-approve").click();
    await expect(page).toHaveURL(/\/verifier\/\?response_code=/, { timeout: 45_000 });

    const result = await verifierResult(id);
    expect(result.status).toBe("verified");
    expect(result.claims.cred_0.nationalities).toEqual(["NL"]);
  });

  // The demo holds at least two SD-JWT PIDs that answer urn:eudi:pid:1: the EUDI PID
  // and the German PID that extends it. Earlier tests may add more.
  test("a multiple query presents every matching credential by default", async ({ page }) => {
    const { id, schemeURI } = await buildCustom(page, "nationalities[*]", { multiple: true });

    await present(page, schemeURI);
    const cards = page.locator("#consent-dialog .consent-credential[data-credential-id]");
    await expect(cards.nth(1)).toBeVisible();
    const shown = await cards.count();

    await page.locator("#consent-approve").click();
    await expect(page).toHaveURL(/\/verifier\/\?response_code=/, { timeout: 45_000 });

    const result = await verifierResult(id);
    expect(result.status).toBe("verified");
    expect(result.claims.cred_0).toHaveLength(shown);
  });

  test("a multiple query lets the user withhold all but one credential", async ({ page }) => {
    const { id, schemeURI } = await buildCustom(page, "nationalities[*]", { multiple: true });

    await present(page, schemeURI);
    await page.locator("#consent-edit-selection").click();
    const query = page.locator("#consent-query-cred_0");
    await expect(query).toHaveAttribute("data-multiple", "true");
    const candidates = query.locator('.candidate[role="checkbox"]');
    await expect(candidates.nth(1)).toBeVisible();
    const total = await candidates.count();
    for (let i = 0; i < total; i++) {
      await expect(candidates.nth(i)).toHaveAttribute("aria-checked", "true");
    }

    for (let i = 1; i < total; i++) {
      await candidates.nth(i).click();
      await expect(candidates.nth(i)).toHaveAttribute("aria-checked", "false");
    }
    // The last selected credential stays selected.
    await candidates.nth(0).click();
    await expect(candidates.nth(0)).toHaveAttribute("aria-checked", "true");
    const kept = await candidates.nth(0).getAttribute("data-cred");

    await page.locator("#consent-selection-done").click();
    await expect(page.locator("#consent-dialog .consent-credential[data-credential-id]")).toHaveCount(1);
    await expect(page.locator("#consent-selection-row")).toContainText("Your selection");

    await page.locator("#consent-approve").click();
    await expect(page).toHaveURL(/\/verifier\/\?response_code=/, { timeout: 45_000 });

    const result = await verifierResult(id);
    expect(result.status).toBe("verified");
    expect(result.claims.cred_0).toHaveLength(1);
    const keptCredential = await (await fetch(`${BASE}/api/credentials/${kept}`)).json();
    expect(result.claims.cred_0[0].given_name).toBe(keptCredential.claims.given_name);
  });

  test("the client id scheme selection reaches the request", async ({ page }) => {
    await page.goto(`${BASE}/verifier/`);
    await page.locator('#credential-toggle [data-credential="custom"]').click();
    await page.locator('#scheme-toggle [data-scheme="redirect_uri"]').click();
    const [resp] = await Promise.all([
      page.waitForResponse(
        (r) => r.url().endsWith("/verifier/api/requests") && r.request().method() === "POST"
      ),
      page.locator("#create-request").click(),
    ]);
    const body = await resp.json();
    // Unsigned redirect_uri requests carry client_id in the wallet URL.
    expect(body.wallet_url).toContain("client_id=redirect_uri");
  });
});

test.describe("Demo verifier identity", () => {
  test("an unsigned client identifier prefix sends no registration certificate", async ({ page }) => {
    await page.goto(`${BASE}/verifier/`);
    await page.locator('#credential-toggle [data-credential="custom"]').click();
    await page.locator('#scheme-toggle [data-scheme="redirect_uri"]').click();
    await expect(page.locator("#identity-registered")).toBeDisabled();
    await expect(page.locator("#identity-own")).toBeDisabled();
    await expect(page.locator("#identity-unregistered")).toHaveAttribute("aria-checked", "true");
    await expect(page.locator("#identity-hint")).toHaveText("Needs a signed request object (x509_hash or x509_san_dns).");

    // A signed request again uses the registration the user chose.
    await page.locator('#scheme-toggle [data-scheme="x509_hash"]').click();
    await expect(page.locator("#identity-registered")).toHaveAttribute("aria-checked", "true");
  });

  test("own certificates need a signing key", async ({ page }) => {
    await page.goto(`${BASE}/verifier/`);
    await page.locator("#identity-own").click();
    await page.locator("#create-request").click();
    await expect(page.locator("#status")).toContainText("Paste the signing key and access certificate chain.");
  });
});
