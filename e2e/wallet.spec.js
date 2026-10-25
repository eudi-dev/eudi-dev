// @ts-check
const { test, expect } = require("@playwright/test");
const { waitForServer } = require("./helpers");
const { execSync } = require("child_process");
const crypto = require("crypto");
const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");

const WALLET_PORT = 18924;
const WALLET_URL = `http://localhost:${WALLET_PORT}`;

let walletProcess;

test.describe.configure({ mode: "serial" });
test.setTimeout(60_000);

test.beforeAll(async () => {
  // Cold Go builds can exceed the default hook timeout on CI.
  test.setTimeout(120_000);

  execSync("go build -o /tmp/eudi-dev-wallet-e2e ..", {
    cwd: __dirname,
  });

  // A fresh directory keeps stored serving URLs from changing the test ports.
  const { spawn } = require("child_process");
  const walletDir = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-dev-wallet-e2e-"));
  walletProcess = spawn(
    "/tmp/eudi-dev-wallet-e2e",
    [
      "wallet",
      "serve",
      "--pid",
      "--port",
      String(WALLET_PORT),
      "--wallet-dir",
      walletDir,
      "--base-url",
      "https://localhost:18926",
    ],
    { stdio: "pipe" }
  );

  await waitForServer(WALLET_URL, 30_000);
});

test.afterAll(async () => {
  if (walletProcess) {
    walletProcess.kill("SIGTERM");
  }
});

async function jsonPost(url, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const parsed = new URL(url);
    const req = http.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(data),
        },
      },
      (res) => {
        let body = "";
        res.on("data", (d) => (body += d));
        res.on("end", () =>
          resolve({ status: res.statusCode, body: JSON.parse(body || "{}") })
        );
      }
    );
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

async function jsonGet(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () =>
        resolve({ status: res.statusCode, body: JSON.parse(body || "{}") })
      );
      res.on("error", reject);
    });
  });
}

function registrationCertificateClaims(issuerInfo) {
  const jwt = issuerInfo.find((e) => e.format === "registration_cert").data;
  return JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString());
}

// Each test starts without pending requests.
async function denyPendingRequests() {
  const pending = await jsonGet(`${WALLET_URL}/api/requests`);
  for (const r of Array.isArray(pending.body) ? pending.body : []) {
    await jsonPost(`${WALLET_URL}/api/requests/${r.id}/deny`, {});
  }
}

async function waitForPendingRequest() {
  let pending = [];
  for (let i = 0; i < 50 && pending.length === 0; i++) {
    pending = (await jsonGet(`${WALLET_URL}/api/requests`)).body;
    if (pending.length === 0) await new Promise((r) => setTimeout(r, 100));
  }
  expect(pending.length).toBeGreaterThan(0);
  return pending[0].id;
}

test.describe("Sponsor link outside demo mode", () => {
  for (const [pagePath, configPath] of [
    ["/", "/api/config"],
    ["/issuer/", "/api/config"],
    ["/verifier/", "/api/config"],
    ["/decoder/", "/decoder/api/meta"],
  ]) {
    test(`is hidden on ${pagePath}`, async ({ page }) => {
      const configLoaded = page.waitForResponse((r) => new URL(r.url()).pathname === configPath);
      await page.goto(`${WALLET_URL}${pagePath}`);
      await (await configLoaded).finished();
      // The page applies the config one task after the response arrives.
      await page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 0)));
      await expect(page.locator("#sponsor-link")).toBeHidden();
    });
  }
});

test.describe("Wallet Dashboard", () => {
  test("shows wallet title", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator("h1")).toHaveText("EUDI Dev Wallet");
  });

  test("how to use has a registrar tab with the registrar API", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.click("#how-to-use-link");
    await expect(page.locator("#howto-panel-basics")).toBeVisible();
    await expect(page.locator("#howto-panel-registrar")).toBeHidden();

    await page.click("#howto-tab-registrar");
    await expect(page.locator("#howto-tab-registrar")).toHaveAttribute("aria-selected", "true");
    await expect(page.locator("#howto-panel-basics")).toBeHidden();
    const panel = page.locator("#howto-panel-registrar");
    await expect(panel).toContainText(`${WALLET_URL}/api/registrar/wrp`);
    await expect(panel.locator('a[data-doc="docs/wallet/registrar-api.md"]')).toHaveAttribute(
      "href",
      /^https:\/\/github\.com\/eudi-dev\/eudi-dev\/blob\/[^/]+\/docs\/wallet\/registrar-api\.md$/,
    );

    await page.keyboard.press("ArrowLeft");
    await expect(page.locator("#howto-panel-basics")).toBeVisible();
    await page.click("#howto-close");
  });

  test("how to use has a browser extension tab", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.click("#how-to-use-link");
    await page.click("#howto-tab-extension");
    await expect(page.locator("#howto-tab-extension")).toHaveAttribute("aria-selected", "true");
    const panel = page.locator("#howto-panel-extension");
    await expect(panel).toBeVisible();
    await expect(panel.locator("#howto-extension-store-link")).toBeVisible();
    await panel.locator("#howto-extension-manual summary").click();
    await expect(panel.locator("#howto-extension-browser-command")).toHaveText(`eudi wallet browser --wallet-url ${WALLET_URL}`);
    await expect(panel.locator('a[data-doc="docs/wallet/browser-extension.md"]')).toHaveAttribute(
      "href",
      /^https:\/\/github\.com\/eudi-dev\/eudi-dev\/blob\/[^/]+\/docs\/wallet\/browser-extension\.md$/,
    );
    const download = page.waitForEvent("download");
    await panel.locator("#howto-extension-zip-link").click();
    expect((await download).suggestedFilename()).toBe("eudi-dev-dc-api-extension.zip");
    await page.click("#howto-close");
  });

  test("conformance panel changes the local wallet setting via the endpoint", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);
    const configMode = async () =>
      (await page.evaluate(async () => (await (await fetch("/api/config")).json()).validation_mode));

    const before = await configMode();
    const target = before === "strict" ? "debug" : "strict";

    await page.click("#conformance-link");
    await expect(page.locator("#conf-mode-select")).toBeEnabled();
    await page.selectOption("#conf-mode-select", target);
    await expect.poll(configMode).toBe(target);

    const cookie = await page.evaluate(() => document.cookie);
    expect(cookie).not.toContain("eudi_conformance");

    await page.click("#conf-reset");
    await expect.poll(configMode).toBe(before);
  });

  test("the settings dialog sets a fixed client ID and clears it again", async ({ page }) => {
    await page.goto(WALLET_URL);
    const clientID = async () =>
      (await page.evaluate(async () => (await (await fetch("/api/config")).json()).vci_client_id));
    await page.click("#conformance-link");
    const input = page.locator("#conf-vci-client-id");
    try {
      await expect(input).toBeEnabled();
      await expect(input).toHaveValue("");
      await input.fill("registered-wallet");
      await input.press("Enter");
      await expect.poll(clientID).toBe("registered-wallet");
      await input.fill("");
      await input.press("Enter");
      await expect.poll(clientID).toBe("");
    } finally {
      await page.click("#conf-reset");
    }
  });

  test("HTTPS verification overrides the validation mode and resets to its default", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.click("#conformance-link");
    const tlsConfig = async () => await page.evaluate(async () => await (await fetch("/api/config")).json());
    try {
      await page.selectOption("#conf-mode-select", "strict");
      await expect.poll(async () => (await tlsConfig()).tls_verify).toBe(true);
      await page.selectOption("#conf-tls-select", "false");
      await expect.poll(async () => (await tlsConfig()).tls_verify).toBe(false);
      await page.selectOption("#conf-mode-select", "debug");
      await expect.poll(async () => (await tlsConfig()).validation_mode).toBe("debug");
      await page.selectOption("#conf-tls-select", "true");
      await expect.poll(async () => (await tlsConfig()).tls_verify).toBe(true);
      await page.selectOption("#conf-tls-select", { label: "Depends on the mode" });
      await expect.poll(async () => (await tlsConfig()).tls_verify).toBe(false);
      expect((await tlsConfig()).tls_verify_override).toBeNull();
    } finally {
      await page.click("#conf-reset");
      await expect.poll(async () => (await tlsConfig()).tls_verify_override).toBeNull();
    }
  });

  test("shows PID credentials", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator(".credential-card")).toHaveCount(2, {
      timeout: 5000,
    });

    const sdjwtCard = page.locator(".credential-card[data-format='sdjwt']").first();
    await expect(sdjwtCard).toBeVisible();

    const mdocCard = page.locator(".credential-card[data-format='mdoc']").first();
    await expect(mdocCard).toBeVisible();
  });

  test("shows the credential facts in the card meta line", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator(".credential-card")).toHaveCount(2, {
      timeout: 5000,
    });

    const meta = page.locator(".credential-card").first().locator(".cred-meta");
    await expect(meta).toContainText("iat");
    await expect(meta).toContainText("type");
  });

  // The wallet and its decoder share one stored choice. Without one they
  // follow the system.
  test("has theme toggle button", async ({ page }) => {
    await page.emulateMedia({ colorScheme: "dark" });
    await page.goto(WALLET_URL);
    await expect(page.locator("html")).not.toHaveAttribute("data-theme", "light");
    const themeBtn = page.locator("#theme-toggle");
    await expect(themeBtn).toBeVisible();

    await themeBtn.click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    expect(await page.evaluate(() => localStorage.getItem("eudi-dev-theme"))).toBe("light");

    await page.goto(WALLET_URL + "/decoder/");
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await page.locator("#theme-btn").click();
    expect(await page.evaluate(() => localStorage.getItem("eudi-dev-theme"))).toBe("dark");
  });

  test("follows the system theme without a choice", async ({ page }) => {
    await page.emulateMedia({ colorScheme: "light" });
    await page.goto(WALLET_URL);
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await page.emulateMedia({ colorScheme: "dark" });
    await expect(page.locator("html")).not.toHaveAttribute("data-theme", "light");
  });

  test("has process input and button", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator("#offer-input")).toBeVisible();
    await expect(page.locator("#process-btn")).toBeVisible();
  });

  test("has import credential button", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator("#import-btn")).toBeVisible();
  });

  test("shows empty activity section", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator("#log-empty")).toBeVisible();
  });
});

test.describe("Wallet loading states", () => {
  test("loads credentials and activity independently without flashing empty messages", async ({ page }) => {
    let releaseCredentials;
    let releaseActivity;
    const credentialsReady = new Promise((resolve) => { releaseCredentials = resolve; });
    const activityReady = new Promise((resolve) => { releaseActivity = resolve; });
    await page.route("**/api/credentials?*", async (route) => {
      await credentialsReady;
      await route.continue();
    });
    await page.route("**/api/log*", async (route) => {
      await activityReady;
      await route.fulfill({ json: [{ time: "2026-09-13T05:00:00Z", action: "issue", detail: "Credential issued", success: true }] });
    });

    try {
      await page.goto(WALLET_URL);
      await expect(page.getByRole("status", { name: "Loading credentials" })).toBeVisible();
      await expect(page.getByRole("status", { name: "Loading activity" })).toBeVisible();
      await expect(page.locator("#cred-empty")).toBeHidden();
      await expect(page.locator("#log-empty")).toBeHidden();

      releaseCredentials();
      await expect(page.locator(".credential-card")).toHaveCount(2);
      await expect(page.getByRole("status", { name: "Loading credentials" })).toBeHidden();
      await expect(page.getByRole("status", { name: "Loading activity" })).toBeVisible();
      await expect(page.locator("#cred-empty")).toBeHidden();

      releaseActivity();
      await expect(page.getByTestId("log-entry")).toContainText("Credential issued");
      await expect(page.getByRole("status", { name: "Loading activity" })).toBeHidden();
      await expect(page.locator("#log-empty")).toBeHidden();
    } finally {
      releaseCredentials();
      releaseActivity();
    }
  });

  test("shows empty messages only after successful empty responses", async ({ page }) => {
    let release;
    const ready = new Promise((resolve) => { release = resolve; });
    await page.route("**/api/credentials?*", async (route) => {
      await ready;
      await route.fulfill({ json: [] });
    });
    await page.route("**/api/log*", async (route) => {
      await ready;
      await route.fulfill({ contentType: "application/json", body: "null" });
    });
    try {
      await page.goto(WALLET_URL);
      await expect(page.getByRole("status", { name: "Loading credentials" })).toBeVisible();
      await expect(page.getByRole("status", { name: "Loading activity" })).toBeVisible();
      await expect(page.locator("#cred-empty")).toBeHidden();
      await expect(page.locator("#log-empty")).toBeHidden();
      release();
      await expect(page.locator("#cred-empty")).toBeVisible();
      await expect(page.locator("#log-empty")).toBeVisible();
      await expect(page.getByRole("status", { name: "Loading credentials" })).toBeHidden();
      await expect(page.getByRole("status", { name: "Loading activity" })).toBeHidden();
    } finally {
      release();
    }
  });

  test("keeps content visible while a state event refreshes both sections", async ({ page }) => {
    let sendEvent;
    let releaseRefresh;
    const eventReady = new Promise((resolve) => { sendEvent = resolve; });
    const refreshReady = new Promise((resolve) => { releaseRefresh = resolve; });
    let refreshing = false;
    await page.route("**/api/requests/stream?*", async (route) => {
      await eventReady;
      await route.fulfill({ contentType: "text/event-stream", body: "event: state\ndata: {}\n\n" });
    });
    await page.route("**/api/credentials?*", async (route) => {
      if (refreshing) await refreshReady;
      await route.continue();
    });
    await page.route("**/api/log*", async (route) => {
      if (refreshing) await refreshReady;
      await route.fulfill({ json: [{ time: "2026-09-13T05:00:00Z", action: "issue", detail: refreshing ? "Updated activity" : "Original activity", success: true }] });
    });
    try {
      await page.goto(WALLET_URL);
      await expect(page.locator(".credential-card")).toHaveCount(2);
      await expect(page.getByTestId("log-entry")).toContainText("Original activity");
      refreshing = true;
      const requests = Promise.all([
        page.waitForRequest((request) => new URL(request.url()).pathname === "/api/credentials"),
        page.waitForRequest((request) => new URL(request.url()).pathname === "/api/log"),
      ]);
      sendEvent();
      await requests;
      await expect(page.locator(".credential-card")).toHaveCount(2);
      await expect(page.getByTestId("log-entry")).toContainText("Original activity");
      await expect(page.getByRole("status", { name: "Loading credentials" })).toBeHidden();
      await expect(page.getByRole("status", { name: "Loading activity" })).toBeHidden();
      releaseRefresh();
      await expect(page.getByTestId("log-entry")).toContainText("Updated activity");
    } finally {
      sendEvent();
      releaseRefresh();
    }
  });

  for (const failure of ["http", "network", "json"]) {
    test(`recovers from ${failure} failures through Retry`, async ({ page }) => {
      const fail = async (route) => {
        if (failure === "network") await route.abort();
        else if (failure === "json") await route.fulfill({ contentType: "application/json", body: "{" });
        else await route.fulfill({ status: 503, json: { error: "Unavailable" } });
      };
      await page.route("**/api/credentials?*", fail);
      await page.route("**/api/log*", fail);
      await page.goto(WALLET_URL);
      await expect(page.getByText("Could not load credentials.")).toBeVisible();
      await expect(page.getByText("Could not load activity.")).toBeVisible();
      await expect(page.getByRole("status", { name: "Loading credentials" })).toBeHidden();
      await expect(page.getByRole("status", { name: "Loading activity" })).toBeHidden();
      await expect(page.locator("#cred-empty")).toBeHidden();
      await expect(page.locator("#log-empty")).toBeHidden();

      let release;
      const ready = new Promise((resolve) => { release = resolve; });
      const retry = async (route) => { await ready; await route.continue(); };
      await page.route("**/api/credentials?*", retry);
      await page.route("**/api/log*", retry);
      try {
        await page.locator("#credentials").getByRole("button", { name: "Retry" }).click();
        await page.locator("#log").getByRole("button", { name: "Retry" }).click();
        await expect(page.getByRole("status", { name: "Loading credentials" })).toBeVisible();
        await expect(page.getByRole("status", { name: "Loading activity" })).toBeVisible();
        await expect(page.getByText("Could not load credentials.")).toBeHidden();
        await expect(page.getByText("Could not load activity.")).toBeHidden();
        release();
        await expect(page.locator(".credential-card")).toHaveCount(2);
        await expect(page.locator("#log-empty")).toBeVisible();
        await expect(page.getByRole("status", { name: "Loading credentials" })).toBeHidden();
        await expect(page.getByRole("status", { name: "Loading activity" })).toBeHidden();
      } finally {
        release();
      }
    });
  }
});

test.describe("Credential Import via UI", () => {
  test("import modal opens and closes", async ({ page }) => {
    await page.goto(WALLET_URL);

    await page.locator("#import-btn").click();
    await expect(page.locator("#import-overlay")).toHaveClass(/active/);

    await page.locator("#import-cancel").click();
    await expect(page.locator("#import-overlay")).not.toHaveClass(/active/);
  });
});

test.describe("Credential Management API", () => {
  test("GET /api/credentials returns PID credentials", async () => {
    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    expect(res.status).toBe(200);
    expect(res.body.length).toBe(2);

    const formats = res.body.map((c) => c.format);
    expect(formats).toContain("dc+sd-jwt");
    expect(formats).toContain("mso_mdoc");
  });

  test("POST /api/credentials rejects invalid input", async () => {
    const res = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: "localhost",
          port: WALLET_PORT,
          path: "/api/credentials",
          method: "POST",
        },
        (res) => {
          let body = "";
          res.on("data", (d) => (body += d));
          res.on("end", () => resolve({ status: res.statusCode, body }));
        }
      );
      req.on("error", reject);
      req.write("not-a-credential");
      req.end();
    });

    expect(res.status).toBe(400);
  });
});

test.describe("Presentation Flow API", () => {
  test("POST /api/presentations with invalid URI returns error", async () => {
    const res = await jsonPost(`${WALLET_URL}/api/presentations`, {
      uri: "not-a-valid-uri",
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_request");
    expect(res.body.error_description).toBeDefined();
  });
});

test.describe("Credential Offer Endpoint", () => {
  test("GET /credential-offer without parameters returns error", async ({
    request,
  }) => {
    const res = await request.get(`${WALLET_URL}/credential-offer`);
    expect(res.status()).toBe(400);
  });

  test("GET /credential-offer with malformed offer returns error", async ({
    request,
  }) => {
    const res = await request.get(
      `${WALLET_URL}/credential-offer?credential_offer=${encodeURIComponent(
        "not-a-credential-offer"
      )}`
    );
    expect(res.status()).toBe(400);
  });
});

test.describe("Static Files", () => {
  test("serves index.html at /", async ({ page }) => {
    const response = await page.goto(WALLET_URL);
    expect(response.status()).toBe(200);
  });

  test("serves style.css", async ({ page }) => {
    const response = await page.goto(`${WALLET_URL}/style.css`);
    expect(response.status()).toBe(200);
    const body = await response.text();
    expect(body).toContain("--bg");
  });

  test("serves app.js", async ({ page }) => {
    const response = await page.goto(`${WALLET_URL}/app.js`);
    expect(response.status()).toBe(200);
    const body = await response.text();
    expect(body).toContain("'api/credentials");
  });
});

test.describe("Credential Issuing via UI", () => {
  // Earlier errors and consent requests are cleared, so no overlay intercepts clicks.
  test.beforeEach(async () => {
    await new Promise((resolve) => {
      const req = http.request(
        `${WALLET_URL}/api/error`,
        { method: "DELETE" },
        (res) => res.on("data", () => {}).on("end", resolve)
      );
      req.on("error", resolve);
      req.end();
    });
    await denyPendingRequests();
  });

  test("issue modal opens empty with the PID template as a choice", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);

    await page.locator("#issue-btn").click();
    await expect(page.locator("#issue-overlay")).toHaveClass(/active/);

    await expect(page.locator("#issue-vct")).toHaveValue("");
    await expect(page.locator("#issue-exp")).toHaveValue("");
    await expect(page.locator("#issue-claim-rows .claim-row")).toHaveCount(1);
    await expect(page.locator("#issue-claim-key-0")).toHaveValue("");

    await expect(page.locator("#issue-doctype")).toBeHidden();
    await expect(page.locator("#issue-claim-ns-0")).toBeHidden();

    await page.locator("#issue-template").selectOption("german-pid-sdjwt");
    await expect(page.locator("#issue-vct")).toHaveValue("urn:eudi:pid:de:1");
    // The template keeps the default expiry. The placeholder shows it.
    await expect(page.locator("#issue-exp")).toHaveValue("");
    await expect(page.locator("#issue-claim-rows .claim-row")).toHaveCount(13);
    const keys = await page
      .locator("#issue-claim-rows .claim-row input[id^=issue-claim-key]")
      .evaluateAll((inputs) => inputs.map((i) => i.value));
    expect(keys.sort()).toEqual([
      "academic_title",
      "address",
      "age_equal_or_over",
      "birth_name",
      "birthdate",
      "family_name",
      "given_name",
      "issuing_authority",
      "issuing_country",
      "nationalities",
      "place_of_birth",
      "raw_eid_birth_date",
      "source_document_type",
    ]);

    await page.locator("#issue-cancel").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);
  });

  test("fields switch with the selected format and reset on change", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);
    await page.locator("#issue-btn").click();
    await page.locator("#issue-vct").fill("urn:example:leftover");

    await page.locator("#issue-format").selectOption("mdoc");
    await expect(page.locator("#issue-vct")).toBeHidden();
    await expect(page.locator("#issue-doctype")).toBeVisible();
    await expect(page.locator("#issue-claim-ns-0")).toBeVisible();

    await page.locator("#issue-template").selectOption("german-pid-mdoc");
    await expect(page.locator("#issue-doctype")).toHaveValue(
      "eu.europa.ec.eudi.pid.1"
    );

    await page.locator("#issue-format").selectOption("sdjwt");
    await expect(page.locator("#issue-vct")).toBeVisible();
    await expect(page.locator("#issue-vct")).toHaveValue("");
    await expect(page.locator("#issue-doctype")).toBeHidden();
    await expect(page.locator("#issue-claim-rows .claim-row")).toHaveCount(1);
    await expect(page.locator("#issue-claim-key-0")).toHaveValue("");

    await page.locator("#issue-cancel").click();
  });

  test("issues an mdoc with a per-attribute namespace", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#issue-btn").click();
    await page.locator("#issue-format").selectOption("mdoc");
    await page.locator("#issue-doctype").fill("org.example.e2e.doctype");

    await page.locator("#issue-claim-key-0").fill("given_name");
    await page.locator("#issue-claim-value-0").fill("Erika");
    await page.locator("#issue-add-claim").click();
    const lastRow = page.locator("#issue-claim-rows .claim-row").last();
    await lastRow
      .locator('input[id^="issue-claim-ns-"]')
      .fill("org.example.custom");
    await lastRow.locator('input[id^="issue-claim-key-"]').fill("loyalty_tier");
    await lastRow.locator('input[id^="issue-claim-value-"]').fill("gold");

    await page.locator("#issue-submit").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);

    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    const summary = res.body.find(
      (c) => c.doctype === "org.example.e2e.doctype"
    );
    expect(summary).toBeDefined();
    const issued = (await jsonGet(`${WALLET_URL}/api/credentials/${summary.id}`))
      .body;
    expect(issued.claims["org.example.e2e.doctype:given_name"]).toBe("Erika");
    expect(issued.claims["org.example.custom:loyalty_tier"]).toBe("gold");

    await page.goto(WALLET_URL);
    await page.locator(`#delete-${issued.id}`).click();
    await expect(page.locator(`#credential-${issued.id}`)).toHaveCount(0);
  });

  test("issues an SD-JWT credential from the PID template with an added claim", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator(".credential-card")).toHaveCount(2, {
      timeout: 5000,
    });

    await page.locator("#issue-btn").click();
    await page.locator("#issue-template").selectOption("german-pid-sdjwt");
    await expect(page.locator("#issue-vct")).toHaveValue("urn:eudi:pid:de:1");
    await page.locator("#issue-vct").fill("urn:example:e2e-test");

    await page.locator("#issue-add-claim").click();
    const lastRow = page.locator("#issue-claim-rows .claim-row").last();
    await lastRow.locator('input[id^="issue-claim-key-"]').fill("e2e_marker");
    await lastRow.locator('input[id^="issue-claim-value-"]').fill("yes");

    await page.locator("#issue-submit").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);
    await expect(page.locator(".credential-card")).toHaveCount(3);
    const newCard = page.locator(".credential-card", {
      hasText: "urn:example:e2e-test",
    });
    await expect(newCard).toBeVisible();
    await expect(newCard.locator(".credential-name").first()).toHaveText(
      "German PID"
    );

    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    const summary = res.body.find((c) => c.vct === "urn:example:e2e-test");
    expect(summary).toBeDefined();
    const issued = (await jsonGet(`${WALLET_URL}/api/credentials/${summary.id}`))
      .body;
    expect(issued.claims.e2e_marker).toBe("yes");
    expect(issued.claims.given_name).toBeDefined();
  });

  test("JSON mode shows the builder claims as editable JSON", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);
    await page.locator("#issue-btn").click();
    await page.locator("#issue-template").selectOption("german-pid-sdjwt");

    await page.locator("#issue-claims-mode-json").check();
    await expect(page.locator("#issue-claims")).toBeVisible();
    await expect(page.locator("#issue-claim-rows")).toBeHidden();
    await expect(page.locator("#issue-add-claim")).toBeHidden();
    const json = await page.locator("#issue-claims").inputValue();
    expect(JSON.parse(json).given_name).toBeDefined();

    await page
      .locator("#issue-claims")
      .fill('{"given_name": "Changed", "answer": 42}');
    await page.locator("#issue-claims-mode-builder").check();
    await expect(page.locator("#issue-claim-rows")).toBeVisible();
    await expect(page.locator("#issue-claims")).toBeHidden();
    await expect(page.locator("#issue-claim-rows .claim-row")).toHaveCount(2);
    await expect(page.locator("#issue-claim-key-0")).toHaveValue("given_name");
    await expect(page.locator("#issue-claim-value-0")).toHaveValue("Changed");
    await expect(page.locator("#issue-claim-value-1")).toHaveValue("42");

    await page.locator("#issue-claims-mode-json").check();
    await page.locator("#issue-claims").fill("{not json");
    // The UI restores the radio value when JSON is invalid, so the test uses click().
    await page.locator("#issue-claims-mode-builder").click();
    await expect(page.locator("#issue-error")).toContainText(
      "Claims must be valid JSON"
    );
    await expect(page.locator("#issue-claims")).toBeVisible();
    await expect(page.locator("#issue-claims-mode-json")).toBeChecked();

    await page.locator("#issue-cancel").click();
  });

  test("shows a validation error for invalid claims JSON", async ({ page }) => {
    await page.goto(WALLET_URL);

    await page.locator("#issue-btn").click();
    await page.locator("#issue-claims-mode-json").check();
    await page.locator("#issue-claims").fill("{not json");
    await page.locator("#issue-submit").click();

    await expect(page.locator("#issue-error")).toContainText(
      "Claims must be valid JSON"
    );
    await expect(page.locator("#issue-overlay")).toHaveClass(/active/);
    await page.locator("#issue-cancel").click();
  });

  test("shows a server error for an invalid exp duration", async ({ page }) => {
    await page.goto(WALLET_URL);

    await page.locator("#issue-btn").click();
    await page.locator("#issue-exp").fill("tomorrow");
    await page.locator("#issue-submit").click();

    await expect(page.locator("#issue-error")).toContainText("exp");
    await page.locator("#issue-cancel").click();
  });

  test("deletes the issued credential via its card button", async ({ page }) => {
    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    const issued = res.body.find((c) => c.vct === "urn:example:e2e-test");
    expect(issued).toBeDefined();

    await page.goto(WALLET_URL);
    await expect(page.locator(`#credential-${issued.id}`)).toBeVisible();
    await page.locator(`#delete-${issued.id}`).click();
    await expect(page.locator(`#credential-${issued.id}`)).toHaveCount(0);
    await expect(page.locator(".credential-card")).toHaveCount(2);
  });

  test("an SD-JWT with a URI claim name renders and deletes", async ({
    page,
  }) => {
    const claimName = "https://example.org/claims/role";
    const issued = await jsonPost(`${WALLET_URL}/api/issue`, {
      format: "sdjwt",
      vct: "urn:example:colon-claim",
      claims: { [claimName]: "admin", given_name: "ERIKA" },
    });
    expect(issued.status).toBe(201);

    await page.goto(WALLET_URL);
    const card = page.locator(`#credential-${issued.body.id}`);
    await expect(card).toBeVisible();
    await expect(card.locator(".credential-name")).toContainText(
      "urn:example:colon-claim"
    );

    await page.locator(`#delete-${issued.body.id}`).click();
    await expect(card).toHaveCount(0);
  });

  test("marks a credential that is not valid yet", async ({ page }) => {
    const issued = await jsonPost(`${WALLET_URL}/api/issue`, {
      format: "sdjwt",
      vct: "urn:example:e2e-future",
      claims: { given_name: "ERIKA" },
      nbf: "48h",
    });
    expect(issued.status).toBe(201);
    const id = issued.body.id;

    await page.goto(WALLET_URL);
    const card = page.locator(`#credential-${id}`);
    await expect(card).toHaveAttribute("data-expiry", "not-yet-valid");
    await expect(page.locator(`#expiry-${id}`)).toHaveText("Not yet valid");
    await expect(page.locator(`#expiry-${id}`)).toHaveAttribute("title", /^Valid from /);

    await page.locator(`#delete-${id}`).click();
    await expect(card).toHaveCount(0);
  });

  test("the footer labels a prerelease build", async ({ page }) => {
    let version = "3.0.0-beta.4";
    await page.route("**/api/config", async (route) => {
      const response = await route.fetch();
      await route.fulfill({ response, json: { ...(await response.json()), version } });
    });
    await page.goto(WALLET_URL);
    await expect(page.locator("#footer-version")).toHaveText("eudi-dev 3.0.0-beta.4");
    await expect(page.locator("#footer-prerelease")).toBeVisible();
    await expect(page.locator("#footer-prerelease")).toHaveText("Beta");

    version = "3.0.0";
    await page.reload();
    await expect(page.locator("#footer-version")).toHaveText("eudi-dev 3.0.0");
    await expect(page.locator("#footer-prerelease")).toBeHidden();
  });

  test("the header opens the templates, also from the phone menu", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#templates-link").click();
    await expect(page.locator("#templates-overlay")).toHaveClass(/active/);
    await page.locator("#template-close").click();

    await page.setViewportSize({ width: 390, height: 844 });
    await page.locator("#header-menu-toggle").click();
    await page.locator("#templates-link").click();
    await expect(page.locator("#templates-overlay")).toHaveClass(/active/);
    await expect(page.locator("#header-links")).not.toHaveClass(/open/);
  });

  // A new template can start from another one in the template select. It
  // keeps the images shown as previews, except one the user removes.
  test("a new template keeps the images of the template it starts from", async ({ page }) => {
    const saveCopy = async (name, removeLogo) => {
      await page.goto(WALLET_URL);
      await page.locator("#templates-link").click();
      await page.locator("#template-new").click();
      await page.locator("#template-editor-name").fill(name);
      await page.locator("#issue-template").selectOption("demo-ticket");
      await expect(page.locator("#issue-logo-preview")).toBeVisible();
      if (removeLogo) await page.locator("#issue-logo-remove").click();
      await page.locator("#issue-submit").click();
      await expect(page.locator(".template-row-name", { hasText: name })).toBeVisible();
      const resp = await page.request.get(`${WALLET_URL}/api/templates/${name}`);
      const display = (await resp.json()).display || {};
      await page.request.delete(`${WALLET_URL}/api/templates/${name}`);
      return display;
    };

    const kept = await saveCopy("e2e-ticket-copy", false);
    expect(kept.logo).toBe("embedded:images/logo.svg");
    expect(kept.logo_alt_text).toBe("eudi-dev logo");

    const removed = await saveCopy("e2e-ticket-no-logo", true);
    expect(removed.logo).toBeUndefined();
    expect(removed.name).toBe("Demo Event Ticket");
  });

  test("manages templates and issues from one with a non-disclosable claim", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);

    await page.locator("#templates-link").click();
    await expect(page.locator("#templates-overlay")).toHaveClass(/active/);
    await expect(
      page.locator(".template-row-name", { hasText: "german-pid-sdjwt" })
    ).toBeVisible();

    await page.locator("#template-new").click();
    await expect(page.locator("#issue-title")).toHaveText("New template");
    await page.locator("#template-editor-name").fill("e2e-employee");
    await page.locator("#template-editor-mode-json").check();
    await page.locator("#template-editor-json").fill(
      JSON.stringify({
        format: "sdjwt",
        vct: "urn:example:e2e-employee",
        claims: { employee_id: "E-1", department: "IT" },
        always_disclosed: ["department"],
      })
    );
    // Back in the builder, the fields show the JSON.
    await page.locator("#template-editor-mode-builder").check();
    await expect(page.locator("#issue-vct")).toHaveValue("urn:example:e2e-employee");
    await page.locator("#issue-submit").click();
    await expect(
      page.locator(".template-row-name", { hasText: "e2e-employee" })
    ).toBeVisible();
    await page.locator("#template-close").click();

    await page.locator("#issue-btn").click();
    await page.locator("#issue-template").selectOption("e2e-employee");
    await expect(page.locator("#issue-vct")).toHaveValue(
      "urn:example:e2e-employee"
    );
    await expect(page.locator("#issue-always-disclosed")).toHaveValue(
      "department"
    );
    // The form sets properties and leaves attributes unchanged, so the test reads them
    // through evaluate.
    const sdStates = await page.evaluate(() => {
      const states = {};
      document
        .querySelectorAll("#issue-claim-rows .claim-row")
        .forEach((row) => {
          const key = row.querySelector('input[id^="issue-claim-key-"]').value;
          const sd = row.querySelector('input[id^="issue-claim-sd-"]').checked;
          states[key] = sd;
        });
      return states;
    });
    expect(sdStates.department).toBe(false);
    expect(sdStates.employee_id).toBe(true);

    await page.locator("#issue-submit").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);

    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    const summary = res.body.find((c) => c.vct === "urn:example:e2e-employee");
    expect(summary).toBeDefined();
    const issued = (await jsonGet(`${WALLET_URL}/api/credentials/${summary.id}`))
      .body;
    expect(issued.claims.department).toBe("IT");
    expect(issued.claims.employee_id).toBe("E-1");
    const payload = JSON.parse(
      Buffer.from(issued.raw.split(".")[1], "base64url").toString()
    );
    expect(payload.department).toBe("IT");
    expect(payload.employee_id).toBeUndefined();

    await page.goto(WALLET_URL);
    await page.locator(`#delete-${issued.id}`).click();
    await expect(page.locator(`#credential-${issued.id}`)).toHaveCount(0);

    await page.locator("#templates-link").click();
    const templateRow = page
      .locator(".template-row")
      .filter({ hasText: "e2e-employee" });
    await templateRow.locator("button", { hasText: "Delete" }).click();
    await expect(
      page.locator(".template-row-name", { hasText: "e2e-employee" })
    ).toHaveCount(0);
    await page.locator("#template-close").click();
  });

  test("saves the issue dialog contents as a template", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#issue-btn").click();

    await page.locator("#issue-vct").fill("urn:example:e2e-saved");
    await page.locator("#issue-claim-key-0").fill("member_id");
    await page.locator("#issue-claim-value-0").fill("M-1");
    // The catalogue takes a template, so it appears with the template name.
    await expect(page.locator("#issue-catalog")).toBeHidden();
    await page.locator("#issue-save-template").fill("e2e-saved-template");
    await expect(page.locator("#issue-catalog")).toBeVisible();

    await page.locator("#issue-submit").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);

    const tplRes = await jsonGet(
      `${WALLET_URL}/api/templates/e2e-saved-template`
    );
    expect(tplRes.body.vct).toBe("urn:example:e2e-saved");
    expect(tplRes.body.claims.member_id).toBe("M-1");

    // Pagination may hide the credential delete button, so cleanup uses the API.
    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    const issued = res.body.find((c) => c.vct === "urn:example:e2e-saved");
    expect(issued).toBeDefined();
    await fetch(`${WALLET_URL}/api/credentials/${issued.id}`, {
      method: "DELETE",
    });
    await fetch(`${WALLET_URL}/api/templates/e2e-saved-template`, {
      method: "DELETE",
    });
  });

  test("sets display values on the issued credential", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#issue-btn").click();
    await page.locator("#issue-vct").fill("urn:example:e2e-display");
    await page.locator("#issue-display-name").fill("E2E Badge");
    await page.locator("#issue-bg-color").fill("#0f766e");
    await page.locator("#issue-text-color").fill("#ffffff");
    await expect(page.locator("#issue-bg-color-picker")).toHaveValue("#0f766e");

    await page.locator("#issue-submit").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);

    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    const issued = res.body.find((c) => c.vct === "urn:example:e2e-display");
    expect(issued).toBeDefined();
    expect(issued.display.name).toBe("E2E Badge");
    expect(issued.display.background_color).toBe("#0f766e");
    expect(issued.display.text_color).toBe("#ffffff");

    await fetch(`${WALLET_URL}/api/credentials/${issued.id}`, {
      method: "DELETE",
    });
  });

  test("reveals the description behind an About control, only when there is one", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);
    await page.locator("#issue-btn").click();
    await page.locator("#issue-vct").fill("urn:example:e2e-desc");
    await page.locator("#issue-display-name").fill("Described Badge");
    await page
      .locator("#issue-display-description")
      .fill("A sample description shown behind About.");
    await page.locator("#issue-submit").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);

    const described = page.locator(
      '.credential-card[data-vct="urn:example:e2e-desc"]',
    );
    const plain = page.locator(
      '.credential-card[data-vct="urn:example:e2e-nodesc"]',
    );
    await expect(described.locator(".about-btn")).toHaveCount(1);

    await expect(described).not.toHaveClass(/desc-open/);
    await described.locator(".about-btn").click();
    await expect(described).toHaveClass(/desc-open/);
    await expect(described.locator(".cred-desc-body")).toContainText(
      "A sample description",
    );
    await page.locator("#issue-btn").click();
    await page.locator("#issue-vct").fill("urn:example:e2e-nodesc");
    await page.locator("#issue-submit").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);

    await expect(plain).toBeVisible();
    await expect(plain.locator(".about-btn")).toHaveCount(0);
    await expect(described).toHaveClass(/desc-open/);
    await described.locator(".about-btn").click();
    await expect(described).not.toHaveClass(/desc-open/);

    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    for (const vct of ["urn:example:e2e-desc", "urn:example:e2e-nodesc"]) {
      const c = res.body.find((x) => x.vct === vct);
      if (c) await fetch(`${WALLET_URL}/api/credentials/${c.id}`, { method: "DELETE" });
    }
  });

  test("shows status badges and revokes and re-activates a credential", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator(".credential-card")).toHaveCount(2);

    const card = page.locator('.credential-card[data-format="sdjwt"]').first();
    const id = await card.getAttribute("data-credential-id");
    await expect(card).toHaveAttribute("data-status", "active");
    await expect(page.locator(`#status-${id}`)).toHaveText("Active");
    await expect(page.locator(`#revoke-${id}`)).toHaveText("Revoke");

    await page.locator(`#revoke-${id}`).click();
    await expect(page.locator(`#status-${id}`)).toHaveText("Revoked");
    await expect(page.locator(`#credential-${id}`)).toHaveAttribute(
      "data-status",
      "revoked"
    );
    await expect(page.locator(`#revoke-${id}`)).toHaveText("Activate");

    const status = await jsonGet(
      `${WALLET_URL}/api/credentials/${id}/status`
    );
    expect(status.body.status).toBe(1);
    expect(status.body.managed).toBe(true);

    await page.locator(`#revoke-${id}`).click();
    await expect(page.locator(`#status-${id}`)).toHaveText("Active");
    const restored = await jsonGet(
      `${WALLET_URL}/api/credentials/${id}/status`
    );
    expect(restored.body.status).toBe(0);
  });

  test("shows a suspended credential and re-activates it", async ({ page }) => {
    await page.goto(WALLET_URL);
    const card = page.locator('.credential-card[data-format="sdjwt"]').first();
    const id = await card.getAttribute("data-credential-id");

    const suspend = await fetch(`${WALLET_URL}/api/credentials/${id}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: 2 }),
    });
    expect(suspend.ok).toBe(true);

    await page.reload();
    await expect(page.locator(`#status-${id}`)).toHaveText("Suspended");
    await expect(page.locator(`#credential-${id}`)).toHaveAttribute(
      "data-status",
      "suspended"
    );
    await expect(page.locator(`#revoke-${id}`)).toHaveText("Activate");

    await page.locator(`#revoke-${id}`).click();
    await expect(page.locator(`#status-${id}`)).toHaveText("Active");
    const restored = await jsonGet(
      `${WALLET_URL}/api/credentials/${id}/status`
    );
    expect(restored.body.status).toBe(0);
  });

  test("issues a credential without a status list via the dialog", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);
    await page.locator("#issue-btn").click();

    await page.locator("#issue-vct").fill("urn:example:e2e-nostatus");
    await page.locator("#issue-claim-key-0").fill("given_name");
    await page.locator("#issue-claim-value-0").fill("Erika");
    await page.locator("#issue-status-list").selectOption("none");

    await page.locator("#issue-submit").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);

    const card = page.locator(
      '.credential-card[data-vct="urn:example:e2e-nostatus"]'
    );
    await expect(card).toHaveAttribute("data-status", "none");
    const id = await card.getAttribute("data-credential-id");
    await expect(page.locator(`#revoke-${id}`)).toHaveCount(0);

    await page.locator(`#delete-${id}`).click();
    await expect(page.locator(`#credential-${id}`)).toHaveCount(0);
  });

  test("trust and certificate links live in the header dialog", async ({
    page,
    request,
  }) => {
    await page.goto(WALLET_URL);

    await expect(page.locator("#ca-cert-pem-link")).toBeHidden();
    await page.locator("#trust-link").click();
    await expect(page.locator("#trust-overlay")).toHaveClass(/active/);

    for (const id of ["ca-cert-pem-link", "ca-cert-jwks-link", "signing-jwks-link"]) {
      await expect(page.locator(`#${id}`)).toBeVisible();
    }
    const categories = page.locator("#trust-list-links .trust-items dt");
    await expect(categories).toHaveText(["Credential providers", "Relying party certificates", "Wallet providers"]);
    const credentialGroup = page.locator("#trust-list-links .trust-items dd").nth(0);
    await expect(credentialGroup.locator(".trust-links a")).toHaveText(["pid", "qeaa", "pub-eaa", "eaa"]);
    const walletGroup = page.locator("#trust-list-links .trust-items dd").nth(2);
    await expect(walletGroup.locator(".trust-links a")).toHaveText(["wallet-provider"]);
    const relyingPartyGroup = page.locator("#trust-list-links .trust-items dd").nth(1);
    await expect(relyingPartyGroup.locator(".trust-links a")).toHaveText(["access-ca", "registrar"]);
    const names = page.locator("#trust-list-links .trust-list-name");
    expect(await names.count()).toBeGreaterThan(0);
    for (const name of await names.allTextContents()) {
      expect(name.trim()).not.toBe("");
    }
    for (const id of ["tls-cert-pem-link", "tls-cert-jwks-link"]) {
      await expect(page.locator(`#${id}`)).toBeHidden();
    }

    const signing = await request.get(`${WALLET_URL}/.well-known/jwt-vc-issuer`);
    expect(signing.status()).toBe(200);
    expect(await signing.text()).toContain('"keys"');

    for (const href of [
      "/api/certificates/ca",
      "/api/certificates/ca?format=jwks",
      "/api/certificates/tls",
      "/api/certificates/tls?format=jwks",
    ]) {
      const res = await request.get(`${WALLET_URL}${href}`);
      expect(res.status()).toBe(200);
      const body = await res.text();
      if (href.includes("jwks")) {
        expect(body).toContain('"keys"');
      } else {
        expect(body).toContain("BEGIN CERTIFICATE");
      }
    }

    await page.locator("#trust-close").click();
    await expect(page.locator("#trust-overlay")).not.toHaveClass(/active/);
  });

  test("trust dialog adds a provider CA and an external list in popups and shows them under their lists", async ({ page, request }) => {
    // A retry starts without the entries of an earlier attempt.
    const state = await (await request.get(`${WALLET_URL}/api/trust`)).json();
    for (const e of state.entities || []) {
      if (e.name === "E2E provider") await request.delete(`${WALLET_URL}/api/trust/entities/${encodeURIComponent(e.id)}`);
    }
    await request.delete(`${WALLET_URL}/api/trust/lists?url=${encodeURIComponent(`${WALLET_URL}/api/trustlists/pid`)}`);
    const ca = await (await request.get(`${WALLET_URL}/api/certificates/ca`)).text();
    await page.goto(WALLET_URL);
    await page.locator("#trust-link").click();

    await page.locator("#trust-add-provider").click();
    await expect(page.locator("#trust-provider-overlay")).toHaveClass(/active/);
    await expect(page.locator("#trust-overlay")).not.toHaveClass(/active/);
    await page.locator("#trust-entity-list").selectOption("pid");
    await page.locator("#trust-entity-name").fill("E2E provider");
    await page.locator("#trust-entity-ca").fill(ca);
    await page.locator("#trust-entity-add").click();
    await expect(page.locator("#trust-overlay")).toHaveClass(/active/);
    const provider = page.locator("#trust-list-pid-added li").filter({ hasText: "E2E provider" });
    await expect(provider).toHaveCount(1);

    await page.locator("#trust-add-list").click();
    await expect(page.locator("#trust-external-overlay")).toHaveClass(/active/);
    await page.locator("#trust-list-url").fill(`${WALLET_URL}/api/trustlists/pid`);
    await page.locator("#trust-list-add").click();
    await expect(page.locator("#trust-overlay")).toHaveClass(/active/);
    await expect(page.locator("#trust-group-external")).toHaveText("External lists");
    await expect(page.locator("#trust-external-0-url")).toHaveText(`${WALLET_URL}/api/trustlists/pid`);

    await page.locator("#trust-external-0-remove").click();
    await expect(page.locator("#trust-group-external")).toHaveCount(0);
    await provider.locator(".trust-remove").click();
    await expect(provider).toHaveCount(0);

    const after = await (await request.get(`${WALLET_URL}/api/trust`)).json();
    expect((after.entities || []).filter((e) => e.name === "E2E provider")).toEqual([]);
    expect((after.lists || []).filter((l) => l.url === `${WALLET_URL}/api/trustlists/pid`)).toEqual([]);
  });
});

test.describe("Stored XSS", () => {
  // A status URI must remain one attribute value when another visitor renders it.
  test("a credential cannot inject an attribute into another visitor's page", async ({
    page,
    request,
  }) => {
    const b64 = (obj) =>
      Buffer.from(JSON.stringify(obj)).toString("base64url");
    const credential =
      b64({ alg: "ES256", typ: "dc+sd-jwt" }) +
      "." +
      b64({
        vct: "urn:xss-probe:1",
        iss: WALLET_URL,
        // The trailing // comments out text appended by the template.
        status: {
          status_list: {
            idx: 1,
            uri: 'http://x/" onmouseover="window.__XSS_FIRED=1;//',
          },
        },
      }) +
      "." +
      Buffer.alloc(64).toString("base64url");

    const imported = await request.post(`${WALLET_URL}/api/credentials`, {
      headers: { "Content-Type": "text/plain" },
      data: credential,
    });
    expect(imported.status()).toBe(201);

    await page.goto(WALLET_URL);
    await page.waitForSelector(".credential-card");

    const badge = page.locator(".status-badge.status-external").first();
    await expect(badge).toBeVisible();
    const attrs = await badge.evaluate((el) =>
      [...el.attributes].map((a) => a.name),
    );
    expect(attrs).not.toContain("onmouseover");

    const box = await badge.boundingBox();
    // The browser runs a mouseover handler while it dispatches the move.
    if (box) await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    expect(await page.evaluate(() => window.__XSS_FIRED)).toBeUndefined();
  });

  test("the wallet sends browser hardening headers", async ({ request }) => {
    const res = await request.get(`${WALLET_URL}/`);
    const csp = res.headers()["content-security-policy"] || "";
    // CSP blocks injected handlers through script-src without 'unsafe-inline'.
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain("script-src 'self' 'unsafe-inline'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(res.headers()["x-content-type-options"]).toBe("nosniff");
  });
});

test("EUDI offer scheme reports missing offer parameters through issuance", async ({ page }) => {
  await page.goto(WALLET_URL);
  await page.locator("#offer-input").fill("eu-eaa-offer://");
  const responsePromise = page.waitForResponse((response) =>
    response.request().method() === "POST" &&
    ["/api/offers", "/api/presentations"].includes(new URL(response.url()).pathname)
  );
  await page.locator("#process-btn").click();
  const response = await responsePromise;
  expect(new URL(response.url()).pathname).toBe("/api/offers");
  expect(response.status()).toBe(400);
  const body = await response.json();
  expect(body.error).toBe("invalid_request");
  expect(body.error_description).toContain("credential_offer");
  await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
  await expect(page.locator("#error-message")).toHaveText("The wallet refused the credential offer");
  await expect(page.locator("#consent-dialog")).toContainText("credential_offer");
});

// The error dialog is modal: it takes the focus, keeps Tab inside, closes with
// Escape and gives the focus back.
test("the error dialog works with the keyboard", async ({ page }) => {
  await page.goto(WALLET_URL);
  await page.locator("#offer-input").fill("this is garbage");
  await page.locator("#process-btn").click();
  await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
  await expect(page.locator("#error-title")).toBeFocused();
  await page.keyboard.press("Tab");
  await expect.poll(() => page.evaluate(() => !!document.activeElement.closest("#consent-overlay"))).toBe(true);
  await page.keyboard.press("Escape");
  await expect(page.locator("#consent-overlay")).not.toHaveClass(/active/);
  await expect(page.locator("#process-btn")).toBeFocused();
});

// An error from another flow arrives while the user types. A typed key must not
// dismiss it unread, and the focus goes back to the field afterwards.
test("a background error doesn't take keys typed elsewhere", async ({ page }) => {
  await page.goto(WALLET_URL);
  await page.locator("#offer-input").click();
  await page.keyboard.type("abc");
  await page.evaluate(() => fetch("api/offers", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ uri: "openid-credential-offer://?credential_offer=garbage" }),
  }));
  await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
  await page.keyboard.type(" more");
  await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
  await page.keyboard.press("Escape");
  await expect(page.locator("#offer-input")).toBeFocused();
});

test("a credential that can't be imported shows the reason in the import dialog", async ({ page }) => {
  await page.goto(WALLET_URL);
  await page.locator("#import-btn").click();
  await expect(page.locator("#import-overlay")).toHaveClass(/active/);
  await page.locator("#import-textarea").fill("not a credential");
  await page.locator("#import-submit").click();
  await expect(page.locator("#import-error")).toContainText("Import failed");
  await expect(page.locator("#import-overlay")).toHaveClass(/active/);

  await page.locator("#import-cancel").click();
  await page.locator("#import-btn").click();
  await expect(page.locator("#import-error")).toBeEmpty();
});

test.describe("Mobile layout", () => {
  test("footer stays reachable on a small viewport", async ({ page }) => {
    // Mobile browser controls change 100vh, so the footer must stay in the scrollable area.
    await page.setViewportSize({ width: 390, height: 480 });
    await page.goto(WALLET_URL);
    await page.waitForSelector(".credential-card");

    const reachable = await page.evaluate(() => {
      window.scrollTo(0, document.documentElement.scrollHeight);
      const r = document.querySelector("footer").getBoundingClientRect();
      return r.top < window.innerHeight && r.bottom > 0;
    });
    expect(reachable).toBe(true);
  });
});

test.describe("Transaction code in the consent dialog", () => {
  // An unreachable issuer lets the test inspect the transaction code input before issuance
  // completes.
  const offerWithTxCode = (txCode) => {
    const offer = {
      credential_issuer: "https://issuer.invalid",
      credential_configuration_ids: ["test-config"],
      grants: {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
          "pre-authorized_code": "test-code",
          tx_code: txCode,
        },
      },
    };
    return (
      "openid-credential-offer://?credential_offer=" +
      encodeURIComponent(JSON.stringify(offer))
    );
  };

  test.beforeEach(async () => {
    await denyPendingRequests();
  });

  test("dialog asks for the code and blocks an empty approval", async ({
    page,
  }) => {
    // This POST waits for the consent decision below, so it is not awaited.
    jsonPost(`${WALLET_URL}/api/offers`, {
      uri: offerWithTxCode({
        input_mode: "numeric",
        length: 6,
        description: "The code from your letter",
      }),
      interactive: true,
    }).catch(() => {});

    await page.goto(`${WALLET_URL}/?focus=overview&request=${await waitForPendingRequest()}`);
    const input = page.locator("#offer-tx-code-input");
    await expect(input).toBeVisible();

    await expect(input).toHaveAttribute("inputmode", "numeric");
    await expect(input).toHaveAttribute("maxlength", "6");
    await expect(page.locator("#offer-tx-code-description")).toHaveText(
      "The code from your letter"
    );

    await page.locator("#consent-approve").click();
    await expect(input).toHaveClass(/input-error/);
    await expect(page.locator("#consent-approve")).toBeEnabled();
    await expect(input).toBeVisible();
  });

  test("no input appears for an offer that needs no code", async ({ page }) => {
    jsonPost(`${WALLET_URL}/api/offers`, {
      uri: "openid-credential-offer://?credential_offer=" +
        encodeURIComponent(
          JSON.stringify({
            credential_issuer: "https://issuer.invalid",
            credential_configuration_ids: ["test-config"],
            grants: {
              "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "test-code",
              },
            },
          })
        ),
      interactive: true,
    }).catch(() => {});

    await page.goto(`${WALLET_URL}/?focus=overview&request=${await waitForPendingRequest()}`);
    await expect(page.locator("#consent-approve")).toBeVisible();
    await expect(page.locator("#offer-tx-code-input")).toHaveCount(0);
  });
});

test.describe("Offer dialog descriptions", () => {
  const longDescription =
    "A diploma that the university issues after the final examination. " +
    "It names the degree, the field of study, the grade and the date of the examination. " +
    "Employers and other universities ask for it when you apply.";
  let issuer;
  let issuerURL;

  test.beforeAll(async () => {
    issuer = http.createServer((req, res) => {
      if (req.url !== "/.well-known/openid-credential-issuer") {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" }).end(
        JSON.stringify({
          credential_issuer: issuerURL,
          credential_endpoint: issuerURL + "/credential",
          credential_configurations_supported: {
            "long-config": {
              format: "dc+sd-jwt",
              vct: "urn:example:e2e-diploma",
              credential_metadata: { display: [{ name: "Diploma", description: longDescription }] },
            },
            "short-config": {
              format: "dc+sd-jwt",
              vct: "urn:example:e2e-badge",
              credential_metadata: { display: [{ name: "Badge", description: "A badge." }] },
            },
            "employee_id_(eaa)_1.0.0": {
              format: "dc+sd-jwt",
              vct: "urn:example:e2e-employee",
              credential_metadata: { display: [{ name: "Employee ID", background_color: "#12345a" }] },
            },
          },
        })
      );
    });
    await new Promise((resolve) => issuer.listen(0, "127.0.0.1", resolve));
    issuerURL = `http://127.0.0.1:${issuer.address().port}`;
  });

  test.afterAll(async () => {
    await denyPendingRequests();
    await new Promise((resolve) => issuer.close(resolve));
  });

  test("a long description opens behind More and a short one has no button", async ({ page }) => {
    await denyPendingRequests();
    // This POST waits for the consent decision, so it is not awaited.
    jsonPost(`${WALLET_URL}/api/offers`, {
      uri:
        "openid-credential-offer://?credential_offer=" +
        encodeURIComponent(
          JSON.stringify({
            credential_issuer: issuerURL,
            credential_configuration_ids: ["long-config", "short-config"],
            grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "code" } },
          })
        ),
      interactive: true,
    }).catch(() => {});

    await page.setViewportSize({ width: 390, height: 800 });
    await page.goto(`${WALLET_URL}/?focus=overview&request=${await waitForPendingRequest()}`);
    await page.locator("#offer-credential-long-config-fold").click();
    const description = page.locator("#offer-description-long-config");
    const toggle = page.locator("#offer-description-long-config-toggle");
    await expect(description).toContainText("final examination");
    await expect(toggle).toBeVisible();
    await expect(toggle).toHaveText("More");
    const collapsed = await description.evaluate((el) => el.clientHeight);

    await toggle.click();
    await expect(toggle).toHaveText("Less");
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await expect(description).toHaveClass(/offer-description-open/);
    expect(await description.evaluate((el) => el.clientHeight)).toBeGreaterThan(collapsed);

    await toggle.click();
    await expect(toggle).toHaveText("More");
    await page.locator("#offer-credential-short-config-fold").click();
    await expect(page.locator("#offer-description-short-config")).toHaveText("A badge.");
    await expect(page.locator("#offer-description-short-config-toggle")).toBeHidden();

    await page.locator("#consent-deny").click();
  });

  // A configuration ID can hold characters that are not valid in an element
  // ID. The folded summary shows the card too.
  test("the card of a configuration ID with parentheses shows its display", async ({ page }) => {
    await denyPendingRequests();
    jsonPost(`${WALLET_URL}/api/offers`, {
      uri:
        "openid-credential-offer://?credential_offer=" +
        encodeURIComponent(
          JSON.stringify({
            credential_issuer: issuerURL,
            credential_configuration_ids: ["employee_id_(eaa)_1.0.0"],
            grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "code" } },
          })
        ),
      interactive: true,
    }).catch(() => {});

    await page.setViewportSize({ width: 390, height: 800 });
    await page.goto(`${WALLET_URL}/?focus=overview&request=${await waitForPendingRequest()}`);
    const prefix = "#offer-credential-employee_id__eaa__1_0_0";
    const summaryFace = page.locator(`${prefix}-fold-face`);
    await expect(summaryFace).toBeVisible();
    await expect(summaryFace).toHaveCSS("background-image", /rgb\(18, 52, 90\)/);

    await page.locator(`${prefix}-fold`).click();
    await expect(summaryFace).toBeHidden();
    await expect(page.locator(`${prefix}-face`)).toHaveCSS("background-image", /rgb\(18, 52, 90\)/);

    await page.locator("#consent-deny").click();
  });
});

test.describe("Deferred issuance in the UI", () => {
  test("nothing is shown when no issuance is outstanding", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator("#deferred-section")).toBeHidden();
  });

  test("the deferred API reports an empty list", async () => {
    const res = await jsonGet(`${WALLET_URL}/api/deferred`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  test("collecting an unknown deferred id is a 404", async () => {
    const res = await jsonPost(
      `${WALLET_URL}/api/deferred/no-such-id/collect`,
      {}
    );
    expect(res.status).toBe(404);
    expect(res.body.error).toBe("not_found");
    expect(res.body.error_description).toContain("no deferred issuance");
  });
});

test.describe("Auto-accept toggle", () => {
  test("names the mode and flips it at runtime", async ({ page }) => {
    // Earlier tests can leave consent pending, and that opens an overlay on local wallet
    // pages.
    const pending = await (await fetch(`${WALLET_URL}/api/requests`)).json();
    for (const req of pending) {
      await fetch(`${WALLET_URL}/api/requests/${req.id}/deny`, { method: "POST" });
    }
    await page.goto(WALLET_URL);
    const toggle = page.locator("#auto-accept-toggle");
    await expect(toggle).toHaveAttribute("aria-pressed", "false");

    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-pressed", "true");
    let config = await (await fetch(`${WALLET_URL}/api/config`)).json();
    expect(config.auto_accept).toBe(true);

    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-pressed", "false");
    config = await (await fetch(`${WALLET_URL}/api/config`)).json();
    expect(config.auto_accept).toBe(false);
  });
});

test.describe("A credential bound to a key the wallet does not hold", () => {
  // Presentations require the holder key (RFC 9901 §4.3 and ISO 18013-5 §9.1.3).
  // A credential bound to another wallet stays readable and cannot be presented.
  test("is marked on its card and in its summary", async ({ page }) => {
    const b64 = (obj) =>
      Buffer.from(JSON.stringify(obj)).toString("base64url");
    const coordinate = () => crypto.randomBytes(32).toString("base64url");
    const foreign =
      b64({ alg: "ES256", typ: "dc+sd-jwt" }) +
      "." +
      b64({
        iss: "https://foreign-issuer.example",
        vct: "urn:test:foreign-key:1",
        cnf: { jwk: { kty: "EC", crv: "P-256", x: coordinate(), y: coordinate() } },
      }) +
      "." +
      crypto.randomBytes(64).toString("base64url") +
      "~";

    const res = await fetch(`${WALLET_URL}/api/credentials`, {
      method: "POST",
      body: foreign,
    });
    expect(res.status).toBe(201);
    const imported = await res.json();
    expect(imported.key_binding_not_held).toBe(true);

    await page.goto(WALLET_URL);
    const card = page.locator(
      `.credential-card[data-credential-id='${imported.id}']`
    );
    await expect(card.locator(".status-unheld-key")).toHaveText("Bound to another key", {
      timeout: 5000,
    });
    await expect(card.locator(".status-unheld-key")).toHaveAttribute(
      "title",
      /doesn.t hold the holder key/
    );

    const own = page.locator(".credential-card[data-format='mdoc']").first();
    await expect(own.locator(".status-unheld-key")).toHaveCount(0);

    await fetch(`${WALLET_URL}/api/credentials/${imported.id}`, {
      method: "DELETE",
    });
  });
});

function activityJWT(subject) {
  return [JSON.stringify({ alg: "none", typ: "JWT" }), JSON.stringify({ sub: subject })]
    .map(value => Buffer.from(value).toString("base64url")).join(".") + ".fakesig";
}

test("activity starts collapsed and opens the sent presentation in the decoder", async ({ page }) => {
  await page.route("**/api/log*", route => route.fulfill({ json: [{
    time: "2026-10-01T08:00:00Z", action: "presentation", detail: "Sending presentation response", success: true,
    details: {
      event: "presentation_response", direction: "outbound", vp_token: { pid: ["presented-token"] },
      sent_credentials: [{ id: "cred-1", query_id: "pid", format: "dc+sd-jwt", disclosed: ["given_name"] }],
      presented_credentials: [{ id: "cred-1", query_id: "pid", format: "dc+sd-jwt", disclosed: ["given_name"],
        presentation: "presented-token", raw_credential: "private-stored-token", credential: { claims: { family_name: "NOT DISCLOSED" } } }],
    },
    payload: { label: "Response", body: { vp_token: { pid: ["presented-token"] } } },
  }] }));
  await page.goto(WALLET_URL);
  const entry = page.getByTestId("log-entry");
  await expect(entry).toHaveAttribute("data-event", "presentation_response");
  await expect(entry).toHaveAttribute("data-action", "presentation");
  await expect(entry.locator(".log-payload pre")).toBeHidden();
  await entry.getByTestId("log-entry-toggle").click();
  await expect(entry.locator(".log-payload pre")).toBeVisible();
  const labelColor = await entry.locator(".log-key").first().evaluate(el => getComputedStyle(el).color);
  await expect(entry.locator(".log-payload-label")).toHaveCSS("color", labelColor);
  await expect(entry.locator(".log-payload")).toHaveCSS("margin-top", "12px");
  await expect(entry.locator(".log-payload pre")).toContainText("presented-token");
  await expect(entry).not.toContainText("sent_credentials");
  await expect(entry).not.toContainText("presented_credentials");
  await expect(entry).not.toContainText("private-stored-token");
  await expect(entry).not.toContainText("NOT DISCLOSED");
  await expect(entry.getByText("Presented credentials", { exact: true })).toHaveCount(0);
  await expect(entry.locator('[data-testid="log-decoder-link"][data-query-id="pid"][data-token-index="0"]'))
    .toHaveJSProperty("href", WALLET_URL + "/decoder/#credential=presented-token");
});

test("an authorization challenge request opens its presentation in the decoder", async ({ page }) => {
  const form = { openid4vp_response: '{"response":"encrypted.jwe.value.here.tag"}', auth_session: "session-1" };
  await page.route("**/api/log*", route => route.fulfill({ json: [{
    time: "2026-10-01T08:00:00Z", action: "issuance", detail: "Authorization challenge request to https://issuer.example/challenge", success: true,
    details: { event: "authorization_challenge_request", direction: "outbound", method: "POST", url: "https://issuer.example/challenge",
      endpoint: "authorization_challenge", request: form, vp_token: { pid: ["presented-token"] } },
    payload: { label: "Request", body: form, wire: new URLSearchParams(form).toString() },
  }] }));
  await page.goto(WALLET_URL);
  const entry = page.getByTestId("log-entry");
  await entry.getByTestId("log-entry-toggle").click();
  await expect(entry.locator('[data-testid="log-decoder-link"][data-query-id="pid"][data-token-index="0"]'))
    .toHaveJSProperty("href", WALLET_URL + "/decoder/#credential=presented-token");
  await expect(entry.locator(".log-details")).not.toContainText("vp_token");
});

test("activity entries open the tokens inside their payload in the decoder", async ({ page }) => {
  const requestObject = activityJWT("request-object");
  const registration = activityJWT("registration-certificate");
  const proofs = [activityJWT("first-proof"), activityJWT("second-proof")];
  await page.route("**/api/log*", route => route.fulfill({ json: [{
    time: "2026-10-01T08:00:00Z", action: "issuance", detail: "Authorization challenge response from https://issuer.example/challenge", success: true,
    details: { event: "authorization_challenge_response", response: { error: "insufficient_authorization", openid4vp_request: { request: requestObject } } },
  }, {
    time: "2026-10-01T08:00:01Z", action: "issuance", detail: "Issuer metadata response from https://issuer.example", success: true,
    details: { event: "issuer_metadata_response", metadata: JSON.stringify({ issuer_info: [{ format: "registration_cert", data: registration }] }) },
  }, {
    time: "2026-10-01T08:00:02Z", action: "issuance", detail: "Request credential from https://issuer.example/credential", success: true,
    details: { event: "credential_request", proof_jwt: proofs[0], request: { proofs: { jwt: proofs } } },
  }] }));
  await page.goto(WALLET_URL);
  for (const entry of await page.getByTestId("log-entry").all()) await entry.getByTestId("log-entry-toggle").click();
  for (const [path, token] of [["openid4vp_request.request", requestObject], ["issuer_info[0].data", registration]]) {
    const link = page.locator(`[data-testid="log-decoder-link"][data-path="${path}"]`);
    await expect(link).toHaveText(`Open '${path}' in decoder`);
    await expect(link).toHaveJSProperty("href", WALLET_URL + "/decoder/#credential=" + encodeURIComponent(token));
  }
  // The proofs of one request share a button, and a picker chooses the proof.
  const request = page.locator('[data-testid="log-entry"][data-event="credential_request"]');
  const proofLink = request.getByTestId("log-decoder-link");
  await expect(proofLink).toHaveText("Open 'proofs.jwt' in decoder");
  for (const [index, proof] of proofs.entries()) {
    await request.getByTestId("log-decoder-pick").selectOption({ label: `${index + 1}/2` });
    await expect(proofLink).toHaveAttribute("data-path", `proofs.jwt[${index}]`);
    await expect(proofLink).toHaveJSProperty("href", WALLET_URL + "/decoder/#credential=" + encodeURIComponent(proof));
  }
  await expect(page.getByTestId("log-decoder-link")).toHaveCount(3);
});

test("an expanded activity entry shows its whole detail", async ({ page }) => {
  const detail = "The nonce endpoint https://issuer.example/nonce answers a POST with 405 and serves a c_nonce only over GET. "
    + "OID4VCI 1.0 §7.1 requires POST. Debug mode uses GET";
  await page.route("**/api/log*", route => route.fulfill({ json: [{
    time: "2026-10-01T08:00:00Z", action: "issuance", detail, success: true, severity: "warning",
    details: { event: "nonce_endpoint_get", url: "https://issuer.example/nonce" },
  }] }));
  await page.goto(WALLET_URL);
  const text = page.getByTestId("log-entry").locator(".log-detail");
  const clipped = () => text.evaluate(el => el.scrollWidth > el.clientWidth);
  expect(await clipped()).toBe(true);
  await page.getByTestId("log-entry-toggle").click();
  expect(await clipped()).toBe(false);
});

for (const event of ["presentation_response", "interactive_authorization_presentation"]) {
  test(`encrypted presentation activity opens every sent token for ${event}`, async ({ page }) => {
    const first = activityJWT("first-presentation");
    const second = activityJWT("second-presentation");
    const third = activityJWT("mdoc-presentation");
    await page.setViewportSize({ width: 320, height: 800 });
    await page.route("**/api/log*", route => route.fulfill({ json: [{
      time: "2026-10-01T08:00:00Z", action: "presentation", detail: "Sending presentation response", success: true,
      details: { event },
      payload: { label: "Response", encrypted: true, wire: "encrypted-response",
        body: { vp_token: { pid: [first, second], mdl: [third] } } },
    }] }));
    await page.goto(WALLET_URL);
    const entry = page.getByTestId("log-entry");
    await entry.getByTestId("log-entry-toggle").click();
    await expect(entry.locator(".log-payload > pre")).toHaveText("encrypted-response");
    const controls = entry.locator(".log-payload-controls");
    const links = controls.getByTestId("log-decoder-link");
    await expect(links).toHaveText(["Open 'pid' in decoder", "Open 'mdl' in decoder"]);
    await expect(controls.getByTestId("log-decoder-pick")).toHaveCount(1);
    await expect(entry.locator(".log-payload-heading .log-payload-view")).toHaveText("Encrypted view");
    const toggleBounds = await controls.getByTestId("log-payload-toggle").boundingBox();
    const linkBounds = await links.first().boundingBox();
    expect(linkBounds.height).toBeGreaterThanOrEqual(28);
    expect(toggleBounds.height).toBeCloseTo(linkBounds.height, 2);
    const payloadBounds = await entry.locator(".log-payload > pre").boundingBox();
    expect(linkBounds.y + linkBounds.height).toBeLessThanOrEqual(payloadBounds.y);
    for (const [queryID, tokenIndex, token, subject] of [
      ["pid", 0, first, "first-presentation"],
      ["pid", 1, second, "second-presentation"],
      ["mdl", 0, third, "mdoc-presentation"],
    ]) {
      if (queryID === "pid") await controls.getByTestId("log-decoder-pick").selectOption({ label: `${tokenIndex + 1}/2` });
      const link = entry.locator(`[data-testid="log-decoder-link"][data-query-id="${queryID}"][data-token-index="${tokenIndex}"]`);
      await expect(link).toHaveJSProperty("href", WALLET_URL + "/decoder/#credential=" + encodeURIComponent(token));
      const popupPromise = page.waitForEvent("popup");
      await link.click();
      const decoder = await popupPromise;
      await expect(decoder.locator("#input")).toHaveValue(token);
      await expect(decoder.locator('#output .section[data-section="payload"]')).toContainText(subject);
      await decoder.close();
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  });
}

test("request activity formats JSON strings and switches between decoded and encoded views", async ({ page }) => {
  const bodies = ['{"nonce":"test-nonce","claims":["given_name"]}', "signed.token.value"];
  await page.route("**/api/log*", route => route.fulfill({ json: bodies.map(body => ({
    time: "2026-10-01T08:00:00Z", action: "presentation", detail: "Presentation request", success: true,
    payload: { label: "Request", body, wire: "original-wire-value" },
  })) }));
  await page.goto(WALLET_URL);
  const entries = page.getByTestId("log-entry");
  await expect(entries).toHaveCount(2);
  for (const entry of await entries.all()) await entry.getByTestId("log-entry-toggle").click();
  await expect(entries.nth(0).locator(".log-payload > pre")).toHaveText("original-wire-value");
  await expect(entries.nth(0).locator(".log-payload-view")).toHaveText("Encoded view");
  await entries.nth(0).getByTestId("log-payload-toggle").click();
  await expect(entries.nth(0).locator(".log-payload > pre")).toHaveText("signed.token.value");
  await expect(entries.nth(0).locator(".log-payload-view")).toHaveText("Decoded view");
  await expect(entries.nth(0).getByTestId("log-payload-toggle")).toHaveText("View encoded");
  await entries.nth(1).getByTestId("log-payload-toggle").click();
  await expect(entries.nth(1).locator(".log-payload > pre")).toHaveText('{\n  "nonce": "test-nonce",\n  "claims": [\n    "given_name"\n  ]\n}');
});

test("encrypted activity starts with the wire value and toggles plaintext at phone width", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await page.route("**/api/log*", route => route.fulfill({ json: [{
    time: "2026-10-01T08:00:00Z", action: "issuance", detail: "Credential response", success: true,
    details: { event: "credential_response", response: { credential: "test-credential" } },
    payload: { label: "Response", body: '{"credential":"test-credential"}', encrypted: true, wire: "encrypted-wire-value".repeat(30) },
  }] }));
  await page.goto(WALLET_URL);
  const entry = page.getByTestId("log-entry");
  await expect(entry.locator(".log-payload > pre")).toBeHidden();
  await entry.getByTestId("log-entry-toggle").click();
  await expect(entry.locator(".log-payload-view")).toHaveText("Encrypted view");
  await expect(entry.locator(".log-payload > pre")).toBeVisible();
  await expect(entry.locator(".log-payload > pre")).toHaveText("encrypted-wire-value".repeat(30));
  await expect(entry.locator(".log-payload-label")).toHaveText("Response");
  const requests = [];
  page.on("request", request => requests.push(request.url()));
  const toggle = entry.getByTestId("log-payload-toggle");
  await expect(toggle).toHaveText("View decrypted");
  await toggle.click();
  await expect(toggle).toHaveText("View encrypted");
  await expect(entry.locator(".log-payload-view")).toHaveText("Decrypted view");
  await expect(entry.locator(".log-payload > pre")).toHaveText('{\n  "credential": "test-credential"\n}');
  await toggle.click();
  await expect(toggle).toHaveText("View decrypted");
  await expect(entry.locator(".log-payload-view")).toHaveText("Encrypted view");
  await expect(entry.locator(".log-payload > pre")).toHaveText("encrypted-wire-value".repeat(30));
  expect(requests).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test("encrypted activity without plaintext still shows the wire value", async ({ page }) => {
  await page.route("**/api/log*", route => route.fulfill({ json: [{
    time: "2026-10-01T08:00:00Z", action: "presentation", detail: "Presentation response", success: true,
    payload: { label: "Response", encrypted: true, wire: "encrypted-wire-value" },
  }] }));
  await page.goto(WALLET_URL);
  const entry = page.getByTestId("log-entry");
  await entry.getByTestId("log-entry-toggle").click();
  await expect(entry.locator(".log-payload-view")).toHaveText("Encrypted view");
  await expect(entry.locator(".log-payload > pre")).toHaveText("encrypted-wire-value");
  await expect(entry.getByTestId("log-payload-toggle")).toHaveCount(0);
});

test("an encrypted Digital Credentials API response shows the same result in both views", async ({ page }) => {
  await page.route("**/api/log*", route => route.fulfill({ json: [{
    time: "2026-10-01T08:00:00Z", action: "presentation", detail: "Returned the presentation to https://verifier.example through the Digital Credentials API", success: true,
    details: { event: "presentation_response", vp_token: { pid: ["presented-token"] },
      dc_api_result: { protocol: "openid4vp-v1-signed", data: { response: "encrypted-response" } } },
  }] }));
  await page.goto(WALLET_URL);
  const entry = page.getByTestId("log-entry");
  await entry.getByTestId("log-entry-toggle").click();
  await expect(entry.locator(".log-payload > pre"))
    .toHaveText(JSON.stringify({ protocol: "openid4vp-v1-signed", data: { response: "encrypted-response" } }, null, 2));
  await entry.getByTestId("log-payload-toggle").click();
  await expect(entry.locator(".log-payload > pre"))
    .toHaveText(JSON.stringify({ protocol: "openid4vp-v1-signed", data: { vp_token: { pid: ["presented-token"] } } }, null, 2));
});

test("activity details stay visible and decoded request JWTs open in the decoder", async ({ page }) => {
  const claims = { client_id: "https://verifier.example", nonce: "decoded-nonce" };
  const jwt = [JSON.stringify({ alg: "ES256", typ: "oauth-authz-req+jwt" }), JSON.stringify(claims)]
    .map(value => Buffer.from(value).toString("base64url")).join(".") + ".signature";
  await page.route("**/api/log*", route => route.fulfill({ json: [{
    time: "2026-10-01T08:00:00Z", action: "presentation", detail: "Presentation request", success: true,
    details: { event: "presentation_request", direction: "inbound", request_object: claims, request_origin: "https://origin.example" },
    payload: { label: "Request object", body: jwt },
  }] }));
  await page.goto(WALLET_URL);
  const entry = page.getByTestId("log-entry");
  await entry.getByTestId("log-entry-toggle").click();
  await expect(entry.getByText("https://origin.example", { exact: true })).toBeVisible();
  await expect(entry.locator("details > summary", { hasText: /^Details$/ })).toHaveCount(0);
  await expect(entry).not.toContainText("decoded-nonce");
  await expect(entry.locator(".log-payload > pre")).toHaveText(jwt);
  const popupPromise = page.waitForEvent("popup");
  await entry.getByTestId("log-decoder-link").click();
  const decoder = await popupPromise;
  await expect(decoder.locator("#input")).toHaveValue(jwt);
  await decoder.close();
});

test("import activity keeps credential context and links to its original token", async ({ page }) => {
  const jwt = [JSON.stringify({ alg: "ES256" }), JSON.stringify({ name: "decoded-claim" })]
    .map(value => Buffer.from(value).toString("base64url")).join(".") + ".signature";
  await page.route("**/api/log*", route => route.fulfill({ json: [{
    time: "2026-10-01T08:00:00Z", action: "issuance", detail: "Credential imported", success: true,
    details: { event: "credential_imported", credential_id: "deleted-credential", format: "jwt_vc_json",
      raw_credential: jwt, credential: { raw: jwt, claims: { name: "decoded-claim" } } },
    payload: { label: "Credential", body: jwt },
  }] }));
  await page.goto(WALLET_URL);
  const entry = page.getByTestId("log-entry");
  await entry.getByTestId("log-entry-toggle").click();
  await expect(entry.getByText("deleted-credential", { exact: true })).toBeVisible();
  await expect(entry).not.toContainText("decoded-claim");
  await expect(entry.locator(".log-payload > pre")).toHaveText(jwt);
  await expect(entry.getByTestId("log-decoder-link"))
    .toHaveJSProperty("href", WALLET_URL + "/decoder/#credential=" + encodeURIComponent(jwt));
});

for (const shape of ["encrypted JSON", "JSON", "object", "legacy details", "deferred JSON", "encrypted deferred JSON"]) {
  test(`credential response decoder links open every batch instance from ${shape}`, async ({ page }) => {
    const subjects = ["first-instance", "second-instance", "primary-instance"];
    const tokens = subjects.map(activityJWT);
    const response = { credentials: tokens.map(credential => ({ credential })) };
    const encrypted = shape.startsWith("encrypted");
    const event = shape.includes("deferred") ? "deferred_credential_response" : "credential_response";
    await page.route("**/api/log*", route => route.fulfill({ json: [
      { time: "2026-10-01T08:00:00Z", action: "issuance", detail: "Credential response", success: true,
        details: { event, response },
        ...(shape === "legacy details" ? {} : { payload: { label: "Response",
          body: shape === "object" ? response : JSON.stringify(response),
          ...(encrypted ? { encrypted: true, wire: "encrypted-batch-response" } : {}) } }) },
      { time: "2026-10-01T08:00:01Z", action: "issuance", detail: "Imported credential primary-id", success: true,
        details: { event: "credential_imported", credential_id: "primary-id", raw_credential: tokens[2],
          credential: { raw: tokens[2] } } },
    ] }));
    await page.goto(WALLET_URL);
    const responseEntry = page.locator(`[data-testid="log-entry"][data-event="${event}"]`);
    await expect(responseEntry).toHaveCount(1);
    await expect(responseEntry.getByTestId("log-entry-toggle")).toContainText("Credential response (3 copies)");
    await responseEntry.getByTestId("log-entry-toggle").click();
    await expect(responseEntry.getByTestId("log-decoder-link")).toHaveText(["Open in decoder"]);
    if (encrypted) await expect(responseEntry.locator(".log-payload > pre")).toHaveText("encrypted-batch-response");
    else await expect(responseEntry.locator(".log-payload > pre")).toHaveText(JSON.stringify(response, null, 2));
    for (const [index, token] of tokens.entries()) {
      await responseEntry.getByTestId("log-decoder-pick").selectOption({ label: `${index + 1}/3` });
      const link = responseEntry.locator(`[data-testid="log-decoder-link"][data-credential-index="${index}"]`);
      await expect(link).toHaveJSProperty("href", WALLET_URL + "/decoder/#credential=" + encodeURIComponent(token));
      const popupPromise = page.waitForEvent("popup");
      await link.click();
      const decoder = await popupPromise;
      await expect(decoder.locator("#input")).toHaveValue(token);
      await expect(decoder.locator('#output .section[data-section="payload"]')).toContainText(subjects[index]);
      await decoder.close();
    }
    const imported = page.locator('[data-testid="log-entry"][data-event="credential_imported"]');
    await expect(imported).toHaveAttribute("data-credential-id", "primary-id");
    await expect(imported.getByTestId("log-entry-toggle")).toContainText("Imported credential primary-id");
    await imported.getByTestId("log-entry-toggle").click();
    await expect(imported.locator(".log-payload-label")).toHaveText("Credential");
    await expect(imported.getByTestId("log-decoder-link")).toHaveCount(1);
    await expect(imported.getByTestId("log-decoder-link")).toHaveJSProperty("href", WALLET_URL + "/decoder/#credential=" + encodeURIComponent(tokens[2]));
  });
}

test("a signed response in the activity log opens in the decoder", async ({ page }) => {
  const token = activityJWT("signed-metadata");
  await page.route("**/api/log*", route => route.fulfill({ json: [
    { time: "2026-10-01T08:00:00Z", action: "issuance", detail: "Issuer metadata response from https://issuer.example", success: true,
      details: { event: "issuer_metadata_response" }, payload: { label: "Response", body: token } },
    { time: "2026-10-01T08:00:01Z", action: "issuance", detail: "Token response", success: true,
      details: { event: "token_response" }, payload: { label: "Response", body: JSON.stringify({ access_token: "opaque" }) } },
  ] }));
  await page.goto(WALLET_URL);
  const metadata = page.locator('[data-testid="log-entry"][data-event="issuer_metadata_response"]');
  await metadata.getByTestId("log-entry-toggle").click();
  await expect(metadata.getByTestId("log-decoder-link")).toHaveJSProperty("href", WALLET_URL + "/decoder/#credential=" + encodeURIComponent(token));
  const tokenResponse = page.locator('[data-testid="log-entry"][data-event="token_response"]');
  await tokenResponse.getByTestId("log-entry-toggle").click();
  await expect(tokenResponse.locator(".log-payload > pre")).toBeVisible();
  await expect(tokenResponse.getByTestId("log-decoder-link")).toHaveCount(0);
});

for (const shape of ["object", "JSON"]) {
  test(`batch import activity opens every stored credential from ${shape}`, async ({ page }) => {
    const subjects = ["first-import", "second-import", "third-import"];
    const tokens = subjects.map(activityJWT);
    const body = { credentials: tokens.map((credential, index) => ({ credential_id: `stored-${index}`, credential })) };
    await page.route("**/api/log*", route => route.fulfill({ json: [{
      time: "2026-10-02T08:00:00Z", action: "issuance", detail: "Imported credential stored-0", success: true,
      details: { event: "credential_imported", credential_id: "stored-0", raw_credential: tokens[0] },
      payload: { label: "Imported credentials", body: shape === "JSON" ? JSON.stringify(body) : body },
    }] }));
    await page.goto(WALLET_URL);
    const entry = page.getByTestId("log-entry");
    await expect(entry.getByTestId("log-entry-toggle")).toContainText("Imported credential (3 copies)");
    await entry.getByTestId("log-entry-toggle").click();
    await expect(entry.getByTestId("log-decoder-link")).toHaveText(["Open in decoder"]);
    await expect(entry.locator(".log-payload-label")).toHaveText("Credential (3 copies)");
    for (const [index, token] of tokens.entries()) {
      await entry.getByTestId("log-decoder-pick").selectOption(String(index));
      const link = entry.locator(`[data-testid="log-decoder-link"][data-credential-id="stored-${index}"]`);
      await expect(link).toHaveAttribute("data-credential-index", String(index));
      const popupPromise = page.waitForEvent("popup");
      await link.click();
      const decoder = await popupPromise;
      await expect(decoder.locator("#input")).toHaveValue(token);
      await expect(decoder.locator('#output .section[data-section="payload"]')).toContainText(subjects[index]);
      await decoder.close();
    }
    await expect(entry.locator(".log-payload > pre")).toHaveText(JSON.stringify(body, null, 2));
  });
}

test("fetched request objects appear once with HTTP context and a decoder link", async ({ page }) => {
  const jwt = "request.header.signature";
  await page.route("**/api/log*", route => route.fulfill({ json: [
    { time: "2026-10-01T08:00:00Z", action: "presentation", detail: "Fetch request object", success: true,
      details: { event: "request_object_fetch_request", method: "GET", url: "https://verifier.example/request" },
      payload: { label: "Request", body: "GET https://verifier.example/request" } },
    { time: "2026-10-01T08:00:01Z", action: "presentation", detail: "Request object fetch response", success: true,
      details: { event: "request_object_fetch_response", method: "GET", url: "https://verifier.example/request", status_code: 200 },
      payload: { label: "Response", encrypted: true, wire: "encrypted-request-object", body: jwt } },
    { time: "2026-10-01T08:00:02Z", action: "presentation", detail: "Validation warning", success: true, severity: "warning" },
    { time: "2026-10-01T08:00:03Z", action: "presentation", detail: "Received presentation request", success: true,
      details: { event: "presentation_request", source: "http", request_origin: "https://origin.example",
        request_object: { nonce: "decoded-nonce", method: "JWT extension", status_code: 999 } },
      payload: { label: "Request object", body: jwt } },
  ] }));
  await page.goto(WALLET_URL);
  await expect(page.getByTestId("log-entry")).toHaveCount(3);
  await expect(page.getByTestId("log-entry").filter({ hasText: "Fetch request object" })).toHaveCount(1);
  await expect(page.getByTestId("log-entry").filter({ hasText: "Validation warning" })).toHaveCount(1);
  const entry = page.getByTestId("log-entry").filter({ hasText: "Received presentation request" });
  await entry.getByTestId("log-entry-toggle").click();
  await expect(entry.getByText("200", { exact: true })).toBeVisible();
  await expect(entry.getByText("GET", { exact: true })).toBeVisible();
  await expect(entry.getByText("https://origin.example", { exact: true })).toBeVisible();
  await expect(entry.locator(".log-payload > pre")).toHaveText("encrypted-request-object");
  await expect(entry.getByTestId("log-decoder-link"))
    .toHaveJSProperty("href", WALLET_URL + "/decoder/#credential=" + jwt);
  await entry.getByTestId("log-payload-toggle").click();
  await expect(entry.locator(".log-payload > pre")).toHaveText(jwt);
  await expect(entry).not.toContainText("decoded-nonce");
});

for (const scenario of ["different token", "repeated receipt", "failed fetch"]) {
  test(`request object activity keeps separate entries for ${scenario}`, async ({ page }) => {
    const received = { time: "2026-10-01T08:00:01Z", action: "presentation", detail: "Received presentation request", success: true,
      details: { event: "presentation_request", request_object: { nonce: "test-nonce" } },
      payload: { label: "Request object", body: scenario === "different token" ? "another.token.signature" : "request.header.signature" } };
    const log = [{ time: "2026-10-01T08:00:00Z", action: "presentation", detail: "Request object fetch response", success: scenario !== "failed fetch",
      details: { event: "request_object_fetch_response", status_code: scenario === "failed fetch" ? 400 : 200 },
      payload: { label: "Response", body: "request.header.signature" } }, received];
    if (scenario === "repeated receipt") log.push(received);
    await page.route("**/api/log*", route => route.fulfill({ json: log }));
    await page.goto(WALLET_URL);
    await expect(page.getByTestId("log-entry")).toHaveCount(2);
    for (const entry of await page.getByTestId("log-entry").all()) await entry.getByTestId("log-entry-toggle").click();
    await expect(page.getByTestId("log-decoder-link")).toHaveCount(2);
  });
}

// OpenID4VP 1.0 §8.2: the verifier can answer an Authorization Error Response with a
// redirect_uri, and the wallet must send the user agent there.
test.describe("Verifier redirect after an error response", () => {
  let verifier;
  let verifierURL;
  let received;

  test.beforeAll(async () => {
    verifier = http.createServer((req, res) => {
      if (req.method === "POST") {
        let body = "";
        req.on("data", (d) => (body += d));
        req.on("end", () => {
          received = new URLSearchParams(body);
          res.setHeader("Content-Type", "application/json");
          const reply = req.url === "/response" ? { redirect_uri: `${verifierURL}/continue` } : {};
          res.end(JSON.stringify(reply));
        });
        return;
      }
      res.setHeader("Content-Type", "text/html");
      res.end("<title>verifier</title><p>continued</p>");
    });
    await new Promise((resolve) => verifier.listen(0, "127.0.0.1", resolve));
    verifierURL = `http://127.0.0.1:${verifier.address().port}`;
  });

  test.afterAll(async () => {
    await new Promise((resolve) => verifier.close(resolve));
  });

  test.beforeEach(async () => {
    received = undefined;
    await denyPendingRequests();
  });

  const requestFor = (vct, responsePath = "/response") => {
    const responseURI = `${verifierURL}${responsePath}`;
    return "openid4vp://authorize?" + new URLSearchParams({
      client_id: `redirect_uri:${responseURI}`,
      response_type: "vp_token",
      response_mode: "direct_post",
      response_uri: responseURI,
      nonce: "n",
      state: "s",
      dcql_query: JSON.stringify({
        credentials: [{ id: "pid", format: "dc+sd-jwt", meta: { vct_values: [vct] } }],
      }),
    });
  };

  test("denying in the consent dialog continues at the verifier", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#offer-input").fill(requestFor("urn:eudi:pid:1"));
    await page.locator("#process-btn").click();
    await page.locator("#consent-deny").click();

    await page.waitForURL(`${verifierURL}/continue`);
    expect(received.get("error")).toBe("access_denied");
  });

  test("denying stays in the wallet when the verifier sends no redirect_uri", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#offer-input").fill(requestFor("urn:eudi:pid:1", "/response-without-redirect"));
    await page.locator("#process-btn").click();
    await page.locator("#consent-deny").click();

    await expect(page.locator("#consent-deny")).toBeHidden();
    await expect.poll(() => received?.get("error")).toBe("access_denied");
    expect(page.url()).toBe(`${WALLET_URL}/`);
  });

  // With consent the dialog asks for a pick (see the non-matching tests below).
  // Auto-accept refuses the request.
  test("a request without a matching credential continues at the verifier", async ({ page, request }) => {
    await request.put(`${WALLET_URL}/api/config/auto-accept`, { data: { enabled: true } });
    try {
      await page.goto(WALLET_URL);
      await page.locator("#offer-input").fill(requestFor("urn:nobody:holds:this"));
      await page.locator("#process-btn").click();

      await page.waitForURL(`${verifierURL}/continue`);
      expect(received.get("error")).toBe("access_denied");
    } finally {
      await request.put(`${WALLET_URL}/api/config/auto-accept`, { data: { enabled: false } });
    }
  });
});

for (const mode of ["debug", "strict"]) {
  // OpenID4VP 1.0 §6.4.1 lets the verifier list claim_sets in preference order.
  // The user can send another matching set.
  test.describe(`Claim set choice in the consent dialog in ${mode} mode`, () => {
    let verifier;
    let verifierURL;
    let received;

    test.beforeAll(async () => {
      verifier = http.createServer((req, res) => {
        let body = "";
        req.on("data", (d) => (body += d));
        req.on("end", () => {
          received = new URLSearchParams(body);
          res.setHeader("Content-Type", "application/json");
          res.end("{}");
        });
      });
      await new Promise((resolve) => verifier.listen(0, "127.0.0.1", resolve));
      verifierURL = `http://127.0.0.1:${verifier.address().port}`;
    });

    test.afterAll(async () => {
      await new Promise((resolve) => verifier.close(resolve));
    });

    test.beforeEach(async ({ request }) => {
      received = undefined;
      await denyPendingRequests();
      await request.put(`${WALLET_URL}/api/config/conformance`, { data: { validation_mode: mode, require_haip: false } });
    });

    test.afterEach(async ({ request }) => {
      await request.delete(`${WALLET_URL}/api/config/conformance`);
    });

    test("the chosen claim set reaches the verifier", async ({ page }) => {
      const responseURI = `${verifierURL}/response`;
      const uri = "openid4vp://authorize?" + new URLSearchParams({
        client_id: `redirect_uri:${responseURI}`,
        response_type: "vp_token",
        response_mode: "direct_post",
        response_uri: responseURI,
        nonce: "n",
        state: "s",
        dcql_query: JSON.stringify({
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
        }),
      });
      jsonPost(`${WALLET_URL}/api/presentations`, { uri, interactive: true }).catch(() => {});
      await page.goto(`${WALLET_URL}/?request=${await waitForPendingRequest()}`);
      // The note names the claim set the wallet sends. The other sets appear after
      // a click on Show all claim sets.
      const note = page.locator("#consent-claim-set-pid-current");
      await expect(note).toHaveText("The verifier accepts 2 claim sets. The wallet sends the first.");
      await expect(page.locator("#consent-claim-set-pid")).toHaveCount(0);
      const toggle = page.locator("#consent-show-claim-sets-pid");
      await toggle.click();
      await expect(toggle).toBeFocused();
      await expect(toggle).toHaveAttribute("aria-expanded", "true");
      await expect(page.locator("#consent-claim-set-pid .consent-claim-set-keys")).toHaveText(["given_name, family_name", "given_name, birthdate"]);
      await page.locator("#consent-claim-set-pid-1").check();
      await expect(note).toHaveText("The verifier accepts 2 claim sets. The wallet sends set 2.");
      await expect(page.locator('.consent-claim input[data-claim="birthdate"]')).toBeChecked();
      await page.locator("#consent-approve").click();

      await expect.poll(() => received?.get("vp_token")).toBeTruthy();
      const presentation = JSON.parse(received.get("vp_token")).pid[0];
      const disclosed = presentation.split("~").slice(1, -1)
        .map((d) => JSON.parse(Buffer.from(d, "base64url").toString())[1])
        .sort();
      expect(disclosed).toEqual(["birthdate", "given_name"]);
    });
  });

  // You can answer a verifier with a credential that does not match its query.
  test.describe(`Non-matching credentials in ${mode} mode`, () => {
    let verifier;
    let verifierURL;
    let received;

    test.beforeAll(async () => {
      verifier = http.createServer((req, res) => {
        let body = "";
        req.on("data", (d) => (body += d));
        req.on("end", () => {
          received = new URLSearchParams(body);
          res.setHeader("Content-Type", "application/json");
          res.end("{}");
        });
      });
      await new Promise((resolve) => verifier.listen(0, "127.0.0.1", resolve));
      verifierURL = `http://127.0.0.1:${verifier.address().port}`;
    });

    test.afterAll(async () => {
      await new Promise((resolve) => verifier.close(resolve));
    });

    test.beforeEach(async ({ request }) => {
      received = undefined;
      await denyPendingRequests();
      await request.put(`${WALLET_URL}/api/config/conformance`, { data: { validation_mode: mode, require_haip: false } });
    });

    test.afterEach(async ({ request }) => {
      await request.delete(`${WALLET_URL}/api/config/conformance`);
    });

    async function openRequest(page, vct) {
      const responseURI = `${verifierURL}/response`;
      const uri = "openid4vp://authorize?" + new URLSearchParams({
        client_id: `redirect_uri:${responseURI}`,
        response_type: "vp_token",
        response_mode: "direct_post",
        response_uri: responseURI,
        nonce: "n",
        state: "s",
        dcql_query: JSON.stringify({
          credentials: [{ id: "pid", format: "dc+sd-jwt", meta: { vct_values: [vct] }, claims: [{ path: ["given_name"] }] }],
        }),
      });
      jsonPost(`${WALLET_URL}/api/presentations`, { uri, interactive: true }).catch(() => {});
      await page.goto(`${WALLET_URL}/?request=${await waitForPendingRequest()}`);
      await expect(page.locator("#consent-approve")).toBeVisible();
    }

    function presentedFormats() {
      return JSON.parse(received.get("vp_token")).pid.map((t) => (t.includes("~") ? "dc+sd-jwt" : "mso_mdoc"));
    }

    test("a picked non-matching credential is sent with its reasons shown", async ({ page }) => {
      await openRequest(page, "urn:eudi:pid:1");
      await page.locator("#consent-edit-selection").click();
      await page.locator("#consent-show-nonmatching-pid").click();
      const other = page.locator('.candidate[data-non-matching="true"][data-query="pid"]').first();
      await expect(other.locator(".consent-mismatch")).toContainText("the query asks for dc+sd-jwt");
      await other.click();
      await page.locator("#consent-selection-done").click();
      await expect(page.locator(".consent-credential .consent-mismatch")).toBeVisible();
      await page.locator("#consent-approve").click();

      await expect.poll(() => received?.get("vp_token")).toBeTruthy();
      expect(presentedFormats()).toEqual(["mso_mdoc"]);
    });

    test("a request without a matching credential waits for a pick", async ({ page }) => {
      await openRequest(page, "urn:nobody:holds:this");
      await expect(page.locator("#consent-unanswered-pid")).toBeVisible();
      await expect(page.locator("#consent-approve")).toBeDisabled();
      await expect(page.locator("#consent-approve")).toHaveAttribute("aria-describedby", "consent-unanswered-pid");

      await page.locator("#consent-edit-selection").click();
      await page.locator('.candidate[data-non-matching="true"][data-query="pid"]').first().click();
      await page.locator("#consent-selection-done").click();
      await expect(page.locator("#consent-approve")).toBeEnabled();
      await page.locator("#consent-approve").click();

      await expect.poll(() => received?.get("vp_token")).toBeTruthy();
      expect(presentedFormats()).toHaveLength(1);
    });
  });
}

test.describe("ARF checks", () => {
  test.beforeEach(denyPendingRequests);
  test.afterEach(async () => {
    await new Promise((resolve) => {
      const req = http.request(`${WALLET_URL}/api/config/conformance`, { method: "DELETE" }, (res) => { res.resume(); res.on("end", resolve); });
      req.end();
    });
  });

  test("strict mode with --arf refuses a request without an access certificate", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#conformance-link").click();
    await page.locator("#conf-mode-select").selectOption("strict");
    await page.locator("#conf-arf-input").check();
    await expect.poll(async () => (await jsonGet(`${WALLET_URL}/api/config`)).body.require_arf).toBe(true);
    // The ARF builds on HAIP, so the HAIP checks turn on with it.
    await expect(page.locator("#conf-haip-input")).toBeChecked();

    const responseURI = "http://127.0.0.1:9/response";
    const uri = "openid4vp://?" + new URLSearchParams({
      client_id: `redirect_uri:${responseURI}`,
      response_type: "vp_token",
      response_mode: "direct_post",
      response_uri: responseURI,
      nonce: "n",
      state: "s",
      dcql_query: JSON.stringify({ credentials: [{ id: "pid", format: "dc+sd-jwt", meta: { vct_values: ["urn:eudi:pid:1"] } }] }),
    });
    // The page's session owns the refused request, so its error dialog stays on this page.
    const { status, body } = await page.evaluate(async (uri) => {
      const resp = await fetch("/api/presentations", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ uri }) });
      return { status: resp.status, body: await resp.json() };
    }, uri);
    expect(status).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("RPA_03");
    expect(body.findings).toEqual(expect.arrayContaining([expect.stringContaining("RPA_03")]));
    // The error dialog lists the findings one by one.
    await expect(page.locator("#error-message")).toHaveText("The wallet refused the request");
    await expect(page.locator("#error-findings li").filter({ hasText: "RPA_03" })).toHaveCount(1);
  });

  test("with --arf the offer dialog warns about an unregistered issuer", async ({ page }) => {
    const res = await fetch(`${WALLET_URL}/api/config/conformance`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ require_arf: true }),
    });
    expect(res.status).toBe(200);
    // The issuer serves unsigned metadata without issuer_info.
    const issuer = http.createServer((req, resp) => {
      const base = `http://127.0.0.1:${issuer.address().port}`;
      resp.setHeader("Content-Type", "application/json");
      resp.end(JSON.stringify({
        credential_issuer: base,
        credential_endpoint: `${base}/credential`,
        credential_configurations_supported: { diploma: { format: "dc+sd-jwt", vct: "urn:example:diploma:1" } },
      }));
    });
    await new Promise((resolve) => issuer.listen(0, "127.0.0.1", resolve));
    try {
      const offer = {
        credential_issuer: `http://127.0.0.1:${issuer.address().port}`,
        credential_configuration_ids: ["diploma"],
        grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "code" } },
      };
      jsonPost(`${WALLET_URL}/api/offers`, {
        uri: "openid-credential-offer://?credential_offer=" + encodeURIComponent(JSON.stringify(offer)),
        interactive: true,
      }).catch(() => {});
      await page.goto(`${WALLET_URL}/?focus=overview&request=${await waitForPendingRequest()}`);
      // The findings start as one collapsed line.
      const summary = page.locator("#consent-findings-summary");
      await expect(summary).toContainText("findings about this issuer");
      await expect(page.locator("#consent-findings-list")).toBeHidden();
      await summary.click();
      await expect(page.locator("#consent-findings-list")).toContainText("ARF ISSU_34: the Credential Issuer Metadata is not signed");
      await expect(page.locator("#consent-findings-list")).toContainText("ARF RPRC_22a");
    } finally {
      issuer.close();
    }
  });
});

test.describe("Registrar", () => {
  test.beforeEach(denyPendingRequests);

  // The register dialogs open from the relying parties list.
  async function openRegisterDialog(page, button = "#registrar-parties-register") {
    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();
    await page.locator(button).click();
    await expect(page.locator("#registrar-overlay")).toBeVisible();
  }

  // The list derives its element ids from the identifier like the UI does.
  const domID = (id) => id.replace(/[^A-Za-z0-9_-]/g, "_");

  function publicKeyOf(dir, file, command) {
    return execSync(`openssl ${command} -in ${file} -pubout 2>/dev/null`, { cwd: dir }).toString();
  }

  // A local wallet leaves the demo registrations to the user.
  test("the demo verifier can be changed like any registration", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();
    await page.locator("#registrar-search").fill("EUDI Dev Demo Verifier");
    const card = "#registrar-party-NLTEST_00000001";
    await expect(page.locator(card + "-identifier")).toHaveText("NLTEST.00000001");
    await expect(page.locator(card + "-protected")).toHaveCount(0);
    await expect(page.locator(card + "-delete")).toBeVisible();
    await expect(page.locator(card + "-add-use")).toBeVisible();
    await expect(page.locator(card + ' [id$="-summary-delete"]')).toBeVisible();
    await page.locator(card + ' [id$="-details"]').first().click();
    await expect(page.locator('#registrar-cert-body [id$="-delete"]')).toBeVisible();
    await expect(page.locator('#registrar-cert-body [id$="-revoke"]')).toBeVisible();
  });

  test("registering a verifier with the defaults issues both certificates", async ({ page }) => {
    await openRegisterDialog(page);
    await page.locator("#registrar-submit").click();
    await expect(page.locator("#registrar-result")).toBeVisible();
    await expect(page.locator("#registrar-result-identifier")).toHaveText(/^NLTEST\.[0-9A-F]{16}$/);
    await expect(page.locator("#registrar-client-id-0")).toContainText("x509_hash:");
    await expect(page.locator("#registrar-client-id-1")).toHaveText("x509_san_dns:verifier.example");

    // The browser creates the key, and the access certificate is issued for it.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-registrar-"));
    await expect(page.locator("#registrar-pem-label")).toHaveText("Signing key and access certificate chain");
    fs.writeFileSync(path.join(dir, "verifier.pem"), await page.locator("#registrar-pem").inputValue());
    expect(execSync("openssl x509 -in verifier.pem -noout -pubkey", { cwd: dir }).toString())
      .toBe(publicKeyOf(dir, "verifier.pem", "pkey"));

    const verifierInfo = JSON.parse(await page.locator("#registrar-verifier-info").inputValue());
    expect(verifierInfo[0].format).toBe("registration_cert");

    await expect(page.locator("#registrar-submit")).toHaveText("✓ Registered");
    await expect(page.locator("#registrar-submit")).toBeInViewport();
    await expect(page.locator("#registrar-submit")).toBeDisabled();
    await page.locator("#registrar-purpose").fill("Another purpose");
    await expect(page.locator("#registrar-submit")).toHaveText("Register verifier");
    await expect(page.locator("#registrar-submit")).toBeEnabled();
  });

  test("the register dialog parses claim paths and mdoc namespaces", async ({ page }) => {
    await openRegisterDialog(page);
    await page.locator("#registrar-credential-1-claims").fill("nationalities[*], address.locality");
    await page.locator("#registrar-add-credential").click();
    await page.locator("#registrar-credential-2-format").selectOption("mso_mdoc");
    await page.locator("#registrar-credential-2-type").fill("eu.europa.ec.eudi.pid.1");
    await page.locator("#registrar-credential-2-claims").fill("given_name, eu.europa.ec.eudi.pid.de.1:birth_name");
    await page.locator("#registrar-submit").click();
    await expect(page.locator("#registrar-result")).toBeFocused();
    const identifier = await page.locator("#registrar-result-identifier").textContent();
    const credentials = await page.evaluate(async (id) => {
      const resp = await fetch(`api/registrar/wrp/${id}`, { headers: { Accept: "application/json" } });
      return (await resp.json()).data.services[0].intendedUses[0].credentials;
    }, identifier);
    expect(credentials[0].claims).toEqual([{ path: ["nationalities", null] }, { path: ["address", "locality"] }]);
    expect(credentials[1].claims).toEqual([
      { path: ["eu.europa.ec.eudi.pid.1", "given_name"] },
      { path: ["eu.europa.ec.eudi.pid.de.1", "birth_name"] },
    ]);
  });

  test("the register dialog marks a missing name and closes with Escape", async ({ page }) => {
    await openRegisterDialog(page);
    await page.locator("#registrar-name").fill("");
    await page.locator("#registrar-submit").click();
    await expect(page.locator("#registrar-error")).toHaveText("The relying party needs a name.");
    await expect(page.locator("#registrar-name")).toHaveAttribute("aria-invalid", "true");
    await expect(page.locator("#registrar-name")).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(page.locator("#registrar-overlay")).toBeHidden();
    await expect(page.locator("#registrar-parties-overlay")).toBeVisible();
  });

  test("an own CSR keeps the key outside the wallet", async ({ page }) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-registrar-"));
    await openRegisterDialog(page);
    await page.locator("#registrar-csr-help-toggle").click();
    execSync(await page.locator("#registrar-csr-command").textContent(), { cwd: dir });

    await page.locator("#registrar-csr").fill(fs.readFileSync(path.join(dir, "verifier.csr"), "utf8"));
    await page.locator("#registrar-submit").click();
    await expect(page.locator("#registrar-result")).toBeVisible();
    await expect(page.locator("#registrar-pem-label")).toHaveText("Access certificate chain");
    expect(await page.locator("#registrar-pem").inputValue()).not.toContain("PRIVATE KEY");
    fs.writeFileSync(path.join(dir, "chain.pem"), await page.locator("#registrar-pem").inputValue());
    expect(execSync("openssl x509 -in chain.pem -noout -pubkey", { cwd: dir }).toString())
      .toBe(publicKeyOf(dir, "verifier.key", "ec"));
  });

  test("a registration certificate shows its purpose in the consent dialog", async ({ page }) => {
    await openRegisterDialog(page);
    await expect(page.locator("#registrar-credential-1-claims")).toHaveValue("age_equal_or_over.18");
    await page.locator("#registrar-submit").click();
    await expect(page.locator("#registrar-result")).toBeVisible();
    const verifierInfo = JSON.parse(await page.locator("#registrar-verifier-info").inputValue());
    const clientID = await page.locator("#registrar-client-id-0").textContent();
    const pem = await page.locator("#registrar-pem").inputValue();
    await page.locator("#registrar-close").click();

    // The wallet shows the purpose of a registration certificate bound to the
    // access certificate that signs the request (OpenID4VP 1.0 §5.1).
    const key = pem.match(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----/)[0];
    const x5c = [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/g)].map((m) => m[1].replace(/\s/g, ""));
    const responseURI = "http://127.0.0.1:9/response";
    const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
    const input = b64({ alg: "ES256", typ: "oauth-authz-req+jwt", x5c }) + "." + b64({
      client_id: clientID,
      response_type: "vp_token",
      response_mode: "direct_post",
      response_uri: responseURI,
      nonce: "n",
      state: "s",
      verifier_info: verifierInfo,
      dcql_query: { credentials: [{ id: "pid", format: "dc+sd-jwt", meta: { vct_values: ["urn:eudi:pid:1"] }, claims: [{ path: ["age_equal_or_over", "18"] }] }] },
    });
    const signature = crypto.sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" }).toString("base64url");
    const uri = "openid4vp://authorize?" + new URLSearchParams({ client_id: clientID, request: input + "." + signature });
    jsonPost(`${WALLET_URL}/api/presentations`, { uri, interactive: true }).catch(() => {});
    await page.goto(`${WALLET_URL}/?request=${await waitForPendingRequest()}`);
    await expect(page.locator("#consent-purpose-0")).toContainText("Age check before checkout");
    await page.locator("#consent-deny").click();
  });

  test("the relying parties list filters by role and deletes a registration", async ({ page }) => {
    const { status, body } = await jsonPost(`${WALLET_URL}/api/registrar/wrp`, {
      tradeName: "Listed Shop",
      services: [{ intendedUses: [{
        purpose: [{ lang: "en", content: "Listed purpose" }],
        credentials: [{ format: "dc+sd-jwt", meta: { vct_values: ["urn:eudi:pid:1"] }, claims: [{ path: ["given_name"] }] }],
      }] }],
    });
    expect(status).toBe(201);
    const card = "#registrar-party-" + domID(body.identifier[0].identifier);
    const use = card + "-use-" + body.services[0].intendedUses[0].intendedUseIdentifier;

    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();
    await expect(page.locator(card + "-role-verifier")).toBeVisible();
    await expect(page.locator(use + "-summary-title")).toHaveText("Listed purpose");

    // The demo issuer is an issuer in the register.
    const provider = await page.evaluate(async () => {
      const resp = await fetch("api/registrar/wrp?tradename=EUDI%20Dev%20Demo%20Issuer", { headers: { Accept: "application/json" } });
      return (await resp.json()).data[0].identifier[0].identifier;
    });
    await page.locator("#registrar-filter-issuers").check();
    await expect(page.locator(card)).toHaveCount(0);
    await expect(page.locator("#registrar-party-" + domID(provider) + "-role-issuer")).toBeVisible();
    await page.locator("#registrar-filter-verifiers").check();

    // The list shows one line for each certificate. Details opens the rest.
    await expect(page.locator(use + "-summary-status")).toHaveText("No certificate");
    await page.locator(use + "-details").click();
    await expect(page.locator("#registrar-cert-title")).toHaveText("Verifier registration certificate");
    await expect(page.locator(use + "-purpose")).toHaveText("Listed purpose");
    await expect(page.locator(use + "-status")).toHaveText("No certificate");
    await expect(page.locator(use + "-revoke")).toHaveCount(0);
    await expect(page.locator(use + "-issue")).toHaveText("Issue certificate");
    await page.locator(use + "-issue").click();
    await expect(page.locator(use + "-verifier-info")).toHaveValue(/registration_cert/);
    await expect(page.locator(use + "-status")).toHaveText("Active");
    await expect(page.locator(use + "-issue")).toHaveText("Issue new certificate");
    await page.locator(use + "-revoke").click();
    await expect(page.locator(use + "-status")).toHaveText("Revoked");
    await expect(page.locator(use + "-revoke")).toHaveText("Activate");
    await page.locator(use + "-revoke").click();
    await expect(page.locator(use + "-status")).toHaveText("Active");
    await expect(page.locator(use + "-revoke")).toHaveText("Revoke");
    await page.locator("#registrar-cert-close").click();
    await expect(page.locator(use + "-details")).toBeFocused();
    await expect(page.locator(use + "-summary-status")).toHaveText("Active");

    await page.locator(card + "-delete").click();
    await expect(page.locator(card)).toHaveCount(0);
    // Focus stays in the dialog, so Escape closes it.
    await expect(page.locator("#registrar-parties-title")).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(page.locator("#registrar-parties-overlay")).toBeHidden();
  });

  test("a changed intended use shows its certificate revoked for good", async ({ page }) => {
    const { body } = await jsonPost(`${WALLET_URL}/api/registrar/wrp`, {
      tradeName: "Changing Shop",
      services: [{ intendedUses: [{
        purpose: [{ lang: "en", content: "Age check" }],
        credentials: [{ format: "dc+sd-jwt", meta: { vct_values: ["urn:eudi:pid:1"] }, claims: [{ path: ["age_equal_or_over", "18"] }] }],
      }] }],
    });
    const identifier = body.identifier[0].identifier;
    const use = "#registrar-party-" + domID(identifier) + "-use-" + body.services[0].intendedUses[0].intendedUseIdentifier;
    await jsonPost(`${WALLET_URL}/api/registrar/registration-certificates`, { identifier, intendedUseIdentifier: body.services[0].intendedUses[0].intendedUseIdentifier });
    body.services[0].intendedUses[0].purpose = [{ lang: "en", content: "Marketing" }];
    await page.goto(WALLET_URL);
    await page.evaluate(async (rp) => {
      await fetch("api/registrar/wrp", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(rp) });
    }, body);

    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();
    await page.locator(use + "-details").click();
    await expect(page.locator(use + "-status")).toHaveText("Revoked");
    await expect(page.locator(use + "-revoke")).toHaveCount(0);
    await expect(page.locator(use + "-issue")).toHaveText("Issue new certificate");
    await page.locator(use + "-issue").click();
    await expect(page.locator(use + "-status")).toHaveText("Active");
  });

  test("the demo issuer and verifier get new certificates like any registration", async ({ page }) => {
    await page.goto(WALLET_URL);
    const identifierOf = (name) => page.evaluate(async (name) => {
      const resp = await fetch("api/registrar/wrp?tradename=" + encodeURIComponent(name), { headers: { Accept: "application/json" } });
      return (await resp.json()).data[0].identifier[0].identifier;
    }, name);
    const issuer = "#registrar-party-" + domID(await identifierOf("EUDI Dev Demo Issuer")) + "-service-issuance";
    const verifier = "#registrar-party-" + domID(await identifierOf("EUDI Dev Demo Verifier")) + "-use-demo-requests";
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();

    await page.locator("#registrar-search").fill("EUDI Dev Demo Issuer");
    await page.locator(issuer + "-details").click();
    await expect(page.locator(issuer + "-status")).toHaveText("Active");
    await page.locator(issuer + "-issue").click();
    await expect(page.locator(issuer + "-issuer-info")).toHaveValue(/registration_cert/);

    await page.locator("#registrar-cert-close").click();
    await page.locator("#registrar-search").fill("EUDI Dev Demo Verifier");
    await page.locator(verifier + "-details").click();
    await expect(page.locator(verifier + "-status")).toHaveText("Active");
    // The details show every credential and the current verifier_info. Each
    // credential opens its claims.
    await expect(page.locator(verifier + "-credentials > li")).toHaveCount(9);
    await expect(page.locator(verifier + "-verifier-info")).toHaveValue(/registration_cert/);
    await expect(page.locator(verifier + "-credential-0-claims")).toBeHidden();
    await page.locator(verifier + "-credential-0 summary").click();
    await expect(page.locator(verifier + "-credential-0-claims")).toContainText("given_name");
    await page.locator(verifier + "-issue").click();
    await expect(page.locator(verifier + "-verifier-info")).toHaveValue(/registration_cert/);
    await expect(page.locator(verifier + "-status")).toHaveText("Active");
  });

  // More parties than one page of GET /wrp holds, so the list follows the cursor.
  test("the relying parties list searches as you type and pages", async ({ page }) => {
    const tag = "Pager" + Date.now();
    for (let i = 1; i <= 22; i++) {
      await jsonPost(`${WALLET_URL}/api/registrar/wrp`, {
        tradeName: `${tag} Shop ${i}`,
        services: [{ intendedUses: [{
          purpose: [{ lang: "en", content: i === 7 ? `${tag} loyalty card check` : "Age check" }],
          credentials: [{ format: "dc+sd-jwt", meta: { vct_values: ["urn:eudi:pid:1"] }, claims: [{ path: ["given_name"] }] }],
        }] }],
      });
    }

    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();
    await page.locator("#registrar-search").fill(tag);
    await expect(page.locator("#registrar-party-list .registrar-party")).toHaveCount(10);
    await expect(page.locator("#registrar-page-info")).toHaveText("Page 1 of 3 · 22 relying parties");
    await expect(page.locator("#registrar-page-prev")).toBeDisabled();
    // The newest registration comes first.
    await expect(page.locator("#registrar-party-list .registrar-party-name").first()).toHaveText(`${tag} Shop 22`);
    await page.locator("#registrar-page-next").click();
    await page.locator("#registrar-page-next").click();
    await expect(page.locator("#registrar-party-list .registrar-party")).toHaveCount(2);
    await expect(page.locator("#registrar-page-next")).toBeDisabled();

    await expect(page.locator(`#registrar-search-suggestions option[value="${tag} Shop 3"]`)).toHaveCount(1);
    await page.locator("#registrar-search").fill(`${tag} loyalty card`);
    await expect(page.locator("#registrar-party-list .registrar-party-name")).toHaveText([`${tag} Shop 7`]);
    await expect(page.locator("#registrar-pager")).toBeHidden();
    await page.locator("#registrar-search").fill(tag + " nothing");
    await expect(page.locator("#registrar-party-empty")).toHaveText(`No relying party matches "${tag} nothing".`);

  });

  test("a registered relying party gets a further intended use and certificate", async ({ page }) => {
    const { body } = await jsonPost(`${WALLET_URL}/api/registrar/wrp`, {
      tradeName: "Growing Shop",
      services: [{ intendedUses: [{
        purpose: [{ lang: "en", content: "First purpose" }],
        credentials: [{ format: "dc+sd-jwt", meta: { vct_values: ["urn:eudi:pid:1"] }, claims: [{ path: ["given_name"] }] }],
      }] }],
    });
    const card = "#registrar-party-" + domID(body.identifier[0].identifier);

    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();
    await page.locator(card + "-add-use").click();
    await expect(page.locator("#registrar-title")).toContainText("Growing Shop");
    await expect(page.locator("#registrar-name")).toBeHidden();
    await expect(page.locator("#registrar-csr")).toBeHidden();
    await page.locator("#registrar-purpose").fill("Second purpose");
    await page.locator("#registrar-submit").click();
    await expect(page.locator("#registrar-submit")).toHaveText("✓ Added");
    await expect(page.locator("#registrar-verifier-info")).toHaveValue(/registration_cert/);
    await expect(page.locator("#registrar-client-ids")).toBeHidden();

    await page.locator("#registrar-close").click();
    await expect(page.locator("#registrar-parties-overlay")).toBeVisible();
    await expect(page.locator(card + " .registrar-cert-line")).toHaveCount(2);
    await expect(page.locator(card + " .registrar-cert-title").nth(1)).toHaveText("Second purpose");
  });

  test("a registered relying party gets an access certificate for its service", async ({ page }) => {
    const { body } = await jsonPost(`${WALLET_URL}/api/registrar/wrp`, {
      tradeName: "Keyless Shop",
      services: [{ intendedUses: [{
        purpose: [{ lang: "en", content: "Only purpose" }],
        credentials: [{ format: "dc+sd-jwt", meta: { vct_values: ["urn:eudi:pid:1"] }, claims: [{ path: ["given_name"] }] }],
      }] }],
    });
    const card = "#registrar-party-" + domID(body.identifier[0].identifier);

    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();
    await page.locator(card + "-service-default-access").click();
    await expect(page.locator("#registrar-title")).toHaveText("Issue an access certificate for Keyless Shop");
    await expect(page.locator("#registrar-purpose")).toBeHidden();
    await expect(page.locator("#registrar-target-service")).toBeHidden();
    await expect(page.locator("#registrar-registration-validity")).toBeHidden();
    await expect(page.locator("#registrar-csr")).toBeFocused();
    await expect(page.locator("#registrar-dns")).toHaveValue("");
    await page.locator("#registrar-dns").fill("shop.example");
    await page.locator("#registrar-submit").click();
    await expect(page.locator("#registrar-submit")).toHaveText("✓ Issued");
    await expect(page.locator("#registrar-result-identifier")).toHaveText(body.identifier[0].identifier);
    await expect(page.locator("#registrar-client-id-1")).toHaveText("x509_san_dns:shop.example");
    await expect(page.locator("#registrar-verifier-info")).toBeHidden();

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-registrar-"));
    await expect(page.locator("#registrar-pem-label")).toHaveText("Signing key and access certificate chain");
    fs.writeFileSync(path.join(dir, "verifier.pem"), await page.locator("#registrar-pem").inputValue());
    expect(execSync("openssl x509 -in verifier.pem -noout -subject", { cwd: dir }).toString()).toMatch(/CN ?= ?Keyless Shop/);
    expect(execSync("openssl x509 -in verifier.pem -noout -pubkey", { cwd: dir }).toString())
      .toBe(publicKeyOf(dir, "verifier.pem", "pkey"));

    // The registration and its registration certificates don't change.
    await page.locator("#registrar-close").click();
    await expect(page.locator(card + " .registrar-cert-line")).toHaveCount(1);
    await expect(page.locator(card + ' [id$="-summary-status"]')).toHaveText("No certificate");
    await page.locator(card + "-add-use").click();
    await expect(page.locator("#registrar-purpose")).toBeVisible();
    await expect(page.locator("#registrar-registration-validity")).toBeVisible();

    // The next dialog starts without the key and host names of this one.
    await page.locator("#registrar-close").click();
    await page.locator(card + "-service-default-access").click();
    await page.locator("#registrar-csr").fill("-----BEGIN CERTIFICATE REQUEST-----");
    await page.locator("#registrar-dns").fill("other.example");
    await page.locator("#registrar-close").click();
    await page.locator(card + "-service-default-access").click();
    await expect(page.locator("#registrar-csr")).toHaveValue("");
    await expect(page.locator("#registrar-dns")).toHaveValue("");
  });

  test("the registrar submenu works at phone width", async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 800 });
    await page.goto(WALLET_URL);
    await page.locator("#header-menu-toggle").click();
    await page.locator("#registrar-menu-toggle").click();
    await expect(page.locator("#registrar-menu-toggle")).toHaveAttribute("aria-expanded", "true");
    await page.locator("#registrar-parties-link").click();
    await expect(page.locator("#registrar-parties-overlay")).toBeVisible();
    await page.locator("#registrar-parties-register").click();
    await expect(page.locator("#registrar-overlay")).toBeVisible();
  });

  test("long names and service identifiers wrap inside the party card at phone width", async ({ page }) => {
    const name = "Unbrokenpartyname" + "x".repeat(60);
    await jsonPost(`${WALLET_URL}/api/registrar/wrp`, {
      tradeName: name,
      services: [
        { serviceIdentifier: "first", intendedUses: [{
          purpose: [{ lang: "en", content: "Purpose" }],
          credentials: [{ format: "dc+sd-jwt", meta: { vct_values: ["urn:eudi:pid:1"] }, claims: [{ path: ["given_name"] }] }],
        }] },
        { serviceIdentifier: "s" + "y".repeat(70), serviceTradeName: "Second" },
      ],
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(WALLET_URL);
    await page.locator("#header-menu-toggle").click();
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();
    await page.locator("#registrar-search").fill("Unbrokenpartyname");
    await expect(page.locator(".registrar-party")).toHaveCount(1);
    const overflow = (selector) => page.evaluate((s) => {
      const dialog = document.querySelector(s);
      return dialog.scrollWidth - dialog.clientWidth;
    }, selector);
    expect(await overflow("#registrar-parties-dialog")).toBeLessThanOrEqual(0);

    await page.locator('.registrar-party [id$="-access"]').last().click();
    expect(await overflow("#registrar-dialog")).toBeLessThanOrEqual(0);
    await page.locator("#registrar-close").click();
    await page.locator('.registrar-party [id$="-details"]').first().click();
    expect(await overflow("#registrar-cert-dialog")).toBeLessThanOrEqual(0);
  });

  test("registering an issuer issues its access certificate and issuer_info", async ({ page }) => {
    await openRegisterDialog(page, "#registrar-parties-register-issuer");
    await expect(page.locator("#registrar-title")).toHaveText("Register an issuer");
    await expect(page.locator("#registrar-party-section-label")).toHaveText("Issuer");
    await expect(page.locator("#registrar-purpose")).toBeHidden();
    await expect(page.locator("#registrar-dns")).toBeHidden();
    await expect(page.locator("#registrar-name")).toHaveValue("Example University");
    await expect(page.locator("#registrar-attestation-1-type")).toHaveValue("urn:example:diploma:1");

    await page.locator("#registrar-submit").click();
    await expect(page.locator("#registrar-result")).toBeVisible();
    await expect(page.locator("#registrar-submit")).toHaveText("✓ Registered");
    await expect(page.locator("#registrar-client-ids-block")).toBeHidden();
    await expect(page.locator("#registrar-verifier-info-block")).toBeHidden();
    await expect(page.locator("#registrar-pem-label")).toHaveText("Signing key and access certificate chain");
    // ETSI TS 119 472-3 V1.1.1 ISS-MDATA-REG_CERT-4.2.3-04 as adapted by CIR (EU) 2026/1731 Annex XI.
    const issuerInfo = JSON.parse(await page.locator("#registrar-issuer-info").inputValue());
    expect(issuerInfo.map((e) => e.format)).toEqual(["registration_cert"]);
    expect(registrationCertificateClaims(issuerInfo).provides_attestations).toEqual([{ format: "dc+sd-jwt", meta: { vct_values: ["urn:example:diploma:1"] } }]);

    // The verifier dialog gets its own fields and defaults back.
    await page.locator("#registrar-close").click();
    await page.locator("#registrar-parties-register").click();
    await expect(page.locator("#registrar-title")).toHaveText("Register a verifier");
    await expect(page.locator("#registrar-name")).toHaveValue("Example Verifier");
    await expect(page.locator("#registrar-purpose")).toBeVisible();
    await expect(page.locator("#registrar-submit")).toHaveText("Register verifier");
  });

  test("an issuer without attestations is not registered", async ({ page }) => {
    await openRegisterDialog(page, "#registrar-parties-register-issuer");
    await page.locator("#registrar-attestation-1-remove").click();
    await page.locator("#registrar-submit").click();
    await expect(page.locator("#registrar-error")).toHaveText("Add at least one attestation.");
    await expect(page.locator("#registrar-result")).toBeHidden();
  });

  test("the relying parties list shows an issuer's service and its certificate", async ({ page }) => {
    const { status, body } = await jsonPost(`${WALLET_URL}/api/registrar/wrp`, {
      tradeName: "Listed University",
      services: [{
        serviceIdentifier: "diplomas",
        entitlements: ["https://uri.etsi.org/19475/Entitlement/QEAA_Provider"],
        providesAttestations: [{ format: "mso_mdoc", type: "org.example.diploma.1" }],
      }],
    });
    expect(status).toBe(201);
    const card = "#registrar-party-" + domID(body.identifier[0].identifier);
    const service = card + "-service-diplomas";

    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();
    await page.locator("#registrar-filter-issuers").check();
    await expect(page.locator(card + "-role-issuer")).toBeVisible();
    await expect(page.locator(service + "-summary-title")).toHaveText("QEAA provider");
    await page.locator(service + "-details").click();
    await expect(page.locator(service + "-entitlement")).toHaveText("QEAA provider");
    await expect(page.locator(service + "-attestation-0 .registrar-credential-type")).toHaveText("org.example.diploma.1");
    await expect(page.locator(service + "-attestation-0 .registrar-credential-meta")).toHaveText("mso_mdoc");
    await expect(page.locator(service + "-status")).toHaveText("No certificate");

    await page.locator(service + "-issue").click();
    await expect(page.locator(service + "-issuer-info")).toHaveValue(/registration_cert/);
    await expect(page.locator(service + "-status")).toHaveText("Active");
    await page.locator(service + "-revoke").click();
    await expect(page.locator(service + "-status")).toHaveText("Revoked");
    await page.locator(service + "-revoke").click();
    await expect(page.locator(service + "-status")).toHaveText("Active");
    await page.locator("#registrar-cert-close").click();

    await page.locator(card + "-delete").click();
    await expect(page.locator(card)).toHaveCount(0);
  });

  test("a verifier adds an issuer registration certificate and issues as well", async ({ page }) => {
    const { body } = await jsonPost(`${WALLET_URL}/api/registrar/wrp`, {
      tradeName: "Ticket Shop",
      services: [{ intendedUses: [{
        purpose: [{ lang: "en", content: "Ticket check" }],
        credentials: [{ format: "dc+sd-jwt", meta: { vct_values: ["urn:eudi:pid:1"] }, claims: [{ path: ["given_name"] }] }],
      }] }],
    });
    const identifier = body.identifier[0].identifier;
    const card = "#registrar-party-" + domID(identifier);

    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();
    await expect(page.locator(card + "-add-issuer")).toHaveText("+ Add issuer registration certificate");
    await page.locator(card + "-add-issuer").click();
    await expect(page.locator("#registrar-title")).toHaveText("Add an issuer registration certificate to Ticket Shop");
    await expect(page.locator("#registrar-target-hint")).toContainText("Lists the attestation types below");
    await expect(page.locator("#registrar-purpose")).toBeHidden();
    await expect(page.locator("#registrar-name")).toBeHidden();
    await page.locator("#registrar-attestation-1-type").fill("urn:example:ticket:1");
    await page.locator("#registrar-submit").click();
    await expect(page.locator("#registrar-submit")).toHaveText("✓ Added");
    const issuerInfo = JSON.parse(await page.locator("#registrar-issuer-info").inputValue());
    expect(issuerInfo.map((e) => e.format)).toEqual(["registration_cert"]);

    await page.locator("#registrar-close").click();
    await expect(page.locator(card + "-role-issuer")).toBeVisible();
    await expect(page.locator(card + "-role-verifier")).toBeVisible();
    await expect(page.locator(card + "-service-default-summary-kind")).toHaveText("Issuer registration certificate");
    await expect(page.locator(card + "-service-default-summary-status")).toHaveText("Active");
    await expect(page.locator(card + "-add-issuer")).toHaveCount(0);

    // The registrar keeps the certificate, so the details show it later too.
    await page.reload();
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();
    await page.locator(card + "-service-default-details").click();
    await expect(page.locator(card + "-service-default-issuer-info")).toHaveValue(/registration_cert/);

    // Editing the types issues a new certificate for the changed list.
    await page.locator(card + "-service-default-edit").click();
    await expect(page.locator("#registrar-title")).toHaveText("Edit the attestation types of Ticket Shop");
    await expect(page.locator('#registrar-attestations [data-field="type"]')).toHaveValue("urn:example:ticket:1");
    await page.locator("#registrar-add-attestation").click();
    await page.locator('#registrar-attestations [data-field="type"]').nth(1).fill("urn:example:ticket:2");
    await expect(page.locator("#registrar-submit")).toHaveText("Save and issue certificate");
    await page.locator("#registrar-submit").click();
    await expect(page.locator("#registrar-submit")).toHaveText("✓ Saved");
    const edited = JSON.parse(await page.locator("#registrar-issuer-info").inputValue());
    expect(registrationCertificateClaims(edited).provides_attestations.map((a) => a.meta.vct_values[0])).toEqual(["urn:example:ticket:1", "urn:example:ticket:2"]);
    await page.locator("#registrar-close").click();
    await expect(page.locator(card + "-service-default-summary-status")).toHaveText("Active");
    await fetch(`${WALLET_URL}/api/registrar/wrp/${encodeURIComponent(body.identifier[0].identifier)}`, { method: "DELETE" });
  });

  test("deleting a registration certificate removes it from the registration and revokes it", async ({ page }) => {
    const { body } = await jsonPost(`${WALLET_URL}/api/registrar/wrp`, {
      tradeName: "Shrinking University",
      services: [{
        serviceIdentifier: "diplomas",
        providesAttestations: [{ format: "dc+sd-jwt", type: "urn:example:diploma:9" }],
        intendedUses: [{
          purpose: [{ lang: "en", content: "Identity check" }],
          credentials: [{ format: "dc+sd-jwt", meta: { vct_values: ["urn:eudi:pid:1"] }, claims: [{ path: ["given_name"] }] }],
        }],
      }],
    });
    const identifier = body.identifier[0].identifier;
    const useID = body.services[0].intendedUses[0].intendedUseIdentifier;
    await jsonPost(`${WALLET_URL}/api/registrar/registration-certificates`, { identifier, intendedUseIdentifier: useID });
    await jsonPost(`${WALLET_URL}/api/registrar/registration-certificates`, { identifier, serviceIdentifier: "diplomas" });
    const card = "#registrar-party-" + domID(identifier);
    const statuses = async () => (await jsonGet(`${WALLET_URL}/api/registrar/registration-certificates?identifier=${identifier}`)).body;

    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();

    // From the list.
    await page.locator(card + "-use-" + useID + "-summary-delete").click();
    await expect(page.locator(card + "-use-" + useID + "-summary")).toHaveCount(0);
    expect((await statuses()).filter((s) => s.intendedUse === useID).every((s) => s.revoked)).toBe(true);

    // From the details.
    await page.locator(card + "-service-diplomas-details").click();
    await page.locator(card + "-service-diplomas-delete").click();
    await expect(page.locator("#registrar-parties-overlay")).toBeVisible();
    await expect(page.locator(card + "-service-diplomas-summary")).toHaveCount(0);
    await expect(page.locator(card + "-add-issuer")).toBeVisible();
    expect((await statuses()).filter((s) => !s.intendedUse).every((s) => s.revoked)).toBe(true);
  });

  test("an issuer adds an intended use to ask for a PID before it issues", async ({ page }) => {
    const { body } = await jsonPost(`${WALLET_URL}/api/registrar/wrp`, {
      tradeName: "Checking University",
      services: [{
        serviceIdentifier: "diplomas",
        entitlements: ["https://uri.etsi.org/19475/Entitlement/QEAA_Provider"],
        providesAttestations: [{ format: "dc+sd-jwt", type: "urn:example:diploma:1" }],
      }],
    });
    const identifier = body.identifier[0].identifier;
    const card = "#registrar-party-" + domID(identifier);

    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();
    await expect(page.locator(card + "-service-diplomas-summary-kind")).toHaveText("Issuer registration certificate");
    await expect(page.locator(card + "-add-use")).toHaveText("+ Add verifier registration certificate");
    await page.locator(card + "-add-use").click();
    await expect(page.locator("#registrar-title")).toHaveText("Add a verifier registration certificate to Checking University");
    await expect(page.locator("#registrar-target-hint")).toContainText("Lets the issuer ask for credentials");
    await expect(page.locator("#registrar-purpose")).toHaveValue("Identity check before issuance");
    await expect(page.locator("#registrar-credentials [data-field=\"claims\"]").first()).toHaveValue("given_name, family_name");
    await page.locator("#registrar-purpose").fill("Checks who you are before a diploma is issued");
    await page.locator("#registrar-submit").click();
    await expect(page.locator("#registrar-submit")).toHaveText("✓ Added");
    await expect(page.locator("#registrar-verifier-info")).toHaveValue(/registration_cert/);

    await page.locator("#registrar-close").click();
    await expect(page.locator(card + "-role-issuer")).toBeVisible();
    await expect(page.locator(card + "-role-verifier")).toBeVisible();
    await expect(page.locator(card + ' [id^="' + card.slice(1) + '-use-"][id$="-summary-kind"]')).toHaveText("Verifier registration certificate");
    await expect(page.locator(card + ' [id^="' + card.slice(1) + '-use-"][id$="-summary-title"]')).toHaveText("Checks who you are before a diploma is issued");
    // One registration holds both roles (CIR (EU) 2025/848 Annex I).
    const signed = await (await fetch(`${WALLET_URL}/api/registrar/wrp/${identifier}`)).text();
    const stored = JSON.parse(Buffer.from(signed.split(".")[1], "base64url").toString()).data;
    expect(stored.services).toHaveLength(1);
    expect(stored.services[0].providesAttestations).toEqual([{ format: "dc+sd-jwt", type: "urn:example:diploma:1" }]);
    expect(stored.services[0].entitlements).toContain("https://uri.etsi.org/19475/Entitlement/Service_Provider");
  });

  // Entitlements belong to a service (TS6 v1.1 row 12). A registration
  // certificate covers a service or one of its intended uses (ARF RPRC_09,
  // RPRC_13) and lists the entitlements of the service.
  async function registerIssuerWithCertificate(name) {
    const { body } = await jsonPost(`${WALLET_URL}/api/registrar/wrp`, {
      tradeName: name,
      services: [{ serviceIdentifier: "diplomas", providesAttestations: [{ format: "dc+sd-jwt", type: "urn:example:diploma:1" }] }],
    });
    const identifier = body.identifier[0].identifier;
    await jsonPost(`${WALLET_URL}/api/registrar/registration-certificates`, { identifier, serviceIdentifier: "diplomas" });
    return { identifier, card: "#registrar-party-" + domID(identifier) };
  }
  async function openAddUse(page, card) {
    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();
    await page.locator(card + "-add-use").click();
  }

  test("an intended use on an issuer service says it revokes the issuer certificate and issues a new one", async ({ page }) => {
    const { card } = await registerIssuerWithCertificate("Reissuing University");
    await openAddUse(page, card);
    await expect(page.locator("#registrar-target-service")).toHaveValue("0");
    await expect(page.locator("#registrar-revocation-notice")).toContainText("The registrar revokes its issuer registration certificate");
    await page.locator("#registrar-submit").click();
    await expect(page.locator("#registrar-submit")).toHaveText("✓ Added");
    await expect(page.locator("#registrar-reissue")).toHaveText("Issue a new issuer registration certificate");
    await page.locator("#registrar-reissue").click();
    await expect(page.locator("#registrar-reissue")).toHaveText("✓ Issued");

    await page.locator("#registrar-close").click();
    await expect(page.locator(card + "-service-diplomas-summary-status")).toHaveText("Active");
  });

  test("a revoked certificate says that the entitlements of its service changed", async ({ page }) => {
    const { card } = await registerIssuerWithCertificate("Changing University");
    await openAddUse(page, card);
    await page.locator("#registrar-submit").click();
    await expect(page.locator("#registrar-submit")).toHaveText("✓ Added");
    await page.locator("#registrar-close").click();
    await expect(page.locator(card + "-service-diplomas-summary-status")).toHaveText("Revoked");
    await expect(page.locator(card + "-service-diplomas-summary-status")).toHaveAttribute("title", /Entitlements changed/);
  });

  test("an intended use on a new service keeps the issuer certificate valid", async ({ page }) => {
    const { identifier, card } = await registerIssuerWithCertificate("Separate University");
    await openAddUse(page, card);
    await page.locator("#registrar-target-service").selectOption("new");
    await expect(page.locator("#registrar-revocation-notice")).toContainText("own access certificate");
    await expect(page.locator("#registrar-csr")).toBeVisible();
    await page.locator("#registrar-new-service-id").fill("checks");
    await page.locator("#registrar-submit").click();
    await expect(page.locator("#registrar-submit")).toHaveText("✓ Added");
    await expect(page.locator("#registrar-pem")).toHaveValue(/BEGIN CERTIFICATE/);
    await expect(page.locator("#registrar-reissue-block")).toBeHidden();

    await page.locator("#registrar-close").click();
    await expect(page.locator(card + "-service-diplomas-summary-status")).toHaveText("Active");
    const signed = await (await fetch(`${WALLET_URL}/api/registrar/wrp/${identifier}`)).text();
    const stored = JSON.parse(Buffer.from(signed.split(".")[1], "base64url").toString()).data;
    expect(stored.services.map((s) => s.serviceIdentifier)).toEqual(["diplomas", "checks"]);
  });

  test("attestation types on a verifier service say they revoke its verifier certificates", async ({ page }) => {
    const { body } = await jsonPost(`${WALLET_URL}/api/registrar/wrp`, {
      tradeName: "Turning Shop",
      services: [{ intendedUses: [{
        purpose: [{ lang: "en", content: "Ticket check" }],
        credentials: [{ format: "dc+sd-jwt", meta: { vct_values: ["urn:eudi:pid:1"] }, claims: [{ path: ["given_name"] }] }],
      }] }],
    });
    const identifier = body.identifier[0].identifier;
    const useID = body.services[0].intendedUses[0].intendedUseIdentifier;
    await jsonPost(`${WALLET_URL}/api/registrar/registration-certificates`, { identifier, intendedUseIdentifier: useID });
    const card = "#registrar-party-" + domID(identifier);

    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();
    await page.locator(card + "-add-issuer").click();
    await expect(page.locator("#registrar-revocation-notice")).toContainText("revokes the certificate of 1 intended use");
    await page.locator("#registrar-attestation-1-type").fill("urn:example:ticket:7");
    await page.locator("#registrar-submit").click();
    await expect(page.locator("#registrar-submit")).toHaveText("✓ Added");
    await page.locator("#registrar-reissue").click();
    await expect(page.locator("#registrar-reissue")).toHaveText("✓ Issued");
    await page.locator("#registrar-close").click();
    await expect(page.locator(card + "-use-" + domID(useID) + "-summary-status")).toHaveText("Active");
  });

  test("the support field takes an email address", async ({ page }) => {
    await openRegisterDialog(page, "#registrar-parties-register");
    await expect(page.locator("#registrar-support-uri-label")).toHaveText("Support URL or email");
  });

  test("outside the demo the predefined catalogue entries can be deleted", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-catalog-link").click();
    const pid = page.locator("#registrar-catalog-list .registrar-party").filter({ hasText: "EUDI PID" }).first();
    await expect(pid.locator('[id$="-delete"]')).toBeVisible();
  });

  test("the attestation catalogue filters by category and security level", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-catalog-link").click();
    const names = page.locator("#registrar-catalog-list .registrar-party-name");
    await expect(names.filter({ hasText: "Demo Event Ticket" })).toHaveCount(1);

    await page.locator("#registrar-catalog-filter-category-pid").click();
    await expect(page.locator("#registrar-catalog-filter-category-pid")).toHaveAttribute("aria-pressed", "true");
    await expect(names.filter({ hasText: "EUDI PID" })).toHaveCount(1);
    await expect(names.filter({ hasText: "Demo Event Ticket" })).toHaveCount(0);

    // Values of one group add up. Groups narrow each other down.
    await page.locator("#registrar-catalog-filter-category-eaa").click();
    await expect(names.filter({ hasText: "Demo Event Ticket" })).toHaveCount(1);
    await page.locator("#registrar-catalog-filter-los-iso_18045_high").click();
    await expect(names.filter({ hasText: "EUDI PID" })).toHaveCount(1);
    await expect(names.filter({ hasText: "Demo Event Ticket" })).toHaveCount(0);

    await page.locator("#registrar-catalog-filter-clear").click();
    await expect(names.filter({ hasText: "Demo Event Ticket" })).toHaveCount(1);
    await expect(page.locator("#registrar-catalog-filter-clear")).toHaveCount(0);
  });

  test("the attestation catalogue lists the PID types and adds an attestation", async ({ page }) => {
    // A retry starts without entries added by an earlier attempt.
    for (const entry of (await jsonGet(`${WALLET_URL}/api/catalog/attestations`)).body) {
      if (entry.name.toLowerCase() === "library card") {
        await fetch(`${WALLET_URL}/api/catalog/schemas/${encodeURIComponent(entry.schema.id)}`, { method: "DELETE" });
      }
    }
    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-catalog-link").click();
    await expect(page.locator("#registrar-catalog-overlay")).toBeVisible();
    const pid = page.locator(".registrar-party", { hasText: "EUDI PID" }).first();
    await expect(pid.locator("[id$='-template']")).toHaveText("From a template");
    await expect(pid.locator("[id$='-formats']")).toContainText("dc+sd-jwt: urn:eudi:pid:1");
    await expect(pid.locator("[id$='-trust']")).toHaveAttribute("href", /\/api\/trustlists\/pid$/);
    await expect(pid.locator("button")).toHaveText(["Delete"]);

    await page.locator("#registrar-catalog-add").click();
    await expect(page.locator("#registrar-catalog-add-overlay")).toBeVisible();
    await expect(page.locator("#registrar-catalog-overlay")).toBeHidden();
    await expect(page.locator("#registrar-catalog-issuer-ca-hint")).toContainText("provider on the EAA trusted list");
    await page.locator("#registrar-catalog-category").selectOption("pid");
    await expect(page.locator("#registrar-catalog-issuer-ca-hint")).toContainText("provider on the PID trusted list");
    await page.locator("#registrar-catalog-category").selectOption("eaa");
    await page.locator("#registrar-catalog-name").fill("Library card");
    await page.locator("#registrar-catalog-format-1-type").fill("urn:example:library:1");
    await page.locator("#registrar-catalog-format-1-claims").fill("member_id, address.locality");
    await page.locator("#registrar-catalog-los").selectOption("iso_18045_moderate");
    await page.locator("#registrar-catalog-save").click();
    await expect(page.locator("#registrar-catalog-overlay")).toBeVisible();
    const card = page.locator(".registrar-party", { hasText: "Library card" });
    await expect(card.locator("[id$='-los']")).toHaveText("Level of security: Moderate");
    await expect(card.locator("[id$='-category']")).toHaveText("Category: EAA");
    await expect(card.locator("[id$='-trust']")).toHaveAttribute("href", /\/api\/trustlists\/eaa$/);

    // The schema link serves SD-JWT VC Type Metadata with the claims.
    const schemaURL = await card.locator("[id$='-schema-0']").getAttribute("href");
    const typeMetadata = await (await fetch(schemaURL.replace("https://localhost:18926", WALLET_URL))).json();
    expect(typeMetadata).toEqual({ vct: "urn:example:library:1", name: "Library card", claims: [{ path: ["member_id"] }, { path: ["address", "locality"] }] });

    // The registration dialogs suggest the new type.
    await page.locator("#registrar-catalog-close").click();
    await openRegisterDialog(page, "#registrar-parties-register-issuer");
    await expect(page.locator("#registrar-attestation-1-type")).toHaveAttribute("list", "registrar-types-sdjwt");
    await expect(page.locator("#registrar-types-sdjwt option[value='urn:example:library:1']")).toHaveCount(1);
    await page.locator("#registrar-close").click();
    await page.locator("#registrar-parties-close").click();

    // A name is listed once, and an added attestation can be deleted.
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-catalog-link").click();
    await page.locator("#registrar-catalog-add").click();
    // The dialog opens with the example again.
    await expect(page.locator("#registrar-catalog-name")).toHaveValue("University diploma");
    await expect(page.locator("#registrar-catalog-formats [data-field=\"type\"]").first()).toHaveValue("urn:example:diploma:1");
    await page.locator("#registrar-catalog-name").fill("library card");
    await page.locator("#registrar-catalog-formats [data-field=\"type\"]").first().fill("urn:example:library:2");
    await page.locator("#registrar-catalog-save").click();
    await expect(page.locator("#registrar-catalog-form-error")).toContainText("already lists");
    await page.keyboard.press("Escape");
    await expect(page.locator("#registrar-catalog-add-overlay")).toBeHidden();
    await card.locator("button").click();
    await expect(page.locator(".registrar-party", { hasText: "Library card" })).toHaveCount(0);
    // After a delete, the next add starts from the example again.
    await page.locator("#registrar-catalog-add").click();
    await expect(page.locator("#registrar-catalog-name")).toHaveValue("University diploma");
    await expect(page.locator("#registrar-catalog-formats [data-field=\"claims\"]").first()).toHaveValue("degree, graduation_date");
    await page.keyboard.press("Escape");
    await page.keyboard.press("Escape");
    await expect(page.locator("#registrar-catalog-overlay")).toBeHidden();
  });

});

// Each dialog shows a command with the same effect. The tests run each command
// as shown against the wallet of the page.
test.describe("Commands in dialogs", () => {
  const cliHome = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-dev-cli-home-"));
  // run runs a command in bash without blocking, so servers in this process
  // can answer the wallet meanwhile. The CLI runs the e2e build with its own
  // home, so it never reaches another wallet.
  function run(command) {
    const script = command.replace(/^eudi /gm, "/tmp/eudi-dev-wallet-e2e ");
    return new Promise((resolve, reject) => {
      const child = require("child_process").spawn("bash", [], { env: { ...process.env, EUDI_DEV_HOME: cliHome } });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (d) => (stdout += d));
      child.stderr.on("data", (d) => (stderr += d));
      child.on("close", (code) => (code === 0 ? resolve(stdout) : reject(new Error(`${script}\nfailed: ${stderr}`))));
      child.stdin.end(script);
    });
  }
  async function vcts() {
    return (await jsonGet(`${WALLET_URL}/api/credentials`)).body.map((c) => c.vct);
  }

  test("dialogs without a command show no command button and close with ×", async ({ page }) => {
    await page.goto(WALLET_URL);
    for (const [name, link] of [["conformance", "#conformance-link"], ["templates", "#templates-link"], ["howto", "#how-to-use-link"]]) {
      await page.locator(link).click();
      await expect(page.locator(`#${name}-overlay`)).toHaveClass(/active/);
      await expect(page.locator(`#${name}-dialog-size`)).toBeVisible();
      await expect(page.locator(`#${name}-dialog-command-toggle`)).toBeHidden();
      await page.locator(`#${name}-dialog-close`).click();
      await expect(page.locator(`#${name}-overlay`)).not.toHaveClass(/active/);
    }
  });

  test("a maximized dialog gives its list and JSON field the extra height", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#templates-link").click();
    const list = page.locator("#templates-list");
    const normal = (await list.boundingBox()).height;
    await page.locator("#templates-dialog-size").click();
    await expect.poll(async () => (await list.boundingBox()).height).toBeGreaterThan(normal + 100);
    await page.locator("#template-close").click();

    await page.locator("#issue-btn").click();
    await page.locator("#issue-claims-mode-json").check();
    const claims = page.locator("#issue-claims");
    const small = (await claims.boundingBox()).height;
    await page.locator("#issue-dialog-size").click();
    await expect.poll(async () => (await claims.boundingBox()).height).toBeGreaterThan(small * 2);
    await page.locator("#issue-dialog-size").click();
  });

  test("the issue dialog's curl and CLI commands issue the credential", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#issue-btn").click();
    await page.locator("#issue-vct").fill("urn:example:command:curl");
    await page.locator("#issue-dialog-command-toggle").click();
    const text = page.locator("#issue-dialog-command-text");
    await expect(text).toContainText("urn:example:command:curl");
    await run(await text.textContent());
    expect(await vcts()).toContain("urn:example:command:curl");

    // The command changes with the form.
    await page.locator("#issue-vct").fill("urn:example:command:cli");
    await page.locator("#issue-dialog-command-cli").check();
    await expect(text).toContainText("eudi issue sdjwt");
    await expect(text).toContainText("urn:example:command:cli");
    await run(await text.textContent());
    expect(await vcts()).toContain("urn:example:command:cli");
  });

  test("a dialog grows almost to full screen and back", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#issue-btn").click();
    const size = page.locator("#issue-dialog-size");
    await size.click();
    await expect(page.locator("#issue-dialog")).toHaveClass(/dialog-maximized/);
    await expect(size).toHaveAttribute("aria-pressed", "true");
    await expect(size).toHaveAttribute("title", "Restore size");
    await size.click();
    await expect(page.locator("#issue-dialog")).not.toHaveClass(/dialog-maximized/);
  });

  // openClaimSetRequest opens a presentation request with two claim sets from a
  // verifier in this process. The request comes from an API call, so every
  // caller sees it.
  async function openClaimSetRequest(page) {
    await denyPendingRequests();
    const verifier = { received: undefined };
    verifier.server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", () => {
        verifier.received = new URLSearchParams(body);
        res.setHeader("Content-Type", "application/json");
        res.end("{}");
      });
    });
    await new Promise((resolve) => verifier.server.listen(0, "127.0.0.1", resolve));
    const responseURI = `http://127.0.0.1:${verifier.server.address().port}/response`;
    const uri = "openid4vp://authorize?" + new URLSearchParams({
      client_id: `redirect_uri:${responseURI}`,
      response_type: "vp_token",
      response_mode: "direct_post",
      response_uri: responseURI,
      nonce: "n",
      state: "s",
      dcql_query: JSON.stringify({
        credentials: [{
          id: "pid",
          format: "dc+sd-jwt",
          meta: { vct_values: ["urn:eudi:pid:1"] },
          claims: [{ id: "a", path: ["given_name"] }, { id: "b", path: ["family_name"] }, { id: "c", path: ["birthdate"] }],
          claim_sets: [["a", "b"], ["a", "c"]],
        }],
      }),
    });
    jsonPost(`${WALLET_URL}/api/presentations`, { uri, interactive: true }).catch(() => {});
    await page.goto(`${WALLET_URL}/?request=${await waitForPendingRequest()}`);
    await page.locator("#consent-show-claim-sets-pid").click();
    await page.locator("#consent-claim-set-pid-1").check();
    // A pending request needs an explicit answer, so it has no × to close it.
    await expect(page.locator("#consent-dialog-close")).toBeHidden();
    await page.locator("#consent-dialog-command-toggle").click();
    return verifier;
  }

  async function disclosedClaims(verifier) {
    await expect.poll(() => verifier.received?.get("vp_token")).toBeTruthy();
    const presentation = JSON.parse(verifier.received.get("vp_token")).pid[0];
    return presentation.split("~").slice(1, -1)
      .map((d) => JSON.parse(Buffer.from(d, "base64url").toString())[1])
      .sort();
  }

  test("the consent dialog's curl command approves with the chosen claim set", async ({ page }) => {
    const verifier = await openClaimSetRequest(page);
    try {
      const text = page.locator("#consent-dialog-command-text");
      await expect(text).toContainText('"pid": 1');
      // The command finds the request itself.
      await expect(text).toContainText('REQUEST_ID="${REQUEST_ID:-$(curl');
      await run((await text.textContent()).split("\n\n# Deny")[0]);
      expect(await disclosedClaims(verifier)).toEqual(["birthdate", "given_name"]);
    } finally {
      await new Promise((resolve) => verifier.server.close(resolve));
    }
  });

  test("the consent dialog's CLI command approves with the chosen claim set", async ({ page }) => {
    const verifier = await openClaimSetRequest(page);
    try {
      await page.locator("#consent-dialog-command-cli").check();
      const text = page.locator("#consent-dialog-command-text");
      await expect(text).toContainText("eudi wallet requests approve");
      await run((await text.textContent()).split("\n\n# Deny it")[0]);
      expect(await disclosedClaims(verifier)).toEqual(["birthdate", "given_name"]);
    } finally {
      await new Promise((resolve) => verifier.server.close(resolve));
    }
  });

  // Without a CSR the dialog creates a key in the browser. The command has a
  // placeholder for the CSR instead.
  test("the registrar dialog's command registers a verifier with a CSR", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();
    await page.locator("#registrar-parties-register").click();
    await page.locator("#registrar-name").fill("Command Shop");
    await page.locator("#registrar-dialog-command-toggle").click();
    const text = page.locator("#registrar-dialog-command-text");
    await expect(text).toContainText("<your certificate signing request in PEM>");
    await expect(page.locator("#registrar-dialog-command-note")).toContainText("openssl req");
    await expect(page.locator("#registrar-dialog-command-docs-link")).toHaveAttribute("href", /docs\/wallet\/registrar\.md#registrar-api$/);

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-dev-csr-"));
    execSync('openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem -out csr.pem -subj "/CN=Command Shop" 2>/dev/null', { cwd: dir });
    const csr = JSON.stringify(fs.readFileSync(path.join(dir, "csr.pem"), "utf8")).slice(1, -1);
    const command = (await text.textContent()).replace("<your certificate signing request in PEM>", csr);
    const registered = JSON.parse(await run(command));
    expect(registered.relyingParty.tradeName).toBe("Command Shop");
    expect(registered.access.chain).toContain("BEGIN CERTIFICATE");
    await fetch(`${WALLET_URL}/api/registrar/wrp/${encodeURIComponent(registered.relyingParty.identifier[0].identifier)}`, { method: "DELETE" });
  });

  test("the registrar dialog's CLI command enrols a verifier with a CSR", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-parties-link").click();
    await page.locator("#registrar-parties-register").click();
    await page.locator("#registrar-name").fill("Command Kiosk");
    await page.locator("#registrar-dialog-command-toggle").click();
    await page.locator("#registrar-dialog-command-cli").check();
    const text = page.locator("#registrar-dialog-command-text");
    await expect(text).toContainText("eudi registrar enrol -");

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-dev-csr-"));
    execSync('openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem -out csr.pem -subj "/CN=Command Kiosk" 2>/dev/null', { cwd: dir });
    const csr = JSON.stringify(fs.readFileSync(path.join(dir, "csr.pem"), "utf8")).slice(1, -1);
    const command = (await text.textContent())
      .replace("<your certificate signing request in PEM>", csr)
      .replace("eudi registrar enrol -", "eudi registrar enrol - --json");
    const enrolled = JSON.parse(await run(command));
    expect(enrolled.relyingParty.tradeName).toBe("Command Kiosk");
    expect(enrolled.access.chain).toContain("BEGIN CERTIFICATE");
    await fetch(`${WALLET_URL}/api/registrar/wrp/${encodeURIComponent(enrolled.relyingParty.identifier[0].identifier)}`, { method: "DELETE" });
  });

  test("the issue dialog's CLI command saves a template with its catalogue entry", async ({ page }) => {
    await fetch(`${WALLET_URL}/api/templates/e2e-gym-template`, { method: "DELETE" });
    await page.goto(WALLET_URL);
    await page.locator("#issue-btn").click();
    await page.locator("#issue-vct").fill("urn:example:gym-template:1");
    await page.locator("#issue-save-template").fill("e2e-gym-template");
    await page.locator("#issue-catalog").check();
    await page.locator("#issue-dialog-command-toggle").click();
    await page.locator("#issue-dialog-command-cli").check();
    const text = page.locator("#issue-dialog-command-text");
    await expect(text).toContainText("--catalog");
    await run(await text.textContent());
    const entries = (await jsonGet(`${WALLET_URL}/api/catalog/attestations`)).body;
    expect(entries.some((e) => (e.credentials || []).some((c) => c.type === "urn:example:gym-template:1"))).toBe(true);
  });

  test("the template editor's CLI command saves the template", async ({ page }) => {
    await fetch(`${WALLET_URL}/api/templates/e2e-command`, { method: "DELETE" });
    await page.goto(WALLET_URL);
    await page.locator("#templates-link").click();
    await page.locator("#template-new").click();
    await page.locator("#template-editor-name").fill("e2e-command");
    await page.locator("#issue-vct").fill("urn:example:e2e-command");
    await page.locator("#issue-dialog-command-toggle").click();
    await page.locator("#issue-dialog-command-cli").check();
    const text = page.locator("#issue-dialog-command-text");
    await expect(text).toContainText("eudi templates import -");
    await run(await text.textContent());
    const saved = (await jsonGet(`${WALLET_URL}/api/templates/e2e-command`)).body;
    expect(saved.vct).toBe("urn:example:e2e-command");
  });

  test("the catalogue dialog's CLI command adds the entry and its issuer CA", async ({ page }) => {
    for (const entry of (await jsonGet(`${WALLET_URL}/api/catalog/attestations`)).body) {
      if (entry.name === "Gym membership") {
        await fetch(`${WALLET_URL}/api/catalog/schemas/${encodeURIComponent(entry.schema.id)}`, { method: "DELETE" });
      }
    }
    await page.goto(WALLET_URL);
    await page.locator("#registrar-menu-toggle").click();
    await page.locator("#registrar-catalog-link").click();
    await page.locator("#registrar-catalog-add").click();
    await page.locator("#registrar-catalog-name").fill("Gym membership");
    await page.locator("#registrar-catalog-format-1-type").fill("urn:example:gym:1");
    await page.locator("#registrar-catalog-format-1-claims").fill("member_id, address.locality");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-dev-ca-"));
    execSync('openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj "/CN=Gym CA" -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -keyout ca.key -out ca.pem 2>/dev/null', { cwd: dir });
    await page.locator("#registrar-catalog-issuer-ca").fill(fs.readFileSync(path.join(dir, "ca.pem"), "utf8"));
    await page.locator("#registrar-catalog-add-dialog-command-toggle").click();
    await page.locator("#registrar-catalog-add-dialog-command-cli").check();
    const text = page.locator("#registrar-catalog-add-dialog-command-text");
    await expect(text).toContainText("--claim 'dc+sd-jwt:address.locality'");
    await run(await text.textContent());

    const added = (await jsonGet(`${WALLET_URL}/api/catalog/attestations`)).body.find((e) => e.name === "Gym membership");
    expect(added.credentials[0].claims).toEqual([["member_id"], ["address", "locality"]]);
    // The issuer CA went on the category's trusted list from stdin.
    const trust = (await jsonGet(`${WALLET_URL}/api/trust`)).body;
    expect(JSON.stringify(trust)).toContain("Gym membership issuer");
  });
});
