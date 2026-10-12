// @ts-check
const { test, expect } = require("@playwright/test");
const { execSync } = require("child_process");
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

  execSync("go build -o /tmp/oid4vc-dev-wallet-e2e ..", {
    cwd: __dirname,
  });

  // A fresh directory keeps stored serving URLs from changing the test ports.
  const { spawn } = require("child_process");
  const walletDir = fs.mkdtempSync(path.join(os.tmpdir(), "oid4vc-dev-wallet-e2e-"));
  walletProcess = spawn(
    "/tmp/oid4vc-dev-wallet-e2e",
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

async function waitForServer(url, timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await new Promise((resolve, reject) => {
        const req = http.get(url, (res) => {
          res.resume();
          resolve(res);
        });
        req.on("error", reject);
        req.setTimeout(500, () => {
          req.destroy();
          reject(new Error("timeout"));
        });
      });
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  throw new Error(`Server at ${url} did not start within ${timeoutMs}ms`);
}

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

test.describe("Wallet Dashboard", () => {
  test("shows wallet title", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator("h1")).toHaveText("EUDI Dev Wallet");
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
      await page.selectOption("#conf-tls-select", { label: "Follow validation mode" });
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

  test("has theme toggle button", async ({ page }) => {
    await page.goto(WALLET_URL);
    const themeBtn = page.locator("#theme-toggle");
    await expect(themeBtn).toBeVisible();

    await themeBtn.click();
    const theme = await page
      .locator("html")
      .getAttribute("data-theme");
    expect(theme).toBe("light");

    await themeBtn.click();
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
    await page.route("**/api/requests/stream", async (route) => {
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
    expect(res.body.error).toBeDefined();
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
    const pending = await jsonGet(`${WALLET_URL}/api/requests`);
    for (const r of Array.isArray(pending.body) ? pending.body : []) {
      await jsonPost(`${WALLET_URL}/api/requests/${r.id}/deny`, {});
    }
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
    await expect(page.locator("#issue-exp")).toHaveValue("720h");
    await expect(page.locator("#issue-claim-rows .claim-row")).toHaveCount(14);
    const keys = await page
      .locator("#issue-claim-rows .claim-row input[id^=issue-claim-key]")
      .evaluateAll((inputs) => inputs.map((i) => i.value));
    expect(keys.sort()).toEqual([
      "academic_title",
      "address",
      "age_equal_or_over",
      "aka_vcts",
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

  test("manages templates and issues from one with a non-disclosable claim", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);

    await page.locator("#templates-btn").click();
    await expect(page.locator("#templates-overlay")).toHaveClass(/active/);
    await expect(
      page.locator(".template-row-name", { hasText: "german-pid-sdjwt" })
    ).toBeVisible();

    await page.locator("#template-name").fill("e2e-employee");
    await page.locator("#template-json").fill(
      JSON.stringify({
        format: "sdjwt",
        vct: "urn:example:e2e-employee",
        claims: { employee_id: "E-1", department: "IT" },
        always_disclosed: ["department"],
      })
    );
    await page.locator("#template-save").click();
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

    await page.locator("#templates-btn").click();
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
    await page.locator("#issue-save-template").fill("e2e-saved-template");

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
    await expect(categories).toHaveText(["Credential providers", "Wallet providers"]);
    const walletGroup = page.locator("#trust-list-links .trust-items dd").nth(1);
    await expect(walletGroup.locator(".trust-links a")).toHaveText(["wallet-provider"]);
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
    if (box) await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.waitForTimeout(200);
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
  page.on("dialog", (dialog) => dialog.dismiss());
  await page.locator("#offer-input").fill("eu-eaa-offer://");
  const responsePromise = page.waitForResponse((response) =>
    response.request().method() === "POST" &&
    ["/api/offers", "/api/presentations"].includes(new URL(response.url()).pathname)
  );
  await page.locator("#process-btn").click();
  const response = await responsePromise;
  expect(new URL(response.url()).pathname).toBe("/api/offers");
  expect(response.status()).toBe(400);
  expect((await response.json()).error).toContain("credential_offer");
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
    const pending = await jsonGet(`${WALLET_URL}/api/requests`);
    for (const r of Array.isArray(pending.body) ? pending.body : []) {
      await jsonPost(`${WALLET_URL}/api/requests/${r.id}/deny`, {});
    }
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

    let pending = [];
    for (let i = 0; i < 50 && pending.length === 0; i++) {
      pending = await (await fetch(`${WALLET_URL}/api/requests`)).json();
      if (pending.length === 0) await new Promise((r) => setTimeout(r, 100));
    }
    await page.goto(`${WALLET_URL}/?focus=overview&request=${pending[0].id}`);
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

    let pending = [];
    for (let i = 0; i < 50 && pending.length === 0; i++) {
      pending = await (await fetch(`${WALLET_URL}/api/requests`)).json();
      if (pending.length === 0) await new Promise((r) => setTimeout(r, 100));
    }
    await page.goto(`${WALLET_URL}/?focus=overview&request=${pending[0].id}`);
    await expect(page.locator("#consent-approve")).toBeVisible();
    await expect(page.locator("#offer-tx-code-input")).toHaveCount(0);
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
    expect(res.body.error).toContain("no deferred issuance");
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
    const crypto = require("crypto");
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
      /does not hold/
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
    .toHaveJSProperty("href", WALLET_URL + "/decoder/?credential=presented-token");
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
    await expect(links).toHaveCount(3);
    await expect(links).toHaveText(["Open 'pid' in decoder", "Open 'pid' in decoder (2)", "Open 'mdl' in decoder"]);
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
      const link = entry.locator(`[data-testid="log-decoder-link"][data-query-id="${queryID}"][data-token-index="${tokenIndex}"]`);
      await expect(link).toHaveJSProperty("href", WALLET_URL + "/decoder/?credential=" + encodeURIComponent(token));
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

test("request activity formats JSON strings and preserves non-JSON payloads", async ({ page }) => {
  const bodies = ['{"nonce":"test-nonce","claims":["given_name"]}', "signed.token.value"];
  await page.route("**/api/log*", route => route.fulfill({ json: bodies.map(body => ({
    time: "2026-10-01T08:00:00Z", action: "presentation", detail: "Presentation request", success: true,
    payload: { label: "Request", body, wire: "original-wire-value" },
  })) }));
  await page.goto(WALLET_URL);
  const entries = page.getByTestId("log-entry");
  await expect(entries).toHaveCount(2);
  for (const entry of await entries.all()) await entry.getByTestId("log-entry-toggle").click();
  await expect(entries.nth(0).locator(".log-payload > pre")).toHaveText("signed.token.value");
  await entries.nth(0).getByTestId("log-wire-toggle").click();
  await expect(entries.nth(0).locator(".log-wire pre")).toHaveText("original-wire-value");
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
    .toHaveJSProperty("href", WALLET_URL + "/decoder/?credential=" + encodeURIComponent(jwt));
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
    await expect(responseEntry.getByTestId("log-decoder-link")).toHaveText([
      "Open copy 1 in decoder", "Open copy 2 in decoder", "Open copy 3 in decoder",
    ]);
    if (encrypted) await expect(responseEntry.locator(".log-payload > pre")).toHaveText("encrypted-batch-response");
    else await expect(responseEntry.locator(".log-payload > pre")).toHaveText(JSON.stringify(response, null, 2));
    for (const [index, token] of tokens.entries()) {
      const link = responseEntry.locator(`[data-testid="log-decoder-link"][data-credential-index="${index}"]`);
      await expect(link).toHaveJSProperty("href", WALLET_URL + "/decoder/?credential=" + encodeURIComponent(token));
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
    await expect(imported.getByTestId("log-decoder-link")).toHaveJSProperty("href", WALLET_URL + "/decoder/?credential=" + encodeURIComponent(tokens[2]));
  });
}

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
    await expect(entry.getByTestId("log-decoder-link")).toHaveText([
      "Open copy 1 in decoder", "Open copy 2 in decoder", "Open copy 3 in decoder",
    ]);
    await expect(entry.locator(".log-payload-label")).toHaveText("Credential (3 copies)");
    for (const [index, token] of tokens.entries()) {
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
    .toHaveJSProperty("href", WALLET_URL + "/decoder/?credential=" + jwt);
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

// OpenID4VP 1.0 §8.2: the response_uri may answer an Authorization Response or an
// Authorization Error Response with a redirect_uri, and the wallet sends the user
// agent there.
test.describe("Verifier redirect after the answer", () => {
  let verifier;
  let verifierURL;

  test.beforeAll(async () => {
    verifier = http.createServer((req, res) => {
      if (req.method === "POST" && req.url === "/response") {
        req.resume();
        req.on("end", () => {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ redirect_uri: `${verifierURL}/after` }));
        });
        return;
      }
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("<title>Verifier</title><h1>Back at the verifier</h1>");
    });
    await new Promise((resolve) => verifier.listen(0, "127.0.0.1", resolve));
    verifierURL = `http://127.0.0.1:${verifier.address().port}`;
  });

  test.afterAll(() => verifier.close());

  function requestQuery() {
    return new URLSearchParams({
      client_id: "https://verifier.example",
      response_type: "vp_token",
      response_mode: "direct_post",
      nonce: "nonce-" + Date.now(),
      state: "state",
      response_uri: `${verifierURL}/response`,
      dcql_query: JSON.stringify({
        credentials: [{
          id: "pid",
          format: "dc+sd-jwt",
          meta: { vct_values: ["urn:eudi:pid:1"] },
          claims: [{ path: ["given_name"] }],
        }],
      }),
    }).toString();
  }

  for (const answer of ["consent-approve", "consent-deny"]) {
    test(`${answer} on a browser request follows the verifier's redirect_uri`, async ({ page }) => {
      await page.goto(`${WALLET_URL}/authorize?${requestQuery()}`);
      await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
      await page.locator(`#${answer}`).click();
      await page.waitForURL(`${verifierURL}/after`);
      await expect(page.locator("h1")).toHaveText("Back at the verifier");
    });
  }

  test("a denied pasted request follows the verifier's redirect_uri", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#offer-input").fill(`openid4vp://?${requestQuery()}`);
    await page.locator("#process-btn").click();
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
    await page.locator("#consent-deny").click();
    await page.waitForURL(`${verifierURL}/after`);
  });
});
