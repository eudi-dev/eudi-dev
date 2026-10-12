// @ts-check
// The trust dialog adds provider CAs and external lists in two popups.
const { test, expect } = require("@playwright/test");
const { waitForServer } = require("./helpers");
const { execSync, spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const PORT = 18970;
const BASE = `http://localhost:${PORT}`;
let walletProcess;

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  test.setTimeout(120_000);
  execSync("go build -o /tmp/eudi-trust-dialogs-e2e ..", { cwd: __dirname });
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-trust-dialogs-e2e-"));
  walletProcess = spawn(
    "/tmp/eudi-trust-dialogs-e2e",
    ["wallet", "serve", "--port", String(PORT), "--wallet-dir", path.join(work, "wallet"), "--base-url", BASE],
    { stdio: "ignore" }
  );
  await waitForServer(`${BASE}/api/version`, 30_000);
});

test.afterAll(() => {
  if (walletProcess) walletProcess.kill("SIGTERM");
});

async function openTrust(page) {
  await page.goto(BASE);
  await page.locator("#trust-link").click();
  await expect(page.locator("#trust-overlay")).toHaveClass(/active/);
}

test("each popup cancels back to the trust dialog without a change", async ({ page, request }) => {
  const before = await (await request.get(`${BASE}/api/trust`)).json();
  await openTrust(page);

  await page.locator("#trust-add-provider").click();
  await expect(page.locator("#trust-provider-overlay")).toHaveClass(/active/);
  await expect(page.locator("#trust-entity-list")).toBeFocused();
  await page.locator("#trust-entity-name").fill("Cancelled provider");
  await page.locator("#trust-provider-cancel").click();
  await expect(page.locator("#trust-provider-overlay")).not.toHaveClass(/active/);
  await expect(page.locator("#trust-overlay")).toHaveClass(/active/);
  await expect(page.locator("#trust-add-provider")).toBeFocused();

  await page.locator("#trust-add-list").click();
  await expect(page.locator("#trust-external-overlay")).toHaveClass(/active/);
  await expect(page.locator("#trust-list-url")).toBeFocused();
  await page.locator("#trust-list-url").fill(`${BASE}/api/trustlists/pid`);
  await page.locator("#trust-external-cancel").click();
  await expect(page.locator("#trust-external-overlay")).not.toHaveClass(/active/);
  await expect(page.locator("#trust-overlay")).toHaveClass(/active/);
  await expect(page.locator("#trust-add-list")).toBeFocused();

  expect(await (await request.get(`${BASE}/api/trust`)).json()).toEqual(before);
});

test("the provider popup offers every list once the trust state arrives", async ({ page }) => {
  await page.route("**/api/trust", async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    await route.continue();
  });
  await page.goto(BASE);
  await page.locator("#trust-link").click();
  await page.locator("#trust-add-provider").click();

  const options = page.locator("#trust-entity-list option");
  await expect(options.first()).toHaveAttribute("value", "pid");
  await expect(page.locator("#trust-entity-list-trusted-list-ca")).toHaveText("trusted-list-ca (CA of a list operator, for external lists)");
  await page.unrouteAll({ behavior: "wait" });
});

test("a refused CA keeps the provider popup open with the reason, and reopening clears it", async ({ page }) => {
  await openTrust(page);
  await page.locator("#trust-add-provider").click();
  await page.locator("#trust-entity-list").selectOption("eaa");
  await page.locator("#trust-entity-ca").fill("not a certificate");
  await page.locator("#trust-entity-add").click();

  await expect(page.locator("#trust-provider-error")).not.toBeEmpty();
  await expect(page.locator("#trust-provider-overlay")).toHaveClass(/active/);
  await expect(page.locator("#trust-entity-ca")).toHaveValue("not a certificate");

  await page.locator("#trust-provider-cancel").click();
  await page.locator("#trust-add-provider").click();
  await expect(page.locator("#trust-provider-error")).toBeEmpty();
});

test("a list operator CA shows under the external lists", async ({ page, request }) => {
  const ca = await (await request.get(`${BASE}/api/certificates/ca`)).text();
  await openTrust(page);
  await page.locator("#trust-add-provider").click();
  await page.locator("#trust-entity-list").selectOption("trusted-list-ca");
  await page.locator("#trust-entity-name").fill("E2E list operator");
  await page.locator("#trust-entity-ca").fill(ca);
  await page.locator("#trust-entity-add").click();

  await expect(page.locator("#trust-overlay")).toHaveClass(/active/);
  await expect(page.locator("#trust-entity-ca")).toHaveValue("");
  await expect(page.locator("#trust-group-external")).toHaveText("External lists");
  await expect(page.locator("#trust-operators-label")).toHaveText("CAs of list operators (trusted-list-ca)");
  const operator = page.locator("#trust-operators li").filter({ hasText: "E2E list operator" });
  await expect(operator).toHaveCount(1);

  await operator.locator(".trust-remove").click();
  await expect(page.locator("#trust-group-external")).toHaveCount(0);
});

test("an external list that cannot be read is listed with the reason it is not used", async ({ page, request }) => {
  const listURL = `${BASE}/api/trustlists/no-such-list`;
  await openTrust(page);
  await page.locator("#trust-add-list").click();
  await page.locator("#trust-list-url").fill(listURL);
  await page.locator("#trust-list-add").click();

  await expect(page.locator("#trust-overlay")).toHaveClass(/active/);
  await expect(page.locator("#trust-list-url")).toHaveValue("");
  const item = page.locator("#trust-external-lists li").filter({ hasText: listURL });
  await expect(item.locator(".trust-list-error")).toContainText("Not used:");

  await item.locator(".trust-remove").click();
  await expect(page.locator("#trust-group-external")).toHaveCount(0);
  const state = await (await request.get(`${BASE}/api/trust`)).json();
  expect((state.lists || []).map((l) => l.url)).toEqual([]);
});
