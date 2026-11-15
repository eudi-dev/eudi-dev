// @ts-check
// The settings view lists the experimental features. One switch turns all of
// them on or off, and each feature keeps its own switch.
const { test, expect } = require("@playwright/test");
const { waitForServer } = require("./helpers");
const { execSync, spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const PORT = 18965;
const BASE = `http://localhost:${PORT}`;
const BINARY = "/tmp/eudi-experimental-e2e";
let walletProcess;

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  test.setTimeout(120_000);
  execSync(`go build -o ${BINARY} ..`, { cwd: __dirname });
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-experimental-e2e-"));
  walletProcess = spawn(
    BINARY,
    ["wallet", "serve", "--port", String(PORT), "--wallet-dir", path.join(work, "wallet"), "--base-url", BASE],
    { stdio: "ignore", env: { ...process.env, EUDI_DEV_HOME: work } }
  );
  await waitForServer(`${BASE}/api/version`, 30_000);
});

test.afterAll(() => {
  if (walletProcess) walletProcess.kill("SIGTERM");
});

const config = async (request) => (await request.get(`${BASE}/api/config`)).json();

test("the experimental switch turns every experimental feature on and off", async ({ page, request }) => {
  await page.goto(BASE);
  await page.click("#conformance-link");
  await page.click("#conf-tab-experimental");

  const all = page.locator("#conf-experimental-input");
  const transactionData = page.locator("#conf-transaction-data-input");
  const delegate = page.locator("#conf-delegate-sd-jwt-input");
  await expect(page.locator("#conf-transaction-data-label")).toHaveText("Accept transaction data");
  await expect(page.locator("#conf-delegate-sd-jwt-label")).toHaveText("Accept delegation requests");
  for (const feature of ["transaction-data", "delegate-sd-jwt"]) {
    await expect(page.locator(`#conf-${feature}-tag`)).toBeVisible();
  }
  await expect(all).not.toBeChecked();

  await all.check();
  await expect(transactionData).toBeChecked();
  await expect(delegate).toBeChecked();
  await expect.poll(async () => (await config(request)).delegate_sd_jwt).toBe(true);
  expect(await config(request)).toMatchObject({ transaction_data: true });

  await delegate.uncheck();
  await expect.poll(() => all.evaluate((input) => input.indeterminate)).toBe(true);
  await expect.poll(async () => (await config(request)).delegate_sd_jwt).toBe(false);

  await all.check();
  await expect(delegate).toBeChecked();
  await expect.poll(async () => (await config(request)).delegate_sd_jwt).toBe(true);
  await all.uncheck();
  await expect(transactionData).not.toBeChecked();
  await expect(delegate).not.toBeChecked();
  await expect.poll(async () => (await config(request)).transaction_data).toBe(false);
});

test("the transaction templates carry the tag while transaction data is on", async ({ page, request }) => {
  await page.goto(BASE);
  await page.click("#templates-menu-toggle");
  await page.click("#transaction-templates-link");
  await expect(page.locator("#transaction-templates-title")).toHaveText("Transaction templates", { useInnerText: true });
  await expect(page.locator("#transaction-templates-tag")).toBeHidden();
  await page.click("#transaction-templates-close");

  await request.put(`${BASE}/api/config/conformance`, { data: { transaction_data: true } });
  await page.reload();
  await page.click("#templates-menu-toggle");
  await page.click("#transaction-templates-link");
  await expect(page.locator("#transaction-templates-tag")).toBeVisible();
  await expect(page.locator("#transaction-templates-tag")).toHaveText("Experimental");
  await request.delete(`${BASE}/api/config/conformance`);
});
