// @ts-check
// An operator's theme brands every page: the example theme in
// examples/themes/acme sets a few colours and the logo.
const { test, expect } = require("@playwright/test");
const { waitForServer } = require("./helpers");
const { execSync, spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const PORT = 18991;
const BASE = `http://localhost:${PORT}`;
const BINARY = "/tmp/eudi-theme-e2e";
const THEME = path.join(__dirname, "..", "examples", "themes", "acme");
let walletProcess;

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  test.setTimeout(120_000);
  execSync(`go build -o ${BINARY} ..`, { cwd: __dirname });
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-theme-e2e-"));
  walletProcess = spawn(
    BINARY,
    ["wallet", "serve", "--port", String(PORT), "--wallet-dir", path.join(work, "wallet"), "--base-url", BASE, "--theme", THEME],
    { stdio: "ignore", env: { ...process.env, EUDI_DEV_HOME: work } }
  );
  await waitForServer(`${BASE}/api/version`, 30_000);
});

test.afterAll(() => {
  if (walletProcess) walletProcess.kill("SIGTERM");
});

const token = (page, name) => page.evaluate((n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim(), name);

for (const [name, url] of [["wallet", "/"], ["decoder", "/decoder/"], ["demo issuer", "/issuer/"], ["demo verifier", "/verifier/"]]) {
  test(`the ${name} page shows the theme logo and colours`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: "dark" });
    await page.goto(BASE + url);
    const logo = page.locator("#header-logo");
    await expect.poll(() => logo.evaluate((img) => img.complete && img.naturalWidth)).toBe(108);
    expect(await token(page, "--accent")).toBe("#2bb39a");
    expect(await token(page, "--bg")).toBe("#0f1a1c");
    // A token the theme leaves out comes from the built-in theme.
    expect(await token(page, "--danger")).toBe("#ff9b8f");

    await page.emulateMedia({ colorScheme: "light" });
    await expect.poll(() => token(page, "--accent")).toBe("#0e7c68");
    expect(await token(page, "--bg")).toBe("#f1f7f5");
    // Dark colours of the theme stay out of the light mode.
    expect(await token(page, "--bg-surface")).toBe("#ffffff");
  });
}

test("the favicon is the theme logo", async ({ page, request }) => {
  await page.goto(BASE);
  const href = await page.locator('link[rel="icon"]').getAttribute("href");
  const favicon = await request.get(new URL(href || "", BASE + "/").href);
  expect(favicon.headers()["content-type"]).toBe("image/svg+xml");
  expect(await favicon.text()).toBe(fs.readFileSync(path.join(THEME, "logo.svg"), "utf8"));
});

test("the theme directory serves only fonts and images", async ({ request }) => {
  expect((await request.get(`${BASE}/theme/../go.mod`)).status()).toBe(404);
  expect((await request.get(`${BASE}/theme/%2e%2e/%2e%2e/go.mod`)).status()).toBe(404);
  expect((await request.get(`${BASE}/theme/theme.go`)).status()).toBe(404);
});
