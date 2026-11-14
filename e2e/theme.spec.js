// @ts-check
// An operator's theme brands every page: the example theme in
// examples/themes/acme sets a few colors, the logo, the wallet name, an
// edition tag, a product and header menu entries.
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
const NO_BUILTINS_PORT = 18977;
const NO_BUILTINS_BASE = `http://localhost:${NO_BUILTINS_PORT}`;
let walletProcess;
let noBuiltinsProcess;
let noBuiltinsTheme;

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

  noBuiltinsTheme = path.join(work, "theme");
  fs.mkdirSync(noBuiltinsTheme);
  fs.writeFileSync(path.join(noBuiltinsTheme, "theme.yaml"), "demo:\n  issuer: https://acme.example/issuer\n");
  noBuiltinsProcess = spawn(
    BINARY,
    ["wallet", "serve", "--port", String(NO_BUILTINS_PORT), "--wallet-dir", path.join(work, "no-builtins"), "--base-url", NO_BUILTINS_BASE, "--theme", noBuiltinsTheme, "--no-builtins"],
    { stdio: "ignore", env: { ...process.env, EUDI_DEV_HOME: work } }
  );
  await waitForServer(`${NO_BUILTINS_BASE}/api/version`, 30_000);
});

test.afterAll(() => {
  if (walletProcess) walletProcess.kill("SIGTERM");
  if (noBuiltinsProcess) noBuiltinsProcess.kill("SIGTERM");
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

test("the pages show the wallet name of the theme", async ({ page }) => {
  await page.goto(BASE);
  await expect(page).toHaveTitle("Acme Wallet");
  await expect(page.locator("#header-title")).toHaveText("Acme Wallet");
  await page.goto(BASE + "/decoder/");
  await expect(page).toHaveTitle("Acme Wallet Decoder");
  await expect(page.locator("#header-title")).toHaveText("Acme Wallet Decoder");
});

test("the header shows the edition tag in line with the logo, the name and the menu", async ({ page }) => {
  for (const url of ["/", "/decoder/"]) {
    await page.goto(BASE + url);
    const tag = page.locator("#edition-tag");
    await expect(tag).toHaveText("Test");
    const centre = async (selector) => {
      const box = await page.locator(selector).boundingBox();
      return box.y + box.height / 2;
    };
    const expected = await centre("#header-logo");
    for (const selector of ["#edition-tag", "#header-title", "#github-link"]) {
      expect(Math.abs((await centre(selector)) - expected), `${selector} on ${url}`).toBeLessThan(1.5);
    }
  }
  await expect(page).toHaveTitle("Acme Wallet Decoder");
});

test("the header menu has the theme's links and hides the entries listed under nav.hide", async ({ page }) => {
  await page.goto(BASE);
  await expect(page.locator("#get-cli-link")).toBeHidden();
  await expect(page.locator("#github-link")).toHaveAttribute("href", "https://acme.example/wallet-kit");
  await expect(page.locator("#theme-nav-link-0")).toHaveText("Scenarios");
  await expect(page.locator("#theme-nav-link-0")).toHaveAttribute("href", "https://acme.example/scenarios");
  await page.goto(BASE + "/decoder/");
  await expect(page.locator("#get-cli-link")).toBeHidden();
  await page.locator("#theme-nav-link-1").click();
  await expect(page).toHaveURL(BASE + "/issuer/");
});

for (const [name, url] of [["wallet", "/"], ["decoder", "/decoder/"], ["demo issuer", "/issuer/"], ["demo verifier", "/verifier/"]]) {
  test(`the footer of the ${name} page shows the theme's product`, async ({ page }) => {
    await page.goto(BASE + url);
    await expect(page.locator("#footer-version")).toHaveText("Acme Wallet Kit 1.4.0");
    await expect(page.locator("#footer-product")).toHaveAttribute("href", "https://acme.example/wallet-kit");
    await expect(page.locator("#footer-prerelease")).toBeHidden();
  });
}

test("--no-builtins keeps the demo hints that have a theme link", async ({ page }) => {
  await page.goto(NO_BUILTINS_BASE);
  await expect(page.locator("#actions-hint")).toHaveText("No offer at hand? Get one from the demo issuer", { useInnerText: true });
  await expect(page.locator("#actions-hint-issuer-link")).toHaveAttribute("href", "https://acme.example/issuer");
  await expect(page.locator("#actions-hint-verifier-link")).toBeHidden();
  await page.locator("#how-to-use-link").click();
  await expect(page.locator("#howto-demo-hint")).toHaveText("Try the demo issuer.", { useInnerText: true });
  await expect(page.locator("#howto-demo-issuer-link")).toHaveAttribute("href", "https://acme.example/issuer");
});

test("a theme sets the text and the links of the demo hint", async ({ page }) => {
  const yaml = path.join(noBuiltinsTheme, "theme.yaml");
  const before = fs.readFileSync(yaml, "utf8");
  fs.writeFileSync(yaml, "demo:\n  hint:\n    text: New here?\n    links:\n      - label: Start the demo with case 1\n        url: case-1/\n      - label: All test scenarios\n        url: scenarios/\n");
  try {
    await page.goto(NO_BUILTINS_BASE);
    await expect(page.locator("#actions-hint")).toHaveText("New here? Start the demo with case 1 · All test scenarios", { useInnerText: true });
    await expect(page.locator("#actions-hint-link-0")).toHaveAttribute("href", "case-1/");
    await expect(page.locator("#actions-hint-link-1")).toHaveAttribute("href", "scenarios/");
  } finally {
    fs.writeFileSync(yaml, before);
  }
});

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
