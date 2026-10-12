// @ts-check
// wallet serve --catalog pre-registers attestation types that visitors of a
// public demo see in the catalogue and can't delete.
const { test, expect } = require("@playwright/test");
const { waitForServer } = require("./helpers");
const { execSync, spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const PORT = 18947;
const BASE = `http://localhost:${PORT}`;
let walletProcess;

test.beforeAll(async () => {
  test.setTimeout(120_000);
  execSync("go build -o /tmp/eudi-catalog-e2e ..", { cwd: __dirname });
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-catalog-e2e-"));
  const catalogFile = path.join(work, "catalog.yaml");
  fs.writeFileSync(catalogFile, [
    "name: E2E operator diploma",
    "category: qeaa",
    "credentials:",
    "  - format: dc+sd-jwt",
    "    type: urn:example:e2e-operator-diploma:1",
    "    claims: [[degree]]",
    "",
  ].join("\n"));
  walletProcess = spawn(
    "/tmp/eudi-catalog-e2e",
    ["wallet", "serve", "--demo", "--demo-reset", "0", "--port", String(PORT),
      "--wallet-dir", path.join(work, "wallet"), "--base-url", BASE, "--catalog", catalogFile],
    { stdio: "ignore" }
  );
  await waitForServer(`${BASE}/api/version`, 30_000);
});

test.afterAll(() => {
  if (walletProcess) walletProcess.kill("SIGTERM");
});

test("the catalogue lists a pre-registered entry that visitors can't delete", async ({ page }) => {
  await page.goto(BASE);
  await page.locator("#registrar-menu-toggle").click();
  await page.locator("#registrar-catalog-link").click();
  const entry = page.locator("#registrar-catalog-list .registrar-party").filter({ hasText: "E2E operator diploma" });
  await expect(entry).toHaveCount(1);
  await expect(entry.locator('[id$="-operator"]')).toHaveText("Pre-registered");
  await expect(entry.locator('[id$="-category"]')).toContainText("QEAA");
  await expect(entry.locator('[id$="-delete"]')).toHaveCount(0);
});
