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
  const catalogDir = path.join(work, "catalog");
  fs.mkdirSync(catalogDir);
  fs.writeFileSync(path.join(catalogDir, "tickets.json"), JSON.stringify([
    { name: "E2E operator ticket", category: "eaa", credentials: [{ format: "mso_mdoc", type: "org.example.e2e.ticket.1", claims: [["org.example.e2e.ticket.1", "seat"]] }] },
  ]));
  fs.writeFileSync(path.join(catalogDir, "diploma.yaml"), [
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
      "--wallet-dir", path.join(work, "wallet"), "--base-url", BASE, "--catalog", catalogDir],
    { stdio: "ignore" }
  );
  await waitForServer(`${BASE}/api/version`, 30_000);
});

test.describe.configure({ mode: "serial" });

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

async function openCatalog(page) {
  await page.goto(BASE);
  await page.locator("#registrar-menu-toggle").click();
  await page.locator("#registrar-catalog-link").click();
  await expect(page.locator("#registrar-catalog-overlay")).toHaveClass(/active/);
}

const entryNames = (page) => page.locator("#registrar-catalog-list .registrar-party-name");

test("every file of a catalogue directory is pre-registered", async ({ page }) => {
  await openCatalog(page);
  const ticket = page.locator("#registrar-catalog-list .registrar-party").filter({ hasText: "E2E operator ticket" });
  await expect(ticket.locator('[id$="-operator"]')).toHaveText("Pre-registered");
  await expect(ticket.locator('[id$="-format-0"]')).toContainText("mso_mdoc: org.example.e2e.ticket.1");
  await expect(ticket.locator('[id$="-delete"]')).toHaveCount(0);
});

test("the source filter and the search narrow the catalogue", async ({ page }) => {
  await openCatalog(page);
  await expect(entryNames(page).filter({ hasText: "EUDI PID" })).toHaveCount(1);

  await page.locator("#registrar-catalog-filter-source-operator").click();
  await expect(page.locator("#registrar-catalog-filter-source-operator")).toHaveAttribute("aria-pressed", "true");
  await expect(entryNames(page)).toHaveText(["E2E operator diploma", "E2E operator ticket"]);

  await page.locator("#registrar-catalog-search").fill("e2e.ticket");
  await expect(entryNames(page)).toHaveText(["E2E operator ticket"]);
  await page.locator("#registrar-catalog-search").fill("no such attestation");
  await expect(entryNames(page)).toHaveCount(0);
  await expect(page.locator("#registrar-catalog-empty")).toHaveText('No attestation matches "no such attestation".');

  await page.locator("#registrar-catalog-search").fill("");
  await page.locator("#registrar-catalog-filter-clear").click();
  await expect(page.locator("#registrar-catalog-filter-clear")).toHaveCount(0);
  await expect(entryNames(page).filter({ hasText: "EUDI PID" })).toHaveCount(1);
});

test("visitors delete only the entries they added", async ({ page, request }) => {
  const added = await request.post(`${BASE}/api/catalog/attestations`, {
    data: { name: "E2E visitor badge", category: "eaa", credentials: [{ format: "dc+sd-jwt", type: "urn:example:e2e-visitor-badge:1" }] },
  });
  expect(added.status()).toBeLessThan(300);
  const { schema } = await added.json();

  const operator = (await (await request.get(`${BASE}/api/catalog/attestations`)).json())
    .find((e) => e.name === "E2E operator diploma");
  const refused = await request.delete(`${BASE}/api/catalog/schemas/${operator.schema.id}`);
  expect(refused.status()).toBe(403);
  expect((await refused.json()).error).toContain("visitors can't delete it");

  await openCatalog(page);
  const pid = page.locator("#registrar-catalog-list .registrar-party").filter({ hasText: "EUDI PID" });
  await expect(pid.locator('[id$="-delete"]')).toHaveCount(0);
  const badge = page.locator(`#registrar-catalog-entry-${schema.id}`);
  await expect(badge.locator('[id$="-name"]')).toHaveText("E2E visitor badge");
  await badge.locator('[id$="-delete"]').click();
  await expect(badge).toHaveCount(0);
  await expect(page.locator("#registrar-catalog-error")).toBeEmpty();
});
