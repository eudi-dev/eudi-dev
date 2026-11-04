// @ts-check
// The YAML of a dialog's command panel is a file that wallet serve reads at
// startup. A second wallet started with these files has the template, the
// relying party and the catalogue entry of the first one.
const { test, expect } = require("@playwright/test");
const { waitForServer } = require("./helpers");
const { execSync, spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const BINARY = "/tmp/eudi-config-files-e2e";
const SOURCE = "http://localhost:18940";
const TARGET = "http://localhost:18942";
const work = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-config-files-e2e-"));
const templatesDir = path.join(work, "templates");
const catalogDir = path.join(work, "catalog");
const partiesDir = path.join(work, "relying-parties");
const processes = [];

function serve(base, args) {
  const port = new URL(base).port;
  processes.push(spawn(BINARY,
    ["wallet", "serve", "--port", port, "--base-url", base, "--wallet-dir", path.join(work, "wallet-" + port), ...args],
    { stdio: "ignore" }));
  return waitForServer(`${base}/api/version`, 30_000);
}

async function jsonGet(url) {
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  return { status: res.status, body: await res.json() };
}

async function yamlOf(page, dialog, note) {
  await page.locator(`#${dialog}-command-toggle`).click();
  await page.locator(`#${dialog}-command-yaml`).check();
  await expect(page.locator(`#${dialog}-command-note`)).toContainText(note);
  return page.locator(`#${dialog}-command-text`).textContent();
}

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  test.setTimeout(120_000);
  execSync(`go build -o ${BINARY} ..`, { cwd: __dirname });
  for (const dir of [templatesDir, catalogDir, partiesDir]) fs.mkdirSync(dir);
  await serve(SOURCE, []);
});

test.afterAll(() => {
  for (const child of processes) child.kill("SIGTERM");
});

let fromCredential;

test("a credential in the wallet fills the template editor, and its YAML is the template file", async ({ page }) => {
  const issued = await fetch(`${SOURCE}/api/issue`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      format: "sdjwt",
      vct: "urn:example:yaml-card:1",
      claims: { member_id: "M-7", active: "yes", address: { locality: "Berlin" } },
      always_disclosed: ["member_id"],
      display: { name: "YAML card", background_color: "#123456" },
    }),
  });
  expect(issued.status).toBe(201);
  const credential = await issued.json();
  fromCredential = (await jsonGet(`${SOURCE}/api/credentials/${credential.id}/template`)).body;
  expect(fromCredential).toMatchObject({
    format: "sdjwt",
    vct: "urn:example:yaml-card:1",
    claims: { member_id: "M-7", active: "yes", address: { locality: "Berlin" } },
    always_disclosed: ["member_id"],
  });

  await page.goto(SOURCE);
  await page.locator("#templates-link").click();
  await page.locator("#template-new").click();
  await page.locator("#issue-template").selectOption(`credential:${credential.id}`);
  await expect(page.locator("#issue-vct")).toHaveValue("urn:example:yaml-card:1");
  await expect(page.locator("#issue-display-name")).toHaveValue("YAML card");
  await expect(page.locator("#template-editor-name")).toHaveValue("yaml-card");

  const yaml = await yamlOf(page, "issue-dialog", "yaml-card.yaml in the templates directory");
  expect(yaml).toContain('active: "yes"');
  fs.writeFileSync(path.join(templatesDir, "yaml-card.yaml"), yaml);
});

test("the registrar dialog's YAML is a relying party file", async ({ page }) => {
  await page.goto(SOURCE);
  await page.locator("#registrar-menu-toggle").click();
  await page.locator("#registrar-parties-link").click();
  await page.locator("#registrar-parties-register").click();
  await page.locator("#registrar-name").fill("YAML Shop");
  await page.locator("#registrar-identifier").fill("NLTEST.00000777");
  const yaml = await yamlOf(page, "registrar-dialog", "EUDI_DEV_RELYING_PARTIES");
  // The file must name the intended use, so the YAML takes it from the purpose.
  expect(yaml).toContain("intendedUseIdentifier: age-check-before-checkout");
  fs.writeFileSync(path.join(partiesDir, "yaml-shop.yaml"), yaml);
});

test("the catalogue dialog's YAML is a catalogue file with its issuer CA", async ({ page }) => {
  await page.goto(SOURCE);
  await page.locator("#registrar-menu-toggle").click();
  await page.locator("#registrar-catalog-link").click();
  await page.locator("#registrar-catalog-add").click();
  await page.locator("#registrar-catalog-name").fill("YAML gym");
  await page.locator("#registrar-catalog-format-1-type").fill("urn:example:yaml-gym:1");
  await page.locator("#registrar-catalog-format-1-claims").fill("member_id, address.locality");
  execSync('openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj "/CN=YAML Gym CA" -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -keyout ca.key -out issuer-ca.pem 2>/dev/null', { cwd: catalogDir });
  fs.rmSync(path.join(catalogDir, "ca.key"));
  await page.locator("#registrar-catalog-issuer-ca").fill(fs.readFileSync(path.join(catalogDir, "issuer-ca.pem"), "utf8"));
  const yaml = await yamlOf(page, "registrar-catalog-add-dialog", "issuer-ca.pem next to it");
  expect(yaml).toContain("issuerCA: issuer-ca.pem");
  fs.writeFileSync(path.join(catalogDir, "yaml-gym.yaml"), yaml);
});

test("a wallet started with the YAML files has the template, the relying party and the catalogue entry", async () => {
  test.setTimeout(60_000);
  await serve(TARGET, ["--templates-dir", templatesDir, "--catalog", catalogDir, "--relying-parties", partiesDir]);

  const template = (await jsonGet(`${TARGET}/api/templates/yaml-card`)).body;
  for (const field of ["format", "vct", "exp", "claims", "always_disclosed", "display"]) {
    expect(template[field]).toEqual(fromCredential[field]);
  }

  const party = await jsonGet(`${TARGET}/api/registrar/wrp/NLTEST.00000777`);
  expect(party.status).toBe(200);
  expect(party.body.data.tradeName).toBe("YAML Shop");
  expect(party.body.data.services[0].intendedUses[0].intendedUseIdentifier).toBe("age-check-before-checkout");

  const entry = (await jsonGet(`${TARGET}/api/catalog/attestations`)).body.find((e) => e.name === "YAML gym");
  expect(entry.credentials[0].claims).toEqual([["member_id"], ["address", "locality"]]);
  const trust = (await jsonGet(`${TARGET}/api/trust`)).body;
  expect(JSON.stringify(trust)).toContain("YAML gym issuer");
});
