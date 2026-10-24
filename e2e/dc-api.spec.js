// @ts-check
// The demo verifier calls navigator.credentials.get(). The eudi-dev browser
// extension answers it with the wallet, which asks for consent in a window.
const { test, expect, chromium } = require("@playwright/test");
const { waitForServer } = require("./helpers");
const { execSync, spawn } = require("child_process");
const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");

// The wallet also listens on PORT + 1 for HTTPS.
const PORT = 18985;
const BASE = `http://localhost:${PORT}`;
const BINARY = "/tmp/eudi-dc-api-e2e";

let walletProcess;
let extensionDir;

test.describe.configure({ mode: "serial" });
test.setTimeout(60_000);

test.beforeAll(async () => {
  test.setTimeout(120_000);
  execSync(`go build -o ${BINARY} ..`, { cwd: __dirname });
  const walletDir = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-dc-api-e2e-"));
  extensionDir = path.join(walletDir, "extension");
  execSync(`${BINARY} wallet extension ${extensionDir} --wallet-url ${BASE}`);

  const resultsDir = path.join(__dirname, "test-results");
  fs.mkdirSync(resultsDir, { recursive: true });
  const logFd = fs.openSync(path.join(resultsDir, "dc-api-wallet.log"), "w");
  walletProcess = spawn(
    BINARY,
    ["wallet", "serve", "--demo", "--demo-reset", "0", "--port", String(PORT), "--wallet-dir", walletDir, "--base-url", BASE],
    { stdio: ["ignore", logFd, logFd], env: { ...process.env, EUDI_DEV_HOME: walletDir } }
  );
  await waitForServer(`${BASE}/api/version`, 30_000);
});

test.afterAll(() => {
  if (walletProcess) walletProcess.kill("SIGTERM");
});

async function withExtension(run) {
  const context = await chromium.launchPersistentContext("", {
    channel: "chromium",
    headless: true,
    args: [`--disable-extensions-except=${extensionDir}`, `--load-extension=${extensionDir}`],
  });
  try {
    await run(context);
  } finally {
    await context.close();
  }
}

async function startDCAPIRequest(context, signing = "signed") {
  const page = await context.newPage();
  await page.goto(`${BASE}/verifier/`);
  await page.locator("#credential-pid").click();
  await page.locator("#format-sd-jwt").click();
  await page.locator("#delivery-dc-api").click();
  await expect(page.locator("#delivery-hint")).toContainText("The eudi-dev extension answers");
  await expect(page.locator("#extension-store")).toHaveCount(0);
  await page.locator(`#signing-${signing}`).click();
  const walletWindow = context.waitForEvent("page");
  await page.locator("#create-request").click();
  return { page, walletWindow: await walletWindow };
}

for (const signing of ["signed", "unsigned", "multisigned"]) {
  test(`the extension answers a ${signing} request with the wallet`, async () => {
    await withExtension(async (context) => {
      const { page, walletWindow } = await startDCAPIRequest(context, signing);
      await walletWindow.locator("#consent-approve").click();
      await expect(page.locator("#status")).toHaveClass(/verified/);
      await expect.poll(() => walletWindow.isClosed()).toBe(true);
    });
  });
}

test("an unsigned request hides the client ID scheme and the identity", async ({ page }) => {
  await page.goto(`${BASE}/verifier/`);
  await page.locator("#credential-custom").click();
  await page.locator("#delivery-dc-api").click();
  await expect(page.locator("#scheme-redirect-uri")).toBeDisabled();
  await page.locator("#signing-unsigned").click();
  await expect(page.locator("#scheme-row")).toBeHidden();
  await expect(page.locator("#identity-registered")).toBeDisabled();
  await page.locator("#delivery-redirect").click();
  await expect(page.locator("#signing-row")).toBeHidden();
  await expect(page.locator("#scheme-redirect-uri")).toBeEnabled();
});

// The next request is the only one its window shows, so approving it answers
// that request and closes the window.
test("closing the wallet window rejects the call and the next request still works", async () => {
  await withExtension(async (context) => {
    const { page, walletWindow } = await startDCAPIRequest(context);
    await expect(walletWindow.locator("#consent-approve")).toBeVisible();
    await walletWindow.close();
    await expect(page.locator("#status")).toHaveClass(/failed/);
    await expect(page.locator("#status")).toContainText("NotAllowedError");

    const next = await startDCAPIRequest(context);
    await next.walletWindow.locator("#consent-approve").click();
    await expect(next.page.locator("#status")).toHaveClass(/verified/);
    await expect.poll(() => next.walletWindow.isClosed()).toBe(true);
  });
});

// W3C Digital Credentials §6.2: the browser checks a request before a wallet
// sees it. The extension makes the same checks.
test("the extension refuses requests the way a browser does", async () => {
  await withExtension(async (context) => {
    const page = await context.newPage();
    await page.goto(`${BASE}/verifier/`);
    const failure = (options) =>
      page.evaluate((opts) => navigator.credentials.get(opts).then(() => "resolved", (e) => `${e.name}: ${e.message}`), options);
    expect(await failure({ digital: { requests: [{ protocol: "org-iso-mdoc", data: {} }] } })).toMatch(/^TypeError: No request uses a supported protocol/);
    // page.evaluate counts as a user action. That activation ends after
    // about five seconds.
    const late = await page.evaluate(async () => {
      await new Promise((resolve) => setTimeout(resolve, 5500));
      return navigator.credentials
        .get({ digital: { requests: [{ protocol: "openid4vp-v1-unsigned", data: {} }] } })
        .then(() => "resolved", (e) => `${e.name}: ${e.message}`);
    });
    expect(late).toMatch(/^NotAllowedError: .*user action/);
  });
});

// A verifier of another origin that only uses the standard API, with no
// eudi-dev code.
const VERIFIER_PORT = 18987;
const VERIFIER_PAGE = `<!doctype html><meta charset="utf-8"><title>Other verifier</title>
<button id="present">Present</button><pre id="out"></pre>
<script>
document.getElementById("present").addEventListener("click", async () => {
  const out = document.getElementById("out");
  try {
    const credential = await navigator.credentials.get({ digital: { requests: [{
      protocol: "openid4vp-v1-unsigned",
      data: {
        response_type: "vp_token",
        response_mode: "dc_api",
        nonce: "other-verifier-nonce",
        dcql_query: { credentials: [{ id: "pid", format: "dc+sd-jwt", meta: { vct_values: ["urn:eudi:pid:1"] }, claims: [{ path: ["given_name"] }] }] },
      },
    }] } });
    const presentation = credential.data.vp_token.pid[0];
    const kb = JSON.parse(atob(presentation.split("~").pop().split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    out.textContent = JSON.stringify({ protocol: credential.protocol, aud: kb.aud, nonce: kb.nonce });
  } catch (e) {
    out.textContent = e.name + ": " + e.message;
  }
});
</script>`;

test("the extension answers a verifier of another origin", async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(VERIFIER_PAGE);
  });
  await new Promise((resolve) => server.listen(VERIFIER_PORT, resolve));
  try {
    await withExtension(async (context) => {
      const page = await context.newPage();
      await page.goto(`http://localhost:${VERIFIER_PORT}/`);
      const walletWindow = context.waitForEvent("page");
      await page.locator("#present").click();
      await (await walletWindow).locator("#consent-approve").click();
      await expect(page.locator("#out")).not.toBeEmpty();
      const result = JSON.parse(await page.locator("#out").textContent());
      // OpenID4VP 1.0 §5.9.3 binds the presentation to the page origin.
      expect(result).toEqual({ protocol: "openid4vp-v1-unsigned", aud: `origin:http://localhost:${VERIFIER_PORT}`, nonce: "other-verifier-nonce" });
    });
  } finally {
    server.close();
  }
});

test("without the extension the verifier offers it from the store and for download", async ({ page }) => {
  await page.goto(`${BASE}/verifier/`);
  await page.locator("#delivery-dc-api").click();
  await expect(page.locator("#extension-store")).toHaveAttribute("href", /chromewebstore\.google\.com\/detail\/nbddeclckpkklpejkmhchmhmajginnok$/);
  await expect(page.locator("#delivery-hint")).toContainText(`set ${BASE} as the wallet in its popup`);
  await expect(page.locator("#extension-download")).toBeHidden();
  await page.locator("#extension-manual summary").click();
  const download = page.waitForEvent("download");
  await page.locator("#extension-download").click();
  expect((await download).suggestedFilename()).toBe("eudi-dev-dc-api-extension.zip");
});

test("the How to use dialog offers the extension from the store until it is installed", async ({ page }) => {
  await page.goto(BASE);
  await page.locator("#how-to-use-link").click();
  await page.locator("#howto-tab-extension").click();
  await expect(page.locator("#howto-extension-store-link")).toBeVisible();
  await expect(page.locator("#howto-extension-store-hint")).toContainText(`set ${BASE} as the wallet`);
  await expect(page.locator("#howto-extension-browser-command")).toBeHidden();
  await page.locator("#howto-extension-manual summary").click();
  await expect(page.locator("#howto-extension-browser-command")).toBeVisible();

  await withExtension(async (context) => {
    const wallet = await context.newPage();
    await wallet.goto(BASE);
    await wallet.locator("#how-to-use-link").click();
    await wallet.locator("#howto-tab-extension").click();
    await expect(wallet.locator("#howto-extension-intro")).toBeVisible();
    await expect(wallet.locator("#howto-extension-store")).toBeHidden();
    await expect(wallet.locator("#howto-extension-manual-summary")).toHaveText("Install");
    await expect(wallet.locator("#howto-extension-browser-command")).toBeVisible();
  });
});

test("each link of a request has a QR code beside it", async ({ page }) => {
  await page.goto(`${BASE}/verifier/`);
  await page.locator("#credential-pid").click();
  await page.locator("#create-request").click();
  for (const id of ["#wallet-link-qr", "#scheme-uri-qr"]) {
    await expect(page.locator(id)).toBeVisible();
    expect(await page.locator(id).evaluate((img) => img.naturalWidth)).toBeGreaterThan(0);
  }
  await page.locator("#scheme-uri-qr").click();
  await expect(page.locator("#scheme-uri-qr")).toHaveClass(/large/);
});

test("each link of a credential offer has a QR code beside it", async ({ page }) => {
  await page.goto(`${BASE}/issuer/`);
  await page.locator("#create-btn").click();
  for (const id of ["#wallet-link-qr", "#scheme-uri-qr"]) {
    await expect(page.locator(id)).toBeVisible();
    expect(await page.locator(id).evaluate((img) => img.naturalWidth)).toBeGreaterThan(0);
  }
  await page.locator("#wallet-link-qr").click();
  await expect(page.locator("#wallet-link-qr")).toHaveClass(/large/);
});
