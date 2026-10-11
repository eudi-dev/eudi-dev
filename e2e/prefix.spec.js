// @ts-check
// Runs the wallet under /some/context and the proxy dashboard under /eudi-proxy, behind
// a TLS proxy that acts like an Istio ingress. Like Istio, it leaves Location headers
// unchanged. It only forwards the prefixes and the three issuer metadata paths at the
// host root. Any other path belongs to another app on the shared host, so a test fails
// when the browser requests one.
const { test, expect } = require("@playwright/test");
const { waitForServer } = require("./helpers");
const { execSync, spawn } = require("child_process");
const fs = require("fs");
const http = require("http");
const https = require("https");
const os = require("os");
const path = require("path");

const WALLET_PORT = 18950;
const PUBLIC_PORT = 18951;
const DEV_PROXY_PORT = 18952;
const DASHBOARD_PORT = 18953;
const PREFIX = "/some/context";
const DASHBOARD_PREFIX = "/eudi-proxy";
const ORIGIN = `https://localhost:${PUBLIC_PORT}`;
const PUBLIC = ORIGIN + PREFIX;
const WELL_KNOWN = ["openid-credential-issuer", "oauth-authorization-server", "jwt-vc-issuer"].map(
  (name) => `/.well-known/${name}${PREFIX}`
);

// rewrite: the proxy replaces the prefix with "/", as Envoy does (/some/context/x
// becomes //x).
// rewrite-header: the same, and the proxy also sends X-Forwarded-Prefix.
// keep: the proxy forwards the path unchanged.
let proxyMode = "rewrite";
const unrouted = [];
const processes = [];
let ingress;

function routeRequest(pathname) {
  const matches = (p, prefix) => p === prefix || p.startsWith(prefix + "/");
  if (matches(pathname, DASHBOARD_PREFIX)) {
    return { port: DASHBOARD_PORT, path: "/" + pathname.slice(DASHBOARD_PREFIX.length) };
  }
  if (WELL_KNOWN.some((p) => matches(pathname, p))) {
    return { port: WALLET_PORT, path: pathname };
  }
  if (matches(pathname, PREFIX)) {
    if (proxyMode === "keep") return { port: WALLET_PORT, path: pathname };
    return {
      port: WALLET_PORT,
      path: "/" + pathname.slice(PREFIX.length),
      prefixHeader: proxyMode === "rewrite-header" ? PREFIX : "",
    };
  }
  return null;
}

function startIngress(cert, key) {
  ingress = https.createServer({ cert, key }, (req, res) => {
    const url = new URL(req.url || "/", ORIGIN);
    const route = routeRequest(url.pathname);
    if (!route) {
      // Browsers ask the host root for a favicon when a page has none.
      if (url.pathname !== "/favicon.ico") unrouted.push(url.pathname);
      res.writeHead(404).end("not routed to eudi-dev");
      return;
    }
    const headers = { ...req.headers, "x-forwarded-proto": "https" };
    if (route.prefixHeader) headers["x-forwarded-prefix"] = route.prefixHeader;
    const upstream = http.request(
      { host: "localhost", port: route.port, method: req.method, path: route.path + url.search, headers },
      (upstreamRes) => {
        res.writeHead(upstreamRes.statusCode || 502, upstreamRes.headers);
        // Send the response headers right away, as Envoy does. An event stream sends no
        // body until its first event.
        res.flushHeaders();
        upstreamRes.pipe(res);
      }
    );
    upstream.on("error", () => res.writeHead(502).end());
    req.pipe(upstream);
  });
  return new Promise((resolve) => ingress.listen(PUBLIC_PORT, resolve));
}

function run(binary, args, logName) {
  const resultsDir = path.join(__dirname, "test-results");
  fs.mkdirSync(resultsDir, { recursive: true });
  const fd = fs.openSync(path.join(resultsDir, logName), "w");
  const child = spawn(binary, args, { stdio: ["ignore", fd, fd] });
  processes.push(child);
  return child;
}

test.describe.configure({ mode: "serial" });
test.use({ ignoreHTTPSErrors: true });

test.beforeAll(async () => {
  test.setTimeout(120_000);
  const binary = "/tmp/eudi-prefix-e2e";
  execSync(`go build -o ${binary} ..`, { cwd: __dirname });
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-prefix-e2e-"));
  execSync(
    `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=localhost ` +
      `-addext subjectAltName=DNS:localhost -keyout key.pem -out cert.pem`,
    { cwd: work, stdio: "ignore" }
  );
  await startIngress(fs.readFileSync(path.join(work, "cert.pem")), fs.readFileSync(path.join(work, "key.pem")));

  run(
    binary,
    ["wallet", "serve", "--port", String(WALLET_PORT), "--wallet-dir", path.join(work, "wallet"), "--pid", "--base-url", PUBLIC],
    "prefix-wallet.log"
  );
  run(
    binary,
    [
      "proxy",
      "--target", `http://localhost:${WALLET_PORT}`,
      "--port", String(DEV_PROXY_PORT),
      "--dashboard", String(DASHBOARD_PORT),
      "--dashboard-base-url", ORIGIN + DASHBOARD_PREFIX,
      "--all-traffic",
    ],
    "prefix-proxy.log"
  );
  await waitForServer(`http://localhost:${WALLET_PORT}/api/version`, 30_000);
  await waitForServer(`http://localhost:${DASHBOARD_PORT}/api/entries`, 30_000);
});

test.afterAll(async () => {
  for (const child of processes) child.kill("SIGTERM");
  if (ingress) await new Promise((r) => ingress.close(r));
});

test.afterEach(() => {
  const missed = unrouted.splice(0);
  expect(missed, "requests outside the published paths").toEqual([]);
});

async function credentialCount(request) {
  const res = await request.get(PUBLIC + "/api/credentials");
  return Number(res.headers()["x-total-count"]);
}

async function approveConsent(page) {
  await expect(page.locator("#consent-overlay")).toHaveClass(/active/, { timeout: 15_000 });
  await page.locator("#consent-approve").click();
}

for (const mode of ["rewrite", "rewrite-header", "keep"]) {
  test.describe(`behind a proxy (${mode})`, () => {
    test.beforeEach(() => {
      proxyMode = mode;
    });

    test("the wallet UI works at the bare prefix", async ({ page, context }) => {
      await page.goto(PUBLIC);
      await expect(page.locator(".credential-card").first()).toBeVisible({ timeout: 15_000 });
      await expect(page.locator("#decoder-link")).toHaveJSProperty("href", PUBLIC + "/decoder/");
      // The cookie is scoped to the prefix, so the lookup uses a URL under it.
      const cookies = await context.cookies(PUBLIC + "/");
      const session = cookies.find((c) => c.name === "eudi_session");
      expect(session && session.path).toBe(PREFIX);
      expect(session && session.secure).toBe(true);
    });

    test("an open wallet page hears about new requests over its event stream", async ({ page }) => {
      await page.goto(PUBLIC + "/");
      await expect(page.locator(".credential-card").first()).toBeVisible({ timeout: 15_000 });
      const offer = await page.request.post(PUBLIC + "/issuer/api/offers").then((r) => r.json());
      // page.request sends this page's cookie, so the consent dialog opens in this page.
      // The request only finishes after consent, so it is not awaited.
      page.request.post(PUBLIC + "/api/offers", { data: { uri: offer.scheme_uri, interactive: true } }).catch(() => {});
      await expect(page.locator("#consent-overlay")).toHaveClass(/active/, { timeout: 15_000 });
      await page.locator("#consent-deny").click();
      await expect(page.locator("#consent-overlay")).not.toHaveClass(/active/, { timeout: 15_000 });
    });

    test("issuer metadata is found at the host root", async ({ request }) => {
      const issuer = await request.get(`${ORIGIN}/.well-known/openid-credential-issuer${PREFIX}/issuer`);
      expect(issuer.ok()).toBe(true);
      expect((await issuer.json()).credential_issuer).toBe(PUBLIC + "/issuer");

      const authServer = await request.get(`${ORIGIN}/.well-known/oauth-authorization-server${PREFIX}/issuer`);
      expect(authServer.ok()).toBe(true);
      expect((await authServer.json()).issuer).toBe(PUBLIC + "/issuer");

      const walletIssuer = await request.get(`${ORIGIN}/.well-known/jwt-vc-issuer${PREFIX}`);
      expect(walletIssuer.ok()).toBe(true);
      expect((await walletIssuer.json()).issuer).toBe(PUBLIC);
    });

    test("a demo issuer offer opened in the browser is issued", async ({ page }) => {
      // The bare mount redirects under the prefix.
      await page.goto(PUBLIC + "/issuer");
      expect(page.url()).toBe(PUBLIC + "/issuer/");
      await page.locator("#create-btn").click();
      await expect(page.locator("#result")).toBeVisible();
      const before = await credentialCount(page.request);

      await page.locator("#wallet-link").click();
      expect(page.url().startsWith(PUBLIC + "/")).toBe(true);
      await approveConsent(page);

      await expect.poll(() => credentialCount(page.request), { timeout: 15_000 }).toBeGreaterThan(before);
    });

    test("a demo verifier request is answered and returns to the verifier", async ({ page }) => {
      await page.goto(PUBLIC + "/verifier/");
      await page.locator('#credential-toggle [data-credential="pid"]').click();
      await page.locator("#create-request").click();
      await expect(page.locator("#wallet-link")).not.toHaveText("…");

      await page.locator("#wallet-link").click();
      await approveConsent(page);

      await page.waitForURL((url) => url.href.startsWith(PUBLIC + "/verifier/"), { timeout: 15_000 });
      await expect(page.locator("#status")).toHaveText(/verified/i, { timeout: 15_000 });
    });

    test("issuer sign-in returns to the wallet under the prefix", async ({ page }) => {
      const offer = await page.request
        .post(PUBLIC + "/issuer/api/offers?grant=authorization_code&authorization=browser")
        .then((r) => r.json());
      const redeemed = await page.request.post(PUBLIC + "/api/offers", { data: { uri: offer.scheme_uri } });
      expect(redeemed.status()).toBe(202);
      const { authorization_url: authURL, offer_id: offerID } = await redeemed.json();
      expect(authURL.startsWith(PUBLIC + "/issuer/authorize")).toBe(true);

      await page.goto(authURL);
      await page.locator('button[type="submit"]').click();
      await page.waitForURL(PUBLIC + "/?focus=overview", { timeout: 15_000 });

      await expect
        .poll(async () => (await page.request.get(`${PUBLIC}/api/offers/${offerID}`).then((r) => r.json())).status, {
          timeout: 15_000,
        })
        .toBe("completed");
    });

    test("the decoder opens under the prefix", async ({ page }) => {
      const credentials = await page.request.get(PUBLIC + "/api/credentials").then((r) => r.json());
      await page.goto(PUBLIC + "/decoder");
      expect(page.url()).toBe(PUBLIC + "/decoder/");
      await page.goto(`${PUBLIC}/decoder/?id=${encodeURIComponent(credentials[0].id)}`);
      await expect(page.locator("#format-badge")).not.toBeEmpty({ timeout: 15_000 });
    });
  });
}

test.describe("without the proxy", () => {
  // Like kubectl port-forward: the wallet is reached at its root although --base-url
  // has a prefix.
  test("the wallet still serves its UI at the root", async ({ page }) => {
    await page.goto(`http://localhost:${WALLET_PORT}/`);
    await expect(page.locator(".credential-card").first()).toBeVisible({ timeout: 15_000 });
    const res = await page.request.get(`http://localhost:${WALLET_PORT}/api/version`);
    expect(res.ok()).toBe(true);
  });
});

test.describe("proxy dashboard under a path prefix", () => {
  test("lists earlier traffic and streams new traffic", async ({ page }) => {
    await fetch(`http://localhost:${DEV_PROXY_PORT}/api/version`);

    await page.goto(ORIGIN + DASHBOARD_PREFIX);
    await page.locator("#show-all").check();
    await expect(page.locator("#entries")).toContainText("/api/version", { timeout: 15_000 });

    // Only the event stream delivers traffic that arrives after the page loaded.
    await fetch(`http://localhost:${DEV_PROXY_PORT}/api/credentials`);
    await expect(page.locator("#entries")).toContainText("/api/credentials", { timeout: 15_000 });
  });
});
