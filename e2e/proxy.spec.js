// @ts-check
// Runs the debugging proxy in front of a small target server and checks the dashboard.
const { test, expect } = require("@playwright/test");
const { execFileSync, execSync, spawn } = require("child_process");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");

const TARGET_PORT = 18960;
const PROXY_PORT = 18961;
const DASHBOARD_PORT = 18962;
const DASHBOARD = `http://localhost:${DASHBOARD_PORT}/`;

const processes = [];
let target;
let work;

function proxied(method, pathAndQuery, headers, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "localhost", port: PROXY_PORT, method, path: pathAndQuery, headers }, (res) => {
      res.resume();
      res.on("end", resolve);
    });
    req.on("error", reject);
    req.end(body);
  });
}

async function waitFor(url, timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.status < 500) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`${url} did not start within ${timeoutMs}ms`);
}

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  test.setTimeout(120_000);
  work = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-proxy-e2e-"));
  const binary = path.join(work, "eudi");
  execSync(`go build -o ${binary} ..`, { cwd: __dirname });

  target = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ access_token: "at-1", token_type: "Bearer" }));
  });
  await new Promise((resolve) => target.listen(TARGET_PORT, resolve));

  const resultsDir = path.join(__dirname, "test-results");
  fs.mkdirSync(resultsDir, { recursive: true });
  const log = fs.openSync(path.join(resultsDir, "proxy.log"), "w");
  processes.push(
    spawn(
      binary,
      ["proxy", "--target", `http://localhost:${TARGET_PORT}`, "--port", String(PROXY_PORT), "--dashboard", String(DASHBOARD_PORT), "--all-traffic"],
      { stdio: ["ignore", log, log], env: { ...process.env, EUDI_DEV_HOME: path.join(work, "home") } }
    )
  );
  await waitFor(`${DASHBOARD}api/entries`, 30_000);
});

test.afterAll(async () => {
  for (const p of processes) p.kill();
  if (target) await new Promise((resolve) => target.close(resolve));
});

test("Copy cURL quotes what the target controls", async ({ page, context }) => {
  const marker = path.join(work, "pwned");
  const injection = `'$(touch${"${IFS}"}${marker})'`;
  await proxied("GET", `/authorize?client_id=x&response_type=vp_token&state=${injection}`, { "X-Note": `a ${injection} b` });

  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto(DASHBOARD);
  const entry = page.locator(".entry").filter({ hasText: "VP Auth Request" }).first();
  await entry.locator(".entry-header").click();
  await entry.locator(".btn-copy-curl").click();
  await expect(entry.locator(".btn-copy-curl")).toHaveText("Copied!");
  const curl = await page.evaluate(() => navigator.clipboard.readText());

  // The shell parses the command, and printf shows each argument curl would get.
  const args = execFileSync("bash", ["-c", curl.replace(/^curl /, "printf '%s\\n' ")], { encoding: "utf8" }).split("\n");
  expect(fs.existsSync(marker)).toBe(false);
  expect(args.slice(0, 3)).toEqual([
    "-X",
    "GET",
    `http://localhost:${PROXY_PORT}/authorize?client_id=x&response_type=vp_token&state=${injection}`,
  ]);
  expect(args).toContain(`X-Note: a ${injection} b`);
});

test("the dashboard carries the EUDI Dev name and exports eudi-dev.har", async ({ page }) => {
  await page.goto(DASHBOARD);
  await expect(page).toHaveTitle("EUDI Dev Proxy");
  await expect(page.locator("#header-title")).toHaveText("EUDI Dev Proxy");
  const download = page.waitForEvent("download");
  await page.locator("#har-export").click();
  expect((await download).suggestedFilename()).toBe("eudi-dev.har");
});

test("an entry that arrives twice is shown once", async ({ page }) => {
  const entry = { id: 7, timestamp: new Date().toISOString(), method: "GET", url: "http://x/twice", statusCode: 200, classLabel: "VP Auth Request", durationMs: 1 };
  await page.route("**/api/entries", (route) => route.fulfill({ contentType: "application/json", body: "[]" }));
  // Every reconnect of the stream delivers the same entry again.
  await page.route("**/api/stream", (route) =>
    route.fulfill({ contentType: "text/event-stream", body: `data: ${JSON.stringify(entry)}\n\n` })
  );
  await page.goto(DASHBOARD);
  await expect(page.locator(".entry")).toHaveCount(1);
  await page.waitForResponse("**/api/stream");
  await page.waitForResponse("**/api/stream");
  await expect(page.locator(".entry")).toHaveCount(1);
});

test.describe("theme", () => {
  test("follows the system until the toggle picks one", async ({ page }) => {
    await page.emulateMedia({ colorScheme: "light" });
    await page.goto(DASHBOARD);
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");

    await page.locator("#theme-toggle").click();
    await expect(page.locator("html")).not.toHaveAttribute("data-theme", "light");
    expect(await page.evaluate(() => localStorage.getItem("eudi-dev-theme"))).toBe("dark");

    await page.reload();
    await expect(page.locator("html")).not.toHaveAttribute("data-theme", "light");
  });
});

for (const width of [375, 1280]) {
  for (const scheme of /** @type {const} */ (["light", "dark"])) {
    test(`entry rows fit at ${width} px in ${scheme}`, async ({ page }) => {
      await proxied("POST", "/token", { "Content-Type": "application/x-www-form-urlencoded" }, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code=abc");
      await page.setViewportSize({ width, height: 800 });
      await page.emulateMedia({ colorScheme: scheme });
      await page.goto(DASHBOARD);
      const row = page.locator(".entry").filter({ hasText: "VCI Token Request" }).first();
      const badge = row.locator(".entry-badge");
      await expect(badge).toHaveText("VCI Token Request");

      const fits = await badge.evaluate((el) => el.scrollWidth <= el.clientWidth && el.getBoundingClientRect().right <= window.innerWidth);
      expect(fits).toBe(true);
      expect((await row.locator(".entry-url").boundingBox())?.width).toBeGreaterThan(100);
      await page.screenshot({ path: path.join(__dirname, "test-results", `proxy-${width}-${scheme}.png`) });
    });
  }
}
