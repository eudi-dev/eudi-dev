// @ts-check
// A public demo shows the operator's news once per version of the file.
const { test, expect } = require("@playwright/test");
const { waitForServer } = require("./helpers");
const { execSync, spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const PORT = 18945;
const BASE = `http://localhost:${PORT}`;
let walletProcess;
const PIXEL_PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==";

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  test.setTimeout(120_000);
  execSync("go build -o /tmp/eudi-news-e2e ..", { cwd: __dirname });
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-news-e2e-"));
  const newsFile = path.join(work, "news.html");
  fs.writeFileSync(newsFile, '<h2>Try the beta</h2><p>It runs at <a href="https://preview.example">the preview host</a>.</p><img src="pixel.png" alt="Preview">');
  fs.writeFileSync(path.join(work, "pixel.png"), Buffer.from(PIXEL_PNG, "base64"));
  walletProcess = spawn(
    "/tmp/eudi-news-e2e",
    ["wallet", "serve", "--demo", "--demo-reset", "0", "--port", String(PORT),
      "--wallet-dir", path.join(work, "wallet"), "--base-url", BASE, "--news-file", newsFile],
    { stdio: "ignore" }
  );
  await waitForServer(`${BASE}/api/version`, 30_000);
});

test.afterAll(() => {
  if (walletProcess) walletProcess.kill("SIGTERM");
});

test("the news open on the first visit and stay closed after that", async ({ page }) => {
  await page.goto(BASE);
  await expect(page.locator("#news-overlay")).toHaveClass(/active/);
  await expect(page.locator("#news-content h2")).toHaveText("Try the beta");
  await expect(page.locator("#news-content a")).toHaveAttribute("href", "https://preview.example");
  await page.locator("#news-close").click();
  await expect(page.locator("#news-overlay")).not.toHaveClass(/active/);

  await page.reload();
  await expect(page.locator("#news-link")).toBeVisible();
  await expect(page.locator("#news-overlay")).not.toHaveClass(/active/);
  await page.locator("#news-link").click();
  await expect(page.locator("#news-overlay")).toHaveClass(/active/);
});

test("an image next to the news file is inlined and shown", async ({ page }) => {
  await page.goto(BASE);
  const image = page.locator("#news-content img");
  await expect(image).toHaveAttribute("src", `data:image/png;base64,${PIXEL_PNG}`);
  await expect.poll(() => image.evaluate((img) => img.complete && img.naturalWidth)).toBe(1);
});

test("the news open again only after the file changed", async ({ browser, request }) => {
  const { news_id: id } = await (await request.get(`${BASE}/api/config`)).json();
  for (const [seen, opens] of [[id, false], ["news-of-an-earlier-file", true]]) {
    const page = await browser.newPage();
    const newsRequests = [];
    page.on("request", (r) => { if (r.url().endsWith("/api/news")) newsRequests.push(r.url()); });
    await page.addInitScript((value) => localStorage.setItem("news-seen", value), seen);
    await page.goto(BASE);
    await expect(page.locator("#news-link")).toBeVisible();
    if (opens) {
      await expect(page.locator("#news-overlay")).toHaveClass(/active/);
      expect(await page.evaluate(() => localStorage.getItem("news-seen"))).toBe(id);
    } else {
      await page.waitForTimeout(500);
      expect(newsRequests).toEqual([]);
      await expect(page.locator("#news-overlay")).not.toHaveClass(/active/);
    }
    await page.close();
  }
});

test("a consent link opens the wallet without the news", async ({ page }) => {
  const newsRequests = [];
  page.on("request", (r) => { if (r.url().endsWith("/api/news")) newsRequests.push(r.url()); });
  await page.goto(`${BASE}/?request=e2e-request`);
  await expect(page.locator("#news-link")).toBeVisible();
  await page.waitForTimeout(500);
  expect(newsRequests).toEqual([]);
  await expect(page.locator("#news-overlay")).not.toHaveClass(/active/);
  await page.locator("#news-link").click();
  await expect(page.locator("#news-content h2")).toHaveText("Try the beta");
});
