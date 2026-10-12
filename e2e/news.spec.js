// @ts-check
// A public demo shows the operator's news once per version of the file.
const { test, expect } = require("@playwright/test");
const { execSync, spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const PORT = 18945;
const BASE = `http://localhost:${PORT}`;
let walletProcess;

test.beforeAll(async () => {
  test.setTimeout(120_000);
  execSync("go build -o /tmp/eudi-news-e2e ..", { cwd: __dirname });
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-news-e2e-"));
  const newsFile = path.join(work, "news.html");
  fs.writeFileSync(newsFile, '<h2>Try the beta</h2><p>It runs at <a href="https://preview.example">the preview host</a>.</p>');
  walletProcess = spawn(
    "/tmp/eudi-news-e2e",
    ["wallet", "serve", "--demo", "--demo-reset", "0", "--port", String(PORT),
      "--wallet-dir", path.join(work, "wallet"), "--base-url", BASE, "--news-file", newsFile],
    { stdio: "ignore" }
  );
  const start = Date.now();
  while (Date.now() - start < 30_000) {
    try {
      if ((await fetch(`${BASE}/api/version`)).ok) return;
    } catch (e) {
      // The server is still starting.
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("wallet did not start");
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
