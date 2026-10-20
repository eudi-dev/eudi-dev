// @ts-check
// The guided tour walks through the wallet's use cases from How to use.
const { test, expect } = require("@playwright/test");
const { waitForServer } = require("./helpers");
const { execSync, spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const PORT = 18975;
const BASE = `http://localhost:${PORT}`;
let walletProcess;
let newsID;

const TITLES = [
  "Paste an offer or request",
  "Issue a credential yourself",
  "Try the demo issuer and verifier",
  "Check your credentials",
  "Follow every exchange",
  "Set up trust",
  "Register your verifier or issuer",
  "Choose how strict the wallet is",
  "Define your own credential types",
  "Decode a credential",
];
// The header links behind these steps collapse into the menu on a phone.
const NAV_STEPS = TITLES.slice(5);

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  test.setTimeout(120_000);
  execSync("go build -o /tmp/eudi-tour-e2e ..", { cwd: __dirname });
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-tour-e2e-"));
  const newsFile = path.join(work, "news.html");
  fs.writeFileSync(newsFile, "<h2>New in this release</h2><p>A new feature.</p>");
  walletProcess = spawn(
    "/tmp/eudi-tour-e2e",
    ["wallet", "serve", "--demo", "--demo-reset", "0", "--port", String(PORT),
      "--wallet-dir", path.join(work, "wallet"), "--base-url", BASE, "--news-file", newsFile],
    { stdio: "ignore" }
  );
  await waitForServer(`${BASE}/api/version`, 30_000);
  newsID = (await (await fetch(`${BASE}/api/config`)).json()).news_id;
});

test.afterAll(() => {
  if (walletProcess) walletProcess.kill("SIGTERM");
});

// openWallet loads the wallet with the news and the demo banner already seen.
async function openWallet(page, theme = "dark") {
  await page.addInitScript(({ id, theme }) => {
    localStorage.setItem("news-seen", id);
    localStorage.setItem("demo-banner-dismissed", "1");
    localStorage.setItem("eudi-dev-theme", theme);
  }, { id: newsID, theme });
  await page.goto(BASE);
  await expect(page.locator(".credential-card").first()).toBeVisible();
}

async function startFromHowTo(page) {
  if (await page.locator("#header-menu-toggle").isVisible()) await page.locator("#header-menu-toggle").click();
  await page.locator("#how-to-use-link").click();
  await page.locator("#howto-tour").click();
  await expect(page.locator("#tour")).toBeVisible();
  await expect(page.locator("#howto-overlay")).not.toHaveClass(/active/);
}

// spotCovers reports whether the spotlight lies inside the viewport and
// covers the given element.
async function spotCovers(page, selector) {
  return page.evaluate((sel) => {
    const spot = document.getElementById("tour-spot").getBoundingClientRect();
    const target = document.querySelector(sel).getBoundingClientRect();
    const inView = spot.width > 0 && spot.height > 0 && spot.top >= 0 && spot.left >= 0 &&
      spot.bottom <= window.innerHeight && spot.right <= document.documentElement.clientWidth;
    const covers = spot.left <= target.left && spot.right >= target.right &&
      spot.top <= Math.max(target.top, 0) && spot.bottom >= Math.min(target.bottom, window.innerHeight);
    return inView && covers;
  }, selector);
}

test("the tour starts from How to use and steps through every use case", async ({ page }) => {
  await openWallet(page);
  await startFromHowTo(page);

  const card = page.locator("#tour-card");
  await expect(card).toHaveAttribute("role", "dialog");
  await expect(card).toHaveAttribute("aria-labelledby", "tour-title");
  await expect(page.locator("#tour-next")).toBeFocused();
  await expect(page.locator("#tour-back")).toBeHidden();

  for (let i = 0; i < TITLES.length; i++) {
    await expect(page.locator("#tour-step")).toHaveText(`Step ${i + 1} of ${TITLES.length}`);
    await expect(page.locator("#tour-title")).toHaveText(TITLES[i]);
    await expect(page.locator("#tour-text")).not.toBeEmpty();
    await expect(page.locator("#tour-next")).toHaveText(i === TITLES.length - 1 ? "Done" : "Next");
    if (i === 1) {
      await page.locator("#tour-back").click();
      await expect(page.locator("#tour-title")).toHaveText(TITLES[0]);
      await page.locator("#tour-next").click();
      await expect(page.locator("#tour-title")).toHaveText(TITLES[1]);
    }
    await page.locator("#tour-next").click();
  }
  await expect(page.locator("#tour")).toBeHidden();
});

test("the spotlight covers the element each step is about", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await openWallet(page);
  await startFromHowTo(page);
  // The activity drawer can be taller than the window, so only its head has to be covered.
  const targets = ["#offer-input", "#issue-btn", "#actions-hint", ".credential-card", "#activity-toggle",
    "#trust-link", "#registrar-menu-toggle", "#conformance-link", "#templates-link", "#decoder-link"];
  for (const selector of targets) {
    await expect.poll(() => spotCovers(page, selector)).toBe(true);
    await page.keyboard.press("ArrowRight");
  }
});

test("Escape closes the tour and returns focus to How to use", async ({ page }) => {
  await openWallet(page);
  await startFromHowTo(page);
  await page.keyboard.press("ArrowRight");
  await expect(page.locator("#tour-title")).toHaveText(TITLES[1]);
  await page.keyboard.press("ArrowLeft");
  await expect(page.locator("#tour-title")).toHaveText(TITLES[0]);
  await page.keyboard.press("Escape");
  await expect(page.locator("#tour")).toBeHidden();
  await expect(page.locator("#how-to-use-link")).toBeFocused();
});

test("Tab stays inside the tour card", async ({ page }) => {
  await openWallet(page);
  await startFromHowTo(page);
  await page.locator("#tour-next").click();
  for (const key of ["Tab", "Tab", "Tab", "Tab", "Shift+Tab", "Shift+Tab", "Shift+Tab", "Shift+Tab"]) {
    await page.keyboard.press(key);
    expect(await page.evaluate(() => document.getElementById("tour-card").contains(document.activeElement))).toBe(true);
  }
  await page.locator("#tour-close").click();
  await expect(page.locator("#tour")).toBeHidden();
});

test("at phone width every step points at a visible element", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openWallet(page);
  await startFromHowTo(page);
  for (let i = 0; i < TITLES.length; i++) {
    await expect(page.locator("#tour-title")).toHaveText(TITLES[i]);
    if (NAV_STEPS.includes(TITLES[i])) {
      await expect(page.locator("#tour-text")).toContainText("Find it under Menu.");
      await expect.poll(() => spotCovers(page, "#header-menu-toggle")).toBe(true);
    } else {
      await expect.poll(() => page.evaluate(() => {
        const spot = document.getElementById("tour-spot").getBoundingClientRect();
        return spot.width > 0 && spot.top >= 0 && spot.bottom <= window.innerHeight;
      })).toBe(true);
    }
    const card = await page.locator("#tour-card").boundingBox();
    expect(card.x).toBeGreaterThanOrEqual(16);
    expect(card.x + card.width).toBeLessThanOrEqual(390 - 16);
    await page.locator("#tour-next").click();
  }
  await expect(page.locator("#tour")).toBeHidden();
  await expect(page.locator("#header-menu-toggle")).toBeFocused();
});

test("the tour renders in the light and the dark theme", async ({ browser }) => {
  const backgrounds = {};
  for (const theme of ["dark", "light"]) {
    const page = await browser.newPage();
    await openWallet(page, theme);
    await startFromHowTo(page);
    backgrounds[theme] = await page.locator("#tour-card").evaluate((el) => getComputedStyle(el).backgroundColor);
    await expect(page.locator("#tour-title")).toHaveCSS("color", theme === "light" ? "rgb(21, 23, 26)" : "rgb(236, 238, 241)");
    await page.close();
  }
  expect(backgrounds.light).toBe("rgb(255, 255, 255)");
  expect(backgrounds.dark).toBe("rgb(36, 39, 45)");
});
