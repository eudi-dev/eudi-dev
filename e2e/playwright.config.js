// @ts-check
const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: ".",
  testMatch: "*.spec.js",
  timeout: 30_000,
  // Tests share one wallet. CI retries tolerate occasional timing failures under load.
  retries: process.env.CI ? 2 : 0,
  use: {
    baseURL: "http://localhost:18923",
    headless: true,
  },
  webServer: {
    command: "go build -o /tmp/oid4vc-dev-e2e .. && /tmp/oid4vc-dev-e2e decoder --port 18923",
    url: "http://localhost:18923",
    reuseExistingServer: true,
    // Allow time for a cold Go build before the server becomes healthy.
    timeout: 60_000,
  },
  projects: [
    { name: "chromium", use: { browserName: "chromium" } },
  ],
});
