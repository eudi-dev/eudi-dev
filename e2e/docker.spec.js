// @ts-check
const { test, expect } = require("@playwright/test");
const { waitForServer } = require("./helpers");
const { execSync } = require("child_process");
const http = require("http");

const DOCKER_IMAGE = "eudi-dev-e2e";
const CONTAINER_NAME = "eudi-dev-e2e-test";
// The parallel wallet and decoder tests use ports 18923 through 18926.
const HOST_PORT = 18935;
const WALLET_URL = `http://localhost:${HOST_PORT}`;

test.describe.configure({ mode: "serial" });
// Docker builds and startup can exceed the default 30 second timeout on CI.
test.setTimeout(120_000);

test.beforeAll(async ({ }, testInfo) => {
  testInfo.setTimeout(120_000);
  execSync(`docker build -t ${DOCKER_IMAGE} ..`, {
    cwd: __dirname,
    stdio: "pipe",
    timeout: 120_000,
  });

  try {
    execSync(`docker rm -f ${CONTAINER_NAME}`, { stdio: "pipe" });
  } catch {}

  execSync(
    `docker run -d --name ${CONTAINER_NAME} -p ${HOST_PORT}:8085 ${DOCKER_IMAGE}`,
    { stdio: "pipe" }
  );

  await waitForServer(WALLET_URL, 30_000);
});

test.afterAll(async () => {
  try {
    execSync(`docker rm -f ${CONTAINER_NAME}`, { stdio: "pipe" });
  } catch {}
});

function httpGet(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => resolve({ status: res.statusCode, body }));
      res.on("error", reject);
    });
  });
}

test.describe("Docker Image", () => {
  test("wallet serves UI at /", async ({ page }) => {
    const response = await page.goto(WALLET_URL);
    expect(response.status()).toBe(200);
    await expect(page.locator("h1")).toHaveText("EUDI Dev Wallet");
    await expect(page.locator("#auto-accept-toggle")).toHaveAttribute("aria-pressed", "true");
  });

  test("wallet has PID credentials pre-loaded", async () => {
    const res = await httpGet(`${WALLET_URL}/api/credentials`);
    expect(res.status).toBe(200);
    const creds = JSON.parse(res.body);
    expect(creds.length).toBe(2);

    const formats = creds.map((c) => c.format);
    expect(formats).toContain("dc+sd-jwt");
    expect(formats).toContain("mso_mdoc");
  });

  test("keeps its state in memory and derives its keys from the image seed", async () => {
    const res = await httpGet(`${WALLET_URL}/api/config`);
    expect(res.status).toBe(200);
    const config = JSON.parse(res.body);
    expect(config.storage).toBe("memory");
    expect(config.seeded_keys).toBe(true);
  });

  test("trusted list endpoint is available", async () => {
    const res = await httpGet(`${WALLET_URL}/api/trustlist`);
    expect(res.status).toBe(200);
    expect(res.body.split(".").length).toBe(3);
  });

  test("EUDI_DEV_PORT moves the wallet to another port", async () => {
    const name = `${CONTAINER_NAME}-port`;
    const hostPort = HOST_PORT + 2;
    try {
      execSync(`docker rm -f ${name}`, { stdio: "pipe" });
    } catch {}
    execSync(
      `docker run -d --name ${name} -p ${hostPort}:9100 -e EUDI_DEV_PORT=9100 ${DOCKER_IMAGE}`,
      { stdio: "pipe" }
    );
    try {
      await waitForServer(`http://localhost:${hostPort}`, 30_000);
      const res = await httpGet(`http://localhost:${hostPort}/healthz`);
      expect(res.status).toBe(200);
    } finally {
      execSync(`docker rm -f ${name}`, { stdio: "pipe" });
    }
  });

  // The image sets EUDI_DEV_LISTEN=0.0.0.0, so the wallet and every other
  // server in it answer on the published port.
  test("the decoder in the image answers on its published port", async () => {
    const name = `${CONTAINER_NAME}-decoder`;
    const hostPort = HOST_PORT + 3;
    try {
      execSync(`docker rm -f ${name}`, { stdio: "pipe" });
    } catch {}
    execSync(
      `docker run -d --name ${name} -p ${hostPort}:8080 ${DOCKER_IMAGE} decoder`,
      { stdio: "pipe" }
    );
    try {
      await waitForServer(`http://localhost:${hostPort}`, 30_000);
      const res = await httpGet(`http://localhost:${hostPort}/`);
      expect(res.status).toBe(200);
    } finally {
      execSync(`docker rm -f ${name}`, { stdio: "pipe" });
    }
  });

  test("an unknown EUDI_DEV_ variable stops the wallet", () => {
    let output = "";
    try {
      execSync(`docker run --rm -e EUDI_DEV_PROT=9100 ${DOCKER_IMAGE}`, { stdio: "pipe" });
    } catch (err) {
      output = err.stderr.toString();
    }
    expect(output).toContain("EUDI_DEV_PROT");
  });

  test("version is set", () => {
    const output = execSync(
      `docker run --rm ${DOCKER_IMAGE} version`
    ).toString().trim();
    expect(output).toContain("dev");
  });

  test("decode works via stdin", () => {
    const header = Buffer.from('{"alg":"none","typ":"JWT"}').toString("base64url");
    const payload = Buffer.from('{"sub":"test","iss":"example"}').toString("base64url");
    const jwt = `${header}.${payload}.`;

    const output = execSync(
      `echo '${jwt}' | docker run -i --rm ${DOCKER_IMAGE} decode --json`,
      { encoding: "utf-8" }
    );
    const parsed = JSON.parse(output);
    expect(parsed.payload.sub).toBe("test");
  });
});
