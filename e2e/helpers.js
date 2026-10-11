// @ts-check
// Helpers the specs share.

// waitForServer polls url until the server answers without a server error.
async function waitForServer(url, timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(500) });
      if (res.status < 500) return;
    } catch {
      // The server is still starting.
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`${url} did not start within ${timeoutMs}ms`);
}

module.exports = { waitForServer };
