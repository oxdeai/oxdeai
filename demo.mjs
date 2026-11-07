// PROTOTYPE for a proposed `pnpm demo` (examples/non-bypassable-demo/demo.mjs).
// Single process, loopback only, ephemeral ports, synthetic demo key, no network
// or credentials. Asserts the four outcomes against a side-effect counter held by
// the protected upstream itself; exits nonzero on any mismatch, error or timeout.
//
// Scenario names describe what is tested at the PEP gateway:
//   ALLOW        valid authorization for this exact action      -> executed once
//   NOT_COVERED  authorization issued for a different action    -> refused by the
//                gateway (INTENT_HASH_MISMATCH). This is NOT a policy-engine DENY:
//                no PDP runs in this demo (see examples/openclaw for a policy DENY).
//   REPLAY       same authorization presented again             -> refused
//   BYPASS       direct call to the upstream, skipping the PEP  -> rejected upstream
//
// Usage (prototype): node demo.mjs <repo-root-with-built-core-and-guard>
import assert from "node:assert/strict";
import { request } from "node:http";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const REQUEST_TIMEOUT_MS = 2_000; // per HTTP request
const DEMO_TIMEOUT_MS = 10_000; // whole run; a hung demo must fail, not hang

// Watchdog: last resort if something never settles (e.g. a server that never closes).
const watchdog = setTimeout(() => {
  console.error(`\nFAIL: demo did not finish within ${DEMO_TIMEOUT_MS} ms`);
  process.exit(1);
}, DEMO_TIMEOUT_MS);
watchdog.unref();

const ROOT = process.argv[2] ?? new URL(".", import.meta.url).pathname;
const imp = (p) => import(pathToFileURL(join(ROOT, p)).href);
const { createPepGatewayHttpServer, createProtectedUpstreamHttpServer, createHttpUpstreamExecutor } =
  await imp("packages/guard/dist/index.js");
const { makeAuthorization, DEMO_KEYSET } = await imp("examples/non-bypassable-demo/auth-fixture.mjs");

const TOKEN = "demo-internal-token"; // shared by gateway + upstream only; the "agent" never sees it
const AUDIENCE = "pep-gateway.local";
const ACTION = { type: "EXECUTE", tool: "payments.charge", params: { amount: "500", currency: "USD", user_id: "user_123" } };

let sideEffects = 0; // incremented only inside the protected upstream's execute()

const listen = (server) =>
  new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });

const close = (server) =>
  new Promise((resolve) => {
    if (!server.listening) return resolve();
    server.close(() => resolve());
    server.closeAllConnections?.(); // drop keep-alive sockets so close() can complete
  });

const post = (port, path, body) =>
  new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = request(
      { hostname: "127.0.0.1", port, path, method: "POST", agent: false,
        headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          try { resolve({ status: res.statusCode, body: data ? JSON.parse(data) : null }); }
          catch (e) { reject(new Error(`invalid JSON response: ${e.message}`)); }
        });
      }
    );
    req.setTimeout(REQUEST_TIMEOUT_MS, () => req.destroy(new Error(`request timed out after ${REQUEST_TIMEOUT_MS} ms`)));
    req.on("error", reject);
    req.end(payload);
  });

const results = [];
async function scenario(name, expect, fn) {
  const before = sideEffects;
  let res;
  try {
    res = await fn();
    const delta = sideEffects - before;
    assert.equal(res.status, expect.status, `${name}: status`);
    if (expect.reason) assert.equal(res.body?.reason, expect.reason, `${name}: reason`);
    assert.equal(delta, expect.sideEffects, `${name}: side effects`);
    results.push({ name, ok: true });
    const detail = res.body?.reason ?? (res.status === 200 ? "executed" : res.body?.error ?? "");
    console.log(`${name.padEnd(12)} ${String(res.status).padEnd(4)} ${detail.padEnd(24)} side effects +${delta}  ✓`);
  } catch (e) {
    results.push({ name, ok: false });
    console.log(`${name.padEnd(12)} FAIL ${e.message} (status=${res?.status} reason=${res?.body?.reason} +${sideEffects - before})`);
  }
}

const upstream = createProtectedUpstreamHttpServer({
  path: "/charge", expectedToken: TOKEN,
  execute: async (p) => { sideEffects++; return { ok: true, executed: true, amount: p.amount }; },
});
let gateway;

try {
  const upstreamPort = await listen(upstream);
  gateway = createPepGatewayHttpServer({
    expectedAudience: AUDIENCE,
    trustedAuthorizationAuthorities: [{ issuer: DEMO_KEYSET.issuer, policyId: "demo-policy-v1" }],
    trustedKeySets: [DEMO_KEYSET],
    replayProtection: { mode: "process-local" },
    internalExecutorToken: TOKEN,
    timeoutMs: REQUEST_TIMEOUT_MS / 2, // gateway gives up first, so its 504 is what the client sees
    executeUpstream: createHttpUpstreamExecutor({ hostname: "127.0.0.1", port: upstreamPort, path: "/charge" }),
  });
  const gatewayPort = await listen(gateway);

  const auth = makeAuthorization({ action: ACTION, authId: `demo_${process.pid}_allow`, audience: AUDIENCE });

  await scenario("ALLOW", { status: 200, sideEffects: 1 }, () =>
    post(gatewayPort, "/execute", { action: ACTION, authorization: auth }));

  // Authorization covers 500 USD; the agent tries to spend 50000 with it.
  const altered = { ...ACTION, params: { ...ACTION.params, amount: "50000" } };
  await scenario("NOT_COVERED", { status: 403, reason: "INTENT_HASH_MISMATCH", sideEffects: 0 }, () =>
    post(gatewayPort, "/execute", { action: altered, authorization:
      makeAuthorization({ action: ACTION, authId: `demo_${process.pid}_notcovered`, audience: AUDIENCE }) }));

  await scenario("REPLAY", { status: 403, reason: "AUTH_REPLAY", sideEffects: 0 }, () =>
    post(gatewayPort, "/execute", { action: ACTION, authorization: auth }));

  await scenario("BYPASS", { status: 403, sideEffects: 0 }, () =>
    post(upstreamPort, "/charge", ACTION.params));
} catch (e) {
  results.push({ name: "setup", ok: false });
  console.error(`FAIL setup: ${e.message}`);
} finally {
  await Promise.all([gateway && close(gateway), close(upstream)]);
}

const failed = results.filter((r) => !r.ok).length;
const ok = failed === 0 && results.length === 4 && sideEffects === 1;
console.log(ok
  ? `\nAll 4 scenarios behaved as expected. Total side effects: ${sideEffects}`
  : `\nFAILED: ${failed} scenario(s) failed, total side effects ${sideEffects} (expected 1)`);
process.exitCode = ok ? 0 : 1; // no process.exit(): servers are already closed, the loop drains naturally
