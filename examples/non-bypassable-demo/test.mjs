import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { get, request } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { makeAuthorization } from "./auth-fixture.mjs";

const GATEWAY_PORT = 18877;
const UPSTREAM_PORT = 18878;
const TOKEN = "test-internal-token";
const AUDIENCE = "pep-gateway.local";

const ACTION = {
  type: "EXECUTE",
  tool: "payments.charge",
  params: { amount: "500", currency: "USD", user_id: "user_123" },
};

function spawnService(name, command, args, env) {
  const child = spawn(command, args, {
    cwd: new URL(".", import.meta.url),
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });

  child.stdout.on("data", (chunk) => process.stdout.write(`[${name}] ${chunk}`));
  child.stderr.on("data", (chunk) => process.stderr.write(`[${name}] ${chunk}`));
  return child;
}

function runAgent(env) {
  return new Promise((resolve) => {
    const child = spawn("node", ["agent.mjs"], {
      cwd: new URL(".", import.meta.url),
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    child.stdout.on("data", (chunk) => (output += chunk));
    child.stderr.on("data", (chunk) => (output += chunk));
    const timer = setTimeout(() => child.kill("SIGKILL"), 15_000);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, output });
    });
  });
}

function stop(child) {
  if (!child.killed) child.kill("SIGTERM");
}

async function waitForHealth(port) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const healthy = await new Promise((resolve) => {
      const req = get(`http://localhost:${port}/healthz`, (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      });
      req.on("error", () => resolve(false));
      req.setTimeout(250, () => {
        req.destroy();
        resolve(false);
      });
    });
    if (healthy) return;
    await delay(100);
  }
  throw new Error(`service on port ${port} did not become healthy`);
}

function postJson(url, body, headers = {}) {
  return new Promise((resolve) => {
    const payload = JSON.stringify(body);
    const u = new URL(url);
    const req = request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname,
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(payload),
          ...headers,
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          let parsed = null;
          try {
            parsed = data ? JSON.parse(data) : null;
          } catch {
            parsed = { raw: data };
          }
          resolve({ status: res.statusCode, body: parsed });
        });
      }
    );
    req.on("error", (err) => resolve({ status: 0, body: { error: err.message } }));
    req.write(payload);
    req.end();
  });
}

function authFor(action, suffix, overrides = {}) {
  return makeAuthorization({
    action,
    authId: `test_${suffix}_${Date.now()}`,
    audience: AUDIENCE,
    ...overrides,
  });
}

async function expectNoExecution(res) {
  assert.notEqual(res.body?.executed, true);
}

async function main() {
  const upstream = spawnService("upstream", "node", ["protected-upstream.mjs"], {
    PORT: String(UPSTREAM_PORT),
    UPSTREAM_EXECUTOR_TOKEN: TOKEN,
    UPSTREAM_TEST_DELAY_MS: "1200",
  });
  const gateway = spawnService("gateway", "node", ["pep-gateway.mjs"], {
    PORT: String(GATEWAY_PORT),
    UPSTREAM_PORT: String(UPSTREAM_PORT),
    UPSTREAM_EXECUTOR_TOKEN: TOKEN,
    UPSTREAM_TIMEOUT_MS: "250",
    GATEWAY_AUDIENCE: AUDIENCE,
  });

  try {
    await waitForHealth(UPSTREAM_PORT);
    await waitForHealth(GATEWAY_PORT);

    const allowAuth = authFor(ACTION, "allow");
    const allow = await postJson(`http://localhost:${GATEWAY_PORT}/execute`, {
      action: ACTION,
      authorization: allowAuth,
    });
    assert.equal(allow.status, 200);
    assert.equal(allow.body?.decision, "ALLOW");
    assert.equal(allow.body?.executed, true);

    const invalidSignatureAuth = authFor(ACTION, "bad_sig");
    invalidSignatureAuth.signature = Buffer.alloc(64).toString("base64");
    const invalidSignature = await postJson(`http://localhost:${GATEWAY_PORT}/execute`, {
      action: ACTION,
      authorization: invalidSignatureAuth,
    });
    assert.equal(invalidSignature.status, 403);
    assert.equal(invalidSignature.body?.reason, "AUTH_SIGNATURE_INVALID");
    await expectNoExecution(invalidSignature);

    const mismatchAuth = authFor(ACTION, "intent_mismatch", { intentHash: "deadbeef" });
    const mismatch = await postJson(`http://localhost:${GATEWAY_PORT}/execute`, {
      action: ACTION,
      authorization: mismatchAuth,
    });
    assert.equal(mismatch.status, 403);
    assert.equal(mismatch.body?.reason, "INTENT_HASH_MISMATCH");
    await expectNoExecution(mismatch);

    const replay = await postJson(`http://localhost:${GATEWAY_PORT}/execute`, {
      action: ACTION,
      authorization: allowAuth,
    });
    assert.equal(replay.status, 403);
    assert.equal(replay.body?.reason, "AUTH_REPLAY");
    await expectNoExecution(replay);

    const bypass = await postJson(`http://localhost:${UPSTREAM_PORT}/charge`, ACTION.params);
    assert.equal(bypass.status, 403);
    await expectNoExecution(bypass);

    const errorAction = {
      ...ACTION,
      params: { ...ACTION.params, __upstream_behavior: "error" },
    };
    const upstreamError = await postJson(`http://localhost:${GATEWAY_PORT}/execute`, {
      action: errorAction,
      authorization: authFor(errorAction, "upstream_error"),
    });
    assert.equal(upstreamError.status, 502);
    assert.equal(upstreamError.body?.reason, "UPSTREAM_ERROR");
    await expectNoExecution(upstreamError);

    const timeoutAction = {
      ...ACTION,
      params: { ...ACTION.params, __upstream_behavior: "timeout" },
    };
    const upstreamTimeout = await postJson(`http://localhost:${GATEWAY_PORT}/execute`, {
      action: timeoutAction,
      authorization: authFor(timeoutAction, "upstream_timeout"),
    });
    assert.equal(upstreamTimeout.status, 504);
    assert.equal(upstreamTimeout.body?.reason, "UPSTREAM_TIMEOUT");
    await expectNoExecution(upstreamTimeout);

    // agent.mjs derives its summary and exit code from the responses.
    const agentEnv = {
      GATEWAY_URL: `http://localhost:${GATEWAY_PORT}`,
      UPSTREAM_URL: `http://localhost:${UPSTREAM_PORT}`,
      GATEWAY_AUDIENCE: AUDIENCE,
    };
    const agentRun = await runAgent(agentEnv);
    assert.equal(agentRun.code, 0, agentRun.output);
    for (const name of ["ALLOW", "NOT_COVERED", "REPLAY", "BYPASS"]) {
      assert.match(agentRun.output, new RegExp(`${name}\\s+as expected`), agentRun.output);
    }
    // Negative control: point the "direct upstream" call at the gateway, where
    // /charge is not served. The bypass check no longer sees a 403, so the agent
    // must report it and exit nonzero instead of printing a fixed summary.
    const agentNegative = await runAgent({ ...agentEnv, UPSTREAM_URL: `http://localhost:${GATEWAY_PORT}` });
    assert.equal(agentNegative.code, 1, agentNegative.output);
    assert.match(agentNegative.output, /BYPASS\s+UNEXPECTED/, agentNegative.output);

    console.log("non-bypassable gateway tests: OK");
  } finally {
    stop(gateway);
    stop(upstream);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
