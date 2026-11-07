// examples/non-bypassable-demo/agent.mjs
// How to run:
// 1) node examples/non-bypassable-demo/protected-upstream.mjs
// 2) node examples/non-bypassable-demo/pep-gateway.mjs
// 3) node examples/non-bypassable-demo/agent.mjs
//
// This script simulates an agent/runtime issuing actions through the gateway.
// It demonstrates: valid execution, a gateway refusal for an action the
// authorization does not cover, replay denial, and direct-upstream bypass rejection.
// It exits nonzero if any scenario does not behave as expected.

import { request } from "node:http";
import { hashAction, makeAuthorization } from "./auth-fixture.mjs";

// ---- HTTP helper ----
function postJson(url, body, headers = {}) {
  return new Promise((resolve) => {
    const payload = JSON.stringify(body);
    const u = new URL(url);
    const req = request(
      {
        hostname: u.hostname,
        port: u.port || 80,
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
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          let parsed = null;
          try {
            parsed = data ? JSON.parse(data) : null;
          } catch {
            /* ignore parse errors */
          }
          resolve({ status: res.statusCode, body: parsed, raw: data });
        });
      }
    );
    req.on("error", (err) => resolve({ status: 0, body: null, error: err }));
    req.write(payload);
    req.end();
  });
}

// ---- Demo data ----
const ACTION = {
  type: "EXECUTE",
  tool: "payments.charge",
  params: { amount: "500", currency: "USD", user_id: "user_123" },
};

const GATEWAY_URL = process.env.GATEWAY_URL || "http://localhost:8787";
const UPSTREAM_URL = process.env.UPSTREAM_URL || "http://localhost:8788";

const intentHash = hashAction(ACTION);
const audience = process.env.GATEWAY_AUDIENCE || "pep-gateway.local";

function makeAuth({ authId, hash }) {
  return makeAuthorization({ action: ACTION, authId, audience, intentHash: hash });
}

// ---- Scenarios ----
// Each scenario returns { name, ok, detail }. The summary and the exit code are
// derived from the observed responses, never hard-coded.
async function scenarioAllow() {
  const auth = makeAuth({ authId: `auth_${Date.now()}`, hash: intentHash });
  const res = await postJson(`${GATEWAY_URL}/execute`, { action: ACTION, authorization: auth });
  const ok = res.status === 200 && res.body?.executed === true;
  return { auth, result: { name: "ALLOW", ok, detail: `status=${res.status} executed=${res.body?.executed === true}` } };
}

// Authorization issued for ACTION, presented with a different action (amount changed).
// This is a gateway verification failure (INTENT_HASH_MISMATCH), not a policy DENY:
// no policy engine runs in this example.
async function scenarioNotCovered() {
  const auth = makeAuth({ authId: `auth_nc_${Date.now()}`, hash: intentHash });
  const altered = { ...ACTION, params: { ...ACTION.params, amount: "50000" } };
  const res = await postJson(`${GATEWAY_URL}/execute`, { action: altered, authorization: auth });
  const ok = res.status === 403 && res.body?.reason === "INTENT_HASH_MISMATCH" && res.body?.executed !== true;
  return { name: "NOT_COVERED", ok, detail: `status=${res.status} reason=${res.body?.reason}` };
}

async function scenarioReplay(reusedAuth) {
  const res = await postJson(`${GATEWAY_URL}/execute`, { action: ACTION, authorization: reusedAuth });
  const ok = res.status === 403 && res.body?.reason === "AUTH_REPLAY" && res.body?.executed !== true;
  return { name: "REPLAY", ok, detail: `status=${res.status} reason=${res.body?.reason}` };
}

async function scenarioBypass() {
  const res = await postJson(`${UPSTREAM_URL}/charge`, ACTION.params);
  const ok = res.status === 403 && res.body?.executed !== true;
  return { name: "BYPASS", ok, detail: `status=${res.status}` };
}

async function main() {
  const allow = await scenarioAllow();
  const results = [allow.result, await scenarioNotCovered(), await scenarioReplay(allow.auth), await scenarioBypass()];

  console.log("SUMMARY:");
  for (const r of results) console.log(`  ${r.name.padEnd(12)} ${r.ok ? "as expected" : "UNEXPECTED"}  (${r.detail})`);
  const failed = results.filter((r) => !r.ok).length;
  if (failed > 0) {
    console.log(`${failed} scenario(s) did not behave as expected`);
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error("unexpected error", err);
  process.exitCode = 1;
});
