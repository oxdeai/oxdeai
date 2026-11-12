// H-1 client compatibility: what a retrying client observes after the fix.
//
// The gateway cannot stop a client from retrying. What it guarantees is that an
// uncertain execution is never reported as `executed: false`. These tests pin
// that guarantee from the client's side, including the one pattern the fix
// cannot protect: a truthiness check. `executed` is `null` when the outcome is
// INDETERMINATE, and `null` is falsy, so `if (!res.body.executed) retry()`
// still re-executes. Clients must branch on `outcome`, or compare
// `executed === false` strictly.
import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { createPepGatewayExecutor } from "../gateway.js";
import type { PepGatewayResult } from "../gateway.js";
import { signAuthorizationEd25519, sha256HexFromJson, type KeySet } from "@oxdeai/core";

const kp = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const KS: KeySet = { issuer: "iss", version: "1", keys: [{ kid: "k1", alg: "Ed25519", public_key: kp.publicKey.toString(), status: "active" }] };
const NOW = Math.floor(Date.now() / 1000);
const action = { type: "EXECUTE", tool: "payments.transfer", params: { amount: 500, to: "acct-9" } };
const auth = (auth_id: string, audience = "gw") => signAuthorizationEd25519({ auth_id, issuer: "iss", audience, intent_hash: sha256HexFromJson(action), state_hash: "2".repeat(64), policy_id: "p1", decision: "ALLOW", issued_at: NOW - 5, expiry: NOW + 600, kid: "k1" }, kp.privateKey);
const base = { expectedAudience: "gw", trustedKeySets: [KS], internalExecutorToken: "tok", trustedAuthorizationAuthorities: [{ issuer: "iss", policyId: "p1" }], timeoutMs: 50 };

type RetryPolicy = (res: PepGatewayResult) => boolean;

/**
 * One client attempt, then at most one retry with a FRESH authorization when
 * the policy says so. The upstream commits its side effect on every call; the
 * first response is lost (connection reset), the second succeeds.
 */
async function runClient(shouldRetry: RetryPolicy, tag: string): Promise<{ effects: number; first: PepGatewayResult; last: PepGatewayResult }> {
  let effects = 0;
  const gw = createPepGatewayExecutor({
    ...base,
    executeUpstream: async () => {
      effects += 1;
      if (effects === 1) throw Object.assign(new Error("ECONNRESET"), { code: "ECONNRESET" });
      return { status: 200, body: { ok: true } };
    },
  });
  const first = await gw({ action, authorization: auth(`${tag}-1`) });
  let last = first;
  if (shouldRetry(first)) last = await gw({ action, authorization: auth(`${tag}-2`) });
  return { effects, first, last };
}

test("H-1 client: after a lost upstream response the gateway never says executed:false", async () => {
  const { first } = await runClient(() => false, "shape");
  assert.equal(first.body.outcome, "INDETERMINATE");
  assert.strictEqual(first.body.executed, null);
  assert.notStrictEqual(first.body.executed, false);
  assert.equal(first.body.decision, "ALLOW");
  assert.equal(first.upstreamCalled, true);
});

test("H-1 client: retrying only on outcome NOT_DISPATCHED executes the effect once", async () => {
  const { effects, last } = await runClient((r) => r.body.outcome === "NOT_DISPATCHED", "outcome");
  assert.equal(effects, 1);
  assert.equal(last.body.outcome, "INDETERMINATE");
});

test("H-1 client: retrying only on executed === false (strict) executes the effect once", async () => {
  const { effects } = await runClient((r) => r.body.executed === false, "strict");
  assert.equal(effects, 1);
});

test("H-1 client HAZARD (documented, not fixable in the gateway): a truthiness check `!executed` treats null as false and re-executes", async () => {
  const { effects, first } = await runClient((r) => !r.body.executed, "falsy");
  assert.strictEqual(first.body.executed, null, "the gateway reported the uncertainty correctly");
  assert.equal(effects, 2, "the falsy check retried and the effect ran twice; consumers must branch on outcome");
});

test("H-1 client HAZARD (documented): retrying on `!ok` or on HTTP 5xx is equally unsafe for an INDETERMINATE outcome", async () => {
  const byOk = await runClient((r) => !r.body.ok, "ok");
  const byStatus = await runClient((r) => r.status >= 500, "status");
  assert.equal(byOk.first.body.ok, false);
  assert.equal(byOk.effects, 2);
  assert.ok(byStatus.first.status >= 500);
  assert.equal(byStatus.effects, 2);
});

test("H-1 client: a pre-dispatch denial is the only case reported as executed:false, and retrying it has no side effect", async () => {
  let effects = 0;
  const gw = createPepGatewayExecutor({ ...base, executeUpstream: async () => { effects += 1; return { status: 200, body: {} }; } });
  const denied = await gw({ action, authorization: auth("denied-1", "someone-else") });
  assert.equal(denied.body.outcome, "NOT_DISPATCHED");
  assert.strictEqual(denied.body.executed, false);
  assert.equal(denied.body.decision, "DENY");
  assert.equal(denied.upstreamCalled, false);
  assert.equal(effects, 0);
});

test("H-1 client: the three outcomes map one-to-one onto executed true / false / null", async () => {
  const mk = (executeUpstream: () => Promise<{ status: number; body?: unknown }>) => createPepGatewayExecutor({ ...base, executeUpstream });
  const executed = await mk(async () => ({ status: 200, body: {} }))({ action, authorization: auth("map-1") });
  const indeterminate = await mk(async () => ({ status: 500, body: {} }))({ action, authorization: auth("map-2") });
  const notDispatched = await mk(async () => ({ status: 200, body: {} }))({ action, authorization: auth("map-3", "someone-else") });
  assert.deepEqual(
    [executed, indeterminate, notDispatched].map((r) => [r.body.outcome, r.body.executed]),
    [["EXECUTED", true], ["INDETERMINATE", null], ["NOT_DISPATCHED", false]]
  );
});
