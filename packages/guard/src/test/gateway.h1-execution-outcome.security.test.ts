// Lot 3 - H-1: the PEP gateway reports a three-state execution outcome
// (NOT_DISPATCHED / EXECUTED / INDETERMINATE). A request that was dispatched to
// the upstream and then became uncertain (non-success status incl. 4xx, timeout,
// thrown error) must NEVER be reported as a confirmed non-execution
// (executed:false); it is INDETERMINATE with executed:null. The authorization
// decision stays ALLOW once the gate has opened; decision:DENY is reserved for
// pre-dispatch denials.
import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { createPepGatewayExecutor } from "../gateway.js";
import { signAuthorizationEd25519, sha256HexFromJson, type KeySet } from "@oxdeai/core";

const kp = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const KS: KeySet = { issuer: "iss", version: "1", keys: [{ kid: "k1", alg: "Ed25519", public_key: kp.publicKey.toString(), status: "active" }] };
const NOW = Math.floor(Date.now() / 1000);
const action = { type: "EXECUTE", tool: "t", params: { amount: 1 } };
const auth = (auth_id: string) => signAuthorizationEd25519({ auth_id, issuer: "iss", audience: "gw", intent_hash: sha256HexFromJson(action), state_hash: "2".repeat(64), policy_id: "p1", decision: "ALLOW", issued_at: NOW - 5, expiry: NOW + 600, kid: "k1" }, kp.privateKey);
const base = { expectedAudience: "gw", trustedKeySets: [KS], internalExecutorToken: "tok", trustedAuthorizationAuthorities: [{ issuer: "iss", policyId: "p1" }], timeoutMs: 50 };

test("H-1: upstream 5xx after dispatch -> INDETERMINATE, executed null, decision ALLOW", async () => {
  const gw = createPepGatewayExecutor({ ...base, executeUpstream: async () => ({ status: 503, body: { lost: true } }) });
  const res = await gw({ action, authorization: auth("a1") });
  assert.equal(res.upstreamCalled, true);
  assert.equal(res.body.outcome, "INDETERMINATE");
  assert.equal(res.body.executed, null);
  assert.notEqual(res.body.executed, false, "must not report a confirmed non-execution");
  assert.equal(res.body.decision, "ALLOW", "the gate opened; decision is not retroactively DENY");
});

test("H-1: upstream 4xx after dispatch -> INDETERMINATE (effect cannot be ruled out)", async () => {
  const gw = createPepGatewayExecutor({ ...base, executeUpstream: async () => ({ status: 409, body: { conflict: true } }) });
  const res = await gw({ action, authorization: auth("a2") });
  assert.equal(res.upstreamCalled, true);
  assert.equal(res.body.outcome, "INDETERMINATE");
  assert.equal(res.body.executed, null);
});

test("H-1 (R2): upstream 3xx after dispatch -> INDETERMINATE, not EXECUTED", async () => {
  const gw = createPepGatewayExecutor({ ...base, executeUpstream: async () => ({ status: 302, body: { redirect: "/x" } }) });
  const res = await gw({ action, authorization: auth("a3xx") });
  assert.equal(res.upstreamCalled, true);
  assert.equal(res.body.outcome, "INDETERMINATE");
  assert.equal(res.body.executed, null);
  assert.notEqual(res.body.outcome, "EXECUTED", "a 3xx is not a confirmed success");
});

test("H-1: upstream timeout -> INDETERMINATE, executed null", async () => {
  const gw = createPepGatewayExecutor({ ...base, executeUpstream: () => new Promise((r) => setTimeout(() => r({ status: 200, body: {} }), 500)) });
  const res = await gw({ action, authorization: auth("a3") });
  assert.equal(res.upstreamCalled, true);
  assert.equal(res.body.outcome, "INDETERMINATE");
  assert.equal(res.body.executed, null);
  assert.equal(res.body.reason, "UPSTREAM_TIMEOUT");
});

test("H-1: executor throws after dispatch -> INDETERMINATE, executed null", async () => {
  const gw = createPepGatewayExecutor({ ...base, executeUpstream: async () => { throw new Error("connection reset"); } });
  const res = await gw({ action, authorization: auth("a4") });
  assert.equal(res.upstreamCalled, true);
  assert.equal(res.body.outcome, "INDETERMINATE");
  assert.equal(res.body.executed, null);
});

test("H-1: confirmed success -> EXECUTED, executed true", async () => {
  const gw = createPepGatewayExecutor({ ...base, executeUpstream: async () => ({ status: 200, body: { ok: true } }) });
  const res = await gw({ action, authorization: auth("a5") });
  assert.equal(res.body.outcome, "EXECUTED");
  assert.equal(res.body.executed, true);
  assert.equal(res.body.decision, "ALLOW");
});

test("H-1: pre-dispatch denial -> NOT_DISPATCHED, executed false, upstream never called", async () => {
  let called = 0;
  const gw = createPepGatewayExecutor({ ...base, executeUpstream: async () => { called++; return { status: 200 }; } });
  const bad = auth("a6"); bad.signature = Buffer.alloc(64, 9).toString("base64");
  const res = await gw({ action, authorization: bad });
  assert.equal(called, 0);
  assert.equal(res.upstreamCalled, false);
  assert.equal(res.body.outcome, "NOT_DISPATCHED");
  assert.equal(res.body.executed, false);
  assert.equal(res.body.decision, "DENY");
});
