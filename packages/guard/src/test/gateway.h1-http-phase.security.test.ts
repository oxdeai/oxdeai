// Lot 3 - H-1 (R3): HTTP boundary phase isolation.
//
// The gateway's HTTP handler separates the PARSING phase from the EXECUTION
// phase. NOT_DISPATCHED can be produced only by the parsing phase, which runs
// strictly before the request reaches the executor. A failure during or after
// dispatch - including a SyntaxError - must NEVER be classified as
// NOT_DISPATCHED; it is INDETERMINATE (executed:null).
//
// These tests drive the real createPepGatewayHttpServer over a loopback socket.
import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import type { AddressInfo } from "node:net";
import { createPepGatewayHttpServer } from "../gateway.js";
import { signAuthorizationEd25519, sha256HexFromJson, type KeySet } from "@oxdeai/core";

const kp = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const KS: KeySet = { issuer: "iss", version: "1", keys: [{ kid: "k1", alg: "Ed25519", public_key: kp.publicKey.toString(), status: "active" }] };
const NOW = Math.floor(Date.now() / 1000);
const action = { type: "EXECUTE", tool: "t", params: { amount: 1 } };
const authFor = (auth_id: string) => signAuthorizationEd25519({ auth_id, issuer: "iss", audience: "gw", intent_hash: sha256HexFromJson(action), state_hash: "2".repeat(64), policy_id: "p1", decision: "ALLOW", issued_at: NOW - 5, expiry: NOW + 600, kid: "k1" }, kp.privateKey);
const baseOpts = { expectedAudience: "gw", trustedKeySets: [KS], internalExecutorToken: "tok", trustedAuthorizationAuthorities: [{ issuer: "iss", policyId: "p1" }], timeoutMs: 50 };

async function withServer(opts: any, fn: (base: string) => Promise<void>) {
  const server = createPepGatewayHttpServer(opts);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}
async function postRaw(base: string, raw: string) {
  const res = await fetch(`${base}/execute`, { method: "POST", headers: { "content-type": "application/json" }, body: raw });
  return { status: res.status, body: (await res.json()) as any };
}

// PRE-DISPATCH parsing error: a malformed JSON body is rejected before the
// executor is ever reached -> NOT_DISPATCHED, executed:false, upstream untouched.
test("H-1 R3: malformed JSON body -> NOT_DISPATCHED, executed:false, upstream never called", async () => {
  let dispatched = 0;
  await withServer({ ...baseOpts, executeUpstream: async () => { dispatched++; return { status: 200, body: { ok: true } }; } }, async (base) => {
    const r = await postRaw(base, "{ this is not json ");
    assert.equal(r.status, 403);
    assert.equal(r.body.decision, "DENY");
    assert.equal(r.body.outcome, "NOT_DISPATCHED");
    assert.equal(r.body.executed, false);
    assert.equal(r.body.reason, "INVALID_JSON");
  });
  assert.equal(dispatched, 0, "a parse error must never reach the executor");
});

// POST-DISPATCH exception: the executor is dispatched and then throws. The
// handler must report an uncertain outcome, never NOT_DISPATCHED.
test("H-1 R3: executor throws after dispatch -> INDETERMINATE, executed:null, not NOT_DISPATCHED", async () => {
  await withServer({ ...baseOpts, executeUpstream: async () => { throw new Error("connection reset"); } }, async (base) => {
    const r = await postRaw(base, JSON.stringify({ action, authorization: authFor("http-a1") }));
    assert.notEqual(r.body.outcome, "NOT_DISPATCHED", "a post-dispatch fault must not be NOT_DISPATCHED");
    assert.equal(r.body.outcome, "INDETERMINATE");
    assert.equal(r.body.executed, null);
  });
});

// POST-DISPATCH SyntaxError specifically: a SyntaxError raised after dispatch
// (here, thrown by the executor) must NOT be mistaken for a malformed request.
// This is the exact misclassification R3 isolates against.
test("H-1 R3: SyntaxError raised after dispatch is INDETERMINATE, not INVALID_JSON/NOT_DISPATCHED", async () => {
  await withServer({ ...baseOpts, executeUpstream: async () => { throw new SyntaxError("Unexpected token in upstream payload"); } }, async (base) => {
    const r = await postRaw(base, JSON.stringify({ action, authorization: authFor("http-a2") }));
    assert.notEqual(r.body.reason, "INVALID_JSON", "a post-dispatch SyntaxError is not a malformed request");
    assert.notEqual(r.body.outcome, "NOT_DISPATCHED");
    assert.equal(r.body.outcome, "INDETERMINATE");
    assert.equal(r.body.executed, null);
  });
});

// EXECUTION-PHASE BACKSTOP: force executeThroughPep itself to throw after the
// parsing phase (a now() that raises propagates out of the executor). The
// handler's execution-phase catch must NOT attribute a decision: it is UNKNOWN
// (no verdict reached), with INDETERMINATE / executed:null - never DENY or ALLOW,
// never NOT_DISPATCHED.
test("H-1 R3.1: internal fault after parsing -> decision UNKNOWN, INDETERMINATE, not DENY/NOT_DISPATCHED", async () => {
  const faulting = {
    ...baseOpts,
    now: () => { throw new Error("clock fault after parsing"); },
    executeUpstream: async () => ({ status: 200, body: { ok: true } }),
  };
  await withServer(faulting, async (base) => {
    const r = await postRaw(base, JSON.stringify({ action, authorization: authFor("http-a4") }));
    assert.equal(r.status, 500);
    assert.equal(r.body.reason, "GATEWAY_ERROR");
    assert.equal(r.body.decision, "UNKNOWN", "an unobserved verdict must not be reported as DENY or ALLOW");
    assert.notEqual(r.body.decision, "DENY");
    assert.equal(r.body.outcome, "INDETERMINATE");
    assert.notEqual(r.body.outcome, "NOT_DISPATCHED");
    assert.equal(r.body.executed, null);
  });
});

// Control: a well-formed authorized request over HTTP executes once (EXECUTED).
test("H-1 R3: authorized request over HTTP -> EXECUTED, executed:true", async () => {
  await withServer({ ...baseOpts, executeUpstream: async () => ({ status: 200, body: { ok: true } }) }, async (base) => {
    const r = await postRaw(base, JSON.stringify({ action, authorization: authFor("http-a3") }));
    assert.equal(r.status, 200);
    assert.equal(r.body.outcome, "EXECUTED");
    assert.equal(r.body.executed, true);
  });
});
