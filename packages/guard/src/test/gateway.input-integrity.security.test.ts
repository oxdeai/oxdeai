// SPDX-License-Identifier: Apache-2.0
/**
 * INVREG-F01 / INVREG-F02 / INVREG-F05 — in-process PEP gateway input integrity.
 *
 * `createPepGatewayExecutor` receives a caller-supplied, live, in-process
 * request object. These tests pin that:
 *
 *   F01  the action that is hashed and bound to the authorization is exactly
 *        the action handed to the upstream executor, regardless of mutation
 *        of the caller's object during the awaited replay-store operation,
 *        and that unsupported action values fail closed before execution;
 *   F02  the auth_id that is cryptographically verified is exactly the auth_id
 *        consumed by the replay store, so one single-use authorization cannot
 *        authorize more than one protected execution (getter / Proxy / plain
 *        mutation / concurrency);
 *   F05  issuer-policy authority configuration is captured at construction:
 *        mutating the caller's authority list (or the options object) after
 *        construction cannot widen trust, while documented live state (key-set
 *        rotation in place, replay-store state) stays live.
 *
 * Every test asserts the actual number of upstream invocations and, where
 * relevant, the exact parameters the upstream received.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID } from "node:crypto";

import { sha256HexFromJson, signAuthorizationEd25519, verifyAuthorization } from "@oxdeai/core";
import type { AuthorizationAuthority, AuthorizationV1, KeySet } from "@oxdeai/core";
import { createPepGatewayExecutor } from "../gateway.js";
import type { PepGatewayOptions, UpstreamExecutor } from "../gateway.js";
import { createInMemoryReplayStore } from "../replayStore.js";
import type { ReplayStore } from "../replayStore.js";

// ── Synthetic credentials ───────────────────────────────────────────────────

const KP = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const KP_ROTATED = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const ISSUER = "invreg-issuer";
const POLICY = "invreg-policy";
const OTHER_POLICY = "invreg-policy-unauthorized";
const AUDIENCE = "invreg-gateway";
const TOKEN = "invreg-internal-token";

function keyset(): KeySet {
  return { issuer: ISSUER, version: "v1", keys: [{ kid: "k1", alg: "Ed25519", public_key: KP.publicKey.toString() }] };
}

function makeAction(amount = "10") {
  return {
    type: "EXECUTE",
    tool: "payments.charge",
    params: { amount, recipients: ["alice"], meta: { memo: "invoice-1", tags: ["a", "b"] } },
  };
}

function sign(
  action: unknown,
  overrides: Partial<{ auth_id: string; policy_id: string; kid: string; key: string }> = {}
): AuthorizationV1 {
  const issued_at = Math.floor(Date.now() / 1000);
  return signAuthorizationEd25519(
    {
      auth_id: overrides.auth_id ?? `invreg-${randomUUID()}`,
      issuer: ISSUER,
      audience: AUDIENCE,
      intent_hash: sha256HexFromJson(action),
      state_hash: "s".repeat(64),
      policy_id: overrides.policy_id ?? POLICY,
      decision: "ALLOW",
      issued_at,
      expiry: issued_at + 600,
      kid: overrides.kid ?? "k1",
      nonce: "1",
      capability: "exec",
    },
    overrides.key ?? KP.privateKey.toString()
  );
}

type Recorder = {
  calls: unknown[];
  hashes: string[];
  executeUpstream: UpstreamExecutor;
};

function recorder(): Recorder {
  const calls: unknown[] = [];
  const hashes: string[] = [];
  return {
    calls,
    hashes,
    executeUpstream: async (action) => {
      calls.push(action);
      // Hash what the upstream actually received, at the moment it received it.
      hashes.push(sha256HexFromJson(action));
      return { status: 200, body: { ok: true } };
    },
  };
}

type CountingStore = ReplayStore & { consumed: string[]; consumeCalls: number };

function countingStore(hook?: (authId: string) => void | Promise<void>): CountingStore {
  const inner = createInMemoryReplayStore();
  const store: CountingStore = {
    consumed: [],
    consumeCalls: 0,
    async consumeAuthId(authId, opts) {
      store.consumeCalls++;
      // Genuinely asynchronous boundary, as with a networked store.
      await new Promise((r) => setImmediate(r));
      if (hook) await hook(authId);
      const ok = await inner.consumeAuthId(authId, opts);
      if (ok) store.consumed.push(authId);
      return ok;
    },
  } as CountingStore;
  return store;
}

function gateway(
  rec: Recorder,
  store: ReplayStore,
  extra: Partial<PepGatewayOptions> = {}
) {
  return createPepGatewayExecutor({
    expectedAudience: AUDIENCE,
    trustedKeySets: [keyset()],
    trustedAuthorizationAuthorities: [{ issuer: ISSUER, policyId: POLICY }],
    internalExecutorToken: TOKEN,
    executeUpstream: rec.executeUpstream,
    replayProtection: { mode: "shared", store },
    ...extra,
  });
}

/**
 * Number of times verifyAuthorization reads `auth_id` for a valid artifact,
 * measured against the real verifier rather than hard-coded, so the getter /
 * Proxy attacks below stay aligned with the verifier's read pattern.
 */
function verifierAuthIdReads(auth: AuthorizationV1): number {
  let reads = 0;
  const probe = { ...auth };
  Object.defineProperty(probe, "auth_id", {
    enumerable: true,
    get() {
      reads++;
      return auth.auth_id;
    },
  });
  const r = verifyAuthorization(probe, {
    now: Math.floor(Date.now() / 1000),
    mode: "strict",
    trustedKeySets: [keyset()],
    requireSignatureVerification: true,
    expectedAudience: AUDIENCE,
    trustedAuthorizationAuthorities: [{ issuer: ISSUER, policyId: POLICY }],
  });
  assert.equal(r.status, "ok", "calibration artifact must verify");
  return reads;
}

// ═══════════════════════════════════════════════════════════════════════════
// INVREG-F01 — verified action == executed action
// ═══════════════════════════════════════════════════════════════════════════

test("INVREG-F01 repro: mutating action params during the awaited replay consume does not change the upstream request", async () => {
  const rec = recorder();
  const action = makeAction("10");
  const verifiedHash = sha256HexFromJson(action);
  const store = countingStore(() => {
    // Caller-controlled mutation after verification, before dispatch.
    action.params.amount = "1000000";
  });
  const result = await gateway(rec, store)({ action, authorization: sign(action) });

  assert.equal(result.status, 200);
  assert.equal(rec.calls.length, 1);
  assert.deepEqual(rec.calls[0], makeAction("10"), "upstream must receive the verified action");
  assert.equal(rec.hashes[0], verifiedHash, "upstream action must hash to the authorized intent_hash");
  assert.equal(result.body.intent_hash, verifiedHash);
});

test("INVREG-F01 nested aliases: mutation of nested arrays/objects and property addition/deletion during the await is not observed", async () => {
  const rec = recorder();
  const action = makeAction("10");
  const verifiedHash = sha256HexFromJson(action);
  const store = countingStore(() => {
    action.params.recipients.push("mallory");
    action.params.meta.tags[0] = "z";
    action.params.meta.memo = "changed";
    (action.params as Record<string, unknown>).extra = "injected";
    delete (action as Record<string, unknown>).tool;
  });
  const result = await gateway(rec, store)({ action, authorization: sign(action) });

  assert.equal(result.status, 200);
  assert.equal(rec.calls.length, 1);
  assert.deepEqual(rec.calls[0], makeAction("10"));
  assert.equal(rec.hashes[0], verifiedHash);
});

test("INVREG-F01 replacing the request's action reference during the await is not observed", async () => {
  const rec = recorder();
  const action = makeAction("10");
  const request: { action: unknown; authorization: AuthorizationV1 } = { action, authorization: sign(action) };
  const store = countingStore(() => {
    request.action = makeAction("999999");
  });
  const result = await gateway(rec, store)(request);
  assert.equal(result.status, 200);
  assert.equal(rec.calls.length, 1);
  assert.deepEqual(rec.calls[0], makeAction("10"));
});

test("INVREG-F01 upstream receives an isolated snapshot, never the caller's object or any of its nested references", async () => {
  const rec = recorder();
  const action = makeAction("10");
  await gateway(rec, countingStore())({ action, authorization: sign(action) });
  assert.equal(rec.calls.length, 1);
  const got = rec.calls[0] as ReturnType<typeof makeAction>;
  assert.notEqual(got, action);
  assert.notEqual(got.params, action.params);
  assert.notEqual(got.params.recipients, action.params.recipients);
  assert.notEqual(got.params.meta, action.params.meta);
  assert.notEqual(got.params.meta.tags, action.params.meta.tags);
});

test("INVREG-F01 custom hashAction and upstream observe the same action value (GW-COMP-01: separate mutable copy for the upstream)", async () => {
  const rec = recorder();
  const action = makeAction("10");
  const hashed: unknown[] = [];
  const result = await gateway(rec, countingStore(), {
    hashAction: (a) => {
      hashed.push(a);
      return sha256HexFromJson(a);
    },
  })({ action, authorization: sign(action) });
  assert.equal(result.status, 200);
  assert.equal(hashed.length, 1);
  assert.equal(rec.calls.length, 1);
  // The executed action equals the hashed action by value and canonical hash.
  assert.deepEqual(rec.calls[0], hashed[0], "the hashed action must equal the executed action");
  assert.equal(rec.hashes[0], sha256HexFromJson(hashed[0]), "upstream input hashes to the hashed action's hash");
  // GW-COMP-01: the hashed snapshot stays frozen; the upstream gets its own copy.
  assert.notEqual(rec.calls[0], hashed[0]);
  assert.ok(Object.isFrozen(hashed[0]), "the verified snapshot stays frozen");
  assert.ok(!Object.isFrozen(rec.calls[0]), "the upstream receives a mutable copy");
});

test("INVREG-F01 accessor-backed request.action (different value per read) is rejected; upstream never called", async () => {
  const rec = recorder();
  const benign = makeAction("10");
  const auth = sign(benign);
  let reads = 0;
  const request = { authorization: auth } as Record<string, unknown>;
  Object.defineProperty(request, "action", {
    enumerable: true,
    get() {
      // First reads (shape check, hashing) see the authorized action; the
      // dispatch read sees a different one.
      return reads++ < 2 ? benign : makeAction("1000000");
    },
  });
  const store = countingStore();
  const result = await gateway(rec, store)(request);
  assert.equal(result.status, 403);
  assert.equal(result.upstreamCalled, false);
  assert.equal(rec.calls.length, 0);
  assert.equal(store.consumeCalls, 0, "a rejected input must not consume replay state");
});

test("INVREG-F01 accessor inside the action is rejected and the getter is never invoked", async () => {
  const rec = recorder();
  const action = makeAction("10");
  const auth = sign(action);
  let invoked = 0;
  Object.defineProperty(action.params, "amount", {
    enumerable: true,
    get() {
      invoked++;
      return "10";
    },
  });
  const store = countingStore();
  const result = await gateway(rec, store)({ action, authorization: auth });
  assert.equal(result.status, 403);
  assert.match(String(result.body.reason), /^INVALID_REQUEST_INPUT:/);
  assert.equal(invoked, 0);
  assert.equal(rec.calls.length, 0);
  assert.equal(store.consumeCalls, 0);
});

test("INVREG-F01 Proxy action is rejected without running a trap; upstream never called", async () => {
  const rec = recorder();
  const base = makeAction("10");
  const auth = sign(base);
  let traps = 0;
  const proxied = new Proxy(base, {
    get(t, k, r) {
      traps++;
      return Reflect.get(t, k, r);
    },
    ownKeys(t) {
      traps++;
      return Reflect.ownKeys(t);
    },
    getOwnPropertyDescriptor(t, k) {
      traps++;
      return Reflect.getOwnPropertyDescriptor(t, k);
    },
  });
  const store = countingStore();
  const result = await gateway(rec, store)({ action: proxied, authorization: auth });
  assert.equal(result.status, 403);
  assert.match(String(result.body.reason), /^INVALID_REQUEST_INPUT:/);
  assert.equal(traps, 0);
  assert.equal(rec.calls.length, 0);
  assert.equal(store.consumeCalls, 0);
});

test("INVREG-F01 Proxy request object is rejected; upstream never called", async () => {
  const rec = recorder();
  const action = makeAction("10");
  const store = countingStore();
  const result = await gateway(rec, store)(new Proxy({ action, authorization: sign(action) }, {}));
  assert.equal(result.status, 403);
  assert.match(String(result.body.reason), /^INVALID_REQUEST_INPUT:/);
  assert.equal(rec.calls.length, 0);
  assert.equal(store.consumeCalls, 0);
});

test("INVREG-F01 GATE-ACTION-05: non-plain action values fail closed instead of being hashed as a different action", async () => {
  // canonicalJson treats any non-array object as a plain object and hashes
  // only its own enumerable string keys. A Date hashes like {}, a Buffer like
  // {"0":..,"1":..}, a Map like {}: an authorization for that canonical form
  // must not dispatch the exotic value itself to the upstream.
  class Charge { constructor(readonly amount: string) {} }
  const exotic: Array<[string, unknown]> = [
    ["Date", { params: { when: new Date(0) } }],
    ["Map", { params: { m: new Map([["amount", "1000000"]]) } }],
    ["Buffer", { params: { b: Buffer.from("hi") } }],
    ["Uint8Array", { params: { b: new Uint8Array([1, 2]) } }],
    ["class instance", { params: { c: new Charge("1") } }],
    ["function", { params: { f: () => 1 } }],
    ["symbol-keyed property", { params: { [Symbol("s")]: 1, amount: "1" } }],
    ["sparse array", { params: { list: [1, , 3] } }],
  ];
  for (const [label, action] of exotic) {
    const rec = recorder();
    const store = countingStore();
    let auth: AuthorizationV1;
    try {
      auth = sign(action);
    } catch {
      // Not even canonicalizable; still must be rejected.
      auth = sign({ placeholder: label });
    }
    const result = await gateway(rec, store)({ action, authorization: auth });
    assert.equal(result.status, 403, `${label}: must be denied`);
    assert.equal(rec.calls.length, 0, `${label}: upstream must not be called`);
    assert.equal(store.consumeCalls, 0, `${label}: replay state must not be consumed`);
  }
});

test("INVREG-F01 cyclic action is denied before replay consumption", async () => {
  const rec = recorder();
  const store = countingStore();
  const action: Record<string, unknown> = { type: "EXECUTE" };
  action.self = action;
  const result = await gateway(rec, store)({ action, authorization: sign({ type: "EXECUTE" }) });
  assert.equal(result.status, 403);
  assert.equal(rec.calls.length, 0);
  assert.equal(store.consumeCalls, 0);
});

test("INVREG-F01 deeply nested JSON actions (no new depth limit) still execute", async () => {
  const rec = recorder();
  let action: Record<string, unknown> = { leaf: "x" };
  for (let i = 0; i < 64; i++) action = { n: action };
  const result = await gateway(rec, countingStore())({ action, authorization: sign(action) });
  assert.equal(result.status, 200);
  assert.equal(rec.calls.length, 1);
  assert.deepEqual(rec.calls[0], action);
});

test("INVREG-F01 bigint and null leaves are preserved verbatim (canonicalization semantics unchanged)", async () => {
  const rec = recorder();
  const action = { type: "EXECUTE", params: { amount: 10n, note: null, ok: true, n: 3 } };
  const result = await gateway(rec, countingStore())({ action, authorization: sign(action) });
  assert.equal(result.status, 200);
  assert.deepEqual(rec.calls[0], action);
  assert.equal(typeof (rec.calls[0] as typeof action).params.amount, "bigint");
});

test("INVREG-F01 JSON-decoded input (HTTP transport shape) is unchanged, including an own \"__proto__\" key", async () => {
  const rec = recorder();
  const action = JSON.parse('{"type":"EXECUTE","params":{"__proto__":{"admin":true},"amount":"1"}}');
  const auth = sign(action);
  const result = await gateway(rec, countingStore())(JSON.parse(JSON.stringify({ action, authorization: auth })));
  assert.equal(result.status, 200);
  assert.equal(rec.calls.length, 1);
  const got = rec.calls[0] as { params: object };
  assert.ok(Object.prototype.hasOwnProperty.call(got.params, "__proto__"), "own __proto__ key preserved as data");
  assert.equal(Object.getPrototypeOf(got.params), Object.prototype, "prototype not replaced");
  assert.equal(rec.hashes[0], auth.intent_hash);
});

// ═══════════════════════════════════════════════════════════════════════════
// INVREG-F02 — verified auth_id == replay-consumed auth_id; single use
// ═══════════════════════════════════════════════════════════════════════════

test("INVREG-F02 repro (1): a changing auth_id getter cannot turn one signed authorization into multiple executions", async () => {
  const rec = recorder();
  const store = countingStore();
  const action = makeAction("10");
  const signed = sign(action);
  const verifierReads = verifierAuthIdReads(signed);

  function hostileAuthorization(): AuthorizationV1 {
    let reads = 0;
    const a = { ...signed } as Record<string, unknown>;
    Object.defineProperty(a, "auth_id", {
      enumerable: true,
      get() {
        // The signed id for every read the verifier makes; a fresh id for the
        // replay-consume read that follows.
        return reads++ < verifierReads ? signed.auth_id : `fresh-${randomUUID()}`;
      },
    });
    return a as unknown as AuthorizationV1;
  }

  const gw = gateway(rec, store);
  const r1 = await gw({ action, authorization: hostileAuthorization() });
  const r2 = await gw({ action, authorization: hostileAuthorization() });

  assert.ok(rec.calls.length <= 1, `one signed authorization executed ${rec.calls.length} times`);
  assert.equal(rec.calls.length, 0, "accessor-based authorization input is rejected");
  assert.equal(r1.status, 403);
  assert.equal(r2.status, 403);
  assert.match(String(r1.body.reason), /^INVALID_REQUEST_INPUT:/);
  assert.equal(store.consumeCalls, 0);
  // The genuine artifact is still usable exactly once afterwards.
  const ok = await gw({ action, authorization: signed });
  assert.equal(ok.status, 200);
  assert.deepEqual(store.consumed, [signed.auth_id]);
});

test("INVREG-F02 repro (2): a Proxy returning different auth_ids cannot authorize multiple executions", async () => {
  const rec = recorder();
  const store = countingStore();
  const action = makeAction("10");
  const signed = sign(action);
  const verifierReads = verifierAuthIdReads(signed);

  function proxied(): AuthorizationV1 {
    let reads = 0;
    return new Proxy({ ...signed }, {
      get(t, k, r) {
        if (k === "auth_id") return reads++ < verifierReads ? signed.auth_id : `fresh-${randomUUID()}`;
        return Reflect.get(t, k, r);
      },
    });
  }

  const gw = gateway(rec, store);
  await gw({ action, authorization: proxied() });
  await gw({ action, authorization: proxied() });
  await gw({ action, authorization: proxied() });
  assert.equal(rec.calls.length, 0);
  assert.equal(store.consumeCalls, 0);
});

test("INVREG-F02 (3): plain-object mutation of the authorization during the awaited consume does not change the reported/consumed identity", async () => {
  const rec = recorder();
  const action = makeAction("10");
  const auth = sign(action);
  const original = auth.auth_id;
  const store = countingStore(() => {
    (auth as { auth_id: string }).auth_id = "mutated-after-verification";
    (auth as { expiry: number }).expiry = 1;
  });
  const result = await gateway(rec, store)({ action, authorization: auth });
  assert.equal(result.status, 200);
  assert.equal(rec.calls.length, 1);
  assert.deepEqual(store.consumed, [original]);
  assert.equal(result.body.auth_id, original, "response must report the verified, consumed auth_id");
});

test("INVREG-F02 (3b): caller code running mid-request (hashAction) cannot alter the authorization that is verified and consumed", async () => {
  const rec = recorder();
  const action = makeAction("10");
  const auth = sign(action);
  const verifiedExpiry = auth.expiry;
  let seenExpiry: number | undefined;
  const inner = createInMemoryReplayStore();
  const store: ReplayStore = {
    async consumeAuthId(id, opts) {
      seenExpiry = opts.expiry;
      return inner.consumeAuthId(id, opts);
    },
  };
  const result = await gateway(rec, store, {
    hashAction: (a) => {
      // Caller-controlled code running mid-request.
      (auth as { expiry: number }).expiry = verifiedExpiry + 10_000_000;
      return sha256HexFromJson(a);
    },
  })({ action, authorization: auth });
  assert.equal(result.status, 200);
  assert.equal(seenExpiry, verifiedExpiry);
});

test("INVREG-F02 (4): two concurrent executions with the same authorization dispatch exactly once", async () => {
  const rec = recorder();
  const store = countingStore();
  const action = makeAction("10");
  const auth = sign(action);
  const gw = gateway(rec, store);
  const [a, b] = await Promise.all([gw({ action, authorization: auth }), gw({ action, authorization: auth })]);
  const statuses = [a.status, b.status].sort();
  assert.deepEqual(statuses, [200, 403]);
  const denied = a.status === 403 ? a : b;
  assert.equal(denied.body.reason, "AUTH_REPLAY");
  assert.equal(denied.upstreamCalled, false);
  assert.equal(rec.calls.length, 1);
});

test("INVREG-F02 (5): replay-store failure never results in protected execution", async () => {
  // Scope: a store that throws, rejects, or reports "not consumed". A store
  // that violates the ReplayStore contract by resolving a truthy NON-boolean
  // is treated as consumed by the gateway (and by the Guard) at c214714; that
  // is a separate observation and deliberately not changed by this patch.
  const rec = recorder();
  const action = makeAction("10");
  for (const failing of [
    { async consumeAuthId(): Promise<boolean> { throw new Error("store down"); } },
    { consumeAuthId(): Promise<boolean> { return Promise.reject(new Error("rejected")); } },
    { consumeAuthId(): Promise<boolean> { throw new Error("sync throw"); } },
    { async consumeAuthId(): Promise<boolean> { return false; } },
  ] as ReplayStore[]) {
    const result = await gateway(rec, failing)({ action, authorization: sign(action) });
    assert.equal(result.status, 403);
    assert.equal(result.upstreamCalled, false);
    assert.equal(result.body.outcome, "NOT_DISPATCHED");
  }
  assert.equal(rec.calls.length, 0);
});

test("INVREG-F02 (6): malformed authorization fields are denied without consuming replay state or calling upstream", async () => {
  const action = makeAction("10");
  const good = sign(action);
  const cases: Array<[string, unknown]> = [
    ["auth_id number", { ...good, auth_id: 42 }],
    ["auth_id empty", { ...good, auth_id: "" }],
    ["auth_id non-NFC", { ...good, auth_id: "é" }],
    ["auth_id object", { ...good, auth_id: { toString: () => good.auth_id } }],
    ["missing signature", { ...good, signature: undefined }],
    ["expiry string", { ...good, expiry: String(good.expiry) }],
    ["authorization array", [good]],
    ["authorization string", "token"],
  ];
  for (const [label, authorization] of cases) {
    const rec = recorder();
    const store = countingStore();
    const result = await gateway(rec, store)({ action, authorization });
    assert.equal(result.status, 403, label);
    assert.equal(rec.calls.length, 0, `${label}: upstream`);
    assert.equal(store.consumeCalls, 0, `${label}: replay consumed`);
  }
});

test("INVREG-F02 (7): a successful valid execution is followed by a denied replay", async () => {
  const rec = recorder();
  const store = countingStore();
  const action = makeAction("10");
  const auth = sign(action);
  const gw = gateway(rec, store);
  const first = await gw({ action, authorization: auth });
  const second = await gw({ action, authorization: auth });
  const third = await gw({ action: structuredClone(action), authorization: structuredClone(auth) });
  assert.equal(first.status, 200);
  assert.equal(second.status, 403);
  assert.equal(second.body.reason, "AUTH_REPLAY");
  assert.equal(third.body.reason, "AUTH_REPLAY");
  assert.equal(rec.calls.length, 1);
});

test("INVREG-F02 (8): denied authorizations produce zero upstream invocations and do not consume replay state", async () => {
  const action = makeAction("10");
  const cases: Array<[string, AuthorizationV1]> = [
    ["bad signature", { ...sign(action), signature: sign(makeAction("2")).signature }],
    ["unauthorized policy", sign(action, { policy_id: OTHER_POLICY })],
    ["untrusted key", sign(action, { key: KP_ROTATED.privateKey.toString() })],
    ["intent mismatch", sign(makeAction("2"))],
    ["wrong audience", { ...sign(action), audience: "other" }],
  ];
  for (const [label, authorization] of cases) {
    const rec = recorder();
    const store = countingStore();
    const result = await gateway(rec, store)({ action, authorization });
    assert.equal(result.status, 403, label);
    assert.equal(result.body.decision, "DENY", label);
    assert.equal(result.upstreamCalled, false, label);
    assert.equal(rec.calls.length, 0, `${label}: upstream`);
    assert.equal(store.consumeCalls, 0, `${label}: replay consumed`);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// INVREG-F05 — authority configuration captured at construction
// ═══════════════════════════════════════════════════════════════════════════

test("INVREG-F05 repro: adding an authority to the caller's array after construction does not widen trust", async () => {
  const rec = recorder();
  const authorities: AuthorizationAuthority[] = [{ issuer: ISSUER, policyId: POLICY }];
  const gw = gateway(rec, countingStore(), { trustedAuthorizationAuthorities: authorities });
  const action = makeAction("10");

  const before = await gw({ action, authorization: sign(action, { policy_id: OTHER_POLICY }) });
  assert.equal(before.status, 403);
  assert.match(String(before.body.reason), /AUTH_ISSUER_POLICY_NOT_AUTHORIZED/);

  authorities.push({ issuer: ISSUER, policyId: OTHER_POLICY });

  const after = await gw({ action, authorization: sign(action, { policy_id: OTHER_POLICY }) });
  assert.equal(after.status, 403, "post-construction push must not authorize a new pair");
  assert.match(String(after.body.reason), /AUTH_ISSUER_POLICY_NOT_AUTHORIZED/);
  assert.equal(rec.calls.length, 0);
});

test("INVREG-F05: rewriting an existing authority entry in place does not widen trust", async () => {
  const rec = recorder();
  const entry = { issuer: ISSUER, policyId: POLICY };
  const gw = gateway(rec, countingStore(), { trustedAuthorizationAuthorities: [entry] });
  entry.policyId = OTHER_POLICY;
  const action = makeAction("10");
  const widened = await gw({ action, authorization: sign(action, { policy_id: OTHER_POLICY }) });
  assert.equal(widened.status, 403);
  // The originally configured pair is still the one honored.
  const ok = await gw({ action, authorization: sign(action) });
  assert.equal(ok.status, 200);
  assert.equal(rec.calls.length, 1);
});

test("INVREG-F05: replacing options.trustedAuthorizationAuthorities after construction does not widen trust", async () => {
  const rec = recorder();
  const options: PepGatewayOptions = {
    expectedAudience: AUDIENCE,
    trustedKeySets: [keyset()],
    trustedAuthorizationAuthorities: [{ issuer: ISSUER, policyId: POLICY }],
    internalExecutorToken: TOKEN,
    executeUpstream: rec.executeUpstream,
    replayProtection: { mode: "shared", store: countingStore() },
  };
  const gw = createPepGatewayExecutor(options);
  options.trustedAuthorizationAuthorities = [{ issuer: ISSUER, policyId: OTHER_POLICY }];
  const action = makeAction("10");
  const r = await gw({ action, authorization: sign(action, { policy_id: OTHER_POLICY }) });
  assert.equal(r.status, 403);
  assert.equal(rec.calls.length, 0);
});

test("INVREG-F05 GATE-CFG-05: mutating options.expectedAudience / executeUpstream / internalExecutorToken after construction has no effect", async () => {
  const rec = recorder();
  const swapped: unknown[] = [];
  const headersSeen: Array<Record<string, string>> = [];
  const options: PepGatewayOptions = {
    expectedAudience: AUDIENCE,
    trustedKeySets: [keyset()],
    trustedAuthorizationAuthorities: [{ issuer: ISSUER, policyId: POLICY }],
    internalExecutorToken: TOKEN,
    executeUpstream: async (a, h) => {
      headersSeen.push(h);
      return rec.executeUpstream(a, h);
    },
    replayProtection: { mode: "shared", store: countingStore() },
  };
  const gw = createPepGatewayExecutor(options);
  options.expectedAudience = "attacker-audience";
  options.internalExecutorToken = "attacker-token";
  options.executeUpstream = async (a) => {
    swapped.push(a);
    return { status: 200 };
  };

  const action = makeAction("10");
  const ok = await gw({ action, authorization: sign(action) });
  assert.equal(ok.status, 200, "the construction-time audience still applies");
  assert.equal(rec.calls.length, 1);
  assert.equal(swapped.length, 0, "the construction-time upstream is still used");
  assert.equal(headersSeen[0]["x-internal-executor-token"], TOKEN);
});

test("INVREG-F05 GATE-CFG-01: malformed or non-plain authority configuration fails construction", () => {
  const base = {
    expectedAudience: AUDIENCE,
    trustedKeySets: [keyset()],
    internalExecutorToken: TOKEN,
    executeUpstream: recorder().executeUpstream,
    replayProtection: { mode: "shared" as const, store: countingStore() },
  };
  const accessorEntry = {} as Record<string, unknown>;
  Object.defineProperty(accessorEntry, "issuer", { enumerable: true, get: () => ISSUER });
  Object.defineProperty(accessorEntry, "policyId", { enumerable: true, get: () => POLICY });
  const bad: Array<[string, unknown]> = [
    ["null entry", [null]],
    ["string entry", ["issuer:policy"]],
    ["missing policyId", [{ issuer: ISSUER }]],
    ["empty issuer", [{ issuer: "", policyId: POLICY }]],
    ["non-string policyId", [{ issuer: ISSUER, policyId: 1 }]],
    ["accessor entry", [accessorEntry]],
    ["Proxy list", new Proxy([{ issuer: ISSUER, policyId: POLICY }], {})],
    ["Proxy entry", [new Proxy({ issuer: ISSUER, policyId: POLICY }, {})]],
  ];
  for (const [label, trustedAuthorizationAuthorities] of bad) {
    assert.throws(
      () => createPepGatewayExecutor({ ...base, trustedAuthorizationAuthorities } as unknown as PepGatewayOptions),
      /trustedAuthorizationAuthorities/,
      label
    );
  }
  // An explicit empty list stays valid (authorizes nothing).
  assert.doesNotThrow(() => createPepGatewayExecutor({ ...base, trustedAuthorizationAuthorities: [] }));
});

test("INVREG-F05 GATE-CFG-04: documented live state stays live — in-place key-set rotation and replay-store state", async () => {
  const rec = recorder();
  const store = countingStore();
  const keySets = [keyset()];
  const gw = gateway(rec, store, { trustedKeySets: keySets });
  const action = makeAction("10");

  // A rotated-in key under a new kid is not yet trusted...
  const rotated = sign(action, { kid: "k2", key: KP_ROTATED.privateKey.toString() });
  const before = await gw({ action, authorization: rotated });
  assert.equal(before.status, 403);
  assert.equal(store.consumeCalls, 0);

  // ...and becomes trusted when added in place (documented rotation path).
  keySets[0].keys.push({ kid: "k2", alg: "Ed25519", public_key: KP_ROTATED.publicKey.toString() });
  const after = await gw({ action, authorization: sign(action, { kid: "k2", key: KP_ROTATED.privateKey.toString() }) });
  assert.equal(after.status, 200);

  // Key trust is not policy authority: a rotated key still cannot sign for an
  // unauthorized policy.
  const unauthorized = await gw({
    action,
    authorization: sign(action, { kid: "k2", key: KP_ROTATED.privateKey.toString(), policy_id: OTHER_POLICY }),
  });
  assert.equal(unauthorized.status, 403);
  assert.equal(rec.calls.length, 1);
});
