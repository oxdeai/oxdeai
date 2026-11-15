// SPDX-License-Identifier: Apache-2.0
/**
 * OBS-E: the guard delegation path must read `opts.delegation` once, as one
 * immutable plain-data snapshot, before any security-sensitive read.
 *
 * `opts.delegation` is a caller-supplied, live, in-process object. Without the
 * snapshot an accessor or a Proxy can return the signed value to the verifier
 * and a different value to chain binding, scope enforcement or replay
 * consumption. Each test below counts executions at a mock protected executor
 * and every replay-store consume; a getter or trap invocation alone is never
 * the assertion.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import {
  PolicyEngine,
  RECOMMENDED_TRUSTED_TIME_PROFILE,
  signAuthorizationEd25519,
  createDelegation,
} from "@oxdeai/core";
import type { AuthorizationAuthority, AuthorizationV1, DelegationV1, KeySet } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { OxDeAIGuard } from "../guard.js";
import { createSecureGuard } from "../secureGuard.js";
import { createTrustedExecutionContext } from "../trustedContext.js";
import { createInMemoryReplayStore } from "../replayStore.js";
import type { ReplayStore } from "../replayStore.js";
import { OxDeAIAuthorizationError } from "../errors.js";
import type { GuardBoundaryAuditEvent } from "../boundaryEvent.js";
import type { GuardDelegationInput, OxDeAIGuardConfig, ProposedAction } from "../types.js";

const KP = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const ISSUER = "snap-issuer-A";
const POLICY_1 = "snap-policy-P1";
const POLICY_2 = "snap-policy-P2";
const KEYSET: KeySet = { issuer: ISSUER, version: "v1", keys: [{ kid: "ka", alg: "Ed25519", public_key: KP.publicKey.toString() }] };
const AUTHORITIES: readonly AuthorizationAuthority[] = [{ issuer: ISSUER, policyId: POLICY_1 }];
const T_NOW = Math.floor(Date.now() / 1000);
const PARENT_SCOPE = { tools: ["provision_gpu"], max_amount: 1_000_000n };
const GARBAGE_SIG = Buffer.alloc(64, 7).toString("base64");

let seq = 0;
function makeParent(over: Partial<AuthorizationV1> = {}): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      auth_id: `snap-parent-${seq++}`,
      issuer: ISSUER,
      audience: "agent-A",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: POLICY_1,
      decision: "ALLOW",
      issued_at: T_NOW - 60,
      expiry: T_NOW + 900,
      kid: "ka",
      ...over,
    } as Parameters<typeof signAuthorizationEd25519>[0],
    KP.privateKey.toString()
  );
}
function makeChild(parent: AuthorizationV1, scope = { tools: ["provision_gpu"], max_amount: 500_000n }): DelegationV1 {
  return createDelegation(parent, { delegatee: "agent-B", issuer: ISSUER, scope, expiry: T_NOW + 300, kid: "ka" }, KP.privateKey.toString());
}

type Counted = { store: ReplayStore; authIds: string[]; delegIds: string[] };
function countedStore(onConsume?: () => void): Counted {
  const inner = createInMemoryReplayStore();
  const authIds: string[] = [];
  const delegIds: string[] = [];
  return {
    authIds,
    delegIds,
    store: {
      consumeAuthId: async (id, o) => { authIds.push(id); onConsume?.(); return inner.consumeAuthId(id, o); },
      consumeDelegationId: async (id, o) => { delegIds.push(id); onConsume?.(); return inner.consumeDelegationId!(id, o); },
    },
  };
}

function makeConfig(store: ReplayStore, events: GuardBoundaryAuditEvent[] = []): OxDeAIGuardConfig {
  const state = buildState({
    agent_id: "agent-B",
    allow_action_types: ["PROVISION"],
    budget_limit: 10n ** 18n,
    max_amount_per_action: 10n ** 18n,
    velocity_max_actions: 1000,
    max_concurrent: 16,
  });
  return {
    engine: new PolicyEngine({
      policy_version: "v1",
      engine_secret: "test-secret-must-be-at-least-32-chars!!",
      authorization_signing_alg: "Ed25519",
      authorization_signing_kid: "ka",
      authorization_issuer: ISSUER,
      authorization_audience: "agent-A",
      authorization_ttl_seconds: 600,
      authorization_private_key_pem: KP.privateKey.toString(),
      ...RECOMMENDED_TRUSTED_TIME_PROFILE,
    }),
    getState: () => ({ state, version: 0 }),
    setState: () => true,
    trustedKeySets: [KEYSET],
    expectedAudience: "agent-A",
    trustedDelegationAuthorities: AUTHORITIES,
    replayStore: store,
    onBoundaryEvent: (e) => { events.push(e); },
  };
}

const action = (name = "provision_gpu", estimatedCost = 0): ProposedAction => ({
  name,
  args: { asset: "a100" },
  estimatedCost,
  context: { agent_id: "agent-B", target: "gpu-pool" },
  timestampSeconds: T_NOW,
});

async function run(input: unknown, act = action(), counted = countedStore(), config?: OxDeAIGuardConfig) {
  const events: GuardBoundaryAuditEvent[] = [];
  const guard = OxDeAIGuard(config ?? makeConfig(counted.store, events));
  const executed: string[] = [];
  let error: unknown;
  try {
    await guard(act, async () => { executed.push(act.name); return "ok"; }, { delegation: input as GuardDelegationInput });
  } catch (err) {
    error = err;
  }
  return { executed, error, events, counted };
}

/** Object whose listed fields return `first` for the first `k` reads (all fields together), then `then`. */
function switching<T extends object>(first: T, then: T, fields: (keyof T)[], k: number, reads = { n: 0 }): T {
  const out: Record<string, unknown> = { ...(first as Record<string, unknown>) };
  for (const f of fields) {
    delete out[f as string];
    Object.defineProperty(out, f, {
      enumerable: true,
      configurable: true,
      get() { return reads.n++ < k ? first[f] : then[f]; },
    });
  }
  return out as T;
}

function assertSnapshotRejected(r: Awaited<ReturnType<typeof run>>, pathPattern: RegExp) {
  assert.deepEqual(r.executed, [], "the protected executor must not run");
  assert.ok(r.error instanceof OxDeAIAuthorizationError, `expected OxDeAIAuthorizationError, got ${String(r.error)}`);
  assert.match(String((r.error as Error).message), /Delegation input is not supported plain data/);
  assert.match(String((r.error as Error).message), pathPattern);
  assert.deepEqual(r.counted.authIds, [], "no auth_id may be consumed for a rejected input");
  assert.deepEqual(r.counted.delegIds, [], "no delegation_id may be consumed for a rejected input");
  assert.equal(r.events.length, 1);
  assert.equal(r.events[0].stage, "DELEGATION");
  assert.equal(r.events[0].boundaryFailure, "DELEGATION_INPUT_INVALID");
  assert.equal(r.events[0].executionStarted, false);
}

// ── Legitimate inputs keep working ───────────────────────────────────────────

test("OBS-E: plain delegation input executes once and consumes both ids", async () => {
  const p = makeParent();
  const d = makeChild(p);
  const r = await run({ delegation: d, parentAuth: p, parentScope: PARENT_SCOPE });
  assert.equal(r.error, undefined, String(r.error));
  assert.deepEqual(r.executed, ["provision_gpu"]);
  assert.deepEqual(r.counted.authIds, [p.auth_id]);
  assert.deepEqual(r.counted.delegIds, [d.delegation_id]);
});

test("OBS-E: deep-frozen and null-prototype plain inputs are accepted", async () => {
  const p = makeParent();
  const d = makeChild(p);
  const deepFreeze = <T>(o: T): T => {
    if (o && typeof o === "object") { for (const v of Object.values(o)) deepFreeze(v); Object.freeze(o); }
    return o;
  };
  const frozen = await run(deepFreeze({ delegation: structuredClone(d), parentAuth: structuredClone(p), parentScope: structuredClone(PARENT_SCOPE) }));
  assert.equal(frozen.error, undefined, String(frozen.error));
  assert.deepEqual(frozen.executed, ["provision_gpu"]);

  const p2 = makeParent();
  const d2 = makeChild(p2);
  const nullProto = Object.assign(Object.create(null), { delegation: Object.assign(Object.create(null), d2), parentAuth: Object.assign(Object.create(null), p2), parentScope: PARENT_SCOPE });
  const r2 = await run(nullProto);
  assert.equal(r2.error, undefined, String(r2.error));
  assert.deepEqual(r2.executed, ["provision_gpu"]);
});

test("OBS-E: the hooks receive the snapshot, not the caller's object", async () => {
  const p = makeParent();
  const d = makeChild(p);
  const seen: unknown[] = [];
  const counted = countedStore();
  const config = { ...makeConfig(counted.store), onDecision: (rec: { delegation?: unknown }) => { seen.push(rec.delegation); } };
  const r = await run({ delegation: d, parentAuth: p, parentScope: PARENT_SCOPE }, action(), counted, config as OxDeAIGuardConfig);
  assert.equal(r.error, undefined, String(r.error));
  assert.equal(seen.length, 1);
  assert.notEqual(seen[0], d);
  assert.ok(Object.isFrozen(seen[0]));
  assert.deepEqual(seen[0], d);
});

// ── Signed ceilings and replay protection still hold on plain input ──────────

test("OBS-E: signed scope ceilings remain enforced for plain input", async () => {
  const p = makeParent();
  const tool = await run({ delegation: makeChild(p), parentAuth: p, parentScope: PARENT_SCOPE }, action("delete_cluster"));
  assert.deepEqual(tool.executed, []);
  assert.deepEqual(tool.counted.authIds, []);
  const p2 = makeParent();
  const amount = await run({ delegation: makeChild(p2), parentAuth: p2, parentScope: PARENT_SCOPE }, action("provision_gpu", 900));
  assert.deepEqual(amount.executed, []);
  assert.deepEqual(amount.counted.authIds, []);
});

test("OBS-E: re-presenting a consumed plain delegation is denied", async () => {
  const p = makeParent();
  const d = makeChild(p);
  const counted = countedStore();
  const config = makeConfig(counted.store);
  const first = await run({ delegation: d, parentAuth: p, parentScope: PARENT_SCOPE }, action(), counted, config);
  const second = await run({ delegation: d, parentAuth: p, parentScope: PARENT_SCOPE }, action(), counted, config);
  assert.deepEqual(first.executed, ["provision_gpu"]);
  assert.deepEqual(second.executed, []);
  assert.match(String((second.error as Error).message), /Delegation replay detected/);
});

test("OBS-E: mutating the caller's plain object during the replay consume changes nothing", async () => {
  const p = makeParent();
  const d = makeChild(p);
  const input = { delegation: { ...d, scope: { ...d.scope } }, parentAuth: { ...p }, parentScope: PARENT_SCOPE };
  let mutated = false;
  const counted = countedStore(() => {
    if (mutated) return;
    mutated = true;
    input.delegation.delegation_id = "mutated-delegation-id";
    input.parentAuth.auth_id = "mutated-auth-id";
    input.delegation.scope.tools = ["delete_cluster"];
  });
  const r = await run(input, action(), counted);
  assert.equal(r.error, undefined, String(r.error));
  assert.deepEqual(r.executed, ["provision_gpu"]);
  assert.deepEqual(r.counted.delegIds, [d.delegation_id]);
  assert.deepEqual(r.counted.authIds, [p.auth_id]);
});

// ── Hostile live objects fail closed before verification and consumption ────

test("OBS-E T2: parent accessor substitution (verify A, bind B with an invalid signature) fails closed", async () => {
  const A = makeParent();
  const B = { ...makeParent({ policy_id: POLICY_2 }), signature: GARBAGE_SIG };
  const d = makeChild(B);
  for (const k of [0, 10, 30, 60]) {
    const r = await run({ delegation: d, parentAuth: switching(A, B, Object.keys(A) as (keyof AuthorizationV1)[], k), parentScope: PARENT_SCOPE });
    assertSnapshotRejected(r, /delegation input\.parentAuth\.[a-z_]+: accessor properties are not supported/);
  }
});

test("OBS-E T2: the plain-object control with the same B is rejected by parent verification", async () => {
  const B = { ...makeParent({ policy_id: POLICY_2 }), signature: GARBAGE_SIG };
  const r = await run({ delegation: makeChild(B), parentAuth: B, parentScope: PARENT_SCOPE });
  assert.deepEqual(r.executed, []);
  assert.match(String((r.error as Error).message), /Parent authorization verification failed/);
  assert.deepEqual(r.counted.authIds, []);
});

test("OBS-E T2: a getter is never invoked by the snapshot", async () => {
  const p = makeParent();
  const d = makeChild(p);
  let calls = 0;
  const parentAuth = { ...p };
  Object.defineProperty(parentAuth, "auth_id", { enumerable: true, get() { calls++; return p.auth_id; } });
  const r = await run({ delegation: d, parentAuth, parentScope: PARENT_SCOPE });
  assertSnapshotRejected(r, /parentAuth\.auth_id: accessor properties are not supported/);
  assert.equal(calls, 0);
});

test("OBS-E T3: delegation.scope accessor substitution fails closed", async () => {
  const p = makeParent();
  const d = makeChild(p);
  const wide = { ...d, scope: { tools: ["delete_cluster"], max_amount: 500_000n } };
  for (const k of [0, 1, 2, 5]) {
    const r = await run({ delegation: switching(d, wide, ["scope"], k), parentAuth: p, parentScope: PARENT_SCOPE }, action("delete_cluster"));
    assertSnapshotRejected(r, /delegation input\.delegation\.scope: accessor properties are not supported/);
  }
});

test("OBS-E T4: Proxy-based substitution fails closed and no trap runs", async () => {
  const p = makeParent();
  const d = makeChild(p);
  let traps = 0;
  const handler: ProxyHandler<object> = {
    get: (t, k, r) => { traps++; return Reflect.get(t, k, r); },
    ownKeys: (t) => { traps++; return Reflect.ownKeys(t); },
    getOwnPropertyDescriptor: (t, k) => { traps++; return Reflect.getOwnPropertyDescriptor(t, k); },
    getPrototypeOf: (t) => { traps++; return Reflect.getPrototypeOf(t); },
    has: (t, k) => { traps++; return Reflect.has(t, k); },
  };
  for (const [where, input] of [
    ["delegation", { delegation: new Proxy({ ...d }, handler), parentAuth: p, parentScope: PARENT_SCOPE }],
    ["parentAuth", { delegation: d, parentAuth: new Proxy({ ...p }, handler), parentScope: PARENT_SCOPE }],
    ["parentScope", { delegation: d, parentAuth: p, parentScope: new Proxy({ ...PARENT_SCOPE }, handler) }],
    ["delegation.scope", { delegation: { ...d, scope: new Proxy({ ...d.scope }, handler) }, parentAuth: p, parentScope: PARENT_SCOPE }],
  ] as const) {
    const r = await run(input, action("delete_cluster"));
    assertSnapshotRejected(r, new RegExp(`delegation input\\.${where.replace(".", "\\.")}: Proxy objects are not supported`));
  }
  const whole = await run(new Proxy({ delegation: d, parentAuth: p, parentScope: PARENT_SCOPE }, handler));
  assertSnapshotRejected(whole, /delegation input: Proxy objects are not supported/);
  assert.equal(traps, 0);
});

test("OBS-E T5: nested max_amount accessor substitution fails closed", async () => {
  const p = makeParent();
  const d = makeChild(p);
  const scope = switching(d.scope, { ...d.scope, max_amount: 10n ** 15n }, ["max_amount"], 2);
  const r = await run({ delegation: { ...d, scope }, parentAuth: p, parentScope: PARENT_SCOPE }, action("provision_gpu", 900));
  assertSnapshotRejected(r, /delegation input\.delegation\.scope\.max_amount: accessor properties are not supported/);
});

test("OBS-E T5: parentScope accessor substitution fails closed", async () => {
  const p = makeParent();
  const d = makeChild(p);
  const parentScope = switching(PARENT_SCOPE, { tools: ["provision_gpu", "delete_cluster"], max_amount: 10n ** 15n }, ["tools", "max_amount"], 2);
  const r = await run({ delegation: d, parentAuth: p, parentScope });
  assertSnapshotRejected(r, /delegation input\.parentScope\.tools: accessor properties are not supported/);
});

test("OBS-E T6: replay-id accessor substitution fails closed and consumes nothing", async () => {
  const p = makeParent();
  const d = makeChild(p);
  const counted = countedStore();
  const config = makeConfig(counted.store);
  for (let i = 0; i < 3; i++) {
    const delegation = switching(d, { ...d, delegation_id: `${d.delegation_id}-r${i}` }, ["delegation_id"], 7);
    const parentAuth = switching(p, { ...p, auth_id: `${p.auth_id}-r${i}` }, ["auth_id"], 7);
    const r = await run({ delegation, parentAuth, parentScope: PARENT_SCOPE }, action(), counted, config);
    assert.deepEqual(r.executed, []);
    assert.match(String((r.error as Error).message), /accessor properties are not supported/);
  }
  assert.deepEqual(counted.authIds, []);
  assert.deepEqual(counted.delegIds, []);
});

test("OBS-E: class instances and exotic values in the delegation input fail closed", async () => {
  const p = makeParent();
  const d = makeChild(p);
  class Wrapped { constructor(readonly delegation: DelegationV1, readonly parentAuth: AuthorizationV1, readonly parentScope: typeof PARENT_SCOPE) {} }
  assertSnapshotRejected(await run(new Wrapped(d, p, PARENT_SCOPE)), /delegation input: only plain objects and plain arrays are supported/);
  assertSnapshotRejected(await run({ delegation: { ...d, expiry: new Date() }, parentAuth: p, parentScope: PARENT_SCOPE }), /delegation input\.delegation\.expiry: only plain objects/);
  assertSnapshotRejected(await run({ delegation: d, parentAuth: p, parentScope: { tools: new Set(["provision_gpu"]), max_amount: 1n } }), /delegation input\.parentScope\.tools: only plain objects/);
});

test("OBS-E: opts.delegation is read exactly once", async () => {
  const p = makeParent();
  const d = makeChild(p);
  let reads = 0;
  const opts = {};
  Object.defineProperty(opts, "delegation", { enumerable: true, get() { reads++; return { delegation: d, parentAuth: p, parentScope: PARENT_SCOPE }; } });
  const counted = countedStore();
  const guard = OxDeAIGuard(makeConfig(counted.store));
  const executed: string[] = [];
  await guard(action(), async () => { executed.push("x"); return "ok"; }, opts as { delegation: GuardDelegationInput });
  assert.equal(reads, 1);
  assert.deepEqual(executed, ["x"]);
});

// ── createSecureGuard routes delegation through the same snapshot ────────────

test("OBS-E: createSecureGuard accepts plain delegation input and rejects accessor and Proxy input before any consume", async () => {
  const context = createTrustedExecutionContext({ principalId: "principal-1", agentId: "agent-B", adapterId: "adapter-test", depth: 0 });
  const makeSecure = () => {
    const counted = countedStore();
    const events: GuardBoundaryAuditEvent[] = [];
    return { counted, events, secure: createSecureGuard(makeConfig(counted.store, events), { tenancy: "single-tenant" }) };
  };

  const p = makeParent();
  const d = makeChild(p);
  const ok = makeSecure();
  const executed: string[] = [];
  await ok.secure(context, action(), async () => { executed.push("provision_gpu"); return "ok"; }, { delegation: { delegation: d, parentAuth: p, parentScope: PARENT_SCOPE } });
  assert.deepEqual(executed, ["provision_gpu"]);
  assert.deepEqual(ok.counted.authIds, [p.auth_id]);
  assert.deepEqual(ok.counted.delegIds, [d.delegation_id]);

  const p2 = makeParent();
  const d2 = makeChild(p2);
  const wide = { ...d2, scope: { tools: ["delete_cluster"], max_amount: 500_000n } };
  for (const input of [
    { delegation: switching(d2, wide, ["scope"], 1), parentAuth: p2, parentScope: PARENT_SCOPE },
    { delegation: new Proxy({ ...d2 }, {}), parentAuth: p2, parentScope: PARENT_SCOPE },
  ]) {
    const h = makeSecure();
    const ran: string[] = [];
    let error: unknown;
    try {
      await h.secure(context, action("delete_cluster"), async () => { ran.push("delete_cluster"); return "ok"; }, { delegation: input as GuardDelegationInput });
    } catch (err) {
      error = err;
    }
    assertSnapshotRejected({ executed: ran, error, events: h.events, counted: h.counted }, /delegation input\.delegation(\.scope)?: (accessor properties|Proxy objects) are not supported/);
  }
});
