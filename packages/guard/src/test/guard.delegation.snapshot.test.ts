// SPDX-License-Identifier: Apache-2.0
/**
 * F4-R8-01 (supersedes F4-R6-02) — Lot B: delegation-input snapshot integrity.
 *
 * The guard must authorize, enforce and consume exactly ONE view of the
 * caller-supplied delegation input. Reproduced on the baseline: an accessor on
 * `delegation.scope` executed above the signed cap, and accessors on
 * `delegation_id` / `parentAuth.auth_id` executed one signed delegation twice.
 *
 * Synthetic keys and identities only.
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
import type { AuthorizationV1, DelegationScope, DelegationV1, KeySet } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { OxDeAIGuard } from "../guard.js";
import { createInMemoryReplayStore } from "../replayStore.js";
import type { ReplayStore } from "../replayStore.js";
import { OxDeAIAuthorizationError, OxDeAIDelegationError } from "../errors.js";
import { snapshotPlainData, DelegationSnapshotError, MAX_DEPTH } from "../delegationSnapshot.js";
import type { GuardBoundaryAuditEvent } from "../boundaryEvent.js";
import type { GuardDecisionRecord, OxDeAIGuardConfig, ProposedAction } from "../types.js";

const KP = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const ISSUER = "snap-issuer";
const POLICY = "snap-policy";
const KEYSET: KeySet = { issuer: ISSUER, version: "v1", keys: [{ kid: "k1", alg: "Ed25519", public_key: KP.publicKey.toString() }] };
const T_NOW = Math.floor(Date.now() / 1000);
const PARENT_SCOPE: DelegationScope = { tools: ["provision_gpu"], max_amount: 1_000_000_000n };

let seq = 0;
const uid = () => `${seq++}-${Math.random().toString(16).slice(2)}`;
function makeParent(): AuthorizationV1 {
  return signAuthorizationEd25519({
    auth_id: `snap-parent-${uid()}`, issuer: ISSUER, audience: "agent-A",
    intent_hash: "a".repeat(64), state_hash: "b".repeat(64), policy_id: POLICY, decision: "ALLOW",
    issued_at: T_NOW - 60, expiry: T_NOW + 900, kid: "k1",
  }, KP.privateKey.toString());
}
function makeChild(parent: AuthorizationV1, scope: DelegationScope = { tools: ["provision_gpu"], max_amount: 100n }): DelegationV1 {
  return createDelegation(parent, {
    delegatee: "agent-B", issuer: ISSUER, kid: "k1", scope, expiry: T_NOW + 300, delegationId: `snap-deleg-${uid()}`,
  }, KP.privateKey.toString());
}

function spyStore(hook?: (kind: "auth" | "deleg", id: string) => void): { store: ReplayStore; calls: string[] } {
  const inner = createInMemoryReplayStore();
  const calls: string[] = [];
  return {
    calls,
    store: {
      consumeAuthId: async (id, o) => { calls.push(`auth:${id}`); hook?.("auth", id); await Promise.resolve(); return inner.consumeAuthId(id, o); },
      consumeDelegationId: async (id, o) => { calls.push(`deleg:${id}`); hook?.("deleg", id); await Promise.resolve(); return inner.consumeDelegationId!(id, o); },
    },
  };
}

function makeConfig(store: ReplayStore, overrides: Partial<OxDeAIGuardConfig> = {}): OxDeAIGuardConfig {
  const state = buildState({
    agent_id: "agent-B", allow_action_types: ["PROVISION"], budget_limit: 10n ** 15n,
    max_amount_per_action: 10n ** 15n, velocity_max_actions: 10_000, max_concurrent: 16,
  });
  return {
    engine: new PolicyEngine({
      policy_version: "v1", engine_secret: "synthetic-secret-at-least-32-characters!!",
      authorization_signing_alg: "Ed25519", authorization_signing_kid: "k1",
      authorization_issuer: ISSUER, authorization_audience: "agent-A", authorization_ttl_seconds: 600,
      authorization_private_key_pem: KP.privateKey.toString(), ...RECOMMENDED_TRUSTED_TIME_PROFILE,
    }),
    getState: () => ({ state, version: 0 }),
    setState: () => true,
    trustedKeySets: [KEYSET],
    expectedAudience: "agent-A",
    trustedDelegationAuthorities: [{ issuer: ISSUER, policyId: POLICY }],
    replayProtection: { mode: "shared", store },
    ...overrides,
  };
}

/** estimatedCost is in whole units (x1e6 by the default normalizer). */
const action = (cost: number): ProposedAction => ({
  name: "provision_gpu", args: { asset: "a100" }, estimatedCost: cost,
  context: { agent_id: "agent-B", target: "gpu-pool" }, timestampSeconds: T_NOW,
});

async function present(guard: ReturnType<typeof OxDeAIGuard>, input: unknown, cost = 0) {
  let executed = 0;
  let error: unknown;
  try {
    await guard(action(cost), async () => { executed++; return "ok"; },
      { delegation: input as never });
  } catch (err) { error = err; }
  return { executed, error };
}

const isInputInvalid = (e: unknown) =>
  e instanceof OxDeAIAuthorizationError && !(e instanceof OxDeAIDelegationError) &&
  /Delegation input is not supported plain data/.test(e.message);

// ── Reproductions now denied ─────────────────────────────────────────────────

test("B1 accessor-based signed-cap bypass is rejected; the getter never runs; nothing consumed", async () => {
  const { store, calls } = spyStore();
  const p = makeParent();
  const signed = makeChild(p, { tools: ["provision_gpu"], max_amount: 100n });
  const wide = { tools: ["provision_gpu"], max_amount: 10n ** 18n };
  let getterCalls = 0;
  const evil: Record<string, unknown> = { ...signed };
  delete evil.scope;
  // Signed scope on the first read (what verification would see), wide scope afterwards.
  Object.defineProperty(evil, "scope", { enumerable: true, get: () => (getterCalls++ === 0 ? signed.scope : wide) });
  const events: GuardBoundaryAuditEvent[] = [];
  const guard = OxDeAIGuard(makeConfig(store, { onBoundaryEvent: (e) => { events.push(e); } }));
  const r = await present(guard, { delegation: evil, parentAuth: p, parentScope: PARENT_SCOPE }, 500); // 5e8 > 100
  assert.equal(r.executed, 0, "over-cap execution must not occur");
  assert.ok(isInputInvalid(r.error), String(r.error));
  assert.equal(getterCalls, 0, "the accessor is never invoked");
  assert.deepEqual(calls, [], "no replay state consumed");
  assert.equal(events.at(-1)?.boundaryFailure, "DELEGATION_INPUT_INVALID");
  // The genuine artifact is unaffected and still enforces its signed cap.
  const over = await present(guard, { delegation: signed, parentAuth: p, parentScope: PARENT_SCOPE }, 500);
  assert.equal(over.executed, 0);
  assert.ok(over.error instanceof OxDeAIDelegationError && /exceeds delegation scope.max_amount 100/.test(over.error.message), String(over.error));
});

test("B2 repeated delegation identifiers cannot bypass replay protection (accessor ids rejected; plain replay denied)", async () => {
  const { store } = spyStore();
  const guard = OxDeAIGuard(makeConfig(store));
  const p = makeParent();
  const d = makeChild(p);
  const mk = () => {
    const ed: Record<string, unknown> = { ...d }; delete ed.delegation_id;
    Object.defineProperty(ed, "delegation_id", { enumerable: true, get: () => `fresh-${uid()}` });
    const ep: Record<string, unknown> = { ...p }; delete ep.auth_id;
    Object.defineProperty(ep, "auth_id", { enumerable: true, get: () => `fresh-${uid()}` });
    return { delegation: ed, parentAuth: ep, parentScope: PARENT_SCOPE };
  };
  let total = 0;
  for (let i = 0; i < 3; i++) {
    const r = await present(guard, mk());
    total += r.executed;
    assert.ok(isInputInvalid(r.error), String(r.error));
  }
  assert.equal(total, 0);
  const first = await present(guard, { delegation: d, parentAuth: p, parentScope: PARENT_SCOPE });
  const second = await present(guard, { delegation: d, parentAuth: p, parentScope: PARENT_SCOPE });
  assert.equal(first.executed, 1, String(first.error));
  assert.equal(second.executed, 0);
  assert.match(String((second.error as Error)?.message), /replay/i);
});

test("B3 plain-object mutation during the async replay consume cannot change the consumed ids (snapshot, not live object)", async () => {
  const p = makeParent();
  const d = makeChild(p);
  const callerDelegation = { ...d };
  const callerParent = { ...p };
  const { store, calls } = spyStore((kind) => {
    // Runs while the guard is awaiting the store: mutate the caller's objects.
    if (kind === "deleg") { callerParent.auth_id = `swapped-${uid()}`; callerDelegation.delegation_id = `swapped-${uid()}`; }
  });
  const guard = OxDeAIGuard(makeConfig(store));
  const r = await present(guard, { delegation: callerDelegation, parentAuth: callerParent, parentScope: PARENT_SCOPE });
  assert.equal(r.executed, 1, String(r.error));
  assert.deepEqual(calls, [`deleg:${d.delegation_id}`, `auth:${p.auth_id}`], "the signed ids are consumed, not the mutated ones");
});

// ── Unsupported structures fail closed, no consumption ───────────────────────

test("B4 Proxy at any level is rejected before any trap runs; nothing consumed", async () => {
  const { store, calls } = spyStore();
  const guard = OxDeAIGuard(makeConfig(store));
  let traps = 0;
  const handler: ProxyHandler<object> = {
    get: (t, k, r) => { traps++; return Reflect.get(t, k, r); },
    getOwnPropertyDescriptor: (t, k) => { traps++; return Reflect.getOwnPropertyDescriptor(t, k); },
    ownKeys: (t) => { traps++; return Reflect.ownKeys(t); },
    getPrototypeOf: (t) => { traps++; return Reflect.getPrototypeOf(t); },
  };
  const P = <T extends object>(o: T): T => new Proxy(o, handler) as T;
  const p = makeParent();
  const d = makeChild(p);
  const cases: Record<string, unknown> = {
    container: P({ delegation: d, parentAuth: p, parentScope: PARENT_SCOPE }),
    delegation: { delegation: P({ ...d }), parentAuth: p, parentScope: PARENT_SCOPE },
    scope: { delegation: { ...d, scope: P({ ...d.scope }) }, parentAuth: p, parentScope: PARENT_SCOPE },
    tools: { delegation: { ...d, scope: { ...d.scope, tools: P(["provision_gpu"]) } }, parentAuth: p, parentScope: PARENT_SCOPE },
    parentAuth: { delegation: d, parentAuth: P({ ...p }), parentScope: PARENT_SCOPE },
    parentScope: { delegation: d, parentAuth: p, parentScope: P({ ...PARENT_SCOPE }) },
  };
  for (const [name, input] of Object.entries(cases)) {
    const r = await present(guard, input);
    assert.equal(r.executed, 0, name);
    assert.ok(isInputInvalid(r.error), `${name}: ${String(r.error)}`);
  }
  assert.equal(traps, 0, "no Proxy trap was invoked");
  assert.deepEqual(calls, []);
});

test("B5 unsupported structures fail closed deterministically with no replay consumption", async () => {
  const { store, calls } = spyStore();
  const guard = OxDeAIGuard(makeConfig(store));
  const p = makeParent();
  const d = makeChild(p);
  class Box { constructor(readonly v: unknown) {} }
  const cyclic: Record<string, unknown> = { ...d }; cyclic.self = cyclic;
  const nonEnum = { ...d }; Object.defineProperty(nonEnum, "hidden", { value: 1, enumerable: false });
  const symbolKey = { ...d, [Symbol("s")]: 1 };
  const sparse: unknown[] = ["provision_gpu"]; sparse.length = 3;
  const extra = Object.assign(["provision_gpu"], { extra: 1 });
  let deep: Record<string, unknown> = {}; for (let i = 0; i < MAX_DEPTH + 2; i++) deep = { n: deep };
  const cases: Record<string, unknown> = {
    "class instance delegation": { delegation: Object.assign(new Box(1), d), parentAuth: p, parentScope: PARENT_SCOPE },
    "Date leaf": { delegation: { ...d, extra: new Date() }, parentAuth: p, parentScope: PARENT_SCOPE },
    "Map scope": { delegation: { ...d, scope: new Map() }, parentAuth: p, parentScope: PARENT_SCOPE },
    "function leaf": { delegation: { ...d, extra: () => 1 }, parentAuth: p, parentScope: PARENT_SCOPE },
    "symbol leaf": { delegation: { ...d, extra: Symbol("x") }, parentAuth: p, parentScope: PARENT_SCOPE },
    "symbol key": { delegation: symbolKey, parentAuth: p, parentScope: PARENT_SCOPE },
    "non-enumerable property": { delegation: nonEnum, parentAuth: p, parentScope: PARENT_SCOPE },
    "sparse tools": { delegation: { ...d, scope: { ...d.scope, tools: sparse } }, parentAuth: p, parentScope: PARENT_SCOPE },
    "array with extra property": { delegation: { ...d, scope: { ...d.scope, tools: extra } }, parentAuth: p, parentScope: PARENT_SCOPE },
    "cycle": { delegation: cyclic, parentAuth: p, parentScope: PARENT_SCOPE },
    "too deep": { delegation: { ...d, extra: deep }, parentAuth: p, parentScope: PARENT_SCOPE },
    "boxed primitive": { delegation: { ...d, delegation_id: new String(d.delegation_id) }, parentAuth: p, parentScope: PARENT_SCOPE },
    "accessor parentScope.max_amount": { delegation: d, parentAuth: p, parentScope: Object.defineProperty({ tools: ["provision_gpu"] }, "max_amount", { enumerable: true, get: () => 10n ** 18n }) },
    "accessor on container": Object.defineProperty({ parentAuth: p, parentScope: PARENT_SCOPE }, "delegation", { enumerable: true, get: () => d }),
  };
  for (const [name, input] of Object.entries(cases)) {
    const r = await present(guard, input);
    assert.equal(r.executed, 0, name);
    assert.ok(isInputInvalid(r.error), `${name}: ${String(r.error)}`);
  }
  assert.deepEqual(calls, [], "no replay state consumed by any rejected input");
  // The genuine artifacts were never consumed, so they still execute exactly once.
  const ok = await present(guard, { delegation: d, parentAuth: p, parentScope: PARENT_SCOPE });
  assert.equal(ok.executed, 1, String(ok.error));
});

// ── Supported plain inputs keep working ──────────────────────────────────────

test("B6 supported plain inputs work: createDelegation output, structuredClone, frozen, null-prototype", async () => {
  const { store } = spyStore();
  const guard = OxDeAIGuard(makeConfig(store));
  const variants: Array<[string, (d: DelegationV1, p: AuthorizationV1) => unknown]> = [
    ["as returned", (d, p) => ({ delegation: d, parentAuth: p, parentScope: PARENT_SCOPE })],
    ["structuredClone", (d, p) => structuredClone({ delegation: d, parentAuth: p, parentScope: PARENT_SCOPE })],
    ["deep-frozen", (d, p) => Object.freeze({ delegation: Object.freeze({ ...d, scope: Object.freeze({ ...d.scope, tools: Object.freeze([...(d.scope.tools ?? [])]) }) }), parentAuth: Object.freeze({ ...p }), parentScope: Object.freeze({ ...PARENT_SCOPE }) })],
    ["null-prototype", (d, p) => Object.assign(Object.create(null), { delegation: Object.assign(Object.create(null), d), parentAuth: p, parentScope: PARENT_SCOPE })],
  ];
  for (const [name, build] of variants) {
    const p = makeParent();
    const r = await present(guard, build(makeChild(p), p), 0);
    assert.equal(r.error, undefined, `${name}: ${String(r.error)}`);
    assert.equal(r.executed, 1, name);
  }
});

test("B7 bigint cap semantics are preserved through the snapshot (within cap executes, above cap is denied)", async () => {
  const { store } = spyStore();
  const guard = OxDeAIGuard(makeConfig(store));
  const p1 = makeParent();
  const within = await present(guard, { delegation: makeChild(p1, { tools: ["provision_gpu"], max_amount: 5_000_000n }), parentAuth: p1, parentScope: PARENT_SCOPE }, 5);
  assert.equal(within.executed, 1, String(within.error));
  const p2 = makeParent();
  const above = await present(guard, { delegation: makeChild(p2, { tools: ["provision_gpu"], max_amount: 4_999_999n }), parentAuth: p2, parentScope: PARENT_SCOPE }, 5);
  assert.equal(above.executed, 0);
  assert.ok(above.error instanceof OxDeAIDelegationError, String(above.error));
});

test("B8 hooks receive the frozen snapshot, by value equal to the signed artifacts", async () => {
  const { store } = spyStore();
  const decisions: GuardDecisionRecord[] = [];
  let beforeAuth: unknown;
  const guard = OxDeAIGuard(makeConfig(store, {
    onDecision: (r) => { decisions.push(r); },
    beforeExecute: (_a, auth) => { beforeAuth = auth; },
  }));
  const p = makeParent();
  const d = makeChild(p);
  const r = await present(guard, { delegation: d, parentAuth: p, parentScope: PARENT_SCOPE });
  assert.equal(r.executed, 1, String(r.error));
  const rec = decisions.at(-1)!;
  assert.notEqual(rec.delegation, d, "the caller's object is not passed through");
  assert.deepEqual(rec.delegation, d);
  assert.ok(Object.isFrozen(rec.delegation) && Object.isFrozen(rec.delegation!.scope));
  assert.deepEqual(beforeAuth, p);
  assert.ok(Object.isFrozen(beforeAuth));
});

// ── snapshotPlainData unit contract ──────────────────────────────────────────

test("B9 snapshotPlainData: copies plain data exactly, preserves bigint/undefined/key order, own __proto__ stays data", () => {
  const src = JSON.parse('{"b":1,"a":[1,"x",true,null],"__proto__":{"polluted":true}}') as Record<string, unknown>;
  src.big = 12345678901234567890n;
  src.u = undefined;
  const snap = snapshotPlainData(src) as Record<string, unknown>;
  assert.deepEqual(Object.keys(snap), ["b", "a", "__proto__", "big", "u"]);
  assert.equal(snap.big, 12345678901234567890n);
  assert.ok(Object.hasOwn(snap, "u") && snap.u === undefined);
  assert.equal(Object.getPrototypeOf(snap), Object.prototype, "own __proto__ did not become the prototype");
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
  assert.ok(Object.isFrozen(snap) && Object.isFrozen(snap.a));
  assert.notEqual(snap.a, src.a);
  assert.throws(() => snapshotPlainData({ a: new Uint8Array(1) }), DelegationSnapshotError);
  assert.throws(() => snapshotPlainData(Object.defineProperty({}, "x", { get: () => 1, enumerable: true })), DelegationSnapshotError);
});
