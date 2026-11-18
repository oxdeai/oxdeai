// SPDX-License-Identifier: Apache-2.0
/**
 * ACT-1: the action the guard verified must be the action handed to the
 * protected executor.
 *
 * The caller's `ProposedAction` is a live, in-process object. The guard now
 * reads it once, as one deep-frozen plain-data snapshot, before normalization;
 * normalization, policy evaluation, intent_hash binding, delegation scope
 * enforcement, `beforeExecute`, `execute(action)` and `onDecision` all see that
 * one snapshot. Each test counts executions at a mock protected executor, the
 * action that executor received, and every replay-store consume.
 *
 * Out of scope by design: an executor closure that ignores its argument and
 * reads the caller's own object. The guard cannot make caller-owned in-process
 * state immutable.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import {
  PolicyEngine,
  RECOMMENDED_TRUSTED_TIME_PROFILE,
  signAuthorizationEd25519,
  createDelegation,
  intentHash,
} from "@oxdeai/core";
import type { AuthorizationV1, DelegationV1, KeySet } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { OxDeAIGuard } from "../guard.js";
import { createSecureGuard } from "../secureGuard.js";
import { createTrustedExecutionContext } from "../trustedContext.js";
import { createInMemoryReplayStore } from "../replayStore.js";
import type { ReplayStore } from "../replayStore.js";
import { defaultNormalizeAction } from "../normalizeAction.js";
import { OxDeAINormalizationError } from "../errors.js";
import type { GuardBoundaryAuditEvent } from "../boundaryEvent.js";
import type { GuardDecisionRecord, OxDeAIGuardConfig, ProposedAction } from "../types.js";

const KP = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const ISSUER = "act1-issuer";
const POLICY = "act1-policy";
const KEYSET: KeySet = { issuer: ISSUER, version: "v1", keys: [{ kid: "ka", alg: "Ed25519", public_key: KP.publicKey.toString() }] };
const T_NOW = Math.floor(Date.now() / 1000);
const PARENT_SCOPE = { tools: ["provision_gpu"], max_amount: 1_000_000n };
/** Standard-path per-action cap: 10 units (fixed-point, 6 decimals). */
const CAP = 10_000_000n;

let seq = 0;
function makeParent(): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      auth_id: `act1-parent-${seq++}`,
      issuer: ISSUER,
      audience: "agent-A",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: POLICY,
      decision: "ALLOW",
      issued_at: T_NOW - 60,
      expiry: T_NOW + 900,
      kid: "ka",
    } as Parameters<typeof signAuthorizationEd25519>[0],
    KP.privateKey.toString()
  );
}
function makeDelegationInput() {
  const parentAuth = makeParent();
  const delegation: DelegationV1 = createDelegation(
    parentAuth,
    { delegatee: "agent-B", issuer: ISSUER, scope: { tools: ["provision_gpu"], max_amount: 500_000n }, expiry: T_NOW + 300, kid: "ka" },
    KP.privateKey.toString()
  );
  return { delegation, parentAuth, parentScope: PARENT_SCOPE };
}

type Counted = { store: ReplayStore; authIds: string[]; delegIds: string[] };
/** Replay store that records every consume and can run `onConsume` inside the awaited consume. */
function countedStore(onConsume?: (kind: "auth" | "deleg") => void): Counted {
  const inner = createInMemoryReplayStore();
  const authIds: string[] = [];
  const delegIds: string[] = [];
  return {
    authIds,
    delegIds,
    store: {
      consumeAuthId: async (id, o) => { authIds.push(id); const r = await inner.consumeAuthId(id, o); onConsume?.("auth"); return r; },
      consumeDelegationId: async (id, o) => { delegIds.push(id); const r = await inner.consumeDelegationId!(id, o); onConsume?.("deleg"); return r; },
    },
  };
}

type Harness = { config: OxDeAIGuardConfig; events: GuardBoundaryAuditEvent[]; decisions: GuardDecisionRecord[]; counters: { evaluate: number; setState: number } };
function makeHarness(store: ReplayStore, over: Partial<OxDeAIGuardConfig> = {}): Harness {
  const state = buildState({
    agent_id: "agent-B",
    allow_action_types: ["PROVISION"],
    budget_limit: 10n ** 18n,
    max_amount_per_action: CAP,
    velocity_max_actions: 1000,
    max_concurrent: 16,
  });
  const engine = new PolicyEngine({
    policy_version: "v1",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_signing_alg: "Ed25519",
    authorization_signing_kid: "ka",
    authorization_issuer: ISSUER,
    authorization_audience: "agent-A",
    authorization_ttl_seconds: 600,
    authorization_private_key_pem: KP.privateKey.toString(),
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
  const counters = { evaluate: 0, setState: 0 };
  const evaluatePure = engine.evaluatePure.bind(engine);
  engine.evaluatePure = ((...args: Parameters<typeof evaluatePure>) => { counters.evaluate++; return evaluatePure(...args); }) as typeof engine.evaluatePure;
  const events: GuardBoundaryAuditEvent[] = [];
  const decisions: GuardDecisionRecord[] = [];
  let version = 0;
  let current = state;
  const config: OxDeAIGuardConfig = {
    engine,
    getState: () => ({ state: current, version }),
    setState: (s, v) => { counters.setState++; if (v !== version) return false; current = s; version++; return true; },
    trustedKeySets: [KEYSET],
    expectedAudience: "agent-A",
    trustedDelegationAuthorities: [{ issuer: ISSUER, policyId: POLICY }],
    replayStore: store,
    onBoundaryEvent: (e) => { events.push(e); },
    onDecision: (d) => { decisions.push(d); },
    ...over,
  };
  return { config, events, decisions, counters };
}

const makeAction = (name = "provision_gpu", estimatedCost = 1): ProposedAction => ({
  name,
  args: { asset: "a100" },
  estimatedCost,
  context: { agent_id: "agent-B", target: "gpu-pool" },
  timestampSeconds: T_NOW,
});

type Entry = "guard" | "secure";
const TRUSTED = createTrustedExecutionContext({ principalId: "act1-principal", agentId: "agent-B", adapterId: "act1-adapter", depth: 0 });
function entryPoint(entry: Entry, config: OxDeAIGuardConfig) {
  if (entry === "guard") return OxDeAIGuard(config);
  const secure = createSecureGuard(config, { tenancy: "single-tenant" });
  return (a: ProposedAction, ex: (x: ProposedAction) => Promise<unknown>, o?: Parameters<ReturnType<typeof OxDeAIGuard>>[2]) => secure(TRUSTED, a, ex, o);
}

async function run(entry: Entry, act: unknown, h: Harness, opts?: Parameters<ReturnType<typeof OxDeAIGuard>>[2]) {
  const received: ProposedAction[] = [];
  let error: unknown;
  let result: unknown;
  try {
    result = await entryPoint(entry, h.config)(act as ProposedAction, async (verified) => { received.push(verified); return "ok"; }, opts);
  } catch (err) {
    error = err;
  }
  return { received, error, result };
}

function assertActionRejected(
  r: Awaited<ReturnType<typeof run>>,
  h: Harness,
  counted: Counted,
  pathPattern: RegExp
) {
  assert.deepEqual(r.received, [], "the protected executor must not run");
  assert.ok(r.error instanceof OxDeAINormalizationError, `expected OxDeAINormalizationError, got ${String(r.error)}`);
  assert.match(String((r.error as Error).message), /ProposedAction is not supported plain data/);
  assert.match(String((r.error as Error).message), pathPattern);
  assert.equal(h.counters.evaluate, 0, "policy must not be evaluated for a rejected action");
  assert.equal(h.counters.setState, 0, "state must not be committed for a rejected action");
  assert.deepEqual(counted.authIds, [], "no auth_id may be consumed for a rejected action");
  assert.deepEqual(counted.delegIds, [], "no delegation_id may be consumed for a rejected action");
  assert.equal(h.decisions.length, 0, "a boundary rejection emits no decision record");
  assert.equal(h.events.length, 1);
  assert.equal(h.events[0].stage, "NORMALIZATION");
  assert.equal(h.events[0].boundaryFailure, "NORMALIZATION_FAILURE");
  assert.equal(h.events[0].policyEvaluated, false);
  assert.equal(h.events[0].authorizationConsumed, false);
  assert.equal(h.events[0].executionStarted, false);
}

for (const entry of ["guard", "secure"] as const) {
  const label = entry === "guard" ? "OxDeAIGuard" : "createSecureGuard";

  // ── Legitimate actions keep working ────────────────────────────────────────

  test(`ACT-1 [${label}]: plain action executes once with a frozen copy equal to the caller's action`, async () => {
    const counted = countedStore();
    const h = makeHarness(counted.store);
    const act = makeAction();
    const r = await run(entry, act, h);
    assert.equal(r.error, undefined, String(r.error));
    assert.equal(r.result, "ok");
    assert.equal(r.received.length, 1);
    assert.notEqual(r.received[0], act, "the executor receives the guard's snapshot, not the caller's object");
    assert.ok(Object.isFrozen(r.received[0]) && Object.isFrozen(r.received[0].args) && Object.isFrozen(r.received[0].context));
    assert.deepEqual(r.received[0], act);
    assert.equal(counted.authIds.length, 1);
    assert.equal(h.counters.setState, 1);
    assert.equal(h.decisions.length, 1);
    assert.equal(h.decisions[0].action, r.received[0], "onDecision reports the same object that executed");
  });

  test(`ACT-1 [${label}]: zero-argument executors are unaffected`, async () => {
    const h = makeHarness(countedStore().store);
    let calls = 0;
    const out = await entryPoint(entry, h.config)(makeAction(), async () => { calls++; return 42; });
    assert.equal(out, 42);
    assert.equal(calls, 1);
  });

  test(`ACT-1 [${label}]: frozen, null-prototype, JSON-decoded and bigint-nonce actions are accepted`, async () => {
    const frozen = makeAction();
    Object.freeze(frozen.args); Object.freeze(frozen.context); Object.freeze(frozen);
    const nullProto = makeAction();
    nullProto.args = Object.assign(Object.create(null), { asset: "a100" });
    const json = JSON.parse(JSON.stringify(makeAction())) as ProposedAction;
    const bigintNonce = makeAction();
    bigintNonce.context = { ...bigintNonce.context, nonce: 7n, intent_id: "act1-fixed" };
    const nested = makeAction();
    nested.args = { spec: { gpus: [1, 2, { kind: "a100", tags: ["x", null, undefined] }] }, optional: undefined };
    for (const act of [frozen, nullProto, json, bigintNonce, nested]) {
      const h = makeHarness(countedStore().store);
      const r = await run(entry, act, h);
      assert.equal(r.error, undefined, String(r.error));
      assert.equal(r.received.length, 1);
      assert.deepEqual(r.received[0], act);
    }
  });

  // ── Plain mutation after verification ──────────────────────────────────────

  test(`ACT-1 [${label}] T1: estimatedCost raised during the auth consume does not reach the executor`, async () => {
    const act = makeAction("provision_gpu", 1);
    const counted = countedStore(() => { act.estimatedCost = 900; });
    const h = makeHarness(counted.store);
    const r = await run(entry, act, h);
    assert.equal(r.error, undefined, String(r.error));
    assert.equal(act.estimatedCost, 900, "the caller's own object was mutated");
    assert.equal(r.received.length, 1);
    assert.equal(r.received[0].estimatedCost, 1, "the executor receives the verified cost");
    assert.equal(h.decisions[0].action.estimatedCost, 1, "the audit record reports the verified cost");

    // Control: the mutated value presented directly is refused by policy.
    const h2 = makeHarness(countedStore().store);
    const ctl = await run(entry, makeAction("provision_gpu", 900), h2);
    assert.deepEqual(ctl.received, []);
  });

  test(`ACT-1 [${label}] T2: tool substituted during the auth consume does not reach the executor`, async () => {
    const act = makeAction("provision_gpu");
    const h = makeHarness(countedStore(() => { act.name = "send_payment"; }).store);
    const r = await run(entry, act, h);
    assert.equal(r.error, undefined, String(r.error));
    assert.equal(r.received.length, 1);
    assert.equal(r.received[0].name, "provision_gpu");
  });

  test(`ACT-1 [${label}] T3: nested args mutated through a retained reference do not reach the executor`, async () => {
    const act = makeAction();
    const args = act.args;
    const h = makeHarness(countedStore(() => { args.asset = "h100x8"; }).store);
    const r = await run(entry, act, h);
    assert.equal(r.error, undefined, String(r.error));
    assert.equal(r.received[0].args.asset, "a100");
  });

  test(`ACT-1 [${label}] T4: beforeExecute receives the frozen snapshot and cannot alter what executes`, async () => {
    const act = makeAction("provision_gpu", 1);
    const seen: ProposedAction[] = [];
    const h = makeHarness(countedStore().store, {
      beforeExecute: (a) => {
        seen.push(a);
        assert.throws(() => { (a as { estimatedCost?: number }).estimatedCost = 900; }, TypeError);
      },
    });
    const r = await run(entry, act, h);
    assert.equal(r.error, undefined, String(r.error));
    assert.equal(seen.length, 1);
    assert.notEqual(seen[0], act);
    assert.equal(seen[0], r.received[0], "beforeExecute and execute receive the same snapshot");
    assert.equal(r.received[0].estimatedCost, 1);
    assert.equal(act.estimatedCost, 1, "the caller's object is not touched by the guard");
  });

  // ── Accessors, Proxies and unsupported values fail closed ──────────────────

  test(`ACT-1 [${label}] T5: an accessor on the action is never invoked and nothing is evaluated, consumed or executed`, async () => {
    let getterRuns = 0;
    const act = makeAction();
    delete (act as { estimatedCost?: number }).estimatedCost;
    Object.defineProperty(act, "estimatedCost", { enumerable: true, configurable: true, get: () => (getterRuns++ === 0 ? 1 : 900) });
    const counted = countedStore();
    const h = makeHarness(counted.store);
    const r = await run(entry, act, h);
    assertActionRejected(r, h, counted, /action\.estimatedCost: accessor properties are not supported/);
    assert.equal(getterRuns, 0, "the accessor must not run");
  });

  test(`ACT-1 [${label}] T6: a Proxy action fails closed and no trap runs`, async () => {
    let trapRuns = 0;
    const handler: ProxyHandler<ProposedAction> = {};
    for (const trap of ["get", "has", "ownKeys", "getOwnPropertyDescriptor", "getPrototypeOf"] as const) {
      (handler as Record<string, unknown>)[trap] = (...a: unknown[]) => { trapRuns++; return (Reflect[trap] as (...x: unknown[]) => unknown)(...a); };
    }
    const counted = countedStore();
    const h = makeHarness(counted.store);
    const r = await run(entry, new Proxy(makeAction(), handler), h);
    assertActionRejected(r, h, counted, /action: Proxy objects are not supported/);
    assert.equal(trapRuns, 0, "no Proxy trap may run");

    const nested = makeAction();
    nested.args = new Proxy({ asset: "a100" }, {});
    const counted2 = countedStore();
    const h2 = makeHarness(counted2.store);
    assertActionRejected(await run(entry, nested, h2), h2, counted2, /action\.args: Proxy objects are not supported/);
  });

  test(`ACT-1 [${label}] T7: unsupported action values fail closed before evaluation`, async () => {
    class Args { asset = "a100"; }
    const cyclic = makeAction();
    (cyclic.args as Record<string, unknown>).self = cyclic.args;
    const sparse = makeAction();
    // eslint-disable-next-line no-sparse-arrays
    sparse.args = { list: [1, , 3] };
    const cases: Array<[string, ProposedAction, RegExp]> = [
      ["Date", { ...makeAction(), args: { when: new Date(0) } }, /action\.args\.when: only plain objects/],
      ["Map", { ...makeAction(), args: { m: new Map() } }, /action\.args\.m: only plain objects/],
      ["class instance", { ...makeAction(), args: new Args() as unknown as Record<string, unknown> }, /action\.args: only plain objects/],
      ["function", { ...makeAction(), context: { agent_id: "agent-B", cb: () => 1 } }, /action\.context\.cb: unsupported value type function/],
      ["symbol key", { ...makeAction(), args: { [Symbol("s")]: 1 } as Record<string, unknown> }, /action\.args: symbol-keyed properties/],
      ["sparse array", sparse, /action\.args\.list: sparse arrays/],
      ["cycle", cyclic, /action\.args\.self: cyclic structure/],
    ];
    for (const [name, act, pattern] of cases) {
      const counted = countedStore();
      const h = makeHarness(counted.store);
      const r = await run(entry, act, h);
      assert.ok(r.error, `${name} must be rejected`);
      assertActionRejected(r, h, counted, pattern);
    }
  });

  // ── Delegation path ────────────────────────────────────────────────────────

  test(`ACT-1 [${label}] T8: delegation tool substituted during the delegation consume does not reach the executor`, async () => {
    const act = makeAction("provision_gpu", 0.1);
    const counted = countedStore((kind) => { if (kind === "deleg") { act.name = "delete_cluster"; act.estimatedCost = 900; } });
    const h = makeHarness(counted.store);
    const input = makeDelegationInput();
    const r = await run(entry, act, h, { delegation: input });
    assert.equal(r.error, undefined, String(r.error));
    assert.equal(r.received.length, 1);
    assert.equal(r.received[0].name, "provision_gpu");
    assert.equal(r.received[0].estimatedCost, 0.1);
    assert.deepEqual(counted.delegIds, [input.delegation.delegation_id]);
    assert.deepEqual(counted.authIds, [input.parentAuth.auth_id]);
    assert.equal(h.decisions[0].action, r.received[0]);

    // Control: the substituted tool presented directly is outside the delegation scope.
    const h2 = makeHarness(countedStore().store);
    const ctl = await run(entry, makeAction("delete_cluster", 0.1), h2, { delegation: makeDelegationInput() });
    assert.deepEqual(ctl.received, []);
  });

  test(`ACT-1 [${label}] T9: a delegation call with an accessor action consumes no replay id`, async () => {
    let getterRuns = 0;
    const act = makeAction("provision_gpu", 0.1);
    delete (act as { name?: string }).name;
    Object.defineProperty(act, "name", { enumerable: true, configurable: true, get: () => (getterRuns++ < 2 ? "provision_gpu" : "delete_cluster") });
    const counted = countedStore();
    const h = makeHarness(counted.store);
    const r = await run(entry, act, h, { delegation: makeDelegationInput() });
    assertActionRejected(r, h, counted, /action\.name: accessor properties are not supported/);
    assert.equal(getterRuns, 0);
  });

  test(`ACT-1 [${label}] T10: replay behaviour is unchanged: one delegation executes once`, async () => {
    const counted = countedStore();
    const h = makeHarness(counted.store);
    const input = makeDelegationInput();
    const first = await run(entry, makeAction("provision_gpu", 0.1), h, { delegation: input });
    const second = await run(entry, makeAction("provision_gpu", 0.1), h, { delegation: input });
    assert.equal(first.error, undefined, String(first.error));
    assert.equal(first.received.length, 1);
    assert.deepEqual(second.received, []);
    assert.equal(h.events.at(-1)?.boundaryFailure, "DELEGATION_REPLAY");
  });
}

// OxDeAIGuard only: createSecureGuard reconciles the normalized intent with the
// trusted context, so its bound hash is by design not defaultNormalizeAction's.
test("ACT-1: intent_hash bound by the authorization is unchanged for plain input", async () => {
  const act = makeAction();
  act.context = { ...act.context, intent_id: "act1-intent", nonce: 11n };
  let boundHash: string | undefined;
  const h = makeHarness(countedStore().store, { beforeExecute: (_a, auth) => { boundHash = (auth as AuthorizationV1).intent_hash; } });
  const r = await run("guard", act, h);
  assert.equal(r.error, undefined, String(r.error));
  assert.equal(boundHash, intentHash(defaultNormalizeAction(act)), "snapshotting must not change canonicalization");
});

test("ACT-1: a custom mapActionToIntent receives the frozen snapshot, not the caller's object", async () => {
  const act = makeAction();
  const seen: ProposedAction[] = [];
  const h = makeHarness(countedStore().store, { mapActionToIntent: (a) => { seen.push(a); return defaultNormalizeAction(a); } });
  const r = await run("guard", act, h);
  assert.equal(r.error, undefined, String(r.error));
  assert.equal(seen.length, 1);
  assert.notEqual(seen[0], act);
  assert.ok(Object.isFrozen(seen[0]));
  assert.equal(seen[0], r.received[0], "normalization and execution see the same snapshot");
});

test("ACT-1: a policy DENY reports the snapshot on onDecision", async () => {
  const act = makeAction("provision_gpu", 900);
  const h = makeHarness(countedStore().store);
  const r = await run("guard", act, h);
  assert.deepEqual(r.received, []);
  assert.equal(h.decisions.length, 1);
  assert.equal(h.decisions[0].decision, "DENY");
  assert.notEqual(h.decisions[0].action, act);
  assert.ok(Object.isFrozen(h.decisions[0].action));
  assert.deepEqual(h.decisions[0].action, act);
});
