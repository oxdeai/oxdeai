// SPDX-License-Identifier: Apache-2.0
/**
 * Lot A′ — guard delegation-path input validation.
 *
 * F4-R8-04: the delegation path skips `engine.evaluatePure`, so a custom
 *   `mapActionToIntent` returning a negative `amount` passed every
 *   `amount > scope.max_amount` comparison and EXECUTED (reproduced at
 *   -5e12 against a cap of 100n), while the engine path denied the same intent
 *   with INTENT_AMOUNT_INVALID.
 * F4-R6-06/C9 (Guard side): NaN / Infinity `parentScope` ceilings passed the
 *   guard's type-only check.
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
import type { AuthorizationV1, DelegationScope, DelegationV1, Intent, KeySet } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { OxDeAIGuard } from "../guard.js";
import { defaultNormalizeAction } from "../normalizeAction.js";
import { createInMemoryReplayStore } from "../replayStore.js";
import type { ReplayStore } from "../replayStore.js";
import { OxDeAIAuthorizationError, OxDeAIDelegationError, OxDeAIDenyError, OxDeAINormalizationError } from "../errors.js";
import type { GuardBoundaryAuditEvent } from "../boundaryEvent.js";
import type { OxDeAIGuardConfig, ProposedAction } from "../types.js";

const KP = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const ISSUER = "iv-issuer";
const POLICY = "iv-policy";
const KEYSET: KeySet = { issuer: ISSUER, version: "v1", keys: [{ kid: "k1", alg: "Ed25519", public_key: KP.publicKey.toString() }] };
const T_NOW = Math.floor(Date.now() / 1000);
const PARENT_SCOPE: DelegationScope = { tools: ["provision_gpu"], max_amount: 1_000_000_000n };

let seq = 0;
const uid = () => `${seq++}-${Math.random().toString(16).slice(2)}`;
function makeParent(): AuthorizationV1 {
  return signAuthorizationEd25519({
    auth_id: `iv-parent-${uid()}`, issuer: ISSUER, audience: "agent-A",
    intent_hash: "a".repeat(64), state_hash: "b".repeat(64), policy_id: POLICY, decision: "ALLOW",
    issued_at: T_NOW - 60, expiry: T_NOW + 900, kid: "k1",
  }, KP.privateKey.toString());
}
function makeChild(parent: AuthorizationV1, scope: DelegationScope = { tools: ["provision_gpu"], max_amount: 100n }): DelegationV1 {
  return createDelegation(parent, {
    delegatee: "agent-B", issuer: ISSUER, kid: "k1", scope, expiry: T_NOW + 300, delegationId: `iv-deleg-${uid()}`,
  }, KP.privateKey.toString());
}
function spyStore(): { store: ReplayStore; calls: string[] } {
  const inner = createInMemoryReplayStore();
  const calls: string[] = [];
  return {
    calls,
    store: {
      consumeAuthId: async (id, o) => { calls.push(`auth:${id}`); return inner.consumeAuthId(id, o); },
      consumeDelegationId: async (id, o) => { calls.push(`deleg:${id}`); return inner.consumeDelegationId!(id, o); },
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
const ACTION: ProposedAction = {
  name: "provision_gpu", args: { asset: "a100" }, estimatedCost: 0,
  context: { agent_id: "agent-B", target: "gpu-pool" }, timestampSeconds: T_NOW,
};
const mapperWithAmount = (amount: unknown) => (a: ProposedAction): Intent =>
  ({ ...defaultNormalizeAction(a), amount } as unknown as Intent);

async function present(guard: ReturnType<typeof OxDeAIGuard>, parentAuth: AuthorizationV1, delegation: DelegationV1, parentScope: unknown = PARENT_SCOPE) {
  let executed = 0;
  let error: unknown;
  try {
    await guard(ACTION, async () => { executed++; return "ok"; },
      { delegation: { delegation, parentAuth, parentScope: parentScope as DelegationScope } });
  } catch (err) { error = err; }
  return { executed, error };
}

// ── F4-R8-04: delegated intent amount ────────────────────────────────────────

test("A'1 negative custom-mapper amount is denied on the delegation path; no execute, nothing consumed", async () => {
  const { store, calls } = spyStore();
  const events: GuardBoundaryAuditEvent[] = [];
  const guard = OxDeAIGuard(makeConfig(store, { mapActionToIntent: mapperWithAmount(-5_000_000_000_000n), onBoundaryEvent: (e) => { events.push(e); } }));
  const p = makeParent();
  const r = await present(guard, p, makeChild(p));
  assert.equal(r.executed, 0, "protected execution must not occur");
  assert.ok(r.error instanceof OxDeAINormalizationError, String(r.error));
  assert.match(String((r.error as Error).message), /non-negative bigint/);
  assert.deepEqual(calls, []);
  assert.equal(events.at(-1)?.boundaryFailure, "NORMALIZATION_FAILURE");
});

test("A'2 delegation-path amount must be a bigint: number, string, NaN, undefined, null are denied", async () => {
  for (const amount of [5, "5", Number.NaN, undefined, null, -1n, -0.5]) {
    const { store, calls } = spyStore();
    const guard = OxDeAIGuard(makeConfig(store, { mapActionToIntent: mapperWithAmount(amount) }));
    const p = makeParent();
    const r = await present(guard, p, makeChild(p));
    assert.equal(r.executed, 0, `amount ${String(amount)}`);
    assert.ok(r.error instanceof OxDeAINormalizationError, `${String(amount)}: ${String(r.error)}`);
    assert.deepEqual(calls, []);
  }
});

test("A'3 engine path and delegation path now agree on the same negative intent (both deny, neither executes)", async () => {
  const { store } = spyStore();
  const guard = OxDeAIGuard(makeConfig(store, { mapActionToIntent: mapperWithAmount(-1n) }));
  let executed = 0;
  await assert.rejects(guard(ACTION, async () => { executed++; }), (e: unknown) => e instanceof OxDeAIDenyError || e instanceof OxDeAIAuthorizationError);
  const p = makeParent();
  const r = await present(guard, p, makeChild(p));
  assert.equal(executed + r.executed, 0);
});

test("A'4 valid zero amount executes; amount equal to the cap executes; above the cap is denied", async () => {
  const { store } = spyStore();
  for (const [amount, cap, ok] of [[0n, 0n, true], [0n, 100n, true], [100n, 100n, true], [101n, 100n, false]] as const) {
    const guard = OxDeAIGuard(makeConfig(store, { mapActionToIntent: mapperWithAmount(amount) }));
    const p = makeParent();
    const r = await present(guard, p, makeChild(p, { tools: ["provision_gpu"], max_amount: cap }));
    assert.equal(r.executed, ok ? 1 : 0, `amount ${amount} cap ${cap}: ${String(r.error)}`);
    if (!ok) assert.ok(r.error instanceof OxDeAIDelegationError, String(r.error));
  }
});

// ── F4-R6-06/C9 (Guard side): parentScope ceilings ───────────────────────────

test("A'5 malformed parentScope ceilings are denied before verification; no execute, nothing consumed", async () => {
  const bad: Record<string, unknown> = {
    "max_actions NaN": { ...PARENT_SCOPE, max_actions: Number.NaN },
    "max_actions Infinity": { ...PARENT_SCOPE, max_actions: Number.POSITIVE_INFINITY },
    "max_actions -Infinity": { ...PARENT_SCOPE, max_actions: Number.NEGATIVE_INFINITY },
    "max_actions -1": { ...PARENT_SCOPE, max_actions: -1 },
    "max_actions 1.5": { ...PARENT_SCOPE, max_actions: 1.5 },
    "max_actions string": { ...PARENT_SCOPE, max_actions: "10" },
    "max_actions bigint": { ...PARENT_SCOPE, max_actions: 10n },
    "max_depth NaN": { ...PARENT_SCOPE, max_depth: Number.NaN },
    "max_depth Infinity": { ...PARENT_SCOPE, max_depth: Number.POSITIVE_INFINITY },
    "max_depth -1": { ...PARENT_SCOPE, max_depth: -1 },
    "max_depth 0.5": { ...PARENT_SCOPE, max_depth: 0.5 },
    "max_amount -1n": { ...PARENT_SCOPE, max_amount: -1n },
    "max_amount number": { ...PARENT_SCOPE, max_amount: 1000 },
    "max_amount string": { ...PARENT_SCOPE, max_amount: "1000" },
    "max_amount null": { ...PARENT_SCOPE, max_amount: null },
    "tools string": { ...PARENT_SCOPE, tools: "provision_gpu" },
    "tools [1]": { ...PARENT_SCOPE, tools: [1] },
    "tools [null]": { ...PARENT_SCOPE, tools: [null] },
    "tools null": { ...PARENT_SCOPE, tools: null },
    "scope array": [],
    "scope null": null,
  };
  for (const [name, ps] of Object.entries(bad)) {
    const { store, calls } = spyStore();
    const events: GuardBoundaryAuditEvent[] = [];
    const guard = OxDeAIGuard(makeConfig(store, { onBoundaryEvent: (e) => { events.push(e); } }));
    const p = makeParent();
    const r = await present(guard, p, makeChild(p, { tools: ["provision_gpu"] }), ps);
    assert.equal(r.executed, 0, name);
    assert.ok(r.error instanceof OxDeAIAuthorizationError, `${name}: ${String(r.error)}`);
    assert.equal(events.at(-1)?.boundaryFailure, "DELEGATION_INPUT_INVALID", name);
    assert.deepEqual(calls, [], name);
  }
});

test("A'6 valid ceilings keep the existing contract: zero limits, finite limits, and omitted fields", async () => {
  const { store } = spyStore();
  const guard = OxDeAIGuard(makeConfig(store));
  const cases: Array<[string, DelegationScope, DelegationScope, number]> = [
    ["zero ceilings, zero child", { tools: ["provision_gpu"], max_amount: 0n, max_actions: 0, max_depth: 0 }, { tools: ["provision_gpu"], max_amount: 0n, max_actions: 0, max_depth: 0 }, 1],
    ["finite ceilings, narrower child", { ...PARENT_SCOPE, max_actions: 10, max_depth: 2 }, { tools: ["provision_gpu"], max_amount: 100n, max_actions: 1, max_depth: 0 }, 1],
    ["finite ceilings, wider child", { ...PARENT_SCOPE, max_actions: 10, max_depth: 2 }, { tools: ["provision_gpu"], max_actions: 11 }, 0],
    ["tools only", { tools: ["provision_gpu"] }, { tools: ["provision_gpu"] }, 1],
    ["empty parent scope", {}, { tools: ["provision_gpu"] }, 1],
  ];
  for (const [name, parentScope, childScope, expected] of cases) {
    const p = makeParent();
    const r = await present(guard, p, makeChild(p, childScope), parentScope);
    assert.equal(r.executed, expected, `${name}: ${String(r.error)}`);
  }
});

test("A'7 the amount check cannot be skipped or substituted by an opts.delegation accessor that answers differently per read", async () => {
  // Cap 100n, mapped amount 1e18. Whatever path each read selects, nothing may execute.
  for (let undefinedOnRead = 1; undefinedOnRead <= 6; undefinedOnRead++) {
    const { store } = spyStore();
    const guard = OxDeAIGuard(makeConfig(store, { mapActionToIntent: mapperWithAmount(10n ** 18n) }));
    const p = makeParent();
    const input = { delegation: makeChild(p, { tools: ["provision_gpu"], max_amount: 100n }), parentAuth: p, parentScope: PARENT_SCOPE };
    let reads = 0;
    const opts = Object.defineProperty({}, "delegation", { enumerable: true, get: () => (++reads === undefinedOnRead ? undefined : input) });
    let executed = 0;
    try { await guard(ACTION, async () => { executed++; return "ok"; }, opts as never); } catch { /* denied */ }
    assert.equal(executed, 0, `undefined on read ${undefinedOnRead}`);
  }
});
