// SPDX-License-Identifier: Apache-2.0
/**
 * #320 — replay consumption must follow authentication.
 *
 * Normative rule: `verification-v1.md` §4.2 — input that has not been
 * authenticated MUST NOT cause durable mutation of trusted security state.
 *
 * Before #320 the delegation path consumed `delegation.delegation_id` and
 * `parentAuth.auth_id` before any signature was checked. A forged parent was
 * still rejected — decision correctness was never in question — but the
 * rejected request left a durable replay entry that pre-emptively denied a
 * later legitimate authorization carrying the same id.
 *
 * These tests pin two properties that must hold together:
 *   1. the tested pre-consumption verification denials leave no replay write; and
 *   2. replay protection still works for requests that do execute.
 * Later store/CAS/hook failures may follow a successful consume. These tests
 * do not prove rollback, completed execution, crash recovery or restart durability.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import {
  PolicyEngine,
  RECOMMENDED_TRUSTED_TIME_PROFILE,
  signAuthorizationEd25519,
  createDelegation,
  stateSnapshotHash,
  intentHash,
} from "@oxdeai/core";
import type { AuthorizationAuthority, AuthorizationV1, DelegationV1, KeySet, State } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { OxDeAIGuard } from "../guard.js";
import type { OxDeAIGuardConfig, ProposedAction } from "../types.js";
import type { ReplayStore } from "../replayStore.js";
import { defaultNormalizeAction } from "../normalizeAction.js";

const TRUSTED = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const ROGUE = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const ISSUER = "replay-order-issuer";
const POLICY = "replay-order-policy";
const AUDIENCE = "agent-A";
const T_NOW = Math.floor(Date.now() / 1000);

const KEYSET: KeySet = {
  issuer: ISSUER, version: "v1",
  keys: [{ kid: "ka", alg: "Ed25519", public_key: TRUSTED.publicKey.toString() }],
};
const AUTHORITIES: readonly AuthorizationAuthority[] = [{ issuer: ISSUER, policyId: POLICY }];
const PARENT_SCOPE = { tools: ["provision_gpu"], max_amount: 1_000_000n };

/** A replay store that records every write so a test can assert its ABSENCE. */
function observableStore() {
  const auth = new Set<string>();
  const deleg = new Set<string>();
  const store: ReplayStore = {
    async consumeAuthId(id) { if (auth.has(id)) return false; auth.add(id); return true; },
    async consumeDelegationId(id) { if (deleg.has(id)) return false; deleg.add(id); return true; },
  };
  return { store, auth, deleg };
}

function parentAuth(authId: string, key = TRUSTED, over: Partial<AuthorizationV1> = {}): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      auth_id: authId, issuer: ISSUER, audience: AUDIENCE,
      intent_hash: "a".repeat(64), state_hash: "b".repeat(64),
      policy_id: POLICY, decision: "ALLOW",
      issued_at: T_NOW - 60, expiry: T_NOW + 900, kid: "ka", ...over,
    } as never,
    key.privateKey.toString()
  );
}

function child(parent: AuthorizationV1, over: Partial<{ expiry: number; tools: string[] }> = {}): DelegationV1 {
  return createDelegation(
    parent,
    {
      delegatee: "agent-B", issuer: ISSUER,
      scope: { tools: over.tools ?? ["provision_gpu"], max_amount: 500_000n },
      expiry: over.expiry ?? T_NOW + 300, kid: "ka",
    },
    TRUSTED.privateKey.toString()
  );
}

function makeState(): State {
  return buildState({
    agent_id: "agent-B", allow_action_types: ["PROVISION"],
    budget_limit: 1_000_000_000n, max_amount_per_action: 1_000_000_000n,
    velocity_max_actions: 1000, max_concurrent: 16,
  });
}

function config(store: ReplayStore, over?: Partial<OxDeAIGuardConfig>): OxDeAIGuardConfig {
  const state = makeState();
  return {
    engine: new PolicyEngine({
      policy_version: "v1", engine_secret: "test-secret-must-be-at-least-32-chars!!",
      authorization_signing_alg: "Ed25519", authorization_signing_kid: "ka",
      authorization_issuer: ISSUER, authorization_audience: AUDIENCE,
      authorization_ttl_seconds: 600, authorization_private_key_pem: TRUSTED.privateKey.toString(),
      ...RECOMMENDED_TRUSTED_TIME_PROFILE,
    }),
    getState: () => ({ state, version: 0 }),
    setState: () => true,
    trustedKeySets: [KEYSET],
    expectedAudience: AUDIENCE,
    trustedDelegationAuthorities: AUTHORITIES,
    replayStore: store,
    ...over,
  };
}

const ACTION: ProposedAction = {
  name: "provision_gpu", args: { asset: "a100" }, estimatedCost: 0,
  context: { agent_id: "agent-B", target: "gpu-pool" }, timestampSeconds: T_NOW,
};

/**
 * The direct path binds `intent_hash`, so its action must normalize
 * deterministically — `defaultNormalizeAction` otherwise mints a fresh
 * `intent_id` and `nonce` per call and the precomputed hash would never match.
 */
const DIRECT_ACTION: ProposedAction = {
  ...ACTION,
  context: { ...ACTION.context, intent_id: "replay-order-fixed-intent", nonce: 1n },
};
const DIRECT_INTENT_HASH = intentHash(defaultNormalizeAction(DIRECT_ACTION));

async function callDelegation(cfg: OxDeAIGuardConfig, parent: AuthorizationV1, deleg: DelegationV1) {
  const guard = OxDeAIGuard(cfg);
  let executed = false;
  let error: unknown;
  try {
    await guard(ACTION, async () => { executed = true; return "ok"; },
      { delegation: { delegation: deleg, parentAuth: parent, parentScope: PARENT_SCOPE } });
  } catch (err) { error = err; }
  return { executed, error };
}

// ── the reproduced defect ───────────────────────────────────────────────────

test("#320 forged parent under a rogue key is rejected AND leaves no replay write", async () => {
  const { store, auth, deleg } = observableStore();
  const forged = parentAuth("AID-VICTIM", ROGUE);

  const r = await callDelegation(config(store), forged, child(forged));

  assert.equal(r.executed, false);
  assert.match(String((r.error as Error).message), /AUTH_SIGNATURE_INVALID/);
  assert.equal(auth.has("AID-VICTIM"), false, "an unauthenticated parent must not consume its auth_id");
  assert.equal(deleg.size, 0, "an unauthenticated delegation must not consume its delegation_id");
});

test("#320 the same auth_id, correctly signed, is accepted after the forgery was rejected", async () => {
  const { store, auth } = observableStore();
  const cfg = config(store);

  const forged = parentAuth("AID-VICTIM", ROGUE);
  await callDelegation(cfg, forged, child(forged));

  const legit = parentAuth("AID-VICTIM", TRUSTED);
  const r = await callDelegation(cfg, legit, child(legit));

  assert.equal(r.error, undefined, `expected acceptance, got ${String(r.error)}`);
  assert.equal(r.executed, true, "a forged submission must not pre-emptively deny the legitimate one");
  assert.equal(auth.has("AID-VICTIM"), true, "the legitimate request does consume the id");
});

// ── replay protection still works ───────────────────────────────────────────

test("#320 a valid delegation consumed once: the same auth_id is rejected as replay on resubmission", async () => {
  const { store } = observableStore();
  const cfg = config(store);
  const parent = parentAuth("AID-ONCE", TRUSTED);

  const first = await callDelegation(cfg, parent, child(parent));
  assert.equal(first.executed, true);

  const second = await callDelegation(cfg, parent, child(parent));
  assert.equal(second.executed, false, "replay protection must still block the second use");
  assert.match(String((second.error as Error).message), /replay/i);
});

test("#320 delegation_id replay is still blocked on resubmission of the same delegation", async () => {
  const { store, deleg } = observableStore();
  const cfg = config(store);
  const parent = parentAuth("AID-D1", TRUSTED);
  const d = child(parent);

  assert.equal((await callDelegation(cfg, parent, d)).executed, true);
  assert.equal(deleg.size, 1, "one delegation_id consumed by the accepted call");

  // Fresh parent id so the auth_id replay check cannot be what blocks it.
  const parent2 = parentAuth("AID-D2", TRUSTED);
  const reused = { ...d, parent_auth_hash: (d as { parent_auth_hash?: string }).parent_auth_hash } as DelegationV1;
  const r = await callDelegation(cfg, parent2, reused);
  assert.equal(r.executed, false);
});

// ── no write after ANY denial reason, not only signature failure ────────────

test("#320 no replay write survives any delegation denial reason", async () => {
  const parent = parentAuth("AID-R", TRUSTED);

  const cases: { name: string; run: () => Promise<{ executed: boolean; error: unknown }>; }[] = [
    {
      name: "AUTH_SIGNATURE_INVALID (forged parent)",
      run: () => { const p = parentAuth("AID-R", ROGUE); return callDelegation(config(observableStoreFor("sig")), p, child(p)); },
    },
  ];
  // The stores must be inspectable per case, so build them inline instead.
  const stores: Record<string, ReturnType<typeof observableStore>> = {};
  function observableStoreFor(key: string): ReplayStore {
    stores[key] = observableStore();
    return stores[key].store;
  }
  for (const c of cases) {
    const r = await c.run();
    assert.equal(r.executed, false, c.name);
  }

  // authority rejection: issuer holds a trusted key but is not authorized here
  const sAuthority = observableStore();
  const rAuthority = await callDelegation(
    config(sAuthority.store, { trustedDelegationAuthorities: [] }), parent, child(parent));
  assert.equal(rAuthority.executed, false);
  assert.equal(sAuthority.auth.size, 0, "authority rejection must leave no auth_id write");
  assert.equal(sAuthority.deleg.size, 0, "authority rejection must leave no delegation_id write");

  // audience mismatch: parent authenticates but fails an independent expectation
  const sAudience = observableStore();
  const wrongAud = parentAuth("AID-AUD", TRUSTED, { audience: "someone-else" });
  const rAudience = await callDelegation(config(sAudience.store), wrongAud, child(wrongAud));
  assert.equal(rAudience.executed, false);
  assert.equal(sAudience.auth.size, 0, "audience mismatch must leave no auth_id write");
  assert.equal(sAudience.deleg.size, 0, "audience mismatch must leave no delegation_id write");

  // chain/scope violation: parent is fully valid, the child is out of scope
  const sScope = observableStore();
  const outOfScope = child(parent, { tools: ["something_else"] });
  const rScope = await callDelegation(config(sScope.store), parent, outOfScope);
  assert.equal(rScope.executed, false);
  assert.equal(sScope.auth.size, 0, "a chain/scope denial must leave no auth_id write");
  assert.equal(sScope.deleg.size, 0, "a chain/scope denial must leave no delegation_id write");
});

test("#320 execute() is never reached before the consume on the delegation path", async () => {
  const order: string[] = [];
  const parent = parentAuth("AID-ORDER", TRUSTED);
  const store: ReplayStore = {
    async consumeAuthId() { order.push("consumeAuthId"); return true; },
    async consumeDelegationId() { order.push("consumeDelegationId"); return true; },
  };
  const guard = OxDeAIGuard(config(store));
  await guard(ACTION, async () => { order.push("execute"); return "ok"; },
    { delegation: { delegation: child(parent), parentAuth: parent, parentScope: PARENT_SCOPE } });

  assert.deepEqual(order, ["consumeDelegationId", "consumeAuthId", "execute"]);
  assert.ok(order.indexOf("execute") > order.indexOf("consumeAuthId"), "consume must precede execute");
});

// ── direct path: consistency + self-denial closure (not the reproduced defect) ──

test("#320 direct path: a failed verification does not consume the auth_id", async () => {
  const { store, auth } = observableStore();
  const state = makeState();
  const bad = parentAuth("AID-DIRECT", ROGUE, {
    state_hash: stateSnapshotHash(state),
    intent_hash: DIRECT_INTENT_HASH,
  });
  const guard = OxDeAIGuard(config(store, {
    engine: {
      evaluatePure: () => ({ decision: "ALLOW" as const, reasons: [], authorization: bad as never, nextState: state }),
      computeStateHash: (s: State) => stateSnapshotHash(s),
    } as never,
    getState: () => ({ state, version: 0 }),
  }));

  let executed = false;
  await assert.rejects(() => guard(DIRECT_ACTION, async () => { executed = true; return "ok"; }));
  assert.equal(executed, false);
  assert.equal(auth.has("AID-DIRECT"), false, "a rejected direct authorization must not burn its auth_id");
});

test("#320 direct path: a valid authorization with the same id is accepted afterwards", async () => {
  const { store, auth } = observableStore();
  const state = makeState();
  const good = parentAuth("AID-DIRECT2", TRUSTED, {
    state_hash: stateSnapshotHash(state),
    intent_hash: DIRECT_INTENT_HASH,
  });
  const bad = parentAuth("AID-DIRECT2", ROGUE, {
    state_hash: stateSnapshotHash(state),
    intent_hash: DIRECT_INTENT_HASH,
  });
  const mk = (a: AuthorizationV1) => OxDeAIGuard(config(store, {
    engine: {
      evaluatePure: () => ({ decision: "ALLOW" as const, reasons: [], authorization: a as never, nextState: state }),
      computeStateHash: (s: State) => stateSnapshotHash(s),
    } as never,
    getState: () => ({ state, version: 0 }),
  }));

  await assert.rejects(() => mk(bad)(DIRECT_ACTION, async () => "no"));
  assert.equal(auth.has("AID-DIRECT2"), false);

  let executed = false;
  await mk(good)(DIRECT_ACTION, async () => { executed = true; return "ok"; });
  assert.equal(executed, true, "the corrected resubmission must not be denied as a replay");
});
