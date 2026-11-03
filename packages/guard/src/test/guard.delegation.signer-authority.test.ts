// SPDX-License-Identifier: Apache-2.0
/**
 * F4-1/F4-2 (Lot H) — delegation SIGNER authority on the guard delegation path.
 *
 * A valid delegation signature proves only that a trusted key for the claimed
 * `issuer` signed it. It does not prove that issuer may delegate for the
 * `delegator` (the parent's audience). Core enforces this via
 * `VerifyDelegationOptions.trustedDelegationAuthorities`; the guard exposes it
 * as the distinct, opt-in `trustedDelegationSigners` option. The guard's own
 * `trustedDelegationAuthorities` keeps its separate meaning: parent
 * `(issuer, policyId)` authority.
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
import type { AuthorizationAuthority, AuthorizationV1, DelegationAuthority, DelegationV1, KeySet } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { OxDeAIGuard } from "../guard.js";
import { createInMemoryReplayStore } from "../replayStore.js";
import type { ReplayStore } from "../replayStore.js";
import {
  OxDeAIAuthorityError,
  OxDeAIDelegationError,
  OxDeAIGuardConfigurationError,
} from "../errors.js";
import type { OxDeAIGuardConfig, ProposedAction } from "../types.js";

const kp = () => generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const KP_CENTRAL = kp();
const KP_AGENT_A = kp();
const KP_MALLORY = kp();

const CENTRAL = "central-pdp";
const MALLORY = "mallory";
const POLICY = "signer-policy-1";

const KS_CENTRAL: KeySet = { issuer: CENTRAL, version: "v1", keys: [{ kid: "c1", alg: "Ed25519", public_key: KP_CENTRAL.publicKey.toString() }] };
const KS_AGENT_A: KeySet = { issuer: "agent-A", version: "v1", keys: [{ kid: "a1", alg: "Ed25519", public_key: KP_AGENT_A.publicKey.toString() }] };
const KS_MALLORY: KeySet = { issuer: MALLORY, version: "v1", keys: [{ kid: "m1", alg: "Ed25519", public_key: KP_MALLORY.publicKey.toString() }] };

const PARENT_AUTHORITIES: readonly AuthorizationAuthority[] = [{ issuer: CENTRAL, policyId: POLICY }];
const CENTRAL_SIGNS_FOR_A: readonly DelegationAuthority[] = [{ delegator: "agent-A", issuer: CENTRAL }];

const T_NOW = Math.floor(Date.now() / 1000);
const PARENT_SCOPE = { tools: ["provision_gpu"], max_amount: 1_000_000n };

let seq = 0;
function makeParent(): AuthorizationV1 {
  return signAuthorizationEd25519({
    auth_id: `signer-parent-${seq++}-${Math.random().toString(16).slice(2)}`,
    issuer: CENTRAL, audience: "agent-A",
    intent_hash: "a".repeat(64), state_hash: "b".repeat(64),
    policy_id: POLICY, decision: "ALLOW",
    issued_at: T_NOW - 60, expiry: T_NOW + 900, kid: "c1",
  }, KP_CENTRAL.privateKey.toString());
}

type Signer = "central" | "agent-A" | "mallory";
function makeChild(parent: AuthorizationV1, signer: Signer): DelegationV1 {
  const m = {
    central: { issuer: CENTRAL, kid: "c1", key: KP_CENTRAL },
    "agent-A": { issuer: "agent-A", kid: "a1", key: KP_AGENT_A },
    mallory: { issuer: MALLORY, kid: "m1", key: KP_MALLORY },
  }[signer];
  return createDelegation(parent, {
    delegatee: "agent-B", issuer: m.issuer, kid: m.kid,
    scope: { tools: ["provision_gpu"], max_amount: 500_000n },
    expiry: T_NOW + 300,
    delegationId: `signer-deleg-${seq++}-${Math.random().toString(16).slice(2)}`,
  }, m.key.privateKey.toString());
}

/** Replay store that records every consume so tests can assert none happened. */
function spyStore(): { store: ReplayStore; calls: string[] } {
  const inner = createInMemoryReplayStore();
  const calls: string[] = [];
  const store: ReplayStore = {
    consumeAuthId: async (id, o) => { calls.push(`auth:${id}`); return inner.consumeAuthId(id, o); },
    consumeDelegationId: async (id, o) => { calls.push(`deleg:${id}`); return inner.consumeDelegationId!(id, o); },
  };
  return { store, calls };
}

function makeConfig(overrides: Partial<OxDeAIGuardConfig> = {}, store?: ReplayStore): OxDeAIGuardConfig {
  const state = buildState({
    agent_id: "agent-B", allow_action_types: ["PROVISION"],
    budget_limit: 1_000_000_000n, max_amount_per_action: 1_000_000_000n,
    velocity_max_actions: 1000, max_concurrent: 16,
  });
  return {
    engine: new PolicyEngine({
      policy_version: "v1", engine_secret: "synthetic-secret-at-least-32-characters!!",
      authorization_signing_alg: "Ed25519", authorization_signing_kid: "c1",
      authorization_issuer: CENTRAL, authorization_audience: "agent-A",
      authorization_ttl_seconds: 600, authorization_private_key_pem: KP_CENTRAL.privateKey.toString(),
      ...RECOMMENDED_TRUSTED_TIME_PROFILE,
    }),
    getState: () => ({ state, version: 0 }),
    setState: () => true,
    trustedKeySets: [KS_CENTRAL, KS_AGENT_A, KS_MALLORY],
    expectedAudience: "agent-A",
    trustedDelegationAuthorities: PARENT_AUTHORITIES,
    ...(store ? { replayStore: store } : {}),
    ...overrides,
  };
}

const ACTION: ProposedAction = {
  name: "provision_gpu", args: { asset: "a100" }, estimatedCost: 0,
  context: { agent_id: "agent-B", target: "gpu-pool" }, timestampSeconds: T_NOW,
};

async function run(guard: ReturnType<typeof OxDeAIGuard>, parentAuth: AuthorizationV1, delegation: DelegationV1) {
  let executed = 0;
  let error: unknown;
  try {
    await guard(ACTION, async () => { executed++; return "ok"; },
      { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } });
  } catch (err) { error = err; }
  return { executed, error };
}

const isSignerDenial = (e: unknown) =>
  e instanceof OxDeAIDelegationError &&
  e.violations.some((v) => /not authorized to delegate for this delegator/.test(v));

// ── Pre-existing behavior, made explicit ─────────────────────────────────────

test("H0 default (option absent): signer authority is NOT enforced — unrelated trusted signer executes (documented existing behavior)", async () => {
  const p = makeParent();
  const r = await run(OxDeAIGuard(makeConfig()), p, makeChild(p, "mallory"));
  assert.equal(r.error, undefined, String(r.error));
  assert.equal(r.executed, 1);
});

// ── Enforcement ──────────────────────────────────────────────────────────────

test("H1 configured: unrelated trusted signer (mallory) is rejected before replay consumption and execute()", async () => {
  const { store, calls } = spyStore();
  const guard = OxDeAIGuard(makeConfig({ trustedDelegationSigners: CENTRAL_SIGNS_FOR_A }, store));
  const p = makeParent();
  const r = await run(guard, p, makeChild(p, "mallory"));
  assert.equal(r.executed, 0, "execute must not run");
  assert.ok(isSignerDenial(r.error), `expected signer denial, got ${String(r.error)}`);
  assert.deepEqual(calls, [], "no replay state consumed on denial");
  // The same (unconsumed) parent then still backs a legitimately signed delegation.
  const ok = await run(guard, p, makeChild(p, "central"));
  assert.equal(ok.error, undefined, String(ok.error));
  assert.equal(ok.executed, 1);
});

test("H2 configured []: fails closed — even the central issuer is denied, nothing consumed", async () => {
  const { store, calls } = spyStore();
  const guard = OxDeAIGuard(makeConfig({ trustedDelegationSigners: [] }, store));
  const p = makeParent();
  const r = await run(guard, p, makeChild(p, "central"));
  assert.equal(r.executed, 0);
  assert.ok(isSignerDenial(r.error), String(r.error));
  assert.deepEqual(calls, []);
});

test("H3 configured: authorized centralized issuer succeeds and consumes once", async () => {
  const { store, calls } = spyStore();
  const guard = OxDeAIGuard(makeConfig({ trustedDelegationSigners: CENTRAL_SIGNS_FOR_A }, store));
  const p = makeParent();
  const d = makeChild(p, "central");
  const r = await run(guard, p, d);
  assert.equal(r.error, undefined, String(r.error));
  assert.equal(r.executed, 1);
  assert.deepEqual(calls, [`deleg:${d.delegation_id}`, `auth:${p.auth_id}`]);
  const replay = await run(guard, p, d);
  assert.equal(replay.executed, 0, "replay still blocked");
});

test("H4 configured: self-delegating signer succeeds only when its own pair is listed", async () => {
  const p1 = makeParent();
  const notListed = await run(OxDeAIGuard(makeConfig({ trustedDelegationSigners: CENTRAL_SIGNS_FOR_A })), p1, makeChild(p1, "agent-A"));
  assert.equal(notListed.executed, 0);
  assert.ok(isSignerDenial(notListed.error), String(notListed.error));
  const p2 = makeParent();
  const listed = await run(OxDeAIGuard(makeConfig({ trustedDelegationSigners: [{ delegator: "agent-A", issuer: "agent-A" }] })), p2, makeChild(p2, "agent-A"));
  assert.equal(listed.error, undefined, String(listed.error));
  assert.equal(listed.executed, 1);
});

test("H5 configured: pair is exact — the right issuer for a different delegator does not authorize", async () => {
  const p = makeParent();
  const r = await run(OxDeAIGuard(makeConfig({ trustedDelegationSigners: [{ delegator: "agent-X", issuer: CENTRAL }] })), p, makeChild(p, "central"));
  assert.equal(r.executed, 0);
  assert.ok(isSignerDenial(r.error), String(r.error));
});

// ── Independence of the two authority options ────────────────────────────────

test("H6 independence: signer authority does not authorize the parent — parent authority still required", async () => {
  const p = makeParent();
  const r = await run(OxDeAIGuard(makeConfig({ trustedDelegationAuthorities: [], trustedDelegationSigners: CENTRAL_SIGNS_FOR_A })), p, makeChild(p, "central"));
  assert.equal(r.executed, 0);
  assert.ok(r.error instanceof OxDeAIAuthorityError, `parent authority denial expected, got ${String(r.error)}`);
});

test("H7 independence: parent authority does not authorize the signer", async () => {
  const p = makeParent();
  // Parent authority lists the mallory issuer for the policy; it must not
  // become delegation-signer authority.
  const r = await run(OxDeAIGuard(makeConfig({
    trustedDelegationAuthorities: [...PARENT_AUTHORITIES, { issuer: MALLORY, policyId: POLICY }],
    trustedDelegationSigners: CENTRAL_SIGNS_FOR_A,
  })), p, makeChild(p, "mallory"));
  assert.equal(r.executed, 0);
  assert.ok(isSignerDenial(r.error), String(r.error));
});

test("H8 independence: trustedDelegationAuthorities is still required on delegation calls when only signers are configured", async () => {
  const cfg = makeConfig({ trustedDelegationSigners: CENTRAL_SIGNS_FOR_A });
  delete (cfg as { trustedDelegationAuthorities?: unknown }).trustedDelegationAuthorities;
  const p = makeParent();
  const r = await run(OxDeAIGuard(cfg), p, makeChild(p, "central"));
  assert.equal(r.executed, 0);
  assert.ok(r.error instanceof OxDeAIGuardConfigurationError, String(r.error));
});

// ── Invalid configuration cannot silently disable the check ─────────────────

test("H9 invalid trustedDelegationSigners values fail at construction (never read as 'not configured')", () => {
  const bad: unknown[] = [
    null, {}, "agent-A", 1, true,
    [null], [1], ["agent-A"], [[]],
    [{ delegator: "agent-A" }], [{ issuer: CENTRAL }],
    [{ delegator: "", issuer: CENTRAL }], [{ delegator: "agent-A", issuer: "" }],
    [{ delegator: "agent-A", issuer: 1 }],
    // AuthorizationAuthority-shaped entry: a likely cross-option mistake.
    [{ issuer: CENTRAL, policyId: POLICY }],
    [...CENTRAL_SIGNS_FOR_A, { delegator: "agent-A" }],
  ];
  for (const value of bad) {
    assert.throws(
      () => OxDeAIGuard(makeConfig({ trustedDelegationSigners: value as readonly DelegationAuthority[] })),
      OxDeAIGuardConfigurationError,
      `must reject ${JSON.stringify(value)}`
    );
  }
});

test("H10 configuration is copied at construction: later mutation of the caller's array cannot widen enforcement", async () => {
  const signers: DelegationAuthority[] = [...CENTRAL_SIGNS_FOR_A];
  const guard = OxDeAIGuard(makeConfig({ trustedDelegationSigners: signers }));
  signers.push({ delegator: "agent-A", issuer: MALLORY });
  const p = makeParent();
  const r = await run(guard, p, makeChild(p, "mallory"));
  assert.equal(r.executed, 0);
  assert.ok(isSignerDenial(r.error), String(r.error));
});

test("H11 signer denial reports the core violation without masking other chain defects", async () => {
  const p = makeParent();
  const other = makeParent();
  // Mallory-signed delegation bound to a DIFFERENT parent: parent-hash defect.
  // Chain-level checks run first in core and return early, so the parent-hash
  // mismatch is reported and execution is still blocked.
  const r = await run(OxDeAIGuard(makeConfig({ trustedDelegationSigners: CENTRAL_SIGNS_FOR_A })), p, makeChild(other, "mallory"));
  assert.equal(r.executed, 0);
  assert.ok(r.error instanceof OxDeAIDelegationError, String(r.error));
});
