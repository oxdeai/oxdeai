// SPDX-License-Identifier: Apache-2.0
/**
 * ACT-1 x main-only protections (reconciliation of the 2.0.x line with main).
 *
 * main adds await points on the delegation path that the 2.0.x line does not
 * have: the F4-C `delegationRevocationProvider.check()` and the SignedKRLV1
 * `revocation.provider()`. Each is a window in which caller code runs after the
 * delegation scope check and before `execute`. These tests prove that, with
 * every main-only protection enabled at once (SignedKRLV1, F4-C revocation,
 * delegation signer authority, explicit shared replay protection), the action
 * handed to the protected executor is the verified snapshot, and that every
 * denial still fails closed before any replay id is consumed.
 *
 * Synthetic keys and identities only. Mock executor, in-process, no network.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";

import {
  PolicyEngine,
  RECOMMENDED_TRUSTED_TIME_PROFILE,
  SIGNING_DOMAINS,
  createDelegation,
  signAuthorizationEd25519,
  signEd25519,
  signedKrlSigningPayload,
} from "@oxdeai/core";
import type { AuthorizationV1, DelegationScope, DelegationV1, KeySet, SignedKRLV1 } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { OxDeAIGuard } from "../guard.js";
import { createSecureGuard } from "../secureGuard.js";
import { createTrustedExecutionContext } from "../trustedContext.js";
import { createInMemoryReplayStore } from "../replayStore.js";
import type { ReplayStore } from "../replayStore.js";
import { createInMemoryKrlWatermarkStore } from "../revocation.js";
import type { GuardRevocationConfig } from "../revocation.js";
import { OxDeAINormalizationError } from "../errors.js";
import type { GuardBoundaryAuditEvent } from "../boundaryEvent.js";
import type { DelegationRevocationProvider, GuardCallOptions, OxDeAIGuardConfig, ProposedAction } from "../types.js";

const kp = () => generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
const KP_PDP = kp(), KP_AGENT = kp(), KP_KRL = kp(), KP_MALLORY = kp();
const PDP = "pdp-issuer", POLICY = "recon-policy";
const KS_PDP: KeySet = { issuer: PDP, version: "v1", keys: [{ kid: "k1", alg: "Ed25519", public_key: KP_PDP.publicKey.toString() }] };
const KS_AGENT: KeySet = { issuer: "agent-A", version: "v1", keys: [{ kid: "a1", alg: "Ed25519", public_key: KP_AGENT.publicKey.toString() }] };
const KS_MALLORY: KeySet = { issuer: "mallory", version: "v1", keys: [{ kid: "m1", alg: "Ed25519", public_key: KP_MALLORY.publicKey.toString() }] };
const KS_KRL: KeySet = { issuer: "krl-authority", version: "v1", keys: [{ kid: "r1", alg: "Ed25519", public_key: KP_KRL.publicKey.toString() }] };
const T_NOW = Math.floor(Date.now() / 1000);
const PARENT_SCOPE: DelegationScope = { tools: ["provision_gpu"], max_amount: 1_000_000_000n };
const uid = () => randomBytes(8).toString("hex");

function makeParent(): AuthorizationV1 {
  return signAuthorizationEd25519({
    auth_id: `recon-parent-${uid()}`, issuer: PDP, audience: "agent-A", intent_hash: "a".repeat(64), state_hash: "b".repeat(64),
    policy_id: POLICY, decision: "ALLOW", issued_at: T_NOW - 60, expiry: T_NOW + 900, kid: "k1",
  }, KP_PDP.privateKey.toString());
}
function makeChild(p: AuthorizationV1, signer: "agent-A" | "mallory" = "agent-A"): DelegationV1 {
  const s = signer === "agent-A" ? { issuer: "agent-A", kid: "a1", key: KP_AGENT } : { issuer: "mallory", kid: "m1", key: KP_MALLORY };
  return createDelegation(p, { delegatee: "agent-B", issuer: s.issuer, kid: s.kid, scope: { tools: ["provision_gpu"] }, expiry: T_NOW + 300, delegationId: `recon-deleg-${uid()}` }, s.key.privateKey.toString());
}
function krl(revoked: string[]): SignedKRLV1 {
  const env: SignedKRLV1 = {
    version: "SignedKRLV1", issuer: "krl-authority", krl_version: 1, issued_at: T_NOW - 10,
    not_after: T_NOW + 3600, revoked_kids: revoked, nonce: uid(), signature: { alg: "Ed25519", kid: "r1", sig: "x" },
  };
  return { ...env, signature: { ...env.signature, sig: signEd25519(SIGNING_DOMAINS.KRL_V1, signedKrlSigningPayload(env), KP_KRL.privateKey.toString()) } };
}

type Spy = { store: ReplayStore; calls: string[] };
function spyStore(onConsume?: () => void): Spy {
  const inner = createInMemoryReplayStore(); const calls: string[] = [];
  return { calls, store: {
    consumeAuthId: async (id, x) => { calls.push(`auth:${id}`); const r = await inner.consumeAuthId(id, x); onConsume?.(); return r; },
    consumeDelegationId: async (id, x) => { calls.push(`deleg:${id}`); const r = await inner.consumeDelegationId!(id, x); onConsume?.(); return r; },
  } };
}

const makeAction = (): ProposedAction => ({ name: "provision_gpu", args: { asset: "a100", count: 1 }, estimatedCost: 0, context: { agent_id: "agent-B", target: "gpu-pool" }, timestampSeconds: T_NOW });
/** Hostile in-process mutation of the caller-owned action. */
const hijack = (a: ProposedAction) => { a.name = "delete_cluster"; (a.args as Record<string, unknown>).asset = "prod-db"; (a.args as Record<string, unknown>).count = 64; };

type Windows = { krlProvider?: () => void; revocationCheck?: () => void; consume?: () => void };
type Rig = { config: OxDeAIGuardConfig; spy: Spy; events: GuardBoundaryAuditEvent[]; counters: { krl: number; check: number } };

/** Every main-only protection enabled at once. */
function rig(w: Windows = {}, over: { revokedKids?: string[]; revoked?: boolean; signer?: "agent-A" | "mallory" } & Partial<OxDeAIGuardConfig> = {}): Rig {
  const { revokedKids = [], revoked = false, ...cfgOver } = over;
  const spy = spyStore(w.consume);
  const events: GuardBoundaryAuditEvent[] = [];
  const counters = { krl: 0, check: 0 };
  // One KRL envelope per rig: re-serving the same krl_version with a fresh
  // nonce is (correctly) rejected by the watermark store as a rollback/fork.
  const list = krl(revokedKids);
  const revocation: GuardRevocationConfig = {
    trustedKrlKeySets: [KS_KRL],
    scopes: [{ krlIssuer: "krl-authority", keyIssuers: [PDP, "agent-A", "mallory"] }],
    provider: async () => { counters.krl++; await Promise.resolve(); w.krlProvider?.(); return [list]; },
    watermarkStore: createInMemoryKrlWatermarkStore(),
  };
  const delegationRevocationProvider: DelegationRevocationProvider = {
    async check() { counters.check++; await Promise.resolve(); w.revocationCheck?.(); return { status: revoked ? "REVOKED" : "ACTIVE" }; },
  };
  const state = buildState({ agent_id: "agent-B", allow_action_types: ["PROVISION"], budget_limit: 10n ** 15n, max_amount_per_action: 10n ** 15n, velocity_max_actions: 10_000, max_concurrent: 16 });
  let version = 0; let current = state;
  const config: OxDeAIGuardConfig = {
    engine: new PolicyEngine({ policy_version: "v1", engine_secret: "synthetic-secret-at-least-32-characters!!", authorization_signing_alg: "Ed25519",
      authorization_signing_kid: "k1", authorization_issuer: PDP, authorization_audience: "agent-A", authorization_ttl_seconds: 600,
      authorization_private_key_pem: KP_PDP.privateKey.toString(), ...RECOMMENDED_TRUSTED_TIME_PROFILE }),
    getState: () => ({ state: current, version }),
    setState: (s, v) => { if (v !== version) return false; current = s; version++; return true; },
    trustedKeySets: [KS_PDP, KS_AGENT, KS_MALLORY],
    expectedAudience: "agent-A",
    trustedDelegationAuthorities: [{ issuer: PDP, policyId: POLICY }],
    trustedDelegationSigners: [{ delegator: "agent-A", issuer: "agent-A" }],
    revocation,
    delegationRevocationProvider,
    requireDelegationRevocation: true,
    replayProtection: { mode: "shared", store: spy.store },
    onBoundaryEvent: (e) => { events.push(e); },
    ...cfgOver,
  };
  return { config, spy, events, counters };
}

type Entry = "guard" | "secure";
const TRUSTED = createTrustedExecutionContext({ principalId: "recon-principal", agentId: "agent-B", adapterId: "recon-adapter", depth: 0 });
function entryPoint(entry: Entry, config: OxDeAIGuardConfig) {
  if (entry === "guard") return OxDeAIGuard(config);
  const secure = createSecureGuard(config, { tenancy: "single-tenant" });
  return (a: ProposedAction, ex: (x: ProposedAction) => Promise<unknown>, o?: GuardCallOptions) => secure(TRUSTED, a, ex, o);
}
async function run(guard: ReturnType<typeof entryPoint>, action: ProposedAction, opts?: GuardCallOptions) {
  const received: Array<{ name: string; args: unknown; frozen: boolean }> = [];
  const closureSaw: string[] = [];
  let error: unknown;
  try {
    await guard(action, async (verified) => {
      received.push({ name: verified.name, args: structuredClone(verified.args), frozen: Object.isFrozen(verified) && Object.isFrozen(verified.args) });
      closureSaw.push(action.name);
      return "ok";
    }, opts);
  } catch (e) { error = e; }
  return { received, closureSaw, error };
}
const delegOpts = (signer: "agent-A" | "mallory" = "agent-A"): GuardCallOptions => {
  const p = makeParent();
  return { delegation: { delegation: makeChild(p, signer), parentAuth: p, parentScope: PARENT_SCOPE } };
};
const VERIFIED = { name: "provision_gpu", args: { asset: "a100", count: 1 } };

for (const entry of ["guard", "secure"] as const) {
  const label = entry === "guard" ? "OxDeAIGuard" : "createSecureGuard";

  test(`RECON [${label}] X0: all main-only protections on, untouched action executes once`, async () => {
    const r = rig();
    const out = await run(entryPoint(entry, r.config), makeAction(), delegOpts());
    assert.equal(out.error, undefined, String(out.error));
    assert.deepEqual(out.received, [{ ...VERIFIED, frozen: true }]);
    assert.equal(r.counters.krl, 1); assert.equal(r.counters.check, 1);
    assert.equal(r.spy.calls.filter((c) => c.startsWith("deleg:")).length, 1);
  });

  for (const [win, key] of [["SignedKRLV1 provider", "krlProvider"], ["F4-C revocation check", "revocationCheck"], ["replay consume", "consume"]] as const) {
    test(`RECON [${label}] X1: action mutated inside the ${win} await does not reach the executor`, async () => {
      const action = makeAction();
      const r = rig({ [key]: () => hijack(action) });
      const out = await run(entryPoint(entry, r.config), action, delegOpts());
      assert.equal(out.error, undefined, String(out.error));
      assert.deepEqual(out.received, [{ ...VERIFIED, frozen: true }], "executor must receive the verified snapshot");
      assert.deepEqual(out.closureSaw, ["delete_cluster"], "control: the caller's own object WAS mutated (closure residual)");
    });
  }

  test(`RECON [${label}] X2: SignedKRLV1 revoking the delegation signer key still denies, no replay id consumed`, async () => {
    const action = makeAction();
    const r = rig({ krlProvider: () => hijack(action) }, { revokedKids: ["a1"] });
    const out = await run(entryPoint(entry, r.config), action, delegOpts());
    assert.deepEqual(out.received, []);
    assert.deepEqual(r.spy.calls, []);
    assert.equal(r.events.at(-1)?.boundaryFailure, "DELEGATION_VERIFICATION_FAILED", String(out.error));
  });

  test(`RECON [${label}] X3: F4-C REVOKED still denies, no replay id consumed`, async () => {
    const action = makeAction();
    const r = rig({ revocationCheck: () => hijack(action) }, { revoked: true });
    const out = await run(entryPoint(entry, r.config), action, delegOpts());
    assert.deepEqual(out.received, []);
    assert.deepEqual(r.spy.calls, []);
    assert.equal(r.events.at(-1)?.boundaryFailure, "DELEGATION_REVOKED", String(out.error));
  });

  test(`RECON [${label}] X4: unauthorized delegation signer still denies before revocation lookups and replay`, async () => {
    const r = rig();
    const out = await run(entryPoint(entry, r.config), makeAction(), delegOpts("mallory"));
    assert.deepEqual(out.received, []);
    assert.deepEqual(r.spy.calls, []);
    assert.equal(r.counters.check, 0);
    assert.match(String(out.error), /SIGNER|signer/);
  });

  test(`RECON [${label}] X5: accessor action fails closed at NORMALIZATION before any signer, KRL, F4-C or replay step`, async () => {
    let reads = 0;
    const base = makeAction();
    const action = { args: base.args, context: base.context, estimatedCost: 0, timestampSeconds: base.timestampSeconds } as ProposedAction;
    Object.defineProperty(action, "name", { enumerable: true, configurable: true, get() { reads++; return "provision_gpu"; } });
    const r = rig();
    const out = await run(entryPoint(entry, r.config), action, delegOpts());
    assert.deepEqual(out.received, []);
    assert.ok(out.error instanceof OxDeAINormalizationError, String(out.error));
    assert.equal(reads, 0, "the accessor must never be invoked");
    assert.deepEqual(r.spy.calls, []);
    assert.equal(r.counters.krl, 0); assert.equal(r.counters.check, 0);
    assert.equal(r.events.at(-1)?.stage, "NORMALIZATION");
    assert.equal(r.events.at(-1)?.boundaryFailure, "NORMALIZATION_FAILURE");
  });

  test(`RECON [${label}] X6: replay protection unchanged: the same delegation executes once, then DELEGATION_REPLAY`, async () => {
    const r = rig();
    const guard = entryPoint(entry, r.config);
    const opts = delegOpts();
    const first = await run(guard, makeAction(), opts);
    const second = await run(guard, makeAction(), opts);
    assert.equal(first.received.length, 1, String(first.error));
    assert.deepEqual(second.received, []);
    assert.equal(r.events.at(-1)?.boundaryFailure, "DELEGATION_REPLAY", String(second.error));
  });

  test(`RECON [${label}] X7: standard path with shared replay: mutation inside consumeAuthId does not reach the executor`, async () => {
    const action = makeAction();
    const r = rig({ consume: () => hijack(action) });
    const out = await run(entryPoint(entry, r.config), action);
    assert.equal(out.error, undefined, String(out.error));
    assert.deepEqual(out.received, [{ ...VERIFIED, frozen: true }]);
    assert.equal(r.spy.calls.filter((c) => c.startsWith("auth:")).length, 1);
  });
}
