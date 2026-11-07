// SPDX-License-Identifier: Apache-2.0
/**
 * Targeted F4 remediation regression tests for `createSecureGuard`.
 *
 *  - F4-AUD-01  security configuration is captured at construction; later
 *               mutation of the deployer's config object cannot widen authority
 *               or disable enforcement, while legitimate dynamic state (provider
 *               and store state, in-place key rotation) is still observed.
 *  - AUD-OBS-02 `replayProtection` works on the secure path (it used to make
 *               every call fail with "Ambiguous replay configuration"), without
 *               any replay downgrade.
 *  - F4-AUD-03  the former quadratic pre-signature scope narrowing still fails
 *               closed at the guard boundary.
 *
 * Synthetic keys, mock executors and spy replay stores only. Every denial
 * asserts: no execute, no beforeExecute, no replay consumption.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";

import {
  PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE, SIGNING_DOMAINS, createDelegation,
  signAuthorizationEd25519, signEd25519, signedKrlSigningPayload,
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
import { OxDeAIDelegationError, OxDeAIGuardConfigurationError, OxDeAIAuthorizationError, OxDeAIDenyError } from "../errors.js";
import { defaultNormalizeAction } from "../normalizeAction.js";
import type { GuardBoundaryAuditEvent } from "../boundaryEvent.js";
import type { DelegationRevocationProvider, OxDeAIGuardConfig, ProposedAction } from "../types.js";

const kp = () => generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
const KP_PDP = kp(), KP_PDP2 = kp(), KP_AGENT = kp(), KP_MAL = kp(), KP_KRL = kp();
const PDP = "pdp-issuer", POLICY = "sg-policy";
const pem = (k: { publicKey: string | Buffer }) => k.publicKey.toString();
const ksPdp = (): KeySet => ({ issuer: PDP, version: "v1", keys: [{ kid: "k1", alg: "Ed25519", public_key: pem(KP_PDP) }] });
const ksAgent = (): KeySet => ({ issuer: "agent-A", version: "v1", keys: [{ kid: "a1", alg: "Ed25519", public_key: pem(KP_AGENT) }] });
const ksMal = (): KeySet => ({ issuer: "mallory", version: "v1", keys: [{ kid: "m1", alg: "Ed25519", public_key: pem(KP_MAL) }] });
const KS_KRL: KeySet = { issuer: "krl-authority", version: "v1", keys: [{ kid: "r1", alg: "Ed25519", public_key: pem(KP_KRL) }] };
const T = Math.floor(Date.now() / 1000);
const PARENT_SCOPE: DelegationScope = { tools: ["provision_gpu"], max_amount: 1_000_000_000n };
const uid = () => randomBytes(8).toString("hex");

function parentAuth(o: { kid?: string; key?: typeof KP_PDP; audience?: string } = {}): AuthorizationV1 {
  return signAuthorizationEd25519({
    auth_id: `sg-parent-${uid()}`, issuer: PDP, audience: o.audience ?? "agent-A", intent_hash: "a".repeat(64), state_hash: "b".repeat(64),
    policy_id: POLICY, decision: "ALLOW", issued_at: T - 60, expiry: T + 900, kid: o.kid ?? "k1",
  }, (o.key ?? KP_PDP).privateKey.toString());
}
function delegation(p: AuthorizationV1, o: { issuer?: string; kid?: string; key?: typeof KP_AGENT; scope?: DelegationScope } = {}): DelegationV1 {
  return createDelegation(p, {
    delegatee: "agent-B", issuer: o.issuer ?? "agent-A", kid: o.kid ?? "a1", scope: o.scope ?? { tools: ["provision_gpu"] },
    expiry: T + 300, delegationId: `sg-deleg-${uid()}`,
  }, (o.key ?? KP_AGENT).privateKey.toString());
}
const malloryDelegation = (p: AuthorizationV1) => delegation(p, { issuer: "mallory", kid: "m1", key: KP_MAL });
function krl(revoked: string[], version = 1): SignedKRLV1 {
  const env: SignedKRLV1 = { version: "SignedKRLV1", issuer: "krl-authority", krl_version: version, issued_at: T - 10, not_after: T + 3600, revoked_kids: revoked, nonce: uid(), signature: { alg: "Ed25519", kid: "r1", sig: "x" } };
  return { ...env, signature: { ...env.signature, sig: signEd25519(SIGNING_DOMAINS.KRL_V1, signedKrlSigningPayload(env), KP_KRL.privateKey.toString()) } };
}
const krlConfig = (provider: GuardRevocationConfig["provider"]): GuardRevocationConfig =>
  ({ trustedKrlKeySets: [KS_KRL], scopes: [{ krlIssuer: "krl-authority", keyIssuers: [PDP, "agent-A", "mallory"] }], provider, watermarkStore: createInMemoryKrlWatermarkStore() });

function spyStore(inner: ReplayStore = createInMemoryReplayStore()) {
  const calls: string[] = [];
  const store: ReplayStore = {
    consumeAuthId: async (id, x) => { calls.push(`auth:${id}`); return inner.consumeAuthId(id, x); },
    consumeDelegationId: async (id, x) => { calls.push(`deleg:${id}`); return inner.consumeDelegationId!(id, x); },
  };
  return { store, calls };
}

type Probe = { calls: string[]; hook: { n: number }; events: GuardBoundaryAuditEvent[] };
/** A complete config. Replay posture defaults to `shared` on a spy store; override with `replay`. */
function makeConfig(o: Partial<OxDeAIGuardConfig> & { replay?: Partial<OxDeAIGuardConfig> } = {}) {
  const spy = spyStore();
  const probe: Probe = { calls: spy.calls, hook: { n: 0 }, events: [] };
  const state = buildState({ agent_id: "agent-B", allow_action_types: ["PROVISION"], budget_limit: 10n ** 15n, max_amount_per_action: 10n ** 15n, velocity_max_actions: 10_000, max_concurrent: 16 });
  const { replay, ...rest } = o;
  const config: OxDeAIGuardConfig = {
    engine: new PolicyEngine({ policy_version: "v1", engine_secret: "synthetic-secret-at-least-32-characters!!", authorization_signing_alg: "Ed25519",
      authorization_signing_kid: "k1", authorization_issuer: PDP, authorization_audience: "agent-A", authorization_ttl_seconds: 600,
      authorization_private_key_pem: KP_PDP.privateKey.toString(), ...RECOMMENDED_TRUSTED_TIME_PROFILE }),
    getState: () => ({ state, version: 0 }), setState: () => true,
    trustedKeySets: [ksPdp(), ksAgent(), ksMal()], expectedAudience: "agent-A",
    trustedDelegationAuthorities: [{ issuer: PDP, policyId: POLICY }],
    onBoundaryEvent: (e) => { probe.events.push(e); },
    beforeExecute: async () => { probe.hook.n++; },
    ...(replay ?? { replayProtection: { mode: "shared", store: spy.store } }),
    ...rest,
  };
  return { config, probe, spy };
}
const CTX = () => createTrustedExecutionContext({ principalId: "principal-1", agentId: "agent-B", adapterId: "sg-test", depth: 0 });
const ACTION: ProposedAction = { name: "provision_gpu", args: { asset: "a100" }, estimatedCost: 0, context: { agent_id: "agent-B", target: "gpu-pool" }, timestampSeconds: T };

type SecureGuard = ReturnType<typeof createSecureGuard>;
async function delegated(sg: SecureGuard, p = parentAuth(), d: DelegationV1 | ((p: AuthorizationV1) => DelegationV1) = delegation, parentScope = PARENT_SCOPE) {
  let executed = 0; let error: unknown;
  const del = typeof d === "function" ? d(p) : d;
  try { await sg(CTX(), ACTION, async () => { executed++; return "ok"; }, { delegation: { delegation: del, parentAuth: p, parentScope } }); }
  catch (e) { error = e; }
  return { executed, error, delegation: del, parent: p };
}
async function direct(sg: SecureGuard) {
  let executed = 0; let error: unknown;
  try { await sg(CTX(), ACTION, async () => { executed++; return "ok"; }); } catch (e) { error = e; }
  return { executed, error };
}
function assertDenied(r: { executed: number; error: unknown }, probe: Probe, code: string, label: string, errorType: new (...a: never[]) => Error = OxDeAIDelegationError) {
  assert.equal(r.executed, 0, `${label}: execute must not run (${String(r.error)})`);
  assert.equal(probe.hook.n, 0, `${label}: beforeExecute must not run`);
  assert.deepEqual(probe.calls, [], `${label}: no replay consumption`);
  assert.equal(probe.events.at(-1)?.boundaryFailure, code, `${label}: boundary code (${String(r.error)})`);
  assert.ok(r.error instanceof errorType, `${label}: error type ${String(r.error)}`);
}
const secure = (config: OxDeAIGuardConfig) => createSecureGuard(config, { tenancy: "single-tenant" });

// ════════════════════════════════════════════════════════════════════════════
// F4-AUD-01 — construction-time capture
// ════════════════════════════════════════════════════════════════════════════

test("F4-AUD-01 (1) pushing a pair into the caller's signer array after construction does not widen signer authority", async () => {
  const signers = [{ delegator: "agent-A", issuer: "agent-A" }];
  const { config, probe } = makeConfig({ trustedDelegationSigners: signers });
  const sg = secure(config);
  assertDenied(await delegated(sg, parentAuth(), malloryDelegation), probe, "DELEGATION_VERIFICATION_FAILED", "baseline: mallory denied");
  signers.push({ delegator: "agent-A", issuer: "mallory" });
  assertDenied(await delegated(sg, parentAuth(), malloryDelegation), probe, "DELEGATION_VERIFICATION_FAILED", "after push");
  signers[0] = { delegator: "agent-A", issuer: "mallory" };
  assertDenied(await delegated(sg, parentAuth(), malloryDelegation), probe, "DELEGATION_VERIFICATION_FAILED", "after in-place replace");
});

test("F4-AUD-01 (2) reassigning trustedDelegationSigners to undefined (or another list) does not disable enforcement", async () => {
  const { config, probe } = makeConfig({ trustedDelegationSigners: [{ delegator: "agent-A", issuer: "agent-A" }] });
  const sg = secure(config);
  config.trustedDelegationSigners = undefined;
  assertDenied(await delegated(sg, parentAuth(), malloryDelegation), probe, "DELEGATION_VERIFICATION_FAILED", "undefined");
  config.trustedDelegationSigners = [{ delegator: "agent-A", issuer: "mallory" }];
  assertDenied(await delegated(sg, parentAuth(), malloryDelegation), probe, "DELEGATION_VERIFICATION_FAILED", "reassigned");
  delete (config as { trustedDelegationSigners?: unknown }).trustedDelegationSigners;
  assertDenied(await delegated(sg, parentAuth(), malloryDelegation), probe, "DELEGATION_VERIFICATION_FAILED", "deleted");
});

test("F4-AUD-01 (2b) parent authority list is captured: adding a pair after construction authorizes nothing new", async () => {
  const authorities: Array<{ issuer: string; policyId: string }> = [];
  const { config, probe } = makeConfig({ trustedDelegationAuthorities: authorities });
  const sg = secure(config);
  authorities.push({ issuer: PDP, policyId: POLICY });
  assertDenied(await delegated(sg), probe, "AUTHORIZATION_AUTHORITY_DENIED", "push", Error);
  config.trustedDelegationAuthorities = [{ issuer: PDP, policyId: POLICY }];
  assertDenied(await delegated(sg), probe, "AUTHORIZATION_AUTHORITY_DENIED", "reassign", Error);
});

test("F4-AUD-01 (3) removing revocation configuration after construction keeps enforcement enabled", async () => {
  // SignedKRLV1: the delegation key a1 is revoked by a verified KRL.
  {
    const revokesA1 = krl(["a1"]); // one published KRL; re-presented on every call
    const { config, probe } = makeConfig({ revocation: krlConfig(() => [revokesA1]) });
    const sg = secure(config);
    assertDenied(await delegated(sg), probe, "DELEGATION_VERIFICATION_FAILED", "KRL baseline");
    config.revocation = undefined;
    assertDenied(await delegated(sg), probe, "DELEGATION_VERIFICATION_FAILED", "config.revocation = undefined");
    delete (config as { revocation?: unknown }).revocation;
    assertDenied(await delegated(sg), probe, "DELEGATION_VERIFICATION_FAILED", "delete config.revocation");
  }
  // F4-C: revocation required and provider reports REVOKED.
  {
    const provider: DelegationRevocationProvider = { check: async () => ({ status: "REVOKED" }) };
    const { config, probe } = makeConfig({ delegationRevocationProvider: provider, requireDelegationRevocation: true });
    const sg = secure(config);
    config.delegationRevocationProvider = undefined;
    config.requireDelegationRevocation = false;
    assertDenied(await delegated(sg), probe, "DELEGATION_REVOKED", "provider removed + required=false");
  }
  // F4-C: required with no provider: removing the requirement is not observed.
  {
    const { config, probe } = makeConfig({ requireDelegationRevocation: true });
    const sg = secure(config);
    config.requireDelegationRevocation = false;
    assertDenied(await delegated(sg), probe, "DELEGATION_REVOCATION_UNAVAILABLE", "required flag cleared");
  }
});

test("F4-AUD-01 (4) replacing provider methods or objects after construction cannot weaken revocation", async () => {
  // F4-C provider: replace check(), and reassign the provider object.
  {
    const provider: DelegationRevocationProvider = { check: async () => ({ status: "REVOKED" }) };
    const { config, probe } = makeConfig({ delegationRevocationProvider: provider });
    const sg = secure(config);
    provider.check = async () => ({ status: "ACTIVE" });
    assertDenied(await delegated(sg), probe, "DELEGATION_REVOKED", "check replaced");
    config.delegationRevocationProvider = { check: async () => ({ status: "ACTIVE" }) };
    assertDenied(await delegated(sg), probe, "DELEGATION_REVOKED", "provider reassigned");
  }
  // SignedKRLV1: replace the caller's revocation.provider and watermarkStore.accept.
  {
    const rev = krlConfig(() => [krl(["a1"])]) as { -readonly [K in keyof GuardRevocationConfig]: GuardRevocationConfig[K] };
    const { config, probe } = makeConfig({ revocation: rev });
    const sg = secure(config);
    const clean = krl([], 1);
    rev.provider = () => [clean];
    (rev.watermarkStore as { accept: unknown }).accept = async () => "ACCEPTED";
    rev.scopes = [];
    assertDenied(await delegated(sg), probe, "DELEGATION_VERIFICATION_FAILED", "KRL provider/store/scopes replaced");
  }
});

test("F4-AUD-01 (5) legitimate dynamic revocation state is still observed", async () => {
  // F4-C: provider consults mutable state; the captured bound check reads it.
  {
    const revokedIssuers = new Set<string>();
    const provider = {
      revoked: revokedIssuers,
      async check(this: { revoked: Set<string> }, q: { issuer: string }) { return { status: this.revoked.has(q.issuer) ? "REVOKED" as const : "ACTIVE" as const }; },
    };
    const { config, probe } = makeConfig({ delegationRevocationProvider: provider as unknown as DelegationRevocationProvider });
    const sg = secure(config);
    assert.equal((await delegated(sg)).executed, 1, "ACTIVE executes");
    probe.calls.length = 0; probe.hook.n = 0;
    revokedIssuers.add("agent-A");
    assertDenied(await delegated(sg), probe, "DELEGATION_REVOKED", "state update observed (receiver bound)");
  }
  // SignedKRLV1: the KRL provider returns the current list; a newer KRL revoking a1 is observed,
  // and the captured watermark store keeps rollback protection across calls.
  {
    let current = krl([], 1);
    const { config, probe } = makeConfig({ revocation: krlConfig(() => [current]) });
    const sg = secure(config);
    assert.equal((await delegated(sg)).executed, 1, "v1 clean executes");
    probe.calls.length = 0; probe.hook.n = 0;
    current = krl(["a1"], 2);
    assertDenied(await delegated(sg), probe, "DELEGATION_VERIFICATION_FAILED", "v2 revokes a1");
    current = krl([], 1);
    assertDenied(await delegated(sg), probe, "REVOCATION_STATE_INVALID", "rollback to v1 rejected");
  }
  // In-place key rotation of the retained trustedKeySets array still works (documented contract).
  {
    const pdp = ksPdp();
    const { config } = makeConfig({ trustedKeySets: [pdp, ksAgent(), ksMal()] });
    const sg = secure(config);
    (pdp.keys as unknown[]).push({ kid: "k2", alg: "Ed25519", public_key: pem(KP_PDP2) });
    assert.equal((await delegated(sg, parentAuth({ kid: "k2", key: KP_PDP2 }))).executed, 1, "rotated-in key k2 trusted");
  }
});

test("F4-AUD-01 (5b) reassigning config.trustedKeySets after construction is not observed", async () => {
  const { config, probe } = makeConfig();
  const sg = secure(config);
  config.trustedKeySets = [ksPdp(), { issuer: "agent-A", version: "v1", keys: [{ kid: "a1", alg: "Ed25519", public_key: pem(KP_MAL) }] }];
  // A delegation signed by mallory's key under a1 must not verify through the reassigned array.
  assertDenied(await delegated(sg, parentAuth(), (p) => delegation(p, { key: KP_MAL })), probe, "DELEGATION_VERIFICATION_FAILED", "reassigned trust");
});

test("F4-AUD-01 (6) invalid security configuration fails at construction, with OxDeAIGuard's messages", () => {
  const cases: Array<[string, Partial<OxDeAIGuardConfig>, RegExp]> = [
    ["signers not an array", { trustedDelegationSigners: {} as never }, /trustedDelegationSigners must be an array/],
    ["signer entry malformed", { trustedDelegationSigners: [{ delegator: "", issuer: "x" }] }, /trustedDelegationSigners entries/],
    ["provider without check", { delegationRevocationProvider: {} as never }, /delegationRevocationProvider must provide a check/],
    ["required flag not boolean", { requireDelegationRevocation: "yes" as never }, /requireDelegationRevocation must be a boolean/],
    ["revocation malformed", { revocation: {} as never }, /config\.revocation/],
    ["KRL key reused as authorization key", { revocation: krlConfig(() => []), trustedKeySets: [ksPdp(), ksAgent(), KS_KRL] }, /KRL/],
    ["missing engine", { engine: undefined as never }, /config\.engine/],
    ["missing expectedAudience", { expectedAudience: "" }, /expectedAudience/],
    ["empty trustedKeySets", { trustedKeySets: [] }, /trustedKeySets are required/],
  ];
  for (const [label, override, msg] of cases) {
    const { config } = makeConfig(override);
    assert.throws(() => secure(config), (e: unknown) => e instanceof OxDeAIGuardConfigurationError && msg.test((e as Error).message), label);
  }
});

test("F4-AUD-01 (7) independent secure guards are isolated, including from a config shared between them", async () => {
  const signers = [{ delegator: "agent-A", issuer: "agent-A" }];
  const { config, probe } = makeConfig({ trustedDelegationSigners: signers, replay: { replayProtection: { mode: "process-local" } } });
  const a = secure(config);
  signers.push({ delegator: "agent-A", issuer: "mallory" });
  const b = secure(config); // built after the change: authorizes mallory
  assertDenied(await delegated(a, parentAuth(), malloryDelegation), probe, "DELEGATION_VERIFICATION_FAILED", "guard A keeps its own posture");
  assert.equal((await delegated(b, parentAuth(), malloryDelegation)).executed, 1, "guard B uses the posture it was built with");
  // Separate process-local stores: a replay in A does not consume B's namespace, and vice versa.
  const p = parentAuth(); const d = delegation(p);
  assert.equal((await delegated(b, p, d)).executed, 1);
  const again = await delegated(b, p, d);
  assert.equal(again.executed, 0, "replay denied within B");
  assert.equal((await delegated(a, p, d)).executed, 1, "A has its own process-local namespace");
});

// ════════════════════════════════════════════════════════════════════════════
// AUD-OBS-02 — replay configuration on the secure path
// ════════════════════════════════════════════════════════════════════════════

test("AUD-OBS-02 (1) process-local: delegated and direct calls execute; one instance-lifetime store denies replay", async () => {
  const { config } = makeConfig({ replay: { replayProtection: { mode: "process-local" } } });
  const sg = secure(config);
  assert.equal((await direct(sg)).executed, 1, "direct (standard) path executes");
  const r1 = await delegated(sg);
  assert.equal(r1.executed, 1, String(r1.error));
  const r2 = await delegated(sg, r1.parent, r1.delegation);
  assert.equal(r2.executed, 0, "same delegation replayed");
  assert.ok(r2.error instanceof OxDeAIAuthorizationError && /replay/i.test((r2.error as Error).message), String(r2.error));
});

test("AUD-OBS-02 (2) shared: the configured store is used for every consume; replay denied", async () => {
  const { config, probe } = makeConfig();
  const sg = secure(config);
  const r1 = await delegated(sg);
  assert.equal(r1.executed, 1, String(r1.error));
  assert.deepEqual(probe.calls, [`deleg:${r1.delegation.delegation_id}`, `auth:${r1.parent.auth_id}`], "consumed in the shared store");
  const r2 = await delegated(sg, r1.parent, r1.delegation);
  assert.equal(r2.executed, 0);
  assert.equal(probe.events.at(-1)?.boundaryFailure, "DELEGATION_REPLAY");
  probe.calls.length = 0;
  assert.equal((await direct(sg)).executed, 1);
  assert.equal(probe.calls.length, 1, "direct path consumed its auth_id in the shared store");
  assert.ok(probe.calls[0].startsWith("auth:"));
});

test("AUD-OBS-02 (3) legacy replayStore remains supported on the secure path", async () => {
  const spy = spyStore();
  const { config } = makeConfig({ replay: { replayStore: spy.store } });
  const sg = secure(config);
  const r1 = await delegated(sg);
  assert.equal(r1.executed, 1, String(r1.error));
  assert.equal(spy.calls.length, 2, "legacy store used");
  assert.equal((await delegated(sg, r1.parent, r1.delegation)).executed, 0, "replay denied");
});

test("AUD-OBS-02 (4) explicitly conflicting or invalid replay configuration is still rejected at construction", () => {
  const spy = spyStore();
  const bad: Array<[string, Partial<OxDeAIGuardConfig>]> = [
    ["both replayProtection and replayStore", { replayProtection: { mode: "process-local" }, replayStore: spy.store }],
    ["shared without store", { replayProtection: { mode: "shared" } as never }],
    ["shared with the built-in in-memory store", { replayProtection: { mode: "shared", store: createInMemoryReplayStore() } }],
    ["unknown mode", { replayProtection: { mode: "global" } as never }],
    ["process-local with a store", { replayProtection: { mode: "process-local", store: spy.store } as never }],
  ];
  for (const [label, replay] of bad) {
    const { config } = makeConfig({ replay });
    assert.throws(() => secure(config), OxDeAIGuardConfigurationError, label);
  }
  // Strict mode is unchanged: an undeclared posture fails, a declared one works.
  const undeclared = makeConfig({ replay: {} }).config;
  assert.throws(() => secure({ ...undeclared, requireExplicitReplayProtection: true } as OxDeAIGuardConfig), OxDeAIGuardConfigurationError, "strict, undeclared");
  const declared = makeConfig({ replay: { replayProtection: { mode: "process-local" } } }).config;
  assert.doesNotThrow(() => secure({ ...declared, requireExplicitReplayProtection: true } as OxDeAIGuardConfig), "strict, declared");
});

test("AUD-OBS-02 (5) invalid authorization does not consume replay state; concurrent duplicates execute once", async () => {
  const { config, probe } = makeConfig();
  const sg = secure(config);
  // Parent issued to another audience: denied before any consume.
  assertDenied(await delegated(sg, parentAuth({ audience: "someone-else" })), probe, "AUTHORIZATION_VERIFICATION_FAILED", "bad audience", OxDeAIAuthorizationError);
  // Forged delegation signature: denied before any consume.
  assertDenied(await delegated(sg, parentAuth(), (p) => delegation(p, { key: KP_MAL })), probe, "DELEGATION_VERIFICATION_FAILED", "forged delegation");
  // Concurrent duplicates against the atomic in-memory-backed spy store.
  const p = parentAuth(); const d = delegation(p);
  const results = await Promise.all([delegated(sg, p, d), delegated(sg, p, d), delegated(sg, p, d)]);
  assert.equal(results.reduce((n, r) => n + r.executed, 0), 1, "exactly one concurrent duplicate executes");
});

test("AUD-OBS-02 (6) replay-store failure fails closed on delegated and direct paths", async () => {
  const failing: ReplayStore = {
    consumeAuthId: async () => { throw new Error("backend down"); },
    consumeDelegationId: async () => { throw new Error("backend down"); },
  };
  const { config, probe } = makeConfig({ replay: { replayProtection: { mode: "shared", store: failing } } });
  const sg = secure(config);
  const r = await delegated(sg);
  assert.equal(r.executed, 0); assert.equal(probe.hook.n, 0);
  assert.equal(probe.events.at(-1)?.boundaryFailure, "REPLAY_STORE_UNAVAILABLE", String(r.error));
  const d = await direct(sg);
  assert.equal(d.executed, 0); assert.equal(probe.hook.n, 0);
  assert.equal(probe.events.at(-1)?.boundaryFailure, "REPLAY_STORE_UNAVAILABLE", String(d.error));
});

// ════════════════════════════════════════════════════════════════════════════
// F4-AUD-03 — guard boundary
// ════════════════════════════════════════════════════════════════════════════

test("F4-AUD-03 the audit's wide-scope input fails closed on OxDeAIGuard and createSecureGuard (no execute, no consume)", async () => {
  const n = 20_000;
  const tools = Array.from({ length: n }, (_, i) => `t${i}`);
  const parentScope: DelegationScope = { tools: [...Array.from({ length: n }, (_, i) => `p${i}`), ...tools.slice().reverse()] };
  const wide = (p: AuthorizationV1) => ({ ...delegation(p), scope: { tools: [...tools, "foreign"], max_amount: 1n } }) as DelegationV1;
  {
    const { config, probe } = makeConfig();
    assertDenied(await delegated(secure(config), parentAuth(), wide, parentScope), probe, "DELEGATION_VERIFICATION_FAILED", "secure guard");
  }
  {
    const { config, probe } = makeConfig();
    const g = OxDeAIGuard(config);
    let executed = 0; let error: unknown;
    const p = parentAuth();
    try { await g(ACTION, async () => { executed++; }, { delegation: { delegation: wide(p), parentAuth: p, parentScope } }); } catch (e) { error = e; }
    assertDenied({ executed, error }, probe, "DELEGATION_VERIFICATION_FAILED", "OxDeAIGuard");
  }
});

// ════════════════════════════════════════════════════════════════════════════
// REV-R1 / REV-R2 — configuration forms accepted by the structural contract
// ════════════════════════════════════════════════════════════════════════════
//
// `OxDeAIGuardConfig` is a structural type, and `OxDeAIGuard` reads it through
// ordinary property access. The first F4-AUD-01 capture used `{ ...config }`,
// which keeps only own enumerable properties: a shared replay store, signer
// authority or revocation configuration supplied any other way was silently
// dropped (shared → process-local replay, enforcement off). Every test below
// fails on that implementation.

type Form = "own" | "non-enumerable" | "inherited" | "class-getter" | "proxy" | "proxy-get-trap";
const FORMS: readonly Form[] = ["own", "non-enumerable", "inherited", "class-getter", "proxy", "proxy-get-trap"];

/** Move `keys` of `config` into `form`; every other option stays an own enumerable property. */
function reshape(config: OxDeAIGuardConfig, form: Form, keys: readonly string[]): OxDeAIGuardConfig {
  const src = config as unknown as Record<string, unknown>;
  const moved: Record<string, unknown> = {};
  const rest: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(src)) (keys.includes(k) ? moved : rest)[k] = v;
  switch (form) {
    case "own": return { ...rest, ...moved } as unknown as OxDeAIGuardConfig;
    case "non-enumerable": {
      const o = { ...rest };
      for (const [k, v] of Object.entries(moved)) Object.defineProperty(o, k, { value: v, enumerable: false, writable: true, configurable: true });
      return o as unknown as OxDeAIGuardConfig;
    }
    case "inherited": return Object.assign(Object.create(moved), rest) as OxDeAIGuardConfig;
    case "class-getter": {
      class DeploymentConfig { constructor() { Object.assign(this, rest); } }
      for (const [k, v] of Object.entries(moved)) Object.defineProperty(DeploymentConfig.prototype, k, { get: () => v, configurable: true });
      return new DeploymentConfig() as unknown as OxDeAIGuardConfig;
    }
    case "proxy": return new Proxy({ ...rest, ...moved }, {}) as unknown as OxDeAIGuardConfig;
    case "proxy-get-trap": // the target lacks the moved options; only the get trap supplies them
      return new Proxy({ ...rest }, { get: (t, k, r) => (typeof k === "string" && k in moved ? moved[k] : Reflect.get(t, k, r)) }) as unknown as OxDeAIGuardConfig;
  }
}
/** Every option as a getter on a class prototype; no own properties at all. */
function fullyClassBased(config: OxDeAIGuardConfig): OxDeAIGuardConfig {
  class DeploymentConfig {}
  for (const [k, v] of Object.entries(config)) Object.defineProperty(DeploymentConfig.prototype, k, { get: () => v, configurable: true });
  return new DeploymentConfig() as unknown as OxDeAIGuardConfig;
}
const isConfigError = (re: RegExp) => (e: unknown) => e instanceof OxDeAIGuardConfigurationError && re.test((e as Error).message);

test("REV-R1 (1) shared and legacy replay stores are honoured in every form: two instances, one replay domain", async (t) => {
  const postures = {
    shared: (store: ReplayStore) => ({ replayProtection: { mode: "shared", store } as const }),
    legacy: (store: ReplayStore) => ({ replayStore: store }),
  };
  for (const [posture, replay] of Object.entries(postures)) {
    for (const form of [...FORMS, "fully-class-based"] as const) {
      await t.test(`${posture} via ${form}`, async () => {
        const spy = spyStore();
        const build = () => {
          const { config } = makeConfig({ replay: replay(spy.store) });
          return secure(form === "fully-class-based" ? fullyClassBased(config) : reshape(config, form, Object.keys(replay(spy.store))));
        };
        const a = build(), b = build();
        const p = parentAuth(), d = delegation(p);
        const r1 = await delegated(a, p, d);
        assert.equal(r1.executed, 1, String(r1.error));
        assert.deepEqual(spy.calls, [`deleg:${d.delegation_id}`, `auth:${p.auth_id}`], "consumed in the configured store, not a process-local default");
        const r2 = await delegated(b, p, d);
        assert.equal(r2.executed, 0, "duplicate on a second instance sharing the store is denied");
        assert.ok(r2.error instanceof OxDeAIAuthorizationError && /replay/i.test((r2.error as Error).message), String(r2.error));
        spy.calls.length = 0;
        assert.equal((await direct(b)).executed, 1, "direct path executes");
        assert.equal(spy.calls.length, 1, "direct path consumes in the shared store");
      });
    }
  }
});

test("REV-R1 (2) accessors are read once: a value that changes on later reads cannot change the replay posture", async () => {
  // Top-level getter: shared on the first read, process-local (or absent) afterwards.
  for (const later of [{ mode: "process-local" }, undefined]) {
    const spy = spyStore();
    let reads = 0;
    const { config } = makeConfig({ replay: {} });
    Object.defineProperty(config, "replayProtection", { enumerable: true, get: () => (++reads === 1 ? { mode: "shared", store: spy.store } : later) });
    const sg = secure(config);
    assert.equal(reads, 1, "read exactly once at construction");
    const r = await delegated(sg);
    assert.equal(r.executed, 1, String(r.error));
    assert.equal(spy.calls.length, 2, "the posture of the single read (shared) is enforced");
    assert.equal(reads, 1, "never re-read per call");
  }
  // Nested: `mode` answers "shared" to validation and "process-local" afterwards.
  {
    const spy = spyStore();
    let modeReads = 0;
    const rp = { get mode() { return ++modeReads === 1 ? "shared" : "process-local"; }, store: spy.store };
    const { config } = makeConfig({ replay: { replayProtection: rp as never } });
    const sg = secure(config);
    assert.equal(modeReads, 1, "mode read once");
    assert.equal((await delegated(sg)).executed, 1);
    assert.equal(spy.calls.length, 2, "shared store used");
  }
  // Nested Proxy whose has/get disagree: decided once, deterministically, never downgraded.
  {
    const spy = spyStore();
    let modeReads = 0;
    const rp = new Proxy({ store: spy.store }, {
      get: (tgt, k) => (k === "mode" ? (++modeReads <= 2 ? "shared" : "process-local") : (tgt as Record<PropertyKey, unknown>)[k]),
      has: (tgt, k) => (k === "store" ? false : k in tgt),
    });
    const { config } = makeConfig({ replay: { replayProtection: rp as never } });
    assert.throws(() => secure(config), isConfigError(/mode 'shared' requires a store/), "shared without a (present) store is rejected");
    assert.equal(modeReads, 1);
  }
});

test("REV-R1 (3) the caller's config is not read after construction (counting Proxy)", async () => {
  const counts = new Map<string, number>();
  let phase: "construct" | "call" = "construct";
  const callReads: string[] = [];
  const { config } = makeConfig({ trustedDelegationSigners: [{ delegator: "agent-A", issuer: "agent-A" }] });
  const proxy = new Proxy(config, {
    get: (tgt, k, r) => {
      if (typeof k === "string") { if (phase === "construct") counts.set(k, (counts.get(k) ?? 0) + 1); else callReads.push(k); }
      return Reflect.get(tgt, k, r);
    },
  });
  const sg = secure(proxy);
  phase = "call";
  assert.equal((await delegated(sg)).executed, 1);
  assert.equal((await direct(sg)).executed, 1);
  for (const [k, n] of counts) assert.equal(n, 1, `config.${k} read ${n} times at construction`);
  assert.ok(counts.has("replayProtection") && counts.has("trustedDelegationSigners") && counts.has("revocation"), "every option is resolved by name");
  assert.deepEqual(callReads, [], "no read of the caller's config during calls");
});

test("REV-R1 (4) a throwing accessor or Proxy trap fails construction; it never falls back to process-local", () => {
  const boom = () => { throw new Error("secret manager unavailable"); };
  const cases: Array<[string, () => OxDeAIGuardConfig, RegExp]> = [
    ["own getter", () => { const { config } = makeConfig({ replay: {} }); Object.defineProperty(config, "replayProtection", { get: boom }); return config; }, /config\.replayProtection could not be read/],
    ["inherited (class) getter", () => {
      const { config } = makeConfig({ replay: {} });
      class C { constructor() { Object.assign(this, config); } get replayProtection(): never { return boom(); } }
      return new C() as unknown as OxDeAIGuardConfig;
    }, /config\.replayProtection could not be read/],
    ["legacy replayStore getter", () => { const { config } = makeConfig({ replay: {} }); Object.defineProperty(config, "replayStore", { get: boom }); return config; }, /config\.replayStore could not be read/],
    ["strict flag getter", () => { const { config } = makeConfig(); Object.defineProperty(config, "requireExplicitReplayProtection", { get: boom }); return config; }, /requireExplicitReplayProtection could not be read/],
    ["nested mode getter", () => makeConfig({ replay: { replayProtection: { get mode(): never { return boom(); } } as never } }).config, /replayProtection\.mode could not be read/],
    ["nested store has-trap", () => makeConfig({ replay: { replayProtection: new Proxy({ mode: "shared" }, { has: boom }) as never } }).config, /replayProtection\.store could not be read/],
    ["Proxy get trap", () => new Proxy(makeConfig().config, { get: boom }), /could not be read/],
    ["revoked Proxy", () => { const r = Proxy.revocable(makeConfig().config, {}); r.revoke(); return r.proxy; }, /could not be read/],
  ];
  for (const [label, build, re] of cases) assert.throws(() => secure(build()), isConfigError(re), label);
  assert.throws(() => secure(null as never), isConfigError(/config must be a plain object/), "null config");
  assert.throws(() => secure("config" as never), isConfigError(/config must be a plain object/), "string config");
});

test("REV-R1 (5) strict mode and conflict detection see inherited and accessor values", async () => {
  // Strict flag supplied by a getter, no posture: fails closed (it was silently ignored).
  {
    const { config } = makeConfig({ replay: {} });
    assert.throws(() => secure(reshape({ ...config, requireExplicitReplayProtection: true }, "class-getter", ["requireExplicitReplayProtection"])),
      isConfigError(/posture is required/));
  }
  // Strict flag and a shared posture both inherited: accepted, and the shared store is used.
  {
    const spy = spyStore();
    const { config } = makeConfig({ replay: { replayProtection: { mode: "shared", store: spy.store } } });
    const sg = secure(reshape({ ...config, requireExplicitReplayProtection: true }, "inherited", ["requireExplicitReplayProtection", "replayProtection"]));
    assert.equal((await delegated(sg)).executed, 1);
    assert.equal(spy.calls.length, 2);
  }
  // replayProtection own + replayStore inherited: still the ambiguous-configuration error.
  for (const form of ["inherited", "non-enumerable", "class-getter", "proxy-get-trap"] as const) {
    const spy = spyStore();
    const { config } = makeConfig({ replay: { replayProtection: { mode: "process-local" }, replayStore: spy.store } });
    assert.throws(() => secure(reshape(config, form, ["replayStore"])), isConfigError(/Ambiguous replay configuration/), form);
  }
  // Invalid postures supplied through accessors are rejected exactly like own ones.
  for (const form of ["inherited", "class-getter"] as const) {
    for (const rp of [{ mode: "shared" }, { mode: "global" }, { mode: "shared", store: createInMemoryReplayStore() }, "shared"]) {
      const { config } = makeConfig({ replay: { replayProtection: rp as never } });
      assert.throws(() => secure(reshape(config, form, ["replayProtection"])), OxDeAIGuardConfigurationError, `${form} ${JSON.stringify(rp)}`);
    }
  }
});

test("REV-R1 (6) replay-store failure, unavailability and falsy malformed answers fail closed for accessor-supplied stores", async () => {
  const stores: Array<[string, ReplayStore["consumeAuthId"], string]> = [
    ["throws", async () => { throw new Error("backend down"); }, "REPLAY_STORE_UNAVAILABLE"],
    ["rejects with a non-Error", () => Promise.reject("ECONNRESET"), "REPLAY_STORE_UNAVAILABLE"],
    ["rejects after a delay", () => new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 5)), "REPLAY_STORE_UNAVAILABLE"],
    ["returns false", async () => false, "AUTHORIZATION_REPLAY"],
    ["returns undefined", async () => undefined as never, "REPLAY_STORE_UNAVAILABLE"],
    ["returns null", async () => null as never, "REPLAY_STORE_UNAVAILABLE"],
    ["returns 0", async () => 0 as never, "REPLAY_STORE_UNAVAILABLE"],
  ];
  for (const [label, consumeAuthId, code] of stores) {
    for (const form of ["class-getter", "inherited"] as const) {
      const { config, probe } = makeConfig({ replay: { replayProtection: { mode: "shared", store: { consumeAuthId } } } });
      const sg = secure(reshape(config, form, ["replayProtection"]));
      const d = await direct(sg);
      assert.equal(d.executed, 0, `${label} (${form}) direct`);
      assert.equal(probe.events.at(-1)?.boundaryFailure, code, `${label} (${form}) direct: ${String(d.error)}`);
      const r = await delegated(sg);
      assert.equal(r.executed, 0, `${label} (${form}) delegated`);
      assert.equal(probe.hook.n, 0);
      assert.equal(probe.events.at(-1)?.boundaryFailure, code, `${label} (${form}) delegated: ${String(r.error)}`);
    }
  }
});

test("REV-R1 (7) OPEN pre-existing: a truthy non-boolean consume answer is treated as consumed (shared body and gateway)",
  async () => {
    for (const answer of ["false", 1, {}]) {
      const { config } = makeConfig({ replay: { replayProtection: { mode: "shared", store: { consumeAuthId: async () => answer as never } } } });
      assert.equal((await direct(secure(config))).executed, 0, `answer ${JSON.stringify(answer)} must deny`);
    }
  });

test("REV-R2 (1) signer authority, F4-C and SignedKRLV1 revocation are enforced in every form", async (t) => {
  const revokesA1 = krl(["a1"]);
  const options: Array<[string, Partial<OxDeAIGuardConfig>, string[], (p: AuthorizationV1) => DelegationV1, string]> = [
    ["trustedDelegationSigners", { trustedDelegationSigners: [{ delegator: "agent-A", issuer: "agent-A" }] }, ["trustedDelegationSigners"], malloryDelegation, "DELEGATION_VERIFICATION_FAILED"],
    ["delegationRevocationProvider + requireDelegationRevocation", { delegationRevocationProvider: { check: async () => ({ status: "REVOKED" }) }, requireDelegationRevocation: true },
      ["delegationRevocationProvider", "requireDelegationRevocation"], delegation, "DELEGATION_REVOKED"],
    ["requireDelegationRevocation without provider", { requireDelegationRevocation: true }, ["requireDelegationRevocation"], delegation, "DELEGATION_REVOCATION_UNAVAILABLE"],
    ["revocation (SignedKRLV1)", { revocation: krlConfig(() => [revokesA1]) }, ["revocation"], delegation, "DELEGATION_VERIFICATION_FAILED"],
  ];
  for (const [label, override, keys, del, code] of options) {
    for (const form of FORMS) {
      await t.test(`${label} via ${form}`, async () => {
        const { config, probe } = makeConfig(override);
        assertDenied(await delegated(secure(reshape(config, form, keys)), parentAuth(), del), probe, code, `${label} via ${form}`);
      });
    }
  }
});

test("REV-R2 (2) required options supplied through accessors work; nothing is silently missing", async () => {
  for (const form of FORMS) {
    const { config } = makeConfig();
    for (const key of ["trustedDelegationAuthorities", "expectedAudience", "engine", "getState", "setState", "trustedKeySets", "beforeExecute", "onBoundaryEvent"]) {
      const sg = secure(reshape(config, form, [key]));
      const r = await delegated(sg);
      assert.equal(r.executed, 1, `${key} via ${form}: ${String(r.error)}`);
    }
  }
  // A configuration that is a class instance with prototype getters and prototype methods.
  {
    const { config } = makeConfig();
    const sg = secure(fullyClassBased(config));
    assert.equal((await delegated(sg)).executed, 1);
    assert.equal((await direct(sg)).executed, 1);
  }
  // Prototype methods keep their receiver: `this` is the deployer's object (live state).
  {
    const { config } = makeConfig();
    const { getState, setState: _setState, ...rest } = config;
    void _setState;
    let commits = 0;
    class Deployment {
      version = 0;
      constructor() { Object.assign(this, rest); }
      getState(this: Deployment) { return { ...(getState() as unknown as { state: never }), version: this.version }; }
      setState(this: Deployment) { commits++; this.version++; return true; }
    }
    const dep = new Deployment();
    const sg = secure(dep as unknown as OxDeAIGuardConfig);
    assert.equal((await direct(sg)).executed, 1);
    assert.equal((await direct(sg)).executed, 1);
    assert.equal(commits, 2);
    assert.equal(dep.version, 2, "methods ran against the deployer's object");
  }
  // onDecision through a getter still receives provenance on the secure path.
  {
    const records: Array<{ provenance?: unknown }> = [];
    const { config } = makeConfig({ onDecision: (r) => { records.push(r); } });
    assert.equal((await direct(secure(reshape(config, "class-getter", ["onDecision"])))).executed, 1);
    assert.ok(records.length === 1 && records[0].provenance, "decision recorded with provenance");
  }
});

test("REV-R2 (3) F4-AUD-01 holds for accessor configs: changing what a getter returns after construction is not observed", async () => {
  class Deployment {
    signers: unknown = [{ delegator: "agent-A", issuer: "agent-A" }];
    provider: unknown = { check: async () => ({ status: "REVOKED" }) };
    constructor(rest: object) { Object.assign(this, rest); }
    get trustedDelegationSigners() { return this.signers; }
    get delegationRevocationProvider() { return this.provider; }
  }
  {
    const { config, probe } = makeConfig();
    const dep = new Deployment(config);
    dep.provider = undefined;
    const sg = secure(dep as unknown as OxDeAIGuardConfig);
    dep.signers = [{ delegator: "agent-A", issuer: "mallory" }];
    assertDenied(await delegated(sg, parentAuth(), malloryDelegation), probe, "DELEGATION_VERIFICATION_FAILED", "signers swapped behind getter");
  }
  {
    const { config, probe } = makeConfig();
    const dep = new Deployment(config);
    dep.signers = undefined;
    const sg = secure(dep as unknown as OxDeAIGuardConfig);
    dep.provider = { check: async () => ({ status: "ACTIVE" }) };
    assertDenied(await delegated(sg), probe, "DELEGATION_REVOKED", "provider swapped behind getter");
  }
});

test("REV-R2 (4) nested security members are read once (validation and enforcement see one value)", async () => {
  // Signer entry: valid on the first read, an attacker's issuer on any later read.
  {
    let reads = 0;
    const entry = { delegator: "agent-A", get issuer() { return ++reads === 1 ? "agent-A" : "mallory"; } };
    const { config, probe } = makeConfig({ trustedDelegationSigners: [entry] });
    const sg = secure(config);
    assert.equal(reads, 1, "issuer read once");
    assertDenied(await delegated(sg, parentAuth(), malloryDelegation), probe, "DELEGATION_VERIFICATION_FAILED", "flipping signer entry");
  }
  // Parent authority entry read once.
  {
    let reads = 0;
    const entry = { issuer: PDP, get policyId() { reads++; return POLICY; } };
    const { config } = makeConfig({ trustedDelegationAuthorities: [entry] });
    const sg = secure(config);
    assert.equal((await delegated(sg)).executed, 1);
    assert.equal(reads, 1);
  }
  // F4-C provider `check` getter read once; the method then runs on the original receiver.
  {
    let reads = 0;
    const provider = { revoked: true, get check() { reads++; return async function (this: { revoked: boolean }) { return { status: this.revoked ? "REVOKED" as const : "ACTIVE" as const }; }; } };
    const { config, probe } = makeConfig({ delegationRevocationProvider: provider as never });
    const sg = secure(config);
    assert.equal(reads, 1);
    assertDenied(await delegated(sg), probe, "DELEGATION_REVOKED", "check via getter");
    provider.revoked = false;
    assert.equal((await delegated(sg)).executed, 1, "provider state is live");
    assert.equal(reads, 1);
  }
  // SignedKRLV1: members supplied by getters on a class instance are read once and honoured.
  {
    const reads = new Map<string, number>();
    const revokesA1 = krl(["a1"]);
    const base = krlConfig(() => [revokesA1]);
    const tally = <T>(k: string, v: T) => { reads.set(k, (reads.get(k) ?? 0) + 1); return v; };
    class Rev {
      get trustedKrlKeySets() { return tally("trustedKrlKeySets", base.trustedKrlKeySets); }
      get scopes() { return tally("scopes", base.scopes); }
      get provider() { return tally("provider", base.provider); }
      get watermarkStore() { return tally("watermarkStore", base.watermarkStore); }
    }
    const { config, probe } = makeConfig({ revocation: new Rev() as never });
    const sg = secure(config);
    for (const [k, n] of reads) assert.equal(n, 1, `revocation.${k} read ${n} times`);
    assert.equal(reads.size, 4);
    assertDenied(await delegated(sg), probe, "DELEGATION_VERIFICATION_FAILED", "KRL via getters");
  }
});

test("REV-R2 (5) replay store: methods fixed at construction, identity and state live and shared", async () => {
  const inner = createInMemoryReplayStore();
  // A class-based store: methods on the prototype, state on the instance.
  class SharedStore implements ReplayStore {
    calls = 0;
    async consumeAuthId(id: string, x: { expiry: number }) { this.calls++; return inner.consumeAuthId(id, x); }
    async consumeDelegationId(id: string, x: { expiry: number }) { this.calls++; return inner.consumeDelegationId!(id, x); }
  }
  const store = new SharedStore();
  const a = secure(makeConfig({ replay: { replayProtection: { mode: "shared", store } } }).config);
  const p = parentAuth(), d = delegation(p);
  assert.equal((await delegated(a, p, d)).executed, 1);
  assert.equal(store.calls, 2, "prototype methods ran with the store as receiver");
  // Replacing the methods after construction does not disable replay protection...
  (store as { consumeAuthId: unknown }).consumeAuthId = async () => true;
  (store as { consumeDelegationId: unknown }).consumeDelegationId = async () => true;
  assert.equal((await delegated(a, p, d)).executed, 0, "replay still denied by the captured methods");
  // ...while the store's state remains the one shared replay domain: a guard
  // built later on the same store sees the ids consumed through the first.
  const p2 = parentAuth(), d2 = delegation(p2);
  assert.equal((await delegated(a, p2, d2)).executed, 1);
  delete (store as { consumeAuthId?: unknown }).consumeAuthId;
  delete (store as { consumeDelegationId?: unknown }).consumeDelegationId;
  const b = secure(makeConfig({ replay: { replayProtection: { mode: "shared", store } } }).config);
  assert.equal((await delegated(b, p2, d2)).executed, 0, "second guard on the same store denies the duplicate");
});

// ════════════════════════════════════════════════════════════════════════════
// RV-01 — prototype pollution cannot supply, replace or transform configuration
// ════════════════════════════════════════════════════════════════════════════
//
// R2 looked up per-option handlers with `NESTED_CAPTURE[key]` on an ordinary
// object: for an option without a registered handler the lookup reached
// `Object.prototype`, and a polluted function there was CALLED with the
// deployer's value and its result adopted (a forged parent executed through a
// polluted `trustedKeySets`; a polluted `replayStore` disabled replay).
// Every mutation of a global prototype below is restored in `finally`.

const OPTION_NAMES = [
  "engine", "getState", "setState", "mapActionToIntent", "beforeExecute", "onDecision", "onBoundaryEvent",
  "expectedAudience", "trustedKeySets", "trustedDelegationAuthorities", "trustedDelegationSigners",
  "delegationRevocationProvider", "requireDelegationRevocation", "revocation", "replayStore", "replayProtection",
  "requireExplicitReplayProtection", "computeStateHash",
] as const;
/** The 13 options without a registered nested handler in R2 (the RV-01 gadget surface). */
const UNHANDLED_IN_R2 = OPTION_NAMES.filter((n) => !["replayProtection", "trustedDelegationSigners", "trustedDelegationAuthorities", "delegationRevocationProvider", "revocation"].includes(n));
const NESTED_NAMES = [
  "mode", "store", "consumeAuthId", "consumeDelegationId", "delegator", "issuer", "policyId", "check",
  "trustedKrlKeySets", "scopes", "provider", "watermarkStore", "accept", "krlIssuer", "keyIssuers",
  "version", "keys", "kid", "alg", "public_key", "status", "not_before", "not_after",
] as const;

/** Temporarily define `name` on `proto`; the previous descriptor (or absence) is restored in `finally`. */
async function withPolluted<T>(proto: object, name: string, descriptor: PropertyDescriptor, fn: () => T | Promise<T>): Promise<T> {
  const previous = Object.getOwnPropertyDescriptor(proto, name);
  Object.defineProperty(proto, name, { configurable: true, ...descriptor });
  try {
    return await fn();
  } finally {
    if (previous) Object.defineProperty(proto, name, previous);
    else delete (proto as Record<string, unknown>)[name];
  }
}
const attackerKeySets = () => [{ issuer: PDP, version: "v1", keys: [{ kid: "k1", alg: "Ed25519", public_key: pem(KP_MAL) }] }, ksAgent()];
const alwaysTrueStore = (): ReplayStore => ({ consumeAuthId: async () => true, consumeDelegationId: async () => true });
const forgedParent = () => parentAuth({ key: KP_MAL }); // claims issuer PDP / kid k1, signed by mallory

test("RV-01 (1) reproduction: the R2 trustedKeySets and replayStore gadgets cannot substitute configuration", async () => {
  // Pollution present at construction: refused, and the polluted function never runs.
  {
    let calls = 0;
    await withPolluted(Object.prototype, "trustedKeySets", { value: () => { calls++; return attackerKeySets(); }, writable: true }, () => {
      assert.throws(() => secure(makeConfig().config), isConfigError(/prototype pollution/));
    });
    assert.equal(calls, 0, "polluted trustedKeySets function never invoked");
  }
  {
    let calls = 0;
    const spy = spyStore();
    await withPolluted(Object.prototype, "replayStore", { value: () => { calls++; return alwaysTrueStore(); }, writable: true }, () => {
      assert.throws(() => secure(makeConfig({ replay: { replayStore: spy.store } }).config), isConfigError(/prototype pollution/));
    });
    assert.equal(calls, 0, "polluted replayStore function never invoked");
  }
  // Pollution after construction: no effect on trust or replay.
  {
    const { config, probe } = makeConfig();
    const sg = secure(config);
    const forged = forgedParent(), forgedDelegation = delegation(forged);
    await withPolluted(Object.prototype, "trustedKeySets", { value: () => attackerKeySets(), writable: true }, async () => {
      assertDenied(await delegated(sg, forged, forgedDelegation), probe, "AUTHORIZATION_VERIFICATION_FAILED", "forged parent", OxDeAIAuthorizationError);
    });
  }
  {
    const spy = spyStore();
    const sg = secure(makeConfig({ replay: { replayStore: spy.store } }).config);
    const p = parentAuth(), d = delegation(p);
    await withPolluted(Object.prototype, "replayStore", { value: () => alwaysTrueStore(), writable: true }, async () => {
      assert.equal((await delegated(sg, p, d)).executed, 1);
      assert.equal((await delegated(sg, p, d)).executed, 0, "replay still denied by the deployer's store");
      assert.deepEqual(spy.calls, [`deleg:${d.delegation_id}`, `auth:${p.auth_id}`, `deleg:${d.delegation_id}`], "the deployer's store answered both presentations");
    });
  }
});

test("RV-01 (2) every option and every nested member name polluted before construction is refused; no polluted value runs", async (t) => {
  for (const name of [...OPTION_NAMES, ...NESTED_NAMES]) {
    await t.test(name, async () => {
      let invoked = 0;
      const kinds: Array<[string, PropertyDescriptor]> = [
        ["function", { value: (...a: unknown[]) => { invoked++; return a[0]; }, writable: true }],
        ["object", { value: {}, writable: true }],
        ["string", { value: "polluted", writable: true }],
        ["false", { value: false, writable: true }],
        ["accessor", { get: () => { invoked++; return undefined; } }],
      ];
      for (const [kind, descriptor] of kinds) {
        await withPolluted(Object.prototype, name, descriptor, () => {
          // A configuration that sets everything it can (signers, F4-C, KRL, shared store).
          const { config } = makeConfig({
            trustedDelegationSigners: [{ delegator: "agent-A", issuer: "agent-A" }],
            delegationRevocationProvider: { check: async () => ({ status: "ACTIVE" }) },
            revocation: krlConfig(() => [krl([])]),
          });
          assert.throws(() => secure(config), isConfigError(new RegExp(`Object\\.prototype has a property named "${name}".*prototype pollution`)), `${name} (${kind})`);
        });
      }
      assert.equal(invoked, 0, `${name}: no polluted function or getter was invoked`);
    });
  }
  // Array holes and array-shaped entries.
  await withPolluted(Array.prototype, "0", { value: { delegator: "agent-A", issuer: "mallory" }, writable: true }, () => {
    assert.throws(() => secure(makeConfig().config), isConfigError(/Array\.prototype has a property named "0"/));
  });
  for (const name of ["issuer", "policyId"]) {
    await withPolluted(Array.prototype, name, { value: "x", writable: true }, () => {
      assert.throws(() => secure(makeConfig().config), isConfigError(/Array\.prototype/), name);
    });
  }
  await withPolluted(Function.prototype, "consumeAuthId", { value: async () => true, writable: true }, () => {
    assert.throws(() => secure(makeConfig().config), isConfigError(/Function\.prototype/));
  });
  // Global state is restored: construction works again.
  assert.doesNotThrow(() => secure(makeConfig().config));
});

test("RV-01 (3) the 13 options without a registered handler: pollution never supplies an option the deployer omitted", async () => {
  assert.equal(UNHANDLED_IN_R2.length, 13);
  for (const name of UNHANDLED_IN_R2) {
    const { config } = makeConfig();
    delete (config as unknown as Record<string, unknown>)[name]; // the deployer omits it
    await withPolluted(Object.prototype, name, { value: () => true, writable: true }, () => {
      assert.throws(() => secure(config), isConfigError(/prototype pollution/), name);
    });
  }
});

test("RV-01 (4) pollution AFTER construction cannot widen authority, revocation or replay (all names, all value kinds)", async (t) => {
  const payloads: Array<[string, unknown]> = [
    ["function", () => true],
    ["function-keys", () => attackerKeySets()],
    ["function-store", () => alwaysTrueStore()],
    ["object", {}],
    ["array", [{ issuer: PDP, policyId: POLICY }, { delegator: "agent-A", issuer: "mallory" }]],
    ["string", "mallory"],
    ["false", false],
  ];
  for (const name of [...OPTION_NAMES, ...NESTED_NAMES]) {
    await t.test(name, async () => {
      for (const [kind, value] of payloads) {
        const spy = spyStore();
        const { config, probe } = makeConfig({
          replay: { replayProtection: { mode: "shared", store: spy.store } },
          trustedDelegationSigners: [{ delegator: "agent-A", issuer: "agent-A" }],
          requireDelegationRevocation: true,
          delegationRevocationProvider: { check: async () => ({ status: "ACTIVE" }) },
        });
        const sg = secure(config);
        // Signed artifacts are created BEFORE polluting: core's signing
        // canonicalization would otherwise see the polluted fields.
        const p = parentAuth(), d = delegation(p);
        const forged = forgedParent(), forgedDelegation = delegation(forged);
        const pm = parentAuth(), mallory = malloryDelegation(pm);
        await withPolluted(Object.prototype, name, { value, writable: true }, async () => {
          const label = `${name}=${kind}`;
          const first = await delegated(sg, p, d);
          assert.ok(first.executed <= 1, label);
          probe.calls.length = 0; probe.hook.n = 0; spy.calls.length = 0;
          assert.equal((await delegated(sg, p, d)).executed, 0, `${label}: replay`);
          assert.equal((await delegated(sg, forged, forgedDelegation)).executed, 0, `${label}: forged parent`);
          assert.equal((await delegated(sg, pm, mallory)).executed, 0, `${label}: unauthorized signer`);
          if ((OPTION_NAMES as readonly string[]).includes(name)) {
            // Top-level options are fully captured: legitimate behaviour is unchanged too.
            assert.equal(first.executed, 1, `${label}: legitimate delegation (${String(first.error)})`);
          }
        });
      }
    });
  }
  // Revocation required with no provider configured: polluting a provider in later does not satisfy it.
  {
    const { config, probe } = makeConfig({ requireDelegationRevocation: true });
    const sg = secure(config);
    await withPolluted(Object.prototype, "delegationRevocationProvider", { value: { check: async () => ({ status: "ACTIVE" }) }, writable: true }, async () => {
      assertDenied(await delegated(sg), probe, "DELEGATION_REVOCATION_UNAVAILABLE", "polluted provider after construction");
    });
  }
});

test("RV-01 (5) supported inherited and accessor configuration still works (REV-R1 / REV-R2 forms)", async () => {
  for (const form of FORMS) {
    const spy = spyStore();
    const { config, probe } = makeConfig({
      replay: { replayProtection: { mode: "shared", store: spy.store } },
      trustedDelegationSigners: [{ delegator: "agent-A", issuer: "agent-A" }],
    });
    const sg = secure(reshape(config, form, ["replayProtection", "trustedDelegationSigners", "trustedKeySets", "expectedAudience", "engine"]));
    const p = parentAuth(), d = delegation(p);
    assert.equal((await delegated(sg, p, d)).executed, 1, form);
    assert.equal(spy.calls.length, 2, `${form}: shared store used`);
    assert.equal((await delegated(sg, p, d)).executed, 0, `${form}: replay denied`);
    probe.hook.n = 0; probe.calls.length = 0;
    assertDenied(await delegated(sg, parentAuth(), malloryDelegation), probe, "DELEGATION_VERIFICATION_FAILED", `${form}: signer`);
  }
  // A deployer prototype (not Object.prototype) still supplies options.
  const { config } = makeConfig();
  const proto = { trustedKeySets: config.trustedKeySets, expectedAudience: config.expectedAudience };
  const { trustedKeySets: _k, expectedAudience: _a, ...rest } = config;
  void _k; void _a;
  assert.equal((await delegated(secure(Object.assign(Object.create(proto), rest) as OxDeAIGuardConfig))).executed, 1);
});

// ════════════════════════════════════════════════════════════════════════════
// RV-02 — replay-store methods resolved once, before replay resolution
// ════════════════════════════════════════════════════════════════════════════

test("RV-02 (1) store method getters are read exactly once, keep their receiver, and are not re-read per call", async () => {
  for (const posture of ["shared", "legacy"] as const) {
    const inner = createInMemoryReplayStore();
    const reads = { auth: 0, deleg: 0 };
    class CountingStore {
      seen = 0;
      get consumeAuthId() { reads.auth++; return async function (this: CountingStore, id: string, x: { expiry: number }) { this.seen++; return inner.consumeAuthId(id, x); }; }
      get consumeDelegationId() { reads.deleg++; return async function (this: CountingStore, id: string, x: { expiry: number }) { this.seen++; return inner.consumeDelegationId!(id, x); }; }
    }
    const store = new CountingStore();
    const replay = posture === "shared" ? { replayProtection: { mode: "shared" as const, store } } : { replayStore: store };
    const sg = secure(makeConfig({ replay }).config);
    assert.deepEqual(reads, { auth: 1, deleg: 1 }, `${posture}: one read each at construction`);
    const p = parentAuth(), d = delegation(p);
    assert.equal((await delegated(sg, p, d)).executed, 1);
    assert.equal((await delegated(sg, p, d)).executed, 0, `${posture}: replay denied`);
    assert.equal(store.seen, 3, `${posture}: methods ran with the store as receiver`);
    assert.deepEqual(reads, { auth: 1, deleg: 1 }, `${posture}: never re-read`);
  }
});

test("RV-02 (2) a throwing store-method getter is a configuration error in shared and legacy modes", () => {
  for (const member of ["consumeAuthId", "consumeDelegationId"]) {
    const store = Object.defineProperty({ consumeAuthId: async () => true }, member, { get: () => { throw new Error("vault down"); } });
    for (const replay of [{ replayProtection: { mode: "shared" as const, store: store as ReplayStore } }, { replayStore: store as ReplayStore }]) {
      assert.throws(() => secure(makeConfig({ replay }).config), isConfigError(new RegExp(`${member} could not be read`)), member);
    }
  }
});

test("RV-02 (3) structural validation, built-in-store rejection and fail-closed behaviour are preserved", async () => {
  // shared: a non-callable member is still rejected at construction.
  assert.throws(() => secure(makeConfig({ replay: { replayProtection: { mode: "shared", store: { consumeAuthId: "nope" } as never } } }).config), OxDeAIGuardConfigurationError);
  assert.throws(() => secure(makeConfig({ replay: { replayProtection: { mode: "shared", store: { consumeAuthId: async () => true, consumeDelegationId: 5 } as never } } }).config), OxDeAIGuardConfigurationError);
  // shared: OxDeAI's built-in in-memory store is still refused, with the resolver's message.
  assert.throws(() => secure(makeConfig({ replay: { replayProtection: { mode: "shared", store: createInMemoryReplayStore() } } }).config),
    isConfigError(/mode 'shared' requires a durable backend/));
  // legacy: the built-in store is still accepted (back-compat) and enforces replay.
  {
    const sg = secure(makeConfig({ replay: { replayStore: createInMemoryReplayStore() } }).config);
    const p = parentAuth(), d = delegation(p);
    assert.equal((await delegated(sg, p, d)).executed, 1);
    assert.equal((await delegated(sg, p, d)).executed, 0);
  }
  // legacy: a non-callable consumeAuthId still fails closed per call.
  {
    const { config, probe } = makeConfig({ replay: { replayStore: { consumeAuthId: "nope" } as never } });
    const r = await direct(secure(config));
    assert.equal(r.executed, 0);
    assert.equal(probe.events.at(-1)?.boundaryFailure, "REPLAY_STORE_UNAVAILABLE");
  }
  // Optional consumeDelegationId absent: parent auth is still consumed once.
  {
    const inner = createInMemoryReplayStore(); let n = 0;
    const sg = secure(makeConfig({ replay: { replayProtection: { mode: "shared", store: { consumeAuthId: async (i, x) => { n++; return inner.consumeAuthId(i, x); } } } } }).config);
    const p = parentAuth(), d = delegation(p);
    assert.equal((await delegated(sg, p, d)).executed, 1);
    assert.equal((await delegated(sg, p, d)).executed, 0);
    assert.equal(n, 2);
  }
});

// ════════════════════════════════════════════════════════════════════════════
// IR-01 — pollution introduced DURING construction (time-of-check/time-of-use)
//
// A deployer getter or Proxy trap that runs while the configuration is read can
// pollute an intrinsic prototype after the first RV-01 check. Later reads of an
// omitted option would inherit the polluted value. Construction must fail; no
// guard may be returned that honours the polluted value.

const isPollutionRefusal = isConfigError(/prototype pollution/);
const assertNoOwn = (proto: object, name: string) =>
  assert.equal(Object.getOwnPropertyDescriptor(proto, name), undefined, `${name} must be restored`);

/** Replace `config[key]` by a getter that installs `Object.prototype[name] = value` on its first read. */
function pollutingGetter(config: OxDeAIGuardConfig, key: string, name: string, value: unknown): void {
  const original = (config as unknown as Record<string, unknown>)[key];
  delete (config as unknown as Record<string, unknown>)[key];
  let fired = false;
  Object.defineProperty(config, key, {
    enumerable: true, configurable: true,
    get() {
      if (!fired) { fired = true; Object.defineProperty(Object.prototype, name, { value, configurable: true, writable: true, enumerable: false }); }
      return original;
    },
  });
}

test("IR-01 (1) a getter that pollutes Object.prototype.replayStore during capture fails construction (no replay bypass)", async (t) => {
  for (const key of ["engine", "getState", "expectedAudience", "trustedKeySets", "computeStateHash", "mapActionToIntent", "onBoundaryEvent"]) {
    await t.test(`getter on ${key}`, () => {
      try {
        // Deployer omitted every replay option: a polluted replayStore would be adopted.
        const { config } = makeConfig({ replay: {} });
        pollutingGetter(config, key, "replayStore", alwaysTrueStore());
        assert.throws(() => secure(config), isPollutionRefusal);
      } finally {
        delete (Object.prototype as Record<string, unknown>).replayStore;
      }
      assertNoOwn(Object.prototype, "replayStore");
    });
  }
});

test("IR-01 (2) a getter that pollutes delegationRevocationProvider(ACTIVE) during capture fails construction (no revocation bypass)", () => {
  try {
    const { config } = makeConfig({ requireDelegationRevocation: true });
    pollutingGetter(config, "engine", "delegationRevocationProvider", { check: async () => ({ status: "ACTIVE" }) });
    assert.throws(() => secure(config), isPollutionRefusal);
  } finally {
    delete (Object.prototype as Record<string, unknown>).delegationRevocationProvider;
  }
  assertNoOwn(Object.prototype, "delegationRevocationProvider");
});

test("IR-01 (3) a Proxy get trap that pollutes during capture fails construction", () => {
  try {
    const { config } = makeConfig({ replay: {} });
    let installed = false;
    const px = new Proxy(config, {
      get(target, key, receiver) {
        if (key === "engine" && !installed) {
          installed = true;
          Object.defineProperty(Object.prototype, "replayStore", { value: alwaysTrueStore(), configurable: true, writable: true });
        }
        return Reflect.get(target, key, receiver);
      },
    });
    assert.throws(() => secure(px), isPollutionRefusal);
  } finally {
    delete (Object.prototype as Record<string, unknown>).replayStore;
  }
  assertNoOwn(Object.prototype, "replayStore");
});

test("IR-01 (4) pollution from deployer code run AFTER the capture reads (engine getter during validation) fails construction", () => {
  // The main trustedKeySets entries are live and not read at construction; the
  // engine object is live too, and OxDeAIGuard's validation reads
  // `engine.evaluatePure` after the capture loop. Only the final check in
  // createSecureGuard sees pollution introduced there.
  try {
    const { config } = makeConfig({ replay: {} });
    const engine = config.engine as unknown as Record<string, unknown>;
    const evaluatePure = engine.evaluatePure;
    let fired = false;
    Object.defineProperty(engine, "evaluatePure", {
      enumerable: false, configurable: true,
      get() {
        if (!fired) { fired = true; Object.defineProperty(Object.prototype, "replayStore", { value: alwaysTrueStore(), configurable: true, writable: true }); }
        return evaluatePure;
      },
    });
    assert.throws(() => secure(config), isPollutionRefusal);
    assert.equal(fired, true, "the engine getter ran during construction");
  } finally {
    delete (Object.prototype as Record<string, unknown>).replayStore;
  }
  assertNoOwn(Object.prototype, "replayStore");
});

test("IR-01 (5) control: the same configs without pollution construct, execute once and deny replay", async () => {
  const { config } = makeConfig({ replay: {} });
  pollutingGetter(config, "engine", "__ir01_unrelated_never_read__", 1);
  try {
    const sg = secure(config);
    const p = parentAuth(), d = delegation(p);
    assert.equal((await delegated(sg, p, d)).executed, 1);
    assert.equal((await delegated(sg, p, d)).executed, 0, "replay denied by the process-local store");
  } finally {
    delete (Object.prototype as Record<string, unknown>).__ir01_unrelated_never_read__;
  }
  assertNoOwn(Object.prototype, "__ir01_unrelated_never_read__");
});


// ════════════════════════════════════════════════════════════════════════════
// IR-03 — inherited `then` (thenable gadget) vs callback results
//
// A function on Object.prototype.then (or Array.prototype.then) is called by
// the promise machinery whenever a promise settles with a plain object or
// array, and decides what the promise settles with. Without the fix it turned
// an F4-C REVOKED into ACTIVE, a denying state into a permissive one, and the
// current KRL into an older one, and the request EXECUTED. Every denial below
// asserts that nothing executed, no hook ran and no replay id was consumed.

const IR03 = { calls: 0, rewrites: 0 };
type Rewrite = (v: unknown) => unknown;
/**
 * Stays installed and rewrites the matching value. Every value (rewritten or
 * not) is delivered transparently: `then` is lifted for the synchronous
 * duration of `resolve`, so the value is not adopted again, and reinstalled at
 * once. Unrelated promises in the process (the test runner's) are unaffected.
 */
function persistentThen(rewrite: Rewrite) {
  return function (this: unknown, resolve: (v: unknown) => void) {
    IR03.calls++;
    const r = rewrite(this);
    if (r !== this) IR03.rewrites++;
    const onObject = Object.getOwnPropertyDescriptor(Object.prototype, "then");
    const onArray = Object.getOwnPropertyDescriptor(Array.prototype, "then");
    delete (Object.prototype as Record<string, unknown>).then;
    delete (Array.prototype as unknown as Record<string, unknown>).then;
    try {
      resolve(r);
    } finally {
      if (onObject) Object.defineProperty(Object.prototype, "then", onObject);
      if (onArray) Object.defineProperty(Array.prototype, "then", onArray);
    }
  };
}
/** Removes itself on first use, so no `then` is left for a later check. */
function selfRemovingThen(rewrite: Rewrite) {
  return function (this: unknown, resolve: (v: unknown) => void) {
    IR03.calls++;
    delete (Object.prototype as Record<string, unknown>).then;
    delete (Array.prototype as unknown as Record<string, unknown>).then;
    const r = rewrite(this);
    if (r !== this) IR03.rewrites++;
    resolve(r);
  };
}
function installThen(fn: unknown, proto: object = Object.prototype): void {
  Object.defineProperty(proto, "then", { value: fn, configurable: true, writable: true, enumerable: false });
}
/** Runs `fn` and always removes any `then` from Object.prototype and Array.prototype afterwards. */
async function isolatedThen<T>(fn: () => Promise<T>): Promise<T> {
  IR03.calls = 0; IR03.rewrites = 0;
  try {
    return await fn();
  } finally {
    delete (Object.prototype as Record<string, unknown>).then;
    delete (Array.prototype as unknown as Record<string, unknown>).then;
    assertNoOwn(Object.prototype, "then");
    assertNoOwn(Array.prototype, "then");
  }
}
const revokedToActive: Rewrite = (v) => (v !== null && typeof v === "object" && (v as { status?: unknown }).status === "REVOKED" ? { status: "ACTIVE" } : v);
/** A custom normalizer that installs `then` after getState and before the delegation checks. */
const pollutingNormalizer = (fn: unknown, proto: object = Object.prototype) => (action: ProposedAction) => {
  installThen(fn, proto);
  return defaultNormalizeAction(action);
};
const revokedProvider = (): DelegationRevocationProvider => ({ check: async () => ({ status: "REVOKED" }) });

test("IR-03 (1) then present before the revocation call cannot turn REVOKED into ACTIVE", async () => {
  await isolatedThen(async () => {
    const { config, probe } = makeConfig({
      delegationRevocationProvider: revokedProvider(), requireDelegationRevocation: true,
      mapActionToIntent: pollutingNormalizer(persistentThen(revokedToActive)),
    });
    const r = await delegated(secure(config));
    assertDenied(r, probe, "DELEGATION_REVOCATION_UNAVAILABLE", "then before the call");
    assert.equal(IR03.rewrites, 0, "no provider answer was rewritten");
  });
});

test("IR-03 (2) then installed during the call and removed again is refused (no internal await)", async () => {
  await isolatedThen(async () => {
    const provider: DelegationRevocationProvider = {
      check: async () => { installThen(selfRemovingThen(revokedToActive)); return { status: "REVOKED" }; },
    };
    const { config, probe } = makeConfig({ delegationRevocationProvider: provider, requireDelegationRevocation: true });
    const r = await delegated(secure(config));
    assertDenied(r, probe, "DELEGATION_REVOCATION_UNAVAILABLE", "self-removing then during the call");
  });
  // Same, with a then that stays installed.
  await isolatedThen(async () => {
    const provider: DelegationRevocationProvider = {
      check: async () => { installThen(persistentThen(revokedToActive)); return { status: "REVOKED" }; },
    };
    const { config, probe } = makeConfig({ delegationRevocationProvider: provider, requireDelegationRevocation: true });
    assertDenied(await delegated(secure(config)), probe, "DELEGATION_REVOCATION_UNAVAILABLE", "persistent then during the call");
  });
});

test("IR-03 (3) then installed after the provider's promise settled is refused", async () => {
  await isolatedThen(async () => {
    const provider: DelegationRevocationProvider = {
      check: () => {
        const p = Promise.resolve({ status: "ACTIVE" as const });
        void p.then(() => installThen(persistentThen((v) => v)));
        return p;
      },
    };
    const { config, probe } = makeConfig({ delegationRevocationProvider: provider, requireDelegationRevocation: true });
    assertDenied(await delegated(secure(config)), probe, "DELEGATION_REVOCATION_UNAVAILABLE", "then after the call");
  });
});

test("IR-03 (4) then present before any callback fails closed at state load (secure and OxDeAIGuard paths)", async () => {
  await isolatedThen(async () => {
    const { config, probe } = makeConfig({ delegationRevocationProvider: revokedProvider(), requireDelegationRevocation: true });
    const sg = secure(config);
    installThen(persistentThen(revokedToActive));
    const r = await delegated(sg);
    assertDenied(r, probe, "UNCLASSIFIED", "secure guard", OxDeAIAuthorizationError);
    assert.equal(probe.events.at(-1)?.stage, "STATE_LOAD");
  });
  await isolatedThen(async () => {
    const { config, probe } = makeConfig({ delegationRevocationProvider: revokedProvider(), requireDelegationRevocation: true });
    const g = OxDeAIGuard(config);
    const p = parentAuth(), d = delegation(p);
    let executed = 0; let error: unknown;
    installThen(persistentThen(revokedToActive));
    try { await g(ACTION, async () => { executed++; return "ok"; }, { delegation: { delegation: d, parentAuth: p, parentScope: PARENT_SCOPE } }); }
    catch (e) { error = e; }
    assertDenied({ executed, error }, probe, "UNCLASSIFIED", "OxDeAIGuard", OxDeAIAuthorizationError);
    assert.equal(probe.events.at(-1)?.stage, "STATE_LOAD");
  });
});

const PERMISSIVE_STATE = buildState({ agent_id: "agent-B", allow_action_types: ["PROVISION"], budget_limit: 10n ** 15n, max_amount_per_action: 10n ** 15n, velocity_max_actions: 10_000, max_concurrent: 16 });
const DENYING_STATE = buildState({ agent_id: "agent-B", allow_action_types: [], budget_limit: 0n, max_amount_per_action: 0n, velocity_max_actions: 0, max_concurrent: 0 });
const denyingToPermissive: Rewrite = (v) =>
  v !== null && typeof v === "object" && (v as { state?: unknown }).state === DENYING_STATE
    ? { state: PERMISSIVE_STATE, version: (v as { version: unknown }).version }
    : v;

test("IR-03 (5) getState: a then cannot replace a denying state by a permissive one", async () => {
  const cases: Array<[string, () => OxDeAIGuardConfig["getState"], "before" | "during"]> = [
    ["synchronous getState, then before the call", () => () => ({ state: DENYING_STATE, version: 0 }), "before"],
    ["async getState, then before the call", () => async () => ({ state: DENYING_STATE, version: 0 }), "before"],
    ["synchronous getState installs a self-removing then", () => () => { installThen(selfRemovingThen(denyingToPermissive)); return { state: DENYING_STATE, version: 0 }; }, "during"],
    ["async getState installs a self-removing then (no internal await)", () => async () => { installThen(selfRemovingThen(denyingToPermissive)); return { state: DENYING_STATE, version: 0 }; }, "during"],
  ];
  for (const [label, getState, when] of cases) {
    await isolatedThen(async () => {
      let setStateCalls = 0;
      const { config, probe } = makeConfig({ getState: getState(), setState: () => { setStateCalls++; return true; } });
      const sg = secure(config);
      if (when === "before") installThen(persistentThen(denyingToPermissive));
      const r = await direct(sg);
      assert.equal(r.executed, 0, `${label}: must not execute (${String(r.error)})`);
      assert.equal(setStateCalls, 0, `${label}: no state commit`);
      assert.equal(probe.hook.n, 0, `${label}: beforeExecute must not run`);
      assert.deepEqual(probe.calls, [], `${label}: no replay consumption`);
      assert.ok(r.error instanceof OxDeAIAuthorizationError, `${label}: ${String(r.error)}`);
      assert.equal(probe.events.at(-1)?.stage, "STATE_LOAD", label);
      assert.equal(probe.events.at(-1)?.boundaryFailure, "UNCLASSIFIED", label);
      // A synchronous result never passes through promise resolution, and a
      // then present beforehand is refused before the call. An async getState
      // resolves its own promise, so the rewrite can happen there; the guard
      // detects it right after the call and refuses the value (asserted above).
      if (!label.startsWith("async getState installs")) assert.equal(IR03.rewrites, 0, `${label}: the state was never rewritten`);
    });
  }
  // Controls: the denying state is denied by the PDP; sync and async permissive stores execute.
  {
    const r = await direct(secure(makeConfig({ getState: () => ({ state: DENYING_STATE, version: 0 }) }).config));
    assert.equal(r.executed, 0);
    assert.ok(r.error instanceof OxDeAIDenyError, String(r.error));
  }
  assert.equal((await direct(secure(makeConfig({ getState: () => ({ state: PERMISSIVE_STATE, version: 0 }) }).config))).executed, 1);
  assert.equal((await direct(secure(makeConfig({ getState: async () => { await new Promise((res) => setTimeout(res, 1)); return { state: PERMISSIVE_STATE, version: 0 }; } }).config))).executed, 1);
});

test("IR-03 (6) SignedKRLV1: a then cannot replace the current KRL by an older one", async () => {
  const current = krl(["a1"], 2); // revokes the delegation signer key
  const older = krl([], 1); // validly signed, revokes nothing
  const krlToOlder: Rewrite = (v) => (Array.isArray(v) && (v[0] as SignedKRLV1 | undefined)?.krl_version === 2 ? [older] : v);
  const cases: Array<[string, () => Partial<OxDeAIGuardConfig>]> = [
    ["Object.prototype.then before the KRL call", () => ({ revocation: krlConfig(async () => [current]), mapActionToIntent: pollutingNormalizer(persistentThen(krlToOlder)) })],
    ["Array.prototype.then before the KRL call", () => ({ revocation: krlConfig(async () => [current]), mapActionToIntent: pollutingNormalizer(persistentThen(krlToOlder), Array.prototype) })],
    ["synchronous provider installs a self-removing then", () => ({ revocation: krlConfig(() => { installThen(selfRemovingThen(krlToOlder)); return [current]; }) })],
    ["async provider installs a self-removing then (no internal await)", () => ({ revocation: krlConfig(async () => { installThen(selfRemovingThen(krlToOlder)); return [current]; }) })],
    ["then installed after the provider's promise settled", () => ({ revocation: krlConfig(() => { const p = Promise.resolve([current]); void p.then(() => installThen(persistentThen((v) => v))); return p; }) })],
  ];
  for (const [label, override] of cases) {
    await isolatedThen(async () => {
      const { config, probe } = makeConfig(override());
      assertDenied(await delegated(secure(config)), probe, "REVOCATION_STATE_UNAVAILABLE", label);
      if (!label.startsWith("async provider installs")) assert.equal(IR03.rewrites, 0, `${label}: the KRL list was never rewritten`);
    });
  }
  // Controls: the current KRL denies (key revoked); a clean KRL from an async provider executes.
  {
    const { config, probe } = makeConfig({ revocation: krlConfig(async () => [current]) });
    assertDenied(await delegated(secure(config)), probe, "DELEGATION_VERIFICATION_FAILED", "current KRL");
  }
  assert.equal((await delegated(secure(makeConfig({ revocation: krlConfig(async () => [krl([], 1)]) }).config))).executed, 1);
});

test("IR-03 (7) legitimate providers keep working; invalid or unavailable answers still fail closed", async () => {
  const run = async (check: DelegationRevocationProvider["check"]) => {
    const { config, probe } = makeConfig({ delegationRevocationProvider: { check }, requireDelegationRevocation: true });
    return { r: await delegated(secure(config)), probe };
  };
  const ok = async (label: string, check: DelegationRevocationProvider["check"]) => {
    const { r } = await run(check);
    assert.equal(r.executed, 1, `${label}: ${String(r.error)}`);
  };
  const denied = async (label: string, check: DelegationRevocationProvider["check"], code: string) => {
    const { r, probe } = await run(check);
    assertDenied(r, probe, code, label);
  };
  await ok("async ACTIVE", async () => ({ status: "ACTIVE" }));
  await ok("async ACTIVE after internal awaits", async () => { await null; await new Promise((res) => setTimeout(res, 1)); return { status: "ACTIVE" }; });
  await ok("synchronous plain ACTIVE", (() => ({ status: "ACTIVE" })) as unknown as DelegationRevocationProvider["check"]);
  await ok("non-native thenable ACTIVE", (() => ({ then(res: (v: unknown) => void) { res({ status: "ACTIVE" }); } })) as unknown as DelegationRevocationProvider["check"]);
  await denied("async REVOKED", async () => ({ status: "REVOKED" }), "DELEGATION_REVOKED");
  await denied("synchronous plain REVOKED", (() => ({ status: "REVOKED" })) as unknown as DelegationRevocationProvider["check"], "DELEGATION_REVOKED");
  await denied("rejected promise", async () => { throw new Error("down"); }, "DELEGATION_REVOCATION_UNAVAILABLE");
  await denied("synchronous throw", (() => { throw new Error("down"); }) as unknown as DelegationRevocationProvider["check"], "DELEGATION_REVOCATION_UNAVAILABLE");
  await denied("unknown status", async () => ({ status: "MAYBE" }) as never, "DELEGATION_REVOCATION_UNAVAILABLE");
  await denied("inherited status", async () => Object.create({ status: "ACTIVE" }), "DELEGATION_REVOCATION_UNAVAILABLE");
  // Data-only pollution (a non-callable then) cannot substitute anything, and still fails closed.
  await isolatedThen(async () => {
    const { config, probe } = makeConfig({
      delegationRevocationProvider: revokedProvider(), requireDelegationRevocation: true,
      mapActionToIntent: pollutingNormalizer({ status: "ACTIVE" }),
    });
    assertDenied(await delegated(secure(config)), probe, "DELEGATION_REVOCATION_UNAVAILABLE", "non-callable then");
  });
});

test("IR-03 (8) RESIDUAL: a then installed and removed while an async provider is pending after an internal await",
  { todo: "IR-03 residual, not closable inside the guard: the provider's promise is resolved in its own promise machinery, before the guard sees the value. Requires in-process code execution timed to the request (out of the documented threat model). See README 'Callback results and inherited then'." },
  async () => {
    await isolatedThen(async () => {
      const provider: DelegationRevocationProvider = {
        check: async () => { await null; installThen(selfRemovingThen(revokedToActive)); return { status: "REVOKED" }; },
      };
      const { config } = makeConfig({ delegationRevocationProvider: provider, requireDelegationRevocation: true });
      assert.equal((await delegated(secure(config))).executed, 0);
    });
  });
