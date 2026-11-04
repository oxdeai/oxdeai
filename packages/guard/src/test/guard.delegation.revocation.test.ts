// SPDX-License-Identifier: Apache-2.0
/**
 * F4-R6-07 (Lot C, DECISION_REQUIRED reference implementation) — opt-in
 * SignedKRLV1 revocation enforcement on the guard delegation path.
 *
 * Reproduced on the baseline: a kid revoked by a VALID SignedKRLV1 still
 * authorized delegated execution; a `revocation` config key was ignored.
 *
 * Synthetic keys and identities only.
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
import { createInMemoryReplayStore } from "../replayStore.js";
import type { ReplayStore } from "../replayStore.js";
import { createInMemoryKrlWatermarkStore } from "../revocation.js";
import type { GuardKrlWatermarkStore, GuardRevocationConfig } from "../revocation.js";
import { OxDeAIAuthorizationError, OxDeAIDelegationError, OxDeAIGuardConfigurationError } from "../errors.js";
import type { GuardBoundaryAuditEvent } from "../boundaryEvent.js";
import type { OxDeAIGuardConfig, ProposedAction } from "../types.js";

const kp = () => generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
const KP_PDP = kp(), KP_AGENT = kp(), KP_KRL = kp(), KP_KRL_B = kp(), KP_OTHER = kp();
const PDP = "pdp-issuer", POLICY = "rev-policy";
const KS_PDP: KeySet = { issuer: PDP, version: "v1", keys: [{ kid: "k1", alg: "Ed25519", public_key: KP_PDP.publicKey.toString() }] };
const KS_AGENT: KeySet = { issuer: "agent-A", version: "v1", keys: [{ kid: "a1", alg: "Ed25519", public_key: KP_AGENT.publicKey.toString() }] };
const KS_KRL: KeySet = { issuer: "krl-authority", version: "v1", keys: [{ kid: "r1", alg: "Ed25519", public_key: KP_KRL.publicKey.toString() }] };
const KS_KRL_B: KeySet = { issuer: "krl-authority-b", version: "v1", keys: [{ kid: "rb", alg: "Ed25519", public_key: KP_KRL_B.publicKey.toString() }] };
const T_NOW = Math.floor(Date.now() / 1000);
const PARENT_SCOPE: DelegationScope = { tools: ["provision_gpu"], max_amount: 1_000_000_000n };
const uid = () => randomBytes(8).toString("hex");

function makeParent(): AuthorizationV1 {
  return signAuthorizationEd25519({
    auth_id: `rev-parent-${uid()}`, issuer: PDP, audience: "agent-A", intent_hash: "a".repeat(64), state_hash: "b".repeat(64),
    policy_id: POLICY, decision: "ALLOW", issued_at: T_NOW - 60, expiry: T_NOW + 900, kid: "k1",
  }, KP_PDP.privateKey.toString());
}
/** Self-delegation: agent-A signs with its own key a1. */
function makeChild(p: AuthorizationV1): DelegationV1 {
  return createDelegation(p, { delegatee: "agent-B", issuer: "agent-A", kid: "a1", scope: { tools: ["provision_gpu"] }, expiry: T_NOW + 300, delegationId: `rev-deleg-${uid()}` }, KP_AGENT.privateKey.toString());
}
function krl(revoked: string[], o: { issuer?: string; version?: number; notAfter?: number; key?: typeof KP_KRL; kid?: string } = {}): SignedKRLV1 {
  const env: SignedKRLV1 = {
    version: "SignedKRLV1", issuer: o.issuer ?? "krl-authority", krl_version: o.version ?? 1, issued_at: T_NOW - 10,
    not_after: o.notAfter ?? T_NOW + 3600, revoked_kids: revoked, nonce: uid(), signature: { alg: "Ed25519", kid: o.kid ?? "r1", sig: "x" },
  };
  return { ...env, signature: { ...env.signature, sig: signEd25519(SIGNING_DOMAINS.KRL_V1, signedKrlSigningPayload(env), (o.key ?? KP_KRL).privateKey.toString()) } };
}
function spyStore(): { store: ReplayStore; calls: string[] } {
  const inner = createInMemoryReplayStore(); const calls: string[] = [];
  return { calls, store: {
    consumeAuthId: async (id, x) => { calls.push(`auth:${id}`); return inner.consumeAuthId(id, x); },
    consumeDelegationId: async (id, x) => { calls.push(`deleg:${id}`); return inner.consumeDelegationId!(id, x); },
  } };
}
const SCOPES = [{ krlIssuer: "krl-authority", keyIssuers: [PDP, "agent-A"] }];
const rev = (provider: GuardRevocationConfig["provider"], extra: Partial<GuardRevocationConfig> = {}): GuardRevocationConfig =>
  ({ trustedKrlKeySets: [KS_KRL], scopes: SCOPES, provider, watermarkStore: createInMemoryKrlWatermarkStore(), ...extra });

function makeConfig(store: ReplayStore, overrides: Partial<OxDeAIGuardConfig> = {}): OxDeAIGuardConfig {
  const state = buildState({ agent_id: "agent-B", allow_action_types: ["PROVISION"], budget_limit: 10n ** 15n, max_amount_per_action: 10n ** 15n, velocity_max_actions: 10_000, max_concurrent: 16 });
  return {
    engine: new PolicyEngine({ policy_version: "v1", engine_secret: "synthetic-secret-at-least-32-characters!!", authorization_signing_alg: "Ed25519",
      authorization_signing_kid: "k1", authorization_issuer: PDP, authorization_audience: "agent-A", authorization_ttl_seconds: 600,
      authorization_private_key_pem: KP_PDP.privateKey.toString(), ...RECOMMENDED_TRUSTED_TIME_PROFILE }),
    getState: () => ({ state, version: 0 }), setState: () => true,
    trustedKeySets: [KS_PDP, KS_AGENT], expectedAudience: "agent-A",
    trustedDelegationAuthorities: [{ issuer: PDP, policyId: POLICY }],
    replayProtection: { mode: "shared", store }, ...overrides,
  };
}
const ACTION: ProposedAction = { name: "provision_gpu", args: { asset: "a100" }, estimatedCost: 0, context: { agent_id: "agent-B", target: "gpu-pool" }, timestampSeconds: T_NOW };

async function present(guard: ReturnType<typeof OxDeAIGuard>, p = makeParent(), d = makeChild(p)) {
  let executed = 0; let error: unknown;
  try { await guard(ACTION, async () => { executed++; return "ok"; }, { delegation: { delegation: d, parentAuth: p, parentScope: PARENT_SCOPE } }); }
  catch (e) { error = e; }
  return { executed, error };
}
function setup(revocation: GuardRevocationConfig | undefined, extra: Partial<OxDeAIGuardConfig> = {}) {
  const { store, calls } = spyStore(); const events: GuardBoundaryAuditEvent[] = [];
  const guard = OxDeAIGuard(makeConfig(store, { ...(revocation ? { revocation } : {}), onBoundaryEvent: (e) => { events.push(e); }, ...extra }));
  return { guard, calls, events };
}
function assertDenied(r: { executed: number; error: unknown }, calls: string[], events: GuardBoundaryAuditEvent[], code: string, label: string) {
  assert.equal(r.executed, 0, `${label}: execute must not run`);
  assert.deepEqual(calls, [], `${label}: no replay state consumed`);
  assert.equal(events.at(-1)?.boundaryFailure, code, `${label}: ${String(r.error)}`);
}

test("C0 not configured: behavior unchanged — a kid revoked by a valid KRL still executes (static KeySet.status is the only input)", async () => {
  const { guard } = setup(undefined);
  const r = await present(guard);
  assert.equal(r.executed, 1, String(r.error));
});

test("C1 configured: valid non-revoked keys execute; a verified empty revocation list is positive evidence", async () => {
  for (const list of [[], ["unrelated-kid"]]) {
    const { guard, calls } = setup(rev(() => [krl(list)]));
    const r = await present(guard);
    assert.equal(r.executed, 1, `${JSON.stringify(list)}: ${String(r.error)}`);
    assert.equal(calls.length, 2);
  }
});

test("C2 revoked PARENT authorization key is denied before replay consumption and execution", async () => {
  const { guard, calls, events } = setup(rev(() => [krl(["k1"])]));
  const r = await present(guard);
  assertDenied(r, calls, events, "AUTHORIZATION_VERIFICATION_FAILED", "parent");
  assert.ok(r.error instanceof OxDeAIAuthorizationError && /revoked by a verified SignedKRLV1/.test(r.error.message));
});

test("C3 revoked DELEGATION signing key is denied before replay consumption and execution", async () => {
  const { guard, calls, events } = setup(rev(() => [krl(["a1"])]));
  const r = await present(guard);
  assertDenied(r, calls, events, "DELEGATION_VERIFICATION_FAILED", "delegation");
  assert.ok(r.error instanceof OxDeAIDelegationError, String(r.error));
});

test("C4 invalid KRL signature, KRL signed by an untrusted key, and malformed KRL are denied", async () => {
  const tampered = { ...krl(["k1"]), revoked_kids: [] };
  const otherKey = krl([], { key: KP_OTHER });
  for (const [label, env] of [["tampered", tampered], ["untrusted signer", otherKey], ["malformed", { version: "SignedKRLV1", issuer: "krl-authority" }]] as const) {
    const { guard, calls, events } = setup(rev(() => [env]));
    assertDenied(await present(guard), calls, events, "REVOCATION_STATE_INVALID", label);
  }
});

test("C5 expired KRL (now >= not_after) is denied", async () => {
  for (const notAfter of [T_NOW - 1, T_NOW]) {
    const { guard, calls, events } = setup(rev(() => [krl([], { notAfter })]));
    assertDenied(await present(guard), calls, events, "REVOCATION_STATE_INVALID", `not_after ${notAfter - T_NOW}`);
  }
});

test("C6 unavailable provider is denied: throws, rejects, non-array, empty (missing evidence), null", async () => {
  const providers: Array<[string, GuardRevocationConfig["provider"]]> = [
    ["throws", () => { throw new Error("network down"); }],
    ["rejects", async () => { throw new Error("timeout"); }],
    ["non-array", () => ({}) as unknown as unknown[]],
    ["empty list", () => []],
    ["null", () => null as unknown as unknown[]],
  ];
  for (const [label, provider] of providers) {
    const { guard, calls, events } = setup(rev(provider));
    assertDenied(await present(guard), calls, events, "REVOCATION_STATE_UNAVAILABLE", label);
  }
});

test("C7 rollback to an older krl_version is denied (watermark), and a same-version conflicting KRL is denied", async () => {
  let next: SignedKRLV1 = krl([], { version: 5 });
  const { guard, calls, events } = setup(rev(() => [next]));
  assert.equal((await present(guard)).executed, 1, "v5 accepted");
  calls.length = 0;
  next = krl([], { version: 4 });
  assertDenied(await present(guard), calls, events, "REVOCATION_STATE_INVALID", "rollback v4 < v5");
  next = krl(["other"], { version: 5 });
  assertDenied(await present(guard), calls, events, "REVOCATION_STATE_INVALID", "same version, different content");
  next = krl([], { version: 6 });
  assert.equal((await present(guard)).executed, 1, "v6 accepted");
});

test("C8 multiple issuers are isolated: a kid revoked for one key issuer does not revoke the same kid of another", async () => {
  // KRL-B is authoritative only for an unrelated issuer and revokes "k1" and "a1" there.
  const scopes = [{ krlIssuer: "krl-authority", keyIssuers: [PDP, "agent-A"] }, { krlIssuer: "krl-authority-b", keyIssuers: ["unrelated-issuer"] }];
  const ok = setup(rev(() => [krl([]), krl(["k1", "a1"], { issuer: "krl-authority-b", key: KP_KRL_B, kid: "rb" })], { trustedKrlKeySets: [KS_KRL, KS_KRL_B], scopes }));
  assert.equal((await present(ok.guard)).executed, 1, "isolation");
  // ...but the scoped publisher does revoke for its own key issuers.
  const scopes2 = [{ krlIssuer: "krl-authority", keyIssuers: ["agent-A"] }, { krlIssuer: "krl-authority-b", keyIssuers: [PDP] }];
  const bad = setup(rev(() => [krl([]), krl(["k1"], { issuer: "krl-authority-b", key: KP_KRL_B, kid: "rb" })], { trustedKrlKeySets: [KS_KRL, KS_KRL_B], scopes: scopes2 }));
  assertDenied(await present(bad.guard), bad.calls, bad.events, "AUTHORIZATION_VERIFICATION_FAILED", "scoped revocation");
});

test("C9 every configured KRL issuer must be present exactly once; unknown issuers and uncovered key issuers deny", async () => {
  const two = { trustedKrlKeySets: [KS_KRL, KS_KRL_B], scopes: [{ krlIssuer: "krl-authority", keyIssuers: [PDP, "agent-A"] }, { krlIssuer: "krl-authority-b", keyIssuers: ["x"] }] };
  const missing = setup(rev(() => [krl([])], two));
  assertDenied(await present(missing.guard), missing.calls, missing.events, "REVOCATION_STATE_UNAVAILABLE", "missing second KRL");
  const dup = setup(rev(() => [krl([]), krl([], { version: 2 })]));
  assertDenied(await present(dup.guard), dup.calls, dup.events, "REVOCATION_STATE_INVALID", "duplicate issuer");
  const unknown = setup(rev(() => [krl([]), krl([], { issuer: "krl-authority-b", key: KP_KRL_B, kid: "rb" })], { trustedKrlKeySets: [KS_KRL, KS_KRL_B] }));
  assertDenied(await present(unknown.guard), unknown.calls, unknown.events, "REVOCATION_STATE_INVALID", "unconfigured issuer");
  const uncovered = setup(rev(() => [krl([])], { scopes: [{ krlIssuer: "krl-authority", keyIssuers: [PDP] }] }));
  assertDenied(await present(uncovered.guard), uncovered.calls, uncovered.events, "REVOCATION_STATE_UNAVAILABLE", "delegation key issuer not covered");
});

test("C10 watermark store failures fail closed; a supplied store is used", async () => {
  const failing: GuardKrlWatermarkStore = { accept: async () => { throw new Error("db down"); } };
  const a = setup(rev(() => [krl([])], { watermarkStore: failing }));
  assertDenied(await present(a.guard), a.calls, a.events, "REVOCATION_STATE_UNAVAILABLE", "get throws");
  const noAdvance: GuardKrlWatermarkStore = { accept: async () => { throw new Error("readonly"); } };
  const b = setup(rev(() => [krl([])], { watermarkStore: noAdvance }));
  assertDenied(await present(b.guard), b.calls, b.events, "REVOCATION_STATE_UNAVAILABLE", "advance throws");
  const shared = createInMemoryKrlWatermarkStore();
  assert.equal(await shared.accept("krl-authority", { krlVersion: 9, digest: "a".repeat(64) }), "ACCEPTED");
  const c = setup(rev(() => [krl([], { version: 8 })], { watermarkStore: shared }));
  assertDenied(await present(c.guard), c.calls, c.events, "REVOCATION_STATE_INVALID", "watermark from supplied store");
});

test("C11 provider output is verified, never trusted as returned: Proxy envelope and caller-mutated envelope", async () => {
  const p1 = setup(rev(() => [new Proxy(krl([]), {})]));
  assertDenied(await present(p1.guard), p1.calls, p1.events, "REVOCATION_STATE_INVALID", "Proxy envelope");
  const forged = krl(["k1"]); forged.revoked_kids = []; // contents changed after signing
  const p2 = setup(rev(() => [forged]));
  assertDenied(await present(p2.guard), p2.calls, p2.events, "REVOCATION_STATE_INVALID", "post-signing mutation");
});

test("C12 invalid revocation configuration fails at construction (never silently disables enforcement)", () => {
  const { store } = spyStore();
  const bad: unknown[] = [
    null, "on", [], {},
    { trustedKrlKeySets: [], scopes: SCOPES, provider: () => [] },
    { trustedKrlKeySets: [KS_KRL], scopes: [], provider: () => [] },
    { trustedKrlKeySets: [KS_KRL], scopes: [{ krlIssuer: "krl-authority", keyIssuers: [] }], provider: () => [] },
    { trustedKrlKeySets: [KS_KRL], scopes: [{ krlIssuer: "", keyIssuers: [PDP] }], provider: () => [] },
    { trustedKrlKeySets: [KS_KRL], scopes: [...SCOPES, ...SCOPES], provider: () => [] },
    { trustedKrlKeySets: [KS_KRL], scopes: SCOPES },
    { trustedKrlKeySets: [KS_KRL], scopes: SCOPES, provider: () => [], watermarkStore: {} },
    // KRL trust domain must be separate from the artifact trust domain.
    { trustedKrlKeySets: [{ ...KS_KRL, keys: [{ ...KS_KRL.keys[0], public_key: KP_PDP.publicKey.toString() }] }], scopes: SCOPES, provider: () => [] },
  ];
  for (const revocation of bad) {
    assert.throws(() => OxDeAIGuard(makeConfig(store, { revocation: revocation as GuardRevocationConfig })), OxDeAIGuardConfigurationError, JSON.stringify(revocation));
  }
});

test("C13 static KeySet.status revocation keeps working alongside KRL enforcement", async () => {
  const revokedKs: KeySet = { ...KS_PDP, keys: [{ ...KS_PDP.keys[0], status: "revoked" }] };
  const { guard, calls } = setup(rev(() => [krl([])]), { trustedKeySets: [revokedKs, KS_AGENT] });
  const r = await present(guard);
  assert.equal(r.executed, 0);
  assert.deepEqual(calls, []);
  assert.match(String((r.error as Error)?.message), /AUTH_KEY_INACTIVE/);
});

test("C14 concurrent watermark acceptance remains monotonic", async () => {
  const store = createInMemoryKrlWatermarkStore();

  const v5 = { krlVersion: 5, digest: "a".repeat(64) };
  const v6 = { krlVersion: 6, digest: "b".repeat(64) };
  const conflictingV6 = { krlVersion: 6, digest: "c".repeat(64) };

  const results = await Promise.all([
    store.accept("issuer", v5),
    store.accept("issuer", v6),
  ]);

  assert.ok(results.every((r) => r === "ACCEPTED" || r === "REJECTED"));

  assert.equal(await store.accept("issuer", v5), "REJECTED");
  assert.equal(await store.accept("issuer", v6), "ACCEPTED");
  assert.equal(await store.accept("issuer", conflictingV6), "REJECTED");
});

test("C15 watermark store rejects invalid candidates", async () => {
  const store = createInMemoryKrlWatermarkStore();

  assert.equal(
    await store.accept("issuer", { krlVersion: -1, digest: "a".repeat(64) }),
    "REJECTED"
  );

  assert.equal(
    await store.accept("issuer", { krlVersion: 1, digest: "invalid" }),
    "REJECTED"
  );
});


test("C16 hostile provider array fails closed", async () => {
  const hostile = new Proxy([krl([])], {
    get(target, property, receiver) {
      if (property === "then") return undefined;
      throw new Error("hostile array access");
    },
  });

  const { guard, calls, events } = setup(rev(() => hostile));

  assertDenied(
    await present(guard),
    calls,
    events,
    "REVOCATION_STATE_INVALID",
    "hostile array"
  );
});

test("C17 watermark store rejects null candidate", async () => {
  const store = createInMemoryKrlWatermarkStore();

  assert.equal(
    await store.accept(
      "issuer",
      null as unknown as {
        krlVersion: number;
        digest: string;
      }
    ),
    "REJECTED"
  );
});
