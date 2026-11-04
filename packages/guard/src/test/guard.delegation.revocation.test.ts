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
import { createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";

import {
  PolicyEngine,
  RECOMMENDED_TRUSTED_TIME_PROFILE,
  SIGNING_DOMAINS,
  createDelegation,
  signAuthorizationEd25519,
  signEd25519,
  signedKrlSigningPayload,
  authorizationSigningPayload,
  verifyAuthorization,
  delegationParentHash,
  delegationSigningPayload,
  sha256HexFromJson,
  toPublicAuthorizationV1,
} from "@oxdeai/core";
import type { AuthorizationV1, DelegationScope, DelegationV1, KeySet, SignedKRLV1 } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { OxDeAIGuard } from "../guard.js";
import { createInMemoryReplayStore } from "../replayStore.js";
import type { ReplayStore } from "../replayStore.js";
import { createInMemoryKrlWatermarkStore, resolveAuthorizationSigningKid, pinKeySet, ed25519PublicKeyIdentity } from "../revocation.js";
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

// ── F4-LOT-C-R1 (F1): verified signing-key identity == revocation-checked identity ──
//
// Core selects the parent verification key from `signature.kid` when
// `signature` is an object, and that nested kid is unsigned when top-level
// alg/kid are present. Revocation must apply to the key that actually verified.

const KP_PDP_2 = kp();
const KS_PDP_2KEYS: KeySet = {
  issuer: PDP, version: "v1",
  keys: [...KS_PDP.keys, { kid: "k2", alg: "Ed25519", public_key: KP_PDP_2.publicKey.toString() }],
};

/**
 * Object-valued signature. `topKid === undefined` omits top-level alg/kid;
 * `""` and `null` are emitted verbatim (with top-level alg) for N3 coverage.
 */
function makeNestedParent(o: { sigKid: string; topKid?: string | null; key?: typeof KP_PDP }): AuthorizationV1 {
  const a = {
    auth_id: `rev-nested-${uid()}`, issuer: PDP, audience: "agent-A", intent_hash: "a".repeat(64), state_hash: "b".repeat(64),
    policy_id: POLICY, decision: "ALLOW", issued_at: T_NOW - 60, expiry: T_NOW + 900,
    ...(o.topKid !== undefined ? { alg: "Ed25519", kid: o.topKid } : {}),
    signature: { alg: "Ed25519", kid: o.sigKid, sig: "" },
  } as unknown as AuthorizationV1 & { signature: { alg: string; kid: string; sig: string } };
  a.signature.sig = signEd25519(SIGNING_DOMAINS.AUTH_V1, authorizationSigningPayload(a), (o.key ?? KP_PDP).privateKey.toString());
  return a;
}

function setupWithHook(revocation: GuardRevocationConfig | undefined, extra: Partial<OxDeAIGuardConfig> = {}) {
  const hook = { calls: 0 };
  const s = setup(revocation, { beforeExecute: async () => { hook.calls++; }, ...extra });
  return { ...s, hook };
}
function assertDeniedNoHook(r: { executed: number; error: unknown }, s: ReturnType<typeof setupWithHook>, code: string, label: string) {
  assertDenied(r, s.calls, s.events, code, label);
  assert.equal(s.hook.calls, 0, `${label}: beforeExecute must not run`);
}

test("C18 fixtures: every nested-signature parent used below passes strict core verification", () => {
  const cases = [
    makeNestedParent({ sigKid: "k1", topKid: "k1" }),
    makeNestedParent({ sigKid: "k1", topKid: "k-decoy" }),
    makeNestedParent({ sigKid: "k2", topKid: "k1", key: KP_PDP_2 }),
    makeNestedParent({ sigKid: "k1", topKid: "" }),
    makeNestedParent({ sigKid: "k1", topKid: null }),
    makeNestedParent({ sigKid: "k1" }),
  ];
  for (const p of cases) {
    const r = verifyAuthorization(p, { now: T_NOW, mode: "strict", trustedKeySets: [KS_PDP_2KEYS], requireSignatureVerification: true });
    assert.equal(r.status, "ok", JSON.stringify(r.violations));
  }
});

test("C19 nested signature with matching top-level kid: active key executes, revoked key is denied before replay/hook/execute", async () => {
  const ok = setupWithHook(rev(() => [krl([])]));
  const r1 = await present(ok.guard, makeNestedParent({ sigKid: "k1", topKid: "k1" }));
  assert.equal(r1.executed, 1, String(r1.error));
  assert.equal(ok.hook.calls, 1);

  const bad = setupWithHook(rev(() => [krl(["k1"])]));
  const r2 = await present(bad.guard, makeNestedParent({ sigKid: "k1", topKid: "k1" }));
  assertDeniedNoHook(r2, bad, "AUTHORIZATION_VERIFICATION_FAILED", "nested matching revoked");
  assert.ok(r2.error instanceof OxDeAIAuthorizationError && /revoked by a verified SignedKRLV1/.test(r2.error.message), String(r2.error));
});

test("C20 F1/A4: a top-level decoy kid cannot conceal a revoked nested signing key", async () => {
  const s = setupWithHook(rev(() => [krl(["k1"])]));
  const r = await present(s.guard, makeNestedParent({ sigKid: "k1", topKid: "k-not-revoked" }));
  assertDeniedNoHook(r, s, "AUTHORIZATION_VERIFICATION_FAILED", "decoy top-level kid");
});

test("C21 mismatched top-level/nested kids fail closed even when neither key is revoked, and in both directions", async () => {
  const cases: Array<[string, AuthorizationV1, string[]]> = [
    ["decoy, nothing revoked", makeNestedParent({ sigKid: "k1", topKid: "k-decoy" }), []],
    ["nested active k2, top-level k1 revoked", makeNestedParent({ sigKid: "k2", topKid: "k1", key: KP_PDP_2 }), ["k1"]],
    ["nested revoked k2, top-level active k1", makeNestedParent({ sigKid: "k2", topKid: "k1", key: KP_PDP_2 }), ["k2"]],
  ];
  for (const [label, parent, revoked] of cases) {
    const s = setupWithHook(rev(() => [krl(revoked)]), { trustedKeySets: [KS_PDP_2KEYS, KS_AGENT] });
    const r = await present(s.guard, parent);
    assertDeniedNoHook(r, s, "AUTHORIZATION_VERIFICATION_FAILED", label);
    assert.match(String((r.error as Error).message), /ambiguous or unconfirmed/, label);
  }
});

test("C21b N3: top-level kid \"\" or null beside a valid nested signing key is ambiguous and fails closed, revoked or not", async () => {
  // Pre-R1 these executed even with k1 revoked: revocation was checked for the
  // empty/null top-level kid while core verified with nested `signature.kid`.
  // Both shapes are delegable (the hash payload has no undefined fields), so
  // they genuinely reach the SignedKRLV1 path.
  for (const topKid of ["", null] as const) {
    for (const revoked of [["k1"], []]) {
      const label = `topKid=${JSON.stringify(topKid)} revoked=${JSON.stringify(revoked)}`;
      const p = makeNestedParent({ sigKid: "k1", topKid });
      const d = makeChild(p); // must not throw: the shape is bindable
      const s = setupWithHook(rev(() => [krl(revoked)]));
      const r = await present(s.guard, p, d);
      assertDeniedNoHook(r, s, "AUTHORIZATION_VERIFICATION_FAILED", label);
      assert.ok(r.error instanceof OxDeAIAuthorizationError, label);
      assert.match((r.error as Error).message, /ambiguous or unconfirmed/, label);
    }
  }
});

test("C22 nested signature without top-level alg/kid is structurally undelegable: denied at chain binding, before KRL evaluation, replay, hook and execute", async () => {
  // Intended invariant: such a parent must never reach execution with an
  // unchecked signing key. Under current core that SignedKRLV1 path is
  // UNREACHABLE: delegationParentHash = sha256(canonicalJson(
  // toPublicAuthorizationV1(parent))) and canonicalJson rejects the undefined
  // top-level alg/kid, so no delegation can bind to this parent. This test pins
  // that limitation precisely (a KRL that revokes nothing is used as well, and
  // the KRL provider must never be consulted) instead of passing for an
  // unrelated binding error.
  const p = makeNestedParent({ sigKid: "k1" });
  assert.equal(
    verifyAuthorization(p, { now: T_NOW, mode: "strict", trustedKeySets: [KS_PDP], requireSignatureVerification: true }).status,
    "ok",
    "fixture is a cryptographically valid parent"
  );
  assert.throws(() => delegationParentHash(p), /UNSUPPORTED_TYPE/);

  // Strongest child a presenter can build: correctly signed by a1 and committing
  // to every DEFINED public field of this exact parent.
  const committed = Object.fromEntries(Object.entries(toPublicAuthorizationV1(p)).filter(([, v]) => v !== undefined));
  const unsigned = { ...makeChild(makeParent()), parent_auth_hash: sha256HexFromJson(committed), signature: "" };
  const d: DelegationV1 = {
    ...unsigned,
    signature: signEd25519(SIGNING_DOMAINS.DELEGATION_V1, delegationSigningPayload(unsigned), KP_AGENT.privateKey.toString()),
  };

  for (const revoked of [["k1"], []]) {
    let krlCalls = 0;
    const s = setupWithHook(rev(() => { krlCalls++; return [krl(revoked)]; }));
    const r = await present(s.guard, p, d);
    const label = `revoked=${JSON.stringify(revoked)}`;
    assert.equal(r.executed, 0, label);
    assert.deepEqual(s.calls, [], `${label}: no replay state consumed`);
    assert.equal(s.hook.calls, 0, `${label}: beforeExecute must not run`);
    assert.equal(krlCalls, 0, `${label}: denial precedes SignedKRLV1 evaluation`);
    assert.match(String((r.error as Error)?.message), /UNSUPPORTED_TYPE/, label);
    // Current (pre-existing) classification of a core canonicalization throw.
    assert.equal(s.events.at(-1)?.boundaryFailure, "UNCLASSIFIED", label);
  }
});

test("C23 flat parent signature: active key executes, revoked key denied (identity resolution unchanged)", async () => {
  const ok = setupWithHook(rev(() => [krl(["unrelated"])]));
  assert.equal((await present(ok.guard)).executed, 1);
  const bad = setupWithHook(rev(() => [krl(["k1"])]));
  assertDeniedNoHook(await present(bad.guard), bad, "AUTHORIZATION_VERIFICATION_FAILED", "flat revoked");
});

test("C24 revoked delegation signing key still denied alongside a nested-signature parent", async () => {
  const s = setupWithHook(rev(() => [krl(["a1"])]));
  assertDeniedNoHook(await present(s.guard, makeNestedParent({ sigKid: "k1", topKid: "k1" })), s, "DELEGATION_VERIFICATION_FAILED", "delegation revoked");
});

test("C25 missing evidence: a configured KRL publisher returns nothing while every other condition is valid", async () => {
  // Both publishers cover both key issuers, so key-issuer coverage is satisfied
  // by krl-authority alone: only the missing-evidence rule can deny here.
  const scopes = [
    { krlIssuer: "krl-authority", keyIssuers: [PDP, "agent-A"] },
    { krlIssuer: "krl-authority-b", keyIssuers: [PDP, "agent-A"] },
  ];
  const cfg = { trustedKrlKeySets: [KS_KRL, KS_KRL_B], scopes };
  const krlB = () => krl([], { issuer: "krl-authority-b", key: KP_KRL_B, kid: "rb" });

  const control = setupWithHook(rev(() => [krl([]), krlB()], cfg));
  assert.equal((await present(control.guard)).executed, 1, "control: both KRLs present executes");

  const s = setupWithHook(rev(() => [krl([])], cfg));
  assertDeniedNoHook(await present(s.guard), s, "REVOCATION_STATE_UNAVAILABLE", "missing krl-authority-b evidence");
});

test("C26 not configured: nested-signature parents keep their existing behavior (opt-in compatibility)", async () => {
  const s = setupWithHook(undefined);
  const r = await present(s.guard, makeNestedParent({ sigKid: "k1", topKid: "k1" }));
  assert.equal(r.executed, 1, String(r.error));
});

// ── F4-LOT-C-R2 (N2): signing-key resolution and pinned confirmation ──

const strictPinned = (p: AuthorizationV1, keySets: KeySet[]) =>
  verifyAuthorization(p, { now: T_NOW, mode: "strict", trustedKeySets: keySets, requireSignatureVerification: true });
const codes = (r: { violations?: Array<{ code: string }> }) => (r.violations ?? []).map((v) => v.code);

test("C27 resolveAuthorizationSigningKid mirrors core key selection and rejects every ambiguous shape", () => {
  const base = { issuer: PDP };
  const cases: Array<[string, unknown, string | undefined]> = [
    ["flat string signature", { ...base, kid: "k1", signature: "sig" }, "k1"],
    ["flat, no kid", { ...base, signature: "sig" }, undefined],
    ["flat, empty kid", { ...base, kid: "", signature: "sig" }, undefined],
    ["nested, no top-level kid", { ...base, signature: { kid: "k1" } }, "k1"],
    ["nested, equal top-level kid", { ...base, kid: "k1", signature: { kid: "k1" } }, "k1"],
    ["nested, decoy top-level kid", { ...base, kid: "k9", signature: { kid: "k1" } }, undefined],
    ["nested, empty top-level kid", { ...base, kid: "", signature: { kid: "k1" } }, undefined],
    ["nested, null top-level kid", { ...base, kid: null, signature: { kid: "k1" } }, undefined],
    ["nested, missing kid", { ...base, kid: "k1", signature: {} }, undefined],
    ["nested, empty kid", { ...base, signature: { kid: "" } }, undefined],
    ["nested, non-string kid", { ...base, signature: { kid: 1 } }, undefined],
    ["array signature", { ...base, kid: "k1", signature: ["k1"] }, undefined],
    ["numeric signature", { ...base, kid: "k1", signature: 1 }, undefined],
    ["null signature", { ...base, kid: "k1", signature: null }, undefined],
    ["missing signature", { ...base, kid: "k1" }, undefined],
    ["non-object", "k1", undefined],
    ["null", null, undefined],
  ];
  for (const [label, input, expected] of cases) assert.equal(resolveAuthorizationSigningKid(input), expected, label);

  // Agreement with core on real artifacts: the resolved kid is the only key
  // core can have verified with (pinned trust still verifies).
  for (const p of [makeParent(), makeNestedParent({ sigKid: "k1", topKid: "k1" }), makeNestedParent({ sigKid: "k1" }),
    makeNestedParent({ sigKid: "k2", key: KP_PDP_2 })]) {
    const kid = resolveAuthorizationSigningKid(p);
    assert.ok(kid !== undefined);
    assert.equal(strictPinned(p, pinKeySet([KS_PDP_2KEYS], PDP, kid)).status, "ok", kid);
  }
});

test("C28 pinKeySet selects exactly (issuer, kid) as core lookup would, and pinned verification fails closed otherwise", () => {
  const p = makeParent(); // flat, signed by k1
  const sets: KeySet[] = [KS_PDP_2KEYS, KS_AGENT];
  const before = JSON.stringify(sets);

  // Correct issuer and key: exactly one key, issuer/version preserved.
  const pinned = pinKeySet(sets, PDP, "k1");
  assert.equal(pinned.length, 1);
  assert.equal(pinned[0].issuer, PDP);
  assert.equal(pinned[0].version, KS_PDP_2KEYS.version);
  assert.deepEqual(pinned[0].keys.map((k) => k.kid), ["k1"]);
  assert.equal(strictPinned(p, pinned).status, "ok");

  // Incorrect issuer: no trust material at all.
  assert.deepEqual(pinKeySet(sets, "other-issuer", "k1"), []);
  assert.deepEqual(codes(strictPinned(p, pinKeySet(sets, "other-issuer", "k1"))), ["TRUSTED_KEYSETS_REQUIRED"]);

  // Missing key: issuer present, key absent.
  assert.deepEqual(pinKeySet(sets, PDP, "k-missing")[0].keys, []);
  assert.deepEqual(codes(strictPinned(p, pinKeySet(sets, PDP, "k-missing"))), ["AUTH_KID_UNKNOWN"]);

  // Incorrect signing-key identity: pinned to another real key of the issuer.
  assert.deepEqual(codes(strictPinned(p, pinKeySet(sets, PDP, "k2"))), ["AUTH_KID_UNKNOWN"]);

  // Same kid, different key material: cryptographic failure, not a lookup pass.
  const forgedSet: KeySet = { issuer: PDP, version: "v1", keys: [{ kid: "k1", alg: "Ed25519", public_key: KP_OTHER.publicKey.toString() }] };
  assert.deepEqual(codes(strictPinned(p, pinKeySet([forgedSet], PDP, "k1"))), ["AUTH_SIGNATURE_INVALID"]);

  // Duplicate issuer entries: only the FIRST matching set counts, exactly as
  // core findKeyInKeySets; a kid present only in a later set is not trusted.
  const shadow: KeySet = { issuer: PDP, version: "v0", keys: [{ kid: "k2", alg: "Ed25519", public_key: KP_PDP_2.publicKey.toString() }] };
  const dup = [shadow, KS_PDP];
  assert.deepEqual(pinKeySet(dup, PDP, "k1"), [{ ...shadow, keys: [] }]);
  assert.equal(strictPinned(p, dup).status, "invalid", "core itself ignores the second set");
  assert.deepEqual(codes(strictPinned(p, pinKeySet(dup, PDP, "k1"))), ["AUTH_KID_UNKNOWN"]);

  // Pure: input trust material is never mutated, and frozen input is accepted.
  assert.equal(JSON.stringify(sets), before);
  const frozen = Object.freeze([Object.freeze({ ...KS_PDP, keys: Object.freeze([...KS_PDP.keys]) })]) as unknown as KeySet[];
  assert.equal(pinKeySet(frozen, PDP, "k1")[0].keys.length, 1);
});

test("C29 pinned confirmation is evaluated (not skipped) with the full strict options, before replay/hook/execute", async () => {
  // Controlled harness. The first strict verification and the pinned
  // confirmation are separated by the awaited F4-C delegation-revocation
  // provider. Guard reads the caller-owned trustedKeySets / authority list
  // live (no construction-time copy), so the provider can model a concurrent
  // trust-store change. With an empty KRL, ONLY the pinned confirmation can
  // deny here. If Guard ever snapshots this config at construction, revisit
  // these cases: they would then (correctly) no longer reach the confirmation.
  const variants: Array<[string, (ctx: { ks: KeySet; authorities: Array<{ issuer: string; policyId: string }> }) => void]> = [
    ["control: no change executes", () => {}],
    ["parent key statically revoked mid-request", ({ ks }) => { ks.keys[0] = { ...ks.keys[0], status: "revoked" }; }],
    ["parent authority withdrawn mid-request (strict options preserved)", ({ authorities }) => { authorities.length = 0; }],
    ["trust store throws during pinning (unexpected error)", ({ ks }) => {
      Object.defineProperty(ks, "keys", { get() { throw new Error("synthetic trust-store failure"); } });
    }],
  ];
  for (const [label, mutate] of variants) {
    const ks: KeySet = { ...KS_PDP, keys: [...KS_PDP.keys] };
    const authorities = [{ issuer: PDP, policyId: POLICY }];
    const s = setupWithHook(rev(() => [krl([])]), {
      trustedKeySets: [ks, KS_AGENT],
      trustedDelegationAuthorities: authorities,
      delegationRevocationProvider: { check: async () => { mutate({ ks, authorities }); return { status: "ACTIVE" }; } },
    });
    const r = await present(s.guard);
    if (label.startsWith("control")) {
      assert.equal(r.executed, 1, `${label}: ${String(r.error)}`);
      assert.equal(s.hook.calls, 1);
      continue;
    }
    assertDeniedNoHook(r, s, "AUTHORIZATION_VERIFICATION_FAILED", label);
    if (label.startsWith("trust store throws")) {
      // F4-LOT-C-R3: the re-read trust state is now snapshotted and validated
      // before pinning, so a non-plain (accessor) trust store is classified
      // precisely as a configuration error instead of reaching the catch.
      assert.ok(r.error instanceof OxDeAIGuardConfigurationError, `${label}: ${String(r.error)}`);
      assert.match(String((r.error as Error).message), /trustedKeySets: not supported plain data/, label);
      continue;
    }
    assert.match(String((r.error as Error).message), /ambiguous or unconfirmed/, label);
  }
});

// ── F4-LOT-C-R3 (A5): canonical key identity, trust-domain separation, one identity per key ──
//
// SignedKRLV1 revokes by kid. With enforcement enabled the Guard therefore
// requires each Ed25519 key to have exactly one (issuer, kid) identity and keeps
// KRL signing keys out of trustedKeySets, comparing canonical SPKI DER rather
// than PEM text, on the configuration actually used for each decision.

function pemVariants(pem: string): Record<string, string> {
  const b64 = (createPublicKey(pem).export({ type: "spki", format: "der" }) as Buffer).toString("base64");
  return {
    identical: pem,
    crlf: pem.replace(/\n/g, "\r\n"),
    wrap16: `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,16}/g)!.join("\n")}\n-----END PUBLIC KEY-----\n`,
    base64WrappedPem: Buffer.from(pem, "utf8").toString("base64"), // accepted by core's normalizePem
  };
}
const edKey = (kid: string, public_key: string, extra: Record<string, unknown> = {}) => ({ kid, alg: "Ed25519" as const, public_key, ...extra });
const PDP_PEM = KP_PDP.publicKey.toString();
const KRL_PEM = KP_KRL.publicKey.toString();
function construct(trustedKeySets: KeySet[]): unknown {
  try { setup(rev(() => [krl([])]), { trustedKeySets }); return "ACCEPTED"; } catch (e) { return e; }
}
function assertConfigRejected(result: unknown, pattern: RegExp, label: string) {
  assert.ok(result instanceof OxDeAIGuardConfigurationError, `${label}: expected configuration rejection, got ${String(result)}`);
  assert.match((result as Error).message, pattern, label);
}
function assertTrustDenied(r: { executed: number; error: unknown }, s: ReturnType<typeof setupWithHook>, pattern: RegExp, label: string) {
  assertDeniedNoHook(r, s, "AUTHORIZATION_VERIFICATION_FAILED", label);
  assert.ok(r.error instanceof OxDeAIGuardConfigurationError, `${label}: ${String(r.error)}`);
  assert.match((r.error as Error).message, pattern, label);
}
const flatParent = (kid: string, key = KP_PDP, issuer = PDP) => signAuthorizationEd25519({
  auth_id: `r3-${uid()}`, issuer, audience: "agent-A", intent_hash: "a".repeat(64), state_hash: "b".repeat(64),
  policy_id: POLICY, decision: "ALLOW", issued_at: T_NOW - 60, expiry: T_NOW + 900, kid,
}, key.privateKey.toString());
const ALIAS = /same public key is already registered/;
const CROSS_DOMAIN = /also a trusted KRL signing key/;

test("R3-T1 canonical key identity is representation-independent, key-specific, core-consistent and fail-closed", () => {
  const ids = Object.entries(pemVariants(PDP_PEM)).map(([n, v]) => [n, ed25519PublicKeyIdentity(v)] as const);
  for (const [n, id] of ids) assert.equal(id, ids[0][1], n);
  assert.match(ids[0][1], /^[0-9a-f]{64}$/);
  assert.notEqual(ed25519PublicKeyIdentity(KRL_PEM), ids[0][1], "different keys, different identities");

  // Every variant is a representation core itself verifies with.
  for (const [n, v] of Object.entries(pemVariants(PDP_PEM))) {
    const r = verifyAuthorization(makeParent(), { now: T_NOW, mode: "strict", trustedKeySets: [{ issuer: PDP, version: "v1", keys: [edKey("k1", v)] }], requireSignatureVerification: true });
    assert.equal(r.status, "ok", `core accepts ${n}`);
  }

  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048, publicKeyEncoding: { format: "pem", type: "spki" }, privateKeyEncoding: { format: "pem", type: "pkcs8" } });
  const x25519 = generateKeyPairSync("x25519", { publicKeyEncoding: { format: "pem", type: "spki" }, privateKeyEncoding: { format: "pem", type: "pkcs8" } });
  const privatePem = KP_PDP.privateKey.toString();
  const privateBody = privatePem.split("\n")[1];
  for (const [n, bad] of [["undefined", undefined], ["empty", ""], ["number", 42], ["garbage", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"],
    ["RSA", rsa.publicKey], ["X25519", x25519.publicKey], ["Ed25519 private key", privatePem], ["base64-wrapped private key", Buffer.from(privatePem).toString("base64")]] as const) {
    assert.throws(() => ed25519PublicKeyIdentity(bad), (e: Error) => !e.message.includes(privateBody), n);
  }
});

test("A5-01..03 KRL signing key in trustedKeySets is rejected at construction in every encoding, any issuer or kid", () => {
  for (const [n, v] of Object.entries(pemVariants(KRL_PEM))) {
    assertConfigRejected(construct([{ ...KS_PDP, keys: [...KS_PDP.keys, edKey("k-krl", v)] }, KS_AGENT]), CROSS_DOMAIN, `same issuer, ${n}`);
    assertConfigRejected(construct([KS_PDP, KS_AGENT, { issuer: "other-issuer", version: "v1", keys: [edKey("r1", v)] }]), CROSS_DOMAIN, `other issuer, KRL kid reused, ${n}`);
  }
});

test("A5-04/05 one public key under several (issuer, kid) identities is rejected, within and across issuers, in every encoding", () => {
  for (const [n, v] of Object.entries(pemVariants(PDP_PEM))) {
    assertConfigRejected(construct([{ ...KS_PDP, keys: [...KS_PDP.keys, edKey("k1-alias", v)] }, KS_AGENT]), ALIAS, `A5-04 same issuer, ${n}`);
    assertConfigRejected(construct([KS_PDP, KS_AGENT, { issuer: "pdp-alt", version: "v1", keys: [edKey("z1", v)] }]), ALIAS, `A5-05 cross issuer, ${n}`);
    assertConfigRejected(construct([KS_PDP, KS_AGENT, { issuer: "pdp-alt", version: "v1", keys: [edKey("k1", v)] }]), ALIAS, `A5-05 cross issuer, same kid label, ${n}`);
  }
  // The delegation trust domain is the same trustedKeySets: an alias of the delegation key is rejected too.
  assertConfigRejected(construct([KS_PDP, KS_AGENT, { issuer: "agent-B", version: "v1", keys: [edKey("b1", KP_AGENT.publicKey.toString())] }]), ALIAS, "delegation key alias");
});

test("A5-06 conflicting registrations of one (issuer, kid) are rejected; exact duplicates keep consistent lookup", async () => {
  const OTHER_PEM = KP_OTHER.publicKey.toString();
  assertConfigRejected(construct([{ ...KS_PDP, keys: [edKey("k1", PDP_PEM), edKey("k1", OTHER_PEM)] }, KS_AGENT]), /conflicting registrations/, "same set, different keys");
  assertConfigRejected(construct([KS_PDP, { issuer: PDP, version: "v2", keys: [edKey("k1", OTHER_PEM)] }, KS_AGENT]), /conflicting registrations/, "repeated issuer set, different key");
  assertConfigRejected(construct([{ ...KS_PDP, keys: [edKey("k1", PDP_PEM), edKey("k1", pemVariants(PDP_PEM).crlf, { status: "revoked" })] }, KS_AGENT]), /conflicting registrations/, "same key, conflicting lifecycle");

  // Exact duplicate (same issuer, kid, key material and lifecycle; encoding may differ): tolerated and consistent.
  const dup = setupWithHook(rev(() => [krl([])]), { trustedKeySets: [{ ...KS_PDP, keys: [edKey("k1", PDP_PEM), edKey("k1", pemVariants(PDP_PEM).crlf)] }, KS_PDP, KS_AGENT] });
  assert.equal((await present(dup.guard)).executed, 1, "exact duplicate executes");
  const dupRevoked = setupWithHook(rev(() => [krl(["k1"])]), { trustedKeySets: [{ ...KS_PDP, keys: [edKey("k1", PDP_PEM), edKey("k1", PDP_PEM)] }, KS_AGENT] });
  assertDeniedNoHook(await present(dupRevoked.guard), dupRevoked, "AUTHORIZATION_VERIFICATION_FAILED", "exact duplicate still revocable");
});

test("A5-07/08 distinct keys in separate domains are accepted; non-aliased rotation works live, re-labelling does not", async () => {
  const ks: KeySet = { ...KS_PDP, keys: [...KS_PDP.keys] };
  const stableKrl = krl([]); // one envelope across requests (a new nonce would be a same-version watermark conflict)
  const s = setupWithHook(rev(() => [stableKrl]), { trustedKeySets: [ks, KS_AGENT] });
  assert.equal((await present(s.guard)).executed, 1, "A5-07 baseline executes");

  // A5-08: rotate in NEW key material under a new kid, live, between requests.
  ks.keys.push(edKey("k2", KP_PDP_2.publicKey.toString()));
  const viaK2 = flatParent("k2", KP_PDP_2);
  const rot = await present(s.guard, viaK2, makeChild(viaK2));
  assert.equal(rot.executed, 1, `rotated-in key executes: ${String(rot.error)}`);
  ks.keys[0] = { ...ks.keys[0], status: "revoked" };
  const retired = await present(s.guard);
  assert.equal(retired.executed, 0, "retired k1 denied");
  assert.match(String((retired.error as Error).message), /AUTH_KEY_INACTIVE/, "denied by static retirement, not by trust validation");

  // Re-labelling old material instead of rotating it is an alias (fresh guard,
  // mutated live after construction, so replay accounting starts from zero).
  const ks2: KeySet = { ...KS_PDP, keys: [...KS_PDP.keys, edKey("k2", KP_PDP_2.publicKey.toString())] };
  const s2 = setupWithHook(rev(() => [krl([])]), { trustedKeySets: [ks2, KS_AGENT] });
  ks2.keys.push(edKey("k3", PDP_PEM));
  assertTrustDenied(await present(s2.guard, viaK2, makeChild(viaK2)), s2, ALIAS, "re-labelled k1 material");
});

test("A5-09 malformed or unsupported trusted keys fail closed at construction and when introduced live", async () => {
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048, publicKeyEncoding: { format: "pem", type: "spki" }, privateKeyEncoding: { format: "pem", type: "pkcs8" } });
  const bad: Array<[string, Record<string, unknown>]> = [
    ["unparseable PEM", edKey("kx", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")],
    ["RSA key labelled Ed25519", edKey("kx", rsa.publicKey)],
    ["private key material", edKey("kx", KP_OTHER.privateKey.toString())],
    ["HMAC entry", { kid: "kx", alg: "HMAC-SHA256", public_key: "secret" }],
    ["HMAC-labelled entry carrying valid Ed25519 material", { kid: "kx", alg: "HMAC-SHA256", public_key: KP_PDP_2.publicKey.toString() }],
    ["missing public_key", { kid: "kx", alg: "Ed25519" }],
  ];
  for (const [label, entry] of bad) {
    assertConfigRejected(construct([{ ...KS_PDP, keys: [...KS_PDP.keys, entry as never] }, KS_AGENT]), /trustedKeySets/, `construction: ${label}`);
    const ks: KeySet = { ...KS_PDP, keys: [...KS_PDP.keys] };
    const s = setupWithHook(rev(() => [krl([])]), { trustedKeySets: [ks, KS_AGENT] });
    ks.keys.push(entry as never);
    assertTrustDenied(await present(s.guard), s, /trustedKeySets/, `live: ${label}`);
  }
  // A KRL trust key that is not a usable Ed25519 key fails closed at construction.
  assert.throws(() => setup(rev(() => [krl([])], { trustedKrlKeySets: [{ issuer: "krl-authority", version: "v1", keys: [edKey("r1", "not a key")] }] })),
    (e: Error) => e instanceof OxDeAIGuardConfigurationError && /trustedKrlKeySets\[0\]\.keys\[0\]/.test(e.message));
});

test("A5-10 an alias introduced after construction is rejected before execution (no revoked-key bypass)", async () => {
  // Same issuer: the KRL revokes k1, the same material is added live as k1-alias.
  const ks: KeySet = { ...KS_PDP, keys: [...KS_PDP.keys] };
  const s = setupWithHook(rev(() => [krl(["k1"])]), { trustedKeySets: [ks, KS_AGENT] });
  ks.keys.push(edKey("k1-alias", pemVariants(PDP_PEM).crlf));
  const viaAlias = flatParent("k1-alias");
  assertTrustDenied(await present(s.guard, viaAlias, makeChild(viaAlias)), s, ALIAS, "revoked k1 presented as k1-alias");

  // Cross issuer: an authorized, KRL-covered issuer gains the same material live.
  const live: KeySet[] = [KS_PDP, KS_AGENT];
  const s2 = setupWithHook(rev(() => [krl(["k1"])], { scopes: [{ krlIssuer: "krl-authority", keyIssuers: [PDP, "pdp-alt", "agent-A"] }] }),
    { trustedKeySets: live, trustedDelegationAuthorities: [{ issuer: PDP, policyId: POLICY }, { issuer: "pdp-alt", policyId: POLICY }] });
  live.push({ issuer: "pdp-alt", version: "v1", keys: [edKey("z1", PDP_PEM)] });
  const viaAlt = flatParent("z1", KP_PDP, "pdp-alt");
  assertTrustDenied(await present(s2.guard, viaAlt, makeChild(viaAlt)), s2, ALIAS, "revoked k1 presented as pdp-alt/z1");
});

test("A5-11 a KRL signing key introduced into trustedKeySets after construction is rejected, delegated and direct paths", async () => {
  const ks: KeySet = { ...KS_PDP, keys: [...KS_PDP.keys] };
  const s = setupWithHook(rev(() => [krl([])]), { trustedKeySets: [ks, KS_AGENT] });
  ks.keys.push(edKey("k-krl", pemVariants(KRL_PEM).wrap16));
  const viaKrlKey = flatParent("k-krl", KP_KRL);
  assertTrustDenied(await present(s.guard, viaKrlKey, makeChild(viaKrlKey)), s, CROSS_DOMAIN, "KRL key roots a delegated parent");

  // Direct (non-delegated) path: validated before verification, before replay, state commit, hook and execute.
  const ks2: KeySet = { ...KS_PDP, keys: [...KS_PDP.keys] };
  const d = setupWithHook(rev(() => [krl([])]), { trustedKeySets: [ks2, KS_AGENT] });
  let executed = 0;
  await d.guard(ACTION, async () => { executed++; return "ok"; });
  assert.equal(executed, 1, "direct path control executes");
  const before = d.calls.length;
  ks2.keys.push(edKey("k-krl", KRL_PEM));
  let err: unknown;
  try { await d.guard(ACTION, async () => { executed++; return "ok"; }); } catch (e) { err = e; }
  assert.equal(executed, 1, "direct path: no execution");
  assert.equal(d.calls.length, before, "direct path: no replay consumption");
  assert.equal(d.hook.calls, 1, "direct path: beforeExecute not called again");
  assert.ok(err instanceof OxDeAIGuardConfigurationError && CROSS_DOMAIN.test(err.message), String(err));
  assert.equal(d.events.at(-1)?.boundaryFailure, "AUTHORIZATION_VERIFICATION_FAILED");
});

test("A5-12 mutation across asynchronous boundaries cannot bypass validation", async () => {
  // (a) alias injected during the awaited F4-C provider, i.e. after the first
  // validated snapshot: the post-await re-validation rejects it.
  {
    const ks: KeySet = { ...KS_PDP, keys: [...KS_PDP.keys] };
    const s = setupWithHook(rev(() => [krl([])]), {
      trustedKeySets: [ks, KS_AGENT],
      delegationRevocationProvider: { check: async () => { ks.keys.push(edKey("k1-alias", PDP_PEM)); return { status: "ACTIVE" }; } },
    });
    assertTrustDenied(await present(s.guard), s, ALIAS, "alias injected between snapshots");
  }
  // (b) KRL key injected during the awaited KRL provider, after the last trust
  // read of this request: it took part in no decision of this request (which
  // was fully verified on validated state), and the NEXT request is rejected.
  {
    const ks: KeySet = { ...KS_PDP, keys: [...KS_PDP.keys] };
    let inject = true;
    const stableKrl = krl([]);
    const s = setupWithHook(rev(() => { if (inject) { ks.keys.push(edKey("k-krl", KRL_PEM)); inject = false; } return [stableKrl]; }), { trustedKeySets: [ks, KS_AGENT] });
    assert.equal((await present(s.guard)).executed, 1, "in-flight request verified on validated state");
    const callsBefore = s.calls.length, hookBefore = s.hook.calls;
    const r = await present(s.guard);
    assert.equal(r.executed, 0);
    assert.equal(s.calls.length, callsBefore, "next request: no replay consumption");
    assert.equal(s.hook.calls, hookBefore, "next request: no hook");
    assert.ok(r.error instanceof OxDeAIGuardConfigurationError && CROSS_DOMAIN.test((r.error as Error).message), String(r.error));
  }
  // (c) k1's key material is replaced mid-request (after the first snapshot):
  // the parent cannot pass under trust other than what was validated.
  {
    const ks: KeySet = { ...KS_PDP, keys: [...KS_PDP.keys] };
    const s = setupWithHook(rev(() => [krl([])]), {
      trustedKeySets: [ks, KS_AGENT],
      delegationRevocationProvider: { check: async () => { ks.keys[0] = edKey("k1", KP_OTHER.publicKey.toString()); return { status: "ACTIVE" }; } },
    });
    const r = await present(s.guard);
    assertDeniedNoHook(r, s, "AUTHORIZATION_VERIFICATION_FAILED", "k1 material swapped mid-request");
    assert.match((r.error as Error).message, /ambiguous or unconfirmed/);
  }
  // (d) an alias present when the request STARTS and removed during an await:
  // the parent/chain verification must never run on unvalidated trust, even
  // if the state is clean again by the time of the post-await confirmation.
  {
    const ks: KeySet = { ...KS_PDP, keys: [...KS_PDP.keys] };
    const s = setupWithHook(rev(() => [krl([])]), {
      trustedKeySets: [ks, KS_AGENT],
      delegationRevocationProvider: { check: async () => { ks.keys.pop(); return { status: "ACTIVE" }; } },
    });
    ks.keys.push(edKey("k1-alias", PDP_PEM));
    assertTrustDenied(await present(s.guard), s, ALIAS, "alias present at request start, removed mid-request");
  }
});

test("R3 opt-in compatibility: without config.revocation, trust-set validation is not applied (behavior unchanged)", async () => {
  const aliased: KeySet = { ...KS_PDP, keys: [...KS_PDP.keys, edKey("k1-alias", PDP_PEM), edKey("k-krl", KRL_PEM), { kid: "h", alg: "HMAC-SHA256", public_key: "x" } as never] };
  const s = setupWithHook(undefined, { trustedKeySets: [aliased, KS_AGENT] });
  const r = await present(s.guard);
  assert.equal(r.executed, 1, String(r.error));
});

// ── F4-LOT-C-IR1-F1: every revocation-enabled trust read uses the validated, ──
// frozen snapshot, never the caller's live configuration.
//
// "No await between validation and use" is not sufficient: caller-owned config
// read inside the same synchronous verification (`trustedDelegationAuthorities`
// entries, `expectedAudience`) runs AFTER the snapshot is validated and BEFORE
// core's key lookup. Each probe below uses such an accessor to mutate the live
// trust set inside that window. Against the snapshot the request is denied (or,
// for the control, decided on validated state); against the live objects it
// would not be. Regression targets: IR1 mutants IM5, IM7, IM8, IM9, IM10, IM23.

function buildIr1(revocation: GuardRevocationConfig | undefined, extra: Partial<OxDeAIGuardConfig> = {}) {
  const { store, calls } = spyStore(); const events: GuardBoundaryAuditEvent[] = [];
  const hook = { calls: 0 }; const commits = { calls: 0 };
  const config = makeConfig(store, {
    ...(revocation ? { revocation } : {}),
    onBoundaryEvent: (e) => { events.push(e); },
    beforeExecute: async () => { hook.calls++; },
    setState: () => { commits.calls++; return true; },
    ...extra,
  });
  return { config, guard: OxDeAIGuard(config), calls, events, hook, commits };
}
async function presentDirect(guard: ReturnType<typeof OxDeAIGuard>) {
  let executed = 0; let error: unknown;
  try { await guard(ACTION, async () => { executed++; return "ok"; }); } catch (e) { error = e; }
  return { executed, error };
}
function assertSnapshotDenied(
  r: { executed: number; error: unknown }, s: ReturnType<typeof buildIr1>, code: string,
  errorType: new (...a: never[]) => Error, message: RegExp, label: string,
) {
  assert.equal(r.executed, 0, `${label}: execute must not run (${String(r.error)})`);
  assert.equal(s.hook.calls, 0, `${label}: beforeExecute must not run`);
  assert.deepEqual(s.calls, [], `${label}: no replay state consumed`);
  assert.equal(s.commits.calls, 0, `${label}: no state commit`);
  assert.equal(s.events.at(-1)?.boundaryFailure, code, `${label}: boundary code (${String(r.error)})`);
  assert.ok(r.error instanceof errorType, `${label}: error type ${String(r.error)}`);
  assert.match((r.error as Error).message, message, label);
}
const freshKs = (ks: KeySet): KeySet => ({ ...ks, keys: ks.keys.map((k) => ({ ...k })) as KeySet["keys"] });
/** An authority entry whose `issuer` accessor runs `onRead(n)` on its n-th read (n = 1, 2, …) once armed. */
function accessorAuthority(onRead: (n: number) => void) {
  const state = { armed: false, reads: 0 };
  const authority = { policyId: POLICY } as { issuer: string; policyId: string };
  Object.defineProperty(authority, "issuer", { enumerable: true, get() { if (state.armed) onRead(++state.reads); return PDP; } });
  return { authority, state };
}
const childSignedBy = (p: AuthorizationV1, key: { privateKey: string | Buffer }, kid = "a1") =>
  createDelegation(p, { delegatee: "agent-B", issuer: "agent-A", kid, scope: { tools: ["provision_gpu"] }, expiry: T_NOW + 300, delegationId: `ir1-${uid()}` }, key.privateKey.toString());

test("IR1-F1a chain verification uses the snapshot: a KRL key swapped into live trust during the synchronous parent verify cannot authorize the delegation (IM8, IM23)", async () => {
  const agent = freshKs(KS_AGENT); const orig = agent.keys[0].public_key;
  const probe = accessorAuthority((n) => {
    if (n !== 1) return;
    (agent.keys[0] as { public_key: string }).public_key = KRL_PEM; // after validation, before chain key lookup
    queueMicrotask(() => { (agent.keys[0] as { public_key: string }).public_key = orig; });
  });
  const s = buildIr1(rev(() => [krl([])]), { trustedKeySets: [freshKs(KS_PDP), agent], trustedDelegationAuthorities: [probe.authority] });
  probe.state.armed = true;
  const p = makeParent();
  const r = await present(s.guard, p, childSignedBy(p, KP_KRL));
  assert.ok(probe.state.reads >= 1, "probe ran inside verification");
  assertSnapshotDenied(r, s, "DELEGATION_VERIFICATION_FAILED", OxDeAIDelegationError, /signature verification failed/, "IR1-F1a");
});

test("IR1-F1b parent verification uses the snapshot: a KRL-signed parent fails at parent verification, not later (IM7)", async () => {
  for (const withAwait of [true, false]) {
    const pdp = freshKs(KS_PDP); const orig = pdp.keys[0].public_key;
    const probe = accessorAuthority((n) => {
      if (n !== 1) return;
      (pdp.keys[0] as { public_key: string }).public_key = KRL_PEM; // after validation, before parent key lookup
      queueMicrotask(() => { (pdp.keys[0] as { public_key: string }).public_key = orig; });
    });
    const s = buildIr1(rev(() => [krl([])]), {
      trustedKeySets: [pdp, freshKs(KS_AGENT)], trustedDelegationAuthorities: [probe.authority],
      ...(withAwait ? { delegationRevocationProvider: { check: async () => ({ status: "ACTIVE" as const }) } } : {}),
    });
    probe.state.armed = true;
    const p = flatParent("k1", KP_KRL);
    const r = await present(s.guard, p, makeChild(p));
    assert.ok(probe.state.reads >= 1, "probe ran inside verification");
    // The classification is the load-bearing assertion: on live trust the parent
    // would verify here and be caught only later, by a different control.
    assertSnapshotDenied(r, s, "AUTHORIZATION_VERIFICATION_FAILED", OxDeAIAuthorizationError,
      /Parent authorization verification failed: .*AUTH_SIGNATURE_INVALID/, `IR1-F1b await=${withAwait}`);
  }
});

test("IR1-F1c post-await confirmation uses the fresh snapshot: live key objects restored inside the pinned verify are not consulted (IM5, IM23)", async () => {
  const pdp = freshKs(KS_PDP); const orig = pdp.keys[0].public_key;
  // Read 1 = parent verify (no-op). Read 2 = pinned confirmation: restore the
  // pre-rotation key in the live object, after confirmTrust was validated.
  const probe = accessorAuthority((n) => { if (n === 2) (pdp.keys[0] as { public_key: string }).public_key = orig; });
  const s = buildIr1(rev(() => [krl([])]), {
    trustedKeySets: [pdp, freshKs(KS_AGENT)], trustedDelegationAuthorities: [probe.authority],
    // In-place rotation of k1 during the awaited F4-C provider: the parent,
    // signed by the old k1 material, must no longer be confirmed.
    delegationRevocationProvider: { check: async () => { (pdp.keys[0] as { public_key: string }).public_key = KP_OTHER.publicKey.toString(); return { status: "ACTIVE" as const }; } },
  });
  probe.state.armed = true;
  const r = await present(s.guard);
  assert.ok(probe.state.reads >= 2, "probe reached the pinned confirmation");
  // Message wording: see IR1-F3 (accepted, deferred).
  assertSnapshotDenied(r, s, "AUTHORIZATION_VERIFICATION_FAILED", OxDeAIAuthorizationError, /ambiguous or unconfirmed/, "IR1-F1c");
});

test("IR1-F1d revocation enabled: reassigning config.trustedKeySets is not observed by any path (IM9)", async () => {
  // (a) a KRL key introduced by reassignment cannot authorize a delegation.
  {
    const s = buildIr1(rev(() => [krl([])]));
    (s.config as { trustedKeySets: unknown }).trustedKeySets = [freshKs(KS_PDP), { ...KS_AGENT, keys: [edKey("a1", KRL_PEM)] }];
    const p = makeParent();
    assertSnapshotDenied(await present(s.guard, p, childSignedBy(p, KP_KRL)), s, "DELEGATION_VERIFICATION_FAILED", OxDeAIDelegationError,
      /signature verification failed/, "reassigned KRL key");
  }
  // (b) a key that exists only in the reassigned array is unknown.
  {
    const s = buildIr1(rev(() => [krl([])]));
    (s.config as { trustedKeySets: unknown }).trustedKeySets = [freshKs(KS_PDP), { ...KS_AGENT, keys: [edKey("a2", KP_OTHER.publicKey.toString())] }];
    const p = makeParent();
    assertSnapshotDenied(await present(s.guard, p, childSignedBy(p, KP_OTHER, "a2")), s, "DELEGATION_VERIFICATION_FAILED", OxDeAIDelegationError,
      /kid not found/, "key only in reassigned array");
  }
  // (c) documented consequence: a key removed only by reassignment stays trusted
  // (rotate in place instead; see README). Pinned so the contract cannot drift silently.
  {
    const s = buildIr1(rev(() => [krl([])]));
    (s.config as { trustedKeySets: unknown }).trustedKeySets = [freshKs(KS_PDP), { ...KS_AGENT, keys: [] }];
    assert.equal((await present(s.guard)).executed, 1, "reassignment not observed");
  }
  // (d) in-place removal of the same key IS observed.
  {
    const agent = freshKs(KS_AGENT);
    const s = buildIr1(rev(() => [krl([])]), { trustedKeySets: [freshKs(KS_PDP), agent] });
    (agent.keys as unknown[]).length = 0;
    assertSnapshotDenied(await present(s.guard), s, "DELEGATION_VERIFICATION_FAILED", OxDeAIDelegationError, /kid not found/, "in-place removal");
  }
});

test("IR1-F1e revocation disabled: existing behavior kept — the chain reads config.trustedKeySets, so reassignment is observed there", async () => {
  const s = buildIr1(undefined);
  (s.config as { trustedKeySets: unknown }).trustedKeySets = [freshKs(KS_PDP), { ...KS_AGENT, keys: [edKey("a2", KP_OTHER.publicKey.toString())] }];
  const p = makeParent();
  assert.equal((await present(s.guard, p, childSignedBy(p, KP_OTHER, "a2"))).executed, 1, "new delegation key observed");
  const p2 = makeParent();
  const r = await present(s.guard, p2, makeChild(p2));
  assert.equal(r.executed, 0, "removed delegation key no longer trusted");
  assert.ok(r.error instanceof OxDeAIDelegationError, String(r.error));
});

test("IR1-F1f direct path uses the snapshot: an expectedAudience accessor restoring a live key after validation is not consulted (IM10, IM23)", async () => {
  const pdp = freshKs(KS_PDP); const orig = pdp.keys[0].public_key;
  const s = buildIr1(rev(() => [krl([])]), { trustedKeySets: [pdp, freshKs(KS_AGENT)] });
  // Validated state for this request: k1 rotated in place to an unrelated key,
  // so the engine's k1 signature must not verify.
  (pdp.keys[0] as { public_key: string }).public_key = KP_OTHER.publicKey.toString();
  let reads = 0;
  Object.defineProperty(s.config, "expectedAudience", {
    configurable: true, enumerable: true,
    get() { reads++; (pdp.keys[0] as { public_key: string }).public_key = orig; return "agent-A"; }, // after validatedTrust(), before key lookup
  });
  const r = await presentDirect(s.guard);
  assert.ok(reads >= 1, "probe ran");
  assertSnapshotDenied(r, s, "AUTHORIZATION_VERIFICATION_FAILED", OxDeAIAuthorizationError,
    /Authorization verification failed: .*AUTH_SIGNATURE_INVALID/, "IR1-F1f");
});
