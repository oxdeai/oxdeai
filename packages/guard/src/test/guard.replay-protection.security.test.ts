// P2-1 (transitional): replay-protection configuration contract.
//
// These are CONFIGURATION-ENFORCEMENT tests plus DURABILITY-MODEL tests that
// use a shared in-memory mock to model a shared backend. A mock does NOT prove
// production persistence, atomicity, or cross-node sharing; it only exercises
// the guard's use of whatever store it is given.
import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import {
  resolveReplayProtection,
  REPLAY_MIGRATION_WARNING,
  __resetReplayMigrationWarningForTests,
  type ReplayProtection,
} from "../replayProtection.js";
import { createInMemoryReplayStore } from "../replayStore.js";
import type { ReplayStore } from "../replayStore.js";
import { createPepGatewayExecutor } from "../gateway.js";
import { OxDeAIGuard } from "../guard.js";
import { createSecureGuard } from "../secureGuard.js";
import { OxDeAIGuardConfigurationError } from "../errors.js";
import { signAuthorizationEd25519, sha256HexFromJson, type KeySet } from "@oxdeai/core";

// A custom (non-built-in) durable-looking store. NOT proven durable; a model.
function customStore(): ReplayStore {
  const seen = new Set<string>();
  return { async consumeAuthId(id) { if (seen.has(id)) return false; seen.add(id); return true; } };
}
const noWarn = () => {};

// ── Configuration enforcement (resolver, used by all three entry points) ──────

test("P2-1 (1) legacy zero-config: in-memory default + one-time migration warning", () => {
  __resetReplayMigrationWarningForTests();
  const msgs: string[] = [];
  const r1 = resolveReplayProtection({}, (m) => msgs.push(m));
  const r2 = resolveReplayProtection({}, (m) => msgs.push(m));
  assert.equal(r1.source, "implicit-default");
  assert.equal(r2.source, "implicit-default");
  assert.ok(r1.store && typeof r1.store.consumeAuthId === "function");
  // warning emitted (the injected sink is called each time; the default sink is the one-time latch)
  assert.ok(msgs.includes(REPLAY_MIGRATION_WARNING));
});

test("P2-1 default sink warns at most once per process", () => {
  __resetReplayMigrationWarningForTests();
  let n = 0;
  const orig = console.warn;
  console.warn = () => { n++; };
  try {
    resolveReplayProtection({});   // uses default one-time sink
    resolveReplayProtection({});
  } finally { console.warn = orig; }
  assert.equal(n, 1, "the built-in migration warning must fire at most once");
});

test("P2-1 (2) explicit process-local: in-memory, no warning", () => {
  const msgs: string[] = [];
  const r = resolveReplayProtection({ replayProtection: { mode: "process-local" } }, (m) => msgs.push(m));
  assert.equal(r.source, "explicit-process-local");
  assert.equal(msgs.length, 0);
});

test("P2-1 (3) shared without store: rejected at construction", () => {
  assert.throws(
    () => resolveReplayProtection({ replayProtection: { mode: "shared" } as unknown as ReplayProtection }, noWarn),
    OxDeAIGuardConfigurationError
  );
});

test("P2-1 (4) shared with a custom store: used as given", () => {
  const store = customStore();
  const r = resolveReplayProtection({ replayProtection: { mode: "shared", store } }, noWarn);
  assert.equal(r.source, "explicit-shared");
  assert.equal(r.store, store);
});

test("P2-1 (5) shared with the built-in in-memory store: rejected", () => {
  const builtin = createInMemoryReplayStore();
  assert.throws(
    () => resolveReplayProtection({ replayProtection: { mode: "shared", store: builtin } }, noWarn),
    /built-in in-memory store is process-local|durable backend/
  );
});

test("P2-1 (6) contradictory config (both fields): rejected as ambiguous", () => {
  assert.throws(
    () => resolveReplayProtection({ replayProtection: { mode: "process-local" }, replayStore: customStore() }, noWarn),
    /Ambiguous replay configuration/
  );
});

test("P2-1 (7) legacy replayStore alone: honored, no warning", () => {
  const store = customStore();
  const msgs: string[] = [];
  const r = resolveReplayProtection({ replayStore: store }, (m) => msgs.push(m));
  assert.equal(r.source, "legacy-replay-store");
  assert.equal(r.store, store);
  assert.equal(msgs.length, 0);
});

// ── End-to-end through the gateway (durability-model + fail-closed) ───────────

const kp = generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
const KS: KeySet = { issuer: "iss", version: "1", keys: [{ kid: "k1", alg: "Ed25519", public_key: kp.publicKey.toString(), status: "active" }] };
const NOW = Math.floor(Date.now() / 1000);
const action = { type: "EXECUTE", tool: "t", params: { amount: 1 } };
const mkAuth = (id: string) => signAuthorizationEd25519({ auth_id: id, issuer: "iss", audience: "gw", intent_hash: sha256HexFromJson(action), state_hash: "2".repeat(64), policy_id: "p1", decision: "ALLOW", issued_at: NOW - 5, expiry: NOW + 600, kid: "k1" }, kp.privateKey);
const base = (rp: Partial<{ replayProtection: ReplayProtection; replayStore: ReplayStore }>, exec: any) =>
  createPepGatewayExecutor({ expectedAudience: "gw", trustedKeySets: [KS], internalExecutorToken: "tok", trustedAuthorizationAuthorities: [{ issuer: "iss", policyId: "p1" }], timeoutMs: 50, executeUpstream: exec, ...rp });

test("P2-1 (8) auth replay across two gateways sharing one store is blocked", async () => {
  const shared = customStore();
  const okExec = async () => ({ status: 200, body: { ok: true } });
  const a = mkAuth("op-shared-1");
  const g1 = base({ replayProtection: { mode: "shared", store: shared } }, okExec);
  const g2 = base({ replayProtection: { mode: "shared", store: shared } }, okExec);
  const r1 = await g1({ action, authorization: a });
  const r2 = await g2({ action, authorization: a });
  assert.equal(r1.body.decision, "ALLOW");
  assert.equal(r2.body.decision, "DENY");
  assert.match(String(r2.body.reason), /AUTH_REPLAY/);
});

test("P2-1 (8b) independent process-local stores do NOT share (documents the hazard)", async () => {
  const okExec = async () => ({ status: 200, body: { ok: true } });
  const a = mkAuth("op-local-1");
  const g1 = base({ replayProtection: { mode: "process-local" } }, okExec);
  const g2 = base({ replayProtection: { mode: "process-local" } }, okExec);
  const r1 = await g1({ action, authorization: a });
  const r2 = await g2({ action, authorization: a });
  assert.equal(r1.body.decision, "ALLOW");
  assert.equal(r2.body.decision, "ALLOW"); // not shared: this is why shared mode needs a real backend
});

test("P2-1 (8) store unavailable during consume: fail closed", async () => {
  const throwing: ReplayStore = { async consumeAuthId() { throw new Error("backend down"); } };
  const g = base({ replayProtection: { mode: "shared", store: throwing } }, async () => ({ status: 200, body: {} }));
  const r = await g({ action, authorization: mkAuth("op-down-1") });
  assert.equal(r.body.decision, "DENY");
  assert.notEqual(r.body.outcome, "EXECUTED");
});

test("P2-1 (13) equivalent resolver behavior is used by the gateway entry point", async () => {
  // shared+builtin rejected at construction through the gateway too
  assert.throws(() => base({ replayProtection: { mode: "shared", store: createInMemoryReplayStore() } }, async () => ({ status: 200 })), OxDeAIGuardConfigurationError);
});

// ─────────────────────────────────────────────────────────────────────────────
// B1: runtime configuration-validation hardening.
//
// TypeScript's discriminated union is advisory only. A plain JS caller or a
// deserialized config can carry any shape. Every malformed configuration below
// is injected past the type system (via `as any`) and MUST be rejected
// deterministically with OxDeAIGuardConfigurationError - never interpreted as
// `shared`, never silently defaulted, never merely warned.
// ─────────────────────────────────────────────────────────────────────────────

const INVALID: Array<{ name: string; rp: unknown }> = [
  { name: "unknown mode with a custom store", rp: { mode: "invalid", store: customStore() } },
  { name: "unknown mode without a store", rp: { mode: "invalid" } },
  { name: "missing mode", rp: { store: customStore() } },
  { name: "empty-string mode", rp: { mode: "" } },
  { name: "numeric mode", rp: { mode: 1 } },
  { name: "boolean mode", rp: { mode: true } },
  { name: "null replayProtection", rp: null },
  { name: "array replayProtection", rp: [] },
  { name: "process-local with an additional store", rp: { mode: "process-local", store: customStore() } },
  { name: "shared with null store", rp: { mode: "shared", store: null } },
  { name: "shared with primitive store", rp: { mode: "shared", store: 42 } },
  { name: "shared with missing consumeAuthId", rp: { mode: "shared", store: {} } },
  { name: "shared with non-callable consumeAuthId", rp: { mode: "shared", store: { consumeAuthId: 123 } } },
  { name: "shared with non-callable consumeDelegationId", rp: { mode: "shared", store: { consumeAuthId: async () => true, consumeDelegationId: 7 } } },
  { name: "shared with the built-in in-memory store", rp: { mode: "shared", store: createInMemoryReplayStore() } },
];

test("B1 resolver: every malformed replayProtection is rejected (OxDeAIGuardConfigurationError)", () => {
  for (const c of INVALID) {
    assert.throws(
      () => resolveReplayProtection({ replayProtection: c.rp as unknown as ReplayProtection }, noWarn),
      OxDeAIGuardConfigurationError,
      c.name
    );
  }
});

test("B1 resolver: an unknown mode is NEVER treated as shared (even with a valid store)", () => {
  assert.throws(
    () => resolveReplayProtection({ replayProtection: { mode: "definitely-not-shared", store: customStore() } as unknown as ReplayProtection }, noWarn),
    /mode must be exactly/
  );
});

test("B1 resolver: valid shared custom store still accepted; valid process-local still accepted; legacy still works", () => {
  const s = customStore();
  assert.equal(resolveReplayProtection({ replayProtection: { mode: "shared", store: s } }, noWarn).source, "explicit-shared");
  assert.equal(resolveReplayProtection({ replayProtection: { mode: "process-local" } }, noWarn).source, "explicit-process-local");
  assert.equal(resolveReplayProtection({ replayStore: s }, noWarn).source, "legacy-replay-store");
});

test("B1 resolver: a store exposing only consumeAuthId (optional consumeDelegationId absent) is accepted", () => {
  const minimal: ReplayStore = { async consumeAuthId() { return true; } };
  assert.equal(resolveReplayProtection({ replayProtection: { mode: "shared", store: minimal } }, noWarn).source, "explicit-shared");
});

// ── Entry-point construction rejection (Guard, SecureGuard, Gateway) ──────────
// Each malformed config must be rejected AT CONSTRUCTION, before any execution,
// replay consumption, or state mutation. Construction throwing is the proof that
// none of those downstream steps is reached.

// Minimal otherwise-valid config that passes each entry point's own checks and
// reaches the replay resolver. The engine stub satisfies validateConfig, which
// only checks for an evaluatePure function and never calls it at construction.
const engineStub = { evaluatePure() { throw new Error("must not be called at construction"); } } as any;
function guardConfig(rp: unknown) {
  return {
    engine: engineStub,
    getState: () => ({ state: {}, version: 0 }),
    setState: () => true,
    expectedAudience: "aud",
    trustedKeySets: [KS],   // present so the ONLY construction failure cause is replayProtection
    replayProtection: rp,
  } as any;
}
function gatewayConfig(rp: unknown) {
  return {
    expectedAudience: "gw", trustedKeySets: [KS], internalExecutorToken: "tok",
    trustedAuthorizationAuthorities: [{ issuer: "iss", policyId: "p1" }], timeoutMs: 50,
    executeUpstream: async () => { throw new Error("must not dispatch"); },
    replayProtection: rp,
  } as any;
}

const ENTRY_POINT_CASES: Array<{ name: string; rp: unknown }> = [
  { name: "unknown mode with store", rp: { mode: "invalid", store: customStore() } },
  { name: "process-local with a store", rp: { mode: "process-local", store: customStore() } },
  { name: "shared with built-in store", rp: { mode: "shared", store: createInMemoryReplayStore() } },
  { name: "shared with malformed store", rp: { mode: "shared", store: {} } },
];

for (const c of ENTRY_POINT_CASES) {
  test(`B1 entry points: "${c.name}" is rejected at construction in OxDeAIGuard, SecureGuard and Gateway`, () => {
    assert.throws(() => OxDeAIGuard(guardConfig(c.rp)), OxDeAIGuardConfigurationError, `OxDeAIGuard: ${c.name}`);
    assert.throws(() => createSecureGuard(guardConfig(c.rp), { tenancy: "single-tenant" }), OxDeAIGuardConfigurationError, `SecureGuard: ${c.name}`);
    assert.throws(() => createPepGatewayExecutor(gatewayConfig(c.rp)), OxDeAIGuardConfigurationError, `Gateway: ${c.name}`);
  });
}

test("B1 entry points: both replayProtection and legacy replayStore is rejected at construction (all three)", () => {
  const both = { replayProtection: { mode: "process-local" }, replayStore: customStore() };
  assert.throws(() => OxDeAIGuard({ ...guardConfig(undefined), ...both } as any), OxDeAIGuardConfigurationError);
  assert.throws(() => createSecureGuard({ ...guardConfig(undefined), ...both } as any, { tenancy: "single-tenant" }), OxDeAIGuardConfigurationError);
  assert.throws(() => createPepGatewayExecutor({ ...gatewayConfig(undefined), ...both } as any), OxDeAIGuardConfigurationError);
});

test("B1 entry points: valid process-local constructs cleanly in all three", () => {
  assert.doesNotThrow(() => OxDeAIGuard(guardConfig({ mode: "process-local" })));
  assert.doesNotThrow(() => createSecureGuard(guardConfig({ mode: "process-local" }), { tenancy: "single-tenant" }));
  assert.doesNotThrow(() => createPepGatewayExecutor(gatewayConfig({ mode: "process-local" })));
});

// B2: strict process-local shape and explicit-undefined transitional compatibility.
test("B2 process-local rejects an own store property even when undefined", () => {
  assert.throws(
    () => resolveReplayProtection({ replayProtection: { mode: "process-local", store: undefined } as unknown as ReplayProtection }, noWarn),
    OxDeAIGuardConfigurationError
  );
});

test("B2 process-local without store remains valid", () => {
  assert.equal(resolveReplayProtection({ replayProtection: { mode: "process-local" } }, noWarn).source, "explicit-process-local");
});

test("B2 replayProtection explicitly undefined preserves implicit default and warning", () => {
  const warnings: string[] = [];
  const result = resolveReplayProtection({ replayProtection: undefined }, (message) => warnings.push(message));
  assert.equal(result.source, "implicit-default");
  assert.deepEqual(warnings, [REPLAY_MIGRATION_WARNING]);
});

test("B2 replayProtection undefined plus legacy replayStore preserves legacy store", () => {
  const store = customStore();
  const warnings: string[] = [];
  const result = resolveReplayProtection({ replayProtection: undefined, replayStore: store }, (message) => warnings.push(message));
  assert.equal(result.source, "legacy-replay-store");
  assert.equal(result.store, store);
  assert.deepEqual(warnings, []);
});
