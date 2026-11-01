// P2-1 STRICT MODE (opt-in) prototype regression.
// requireExplicitReplayProtection:true must fail closed at construction when no
// replay posture is declared, across all three entry points. A declared
// process-local posture, a shared store, and legacy replayStore remain accepted.
// Default (flag absent) keeps the transitional behavior (no throw).
import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { resolveReplayProtection } from "../replayProtection.js";
import { createInMemoryReplayStore } from "../replayStore.js";
import type { ReplayStore } from "../replayStore.js";
import { createPepGatewayExecutor } from "../gateway.js";
import { OxDeAIGuard } from "../guard.js";
import { createSecureGuard } from "../secureGuard.js";
import { OxDeAIGuardConfigurationError } from "../errors.js";
import type { KeySet } from "@oxdeai/core";

const kp = generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
const KS: KeySet = { issuer: "iss", version: "1", keys: [{ kid: "k1", alg: "Ed25519", public_key: kp.publicKey.toString(), status: "active" }] };
const custom = (): ReplayStore => ({ async consumeAuthId() { return true; } });
const noWarn = () => {};

// ── resolver level ────────────────────────────────────────────────────────────
test("STRICT resolver: undeclared posture throws", () => {
  assert.throws(() => resolveReplayProtection({}, { strict: true, warn: noWarn }), OxDeAIGuardConfigurationError);
});
test("STRICT resolver: declared process-local still accepted", () => {
  assert.equal(resolveReplayProtection({ replayProtection: { mode: "process-local" } }, { strict: true }).source, "explicit-process-local");
});
test("STRICT resolver: shared store still accepted", () => {
  assert.equal(resolveReplayProtection({ replayProtection: { mode: "shared", store: custom() } }, { strict: true }).source, "explicit-shared");
});
test("STRICT resolver: legacy replayStore still accepted (back-compat preserved)", () => {
  assert.equal(resolveReplayProtection({ replayStore: custom() }, { strict: true }).source, "legacy-replay-store");
});
test("DEFAULT (non-strict) resolver: undeclared still returns implicit-default (transitional)", () => {
  assert.equal(resolveReplayProtection({}, { warn: noWarn }).source, "implicit-default");
});

// ── entry points ───────────────────────────────────────────────────────────────
const engineStub = { evaluatePure() { throw new Error("must not run at construction"); } } as any;
const guardCfg = (extra: any) => ({ engine: engineStub, getState: () => ({ state: {}, version: 0 }), setState: () => true, expectedAudience: "aud", trustedKeySets: [KS], ...extra }) as any;
const gwCfg = (extra: any) => ({ expectedAudience: "gw", trustedKeySets: [KS], internalExecutorToken: "tok", trustedAuthorizationAuthorities: [{ issuer: "iss", policyId: "p1" }], timeoutMs: 50, executeUpstream: async () => { throw new Error("no dispatch"); }, ...extra }) as any;

test("STRICT entry points: undeclared posture + flag throws at construction (all three)", () => {
  assert.throws(() => OxDeAIGuard(guardCfg({ requireExplicitReplayProtection: true })), OxDeAIGuardConfigurationError, "OxDeAIGuard");
  assert.throws(() => createSecureGuard(guardCfg({ requireExplicitReplayProtection: true }), { tenancy: "single-tenant" }), OxDeAIGuardConfigurationError, "SecureGuard");
  assert.throws(() => createPepGatewayExecutor(gwCfg({ requireExplicitReplayProtection: true })), OxDeAIGuardConfigurationError, "Gateway");
});
test("STRICT entry points: declared process-local + flag constructs cleanly (all three)", () => {
  assert.doesNotThrow(() => OxDeAIGuard(guardCfg({ requireExplicitReplayProtection: true, replayProtection: { mode: "process-local" } })));
  assert.doesNotThrow(() => createSecureGuard(guardCfg({ requireExplicitReplayProtection: true, replayProtection: { mode: "process-local" } }), { tenancy: "single-tenant" }));
  assert.doesNotThrow(() => createPepGatewayExecutor(gwCfg({ requireExplicitReplayProtection: true, replayProtection: { mode: "process-local" } })));
});
test("DEFAULT entry points: undeclared posture WITHOUT flag still constructs (transitional, all three)", () => {
  assert.doesNotThrow(() => OxDeAIGuard(guardCfg({})));
  assert.doesNotThrow(() => createSecureGuard(guardCfg({}), { tenancy: "single-tenant" }));
  assert.doesNotThrow(() => createPepGatewayExecutor(gwCfg({})));
});

// ── Correction #1: non-boolean requireExplicitReplayProtection is rejected ─────
// A non-boolean flag value must fail deterministically, never be read as false
// (which would silently disable strict enforcement on a typo like "true"/1).
import { strictFromConfig } from "../replayProtection.js";

const NON_BOOLEAN = [
  { name: 'string "true"', v: "true" },
  { name: "number 1", v: 1 },
  { name: "null", v: null },
  { name: "object", v: {} },
  { name: "array", v: [] },
];

test("C1 resolver helper: non-boolean strict flag throws; boolean/undefined accepted", () => {
  for (const c of NON_BOOLEAN) {
    assert.throws(() => strictFromConfig(c.v), OxDeAIGuardConfigurationError, c.name);
  }
  assert.equal(strictFromConfig(undefined), false);
  assert.equal(strictFromConfig(false), false);
  assert.equal(strictFromConfig(true), true);
});

test("C1 entry points: a non-boolean requireExplicitReplayProtection is rejected at construction (all three)", () => {
  for (const c of NON_BOOLEAN) {
    assert.throws(() => OxDeAIGuard(guardCfg({ requireExplicitReplayProtection: c.v, replayProtection: { mode: "process-local" } })), OxDeAIGuardConfigurationError, `OxDeAIGuard/${c.name}`);
    assert.throws(() => createSecureGuard(guardCfg({ requireExplicitReplayProtection: c.v, replayProtection: { mode: "process-local" } }), { tenancy: "single-tenant" }), OxDeAIGuardConfigurationError, `SecureGuard/${c.name}`);
    assert.throws(() => createPepGatewayExecutor(gwCfg({ requireExplicitReplayProtection: c.v, replayProtection: { mode: "process-local" } })), OxDeAIGuardConfigurationError, `Gateway/${c.name}`);
  }
});

// ── Correction #2: malformed/ambiguous matrix under STRICT across 3 entry points ─
// (Complements the non-strict B1 matrix in guard.replay-protection.security.test.ts;
//  here every case also carries requireExplicitReplayProtection:true.)
const STRICT_INVALID: Array<{ name: string; rp: unknown }> = [
  { name: "unknown mode with store", rp: { mode: "invalid", store: custom() } },
  { name: "missing mode", rp: { store: custom() } },
  { name: "numeric mode", rp: { mode: 1 } },
  { name: "null replayProtection", rp: null },
  { name: "process-local with a store", rp: { mode: "process-local", store: custom() } },
  { name: "shared with null store", rp: { mode: "shared", store: null } },
  { name: "shared with primitive store", rp: { mode: "shared", store: 5 } },
  { name: "shared with missing consumeAuthId", rp: { mode: "shared", store: {} } },
  { name: "shared with built-in store", rp: { mode: "shared", store: createInMemoryReplayStore() } },
];

for (const c of STRICT_INVALID) {
  test(`C2 strict entry points: malformed "${c.name}" rejected at construction (all three)`, () => {
    const g = { requireExplicitReplayProtection: true, replayProtection: c.rp };
    assert.throws(() => OxDeAIGuard(guardCfg(g)), OxDeAIGuardConfigurationError, `OxDeAIGuard/${c.name}`);
    assert.throws(() => createSecureGuard(guardCfg(g), { tenancy: "single-tenant" }), OxDeAIGuardConfigurationError, `SecureGuard/${c.name}`);
    assert.throws(() => createPepGatewayExecutor(gwCfg(g)), OxDeAIGuardConfigurationError, `Gateway/${c.name}`);
  });
}

test("C2 strict entry points: ambiguous (replayProtection + legacy replayStore) rejected (all three)", () => {
  const g = { requireExplicitReplayProtection: true, replayProtection: { mode: "process-local" }, replayStore: custom() };
  assert.throws(() => OxDeAIGuard(guardCfg(g)), OxDeAIGuardConfigurationError);
  assert.throws(() => createSecureGuard(guardCfg(g), { tenancy: "single-tenant" }), OxDeAIGuardConfigurationError);
  assert.throws(() => createPepGatewayExecutor(gwCfg(g)), OxDeAIGuardConfigurationError);
});

// ── Correction #4: process-local is NOT a shared/durable domain ────────────────
test("C4 process-local and shared are distinct: process-local uses the built-in ephemeral store; shared requires a non-built-in backend", () => {
  // process-local resolves to the built-in ephemeral store (not shared/durable).
  const pl = resolveReplayProtection({ replayProtection: { mode: "process-local" } }, { strict: true });
  assert.equal(pl.source, "explicit-process-local");
  // shared must NOT accept that same built-in store (it is process-local, not durable).
  assert.throws(() => resolveReplayProtection({ replayProtection: { mode: "shared", store: createInMemoryReplayStore() } }, { strict: true }), OxDeAIGuardConfigurationError);
  // shared accepts a caller-provided (non-built-in) backend - a DECLARATION, not a durability proof.
  assert.equal(resolveReplayProtection({ replayProtection: { mode: "shared", store: custom() } }, { strict: true }).source, "explicit-shared");
});
