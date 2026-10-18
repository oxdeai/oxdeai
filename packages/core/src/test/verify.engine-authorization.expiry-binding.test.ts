// SPDX-License-Identifier: Apache-2.0
/**
 * verify.engine-authorization.expiry-binding.test.ts
 *
 * Regression tests for F2: `PolicyEngine.verifyAuthorization` must make its
 * time decision on `expires_at`, the only expiry field covered by the engine
 * HMAC, and must treat the authorization as expired at `t == expires_at`
 * (valid iff `t < expires_at`, per authorization-v1.md).
 *
 * Before the fix, the helper checked `authorization.expiry ?? authorization.expires_at`
 * with `t > expiry`. Because `expiry` is outside the HMAC subset, editing it on
 * an expired authorization returned `valid: true, signatureVerified: true`.
 */
import test from "node:test";
import assert from "node:assert/strict";

import { PolicyEngine } from "../policy/PolicyEngine.js";
import { RECOMMENDED_TRUSTED_TIME_PROFILE } from "../policy/trustedTimeProfile.js";
import type { State } from "../types/state.js";
import type { Intent } from "../types/intent.js";
import type { Authorization } from "../types/authorization.js";

const POLICY = "v-engine-expiry-binding";
const T0 = 1_700_000_000;
const TTL = 60;

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: POLICY,
    engine_secret: "engine-expiry-binding-secret-32b!",
    authorization_ttl_seconds: TTL,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

function makeState(): State {
  return {
    policy_version: POLICY,
    period_id: "engine-expiry-binding-period",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: {
      budget_limit:    { "agent-1": 1_000_000n },
      spent_in_period: { "agent-1": 0n },
    },
    max_amount_per_action: { "agent-1": 500_000n },
    velocity: { config: { window_seconds: 3600, max_actions: 100 }, counters: {} },
    replay:   { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { "agent-1": 3 }, active: {}, active_auths: {} },
    recursion: { max_depth: { "agent-1": 5 } },
    tool_limits: { window_seconds: 3600, max_calls: { "agent-1": 100 }, calls: {} },
  };
}

function makeIntent(nonce: bigint): Intent {
  return {
    intent_id:     `engine-expiry-binding-${nonce}`,
    agent_id:      "agent-1",
    action_type:   "PAYMENT",
    amount:        1_000n,
    target:        "vendor-x",
    timestamp:     T0,
    metadata_hash: "0".repeat(64),
    nonce,
    signature:     "",
    depth:         0,
    type:          "EXECUTE",
  } as Intent;
}

function issue(nonce: bigint) {
  const engine = makeEngine();
  const state = makeState();
  const intent = makeIntent(nonce);
  const out = engine.evaluatePure(intent, state, T0);
  assert.equal(out.decision, "ALLOW", "fixture precondition: intent must ALLOW");
  const auth = out.authorization as Authorization;
  // Fixture invariant: the engine emits both fields with the same value.
  assert.equal(auth.expires_at, T0 + TTL);
  assert.equal(auth.expiry, auth.expires_at);
  return { engine, state, intent, auth };
}

test("F2 control: intact authorization is valid one second before expiry", () => {
  const { engine, state, intent, auth } = issue(101n);
  const r = engine.verifyAuthorization(intent, auth, state, auth.expires_at - 1);
  assert.equal(r.valid, true);
  assert.equal(r.signatureVerified, true);
});

test("F2 (B): extending the unauthenticated `expiry` cannot revive an expired authorization", () => {
  const { engine, state, intent, auth } = issue(102n);
  const late = T0 + 3600;
  const tampered = { ...auth, expiry: 9_999_999_999 } as Authorization;
  const r = engine.verifyAuthorization(intent, tampered, state, late);
  assert.equal(r.valid, false);
  assert.equal(r.signatureVerified, false);
  assert.equal(r.reason, "AUTH_SIGNATURE_INVALID");
});

test("F2 (B'): an `expiry` that disagrees with `expires_at` is rejected even before expiry", () => {
  const { engine, state, intent, auth } = issue(103n);
  for (const expiry of [auth.expires_at + 1, auth.expires_at - 1]) {
    const r = engine.verifyAuthorization(intent, { ...auth, expiry } as Authorization, state, T0);
    assert.equal(r.valid, false, `expiry=${expiry} must not be accepted`);
    assert.equal(r.reason, "AUTH_SIGNATURE_INVALID");
    assert.equal(r.signatureVerified, false);
  }
});

test("F2 (D): authorization is expired at exactly t == expires_at", () => {
  const { engine, state, intent, auth } = issue(104n);
  const r = engine.verifyAuthorization(intent, auth, state, auth.expires_at);
  assert.equal(r.valid, false);
  assert.equal(r.reason, "AUTH_EXPIRED");
  assert.equal(r.signatureVerified, false);
});

test("F2: missing or non-integer `expires_at` fails closed before any HMAC check", () => {
  const { engine, state, intent, auth } = issue(105n);
  const variants: Array<[string, unknown]> = [
    ["missing", undefined],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["float", auth.expires_at + 0.5],
    ["string", String(auth.expires_at)],
    ["unsafe integer", Number.MAX_SAFE_INTEGER + 1],
  ];
  for (const [label, value] of variants) {
    const mutated = { ...auth, expires_at: value } as unknown as Authorization;
    if (value === undefined) delete (mutated as Record<string, unknown>).expires_at;
    // Drop `expiry` too so the mismatch branch cannot be what rejects it.
    delete (mutated as Record<string, unknown>).expiry;
    const r = engine.verifyAuthorization(intent, mutated, state, T0);
    assert.equal(r.valid, false, `${label} expires_at must be rejected`);
    assert.equal(r.reason, "AUTH_SIGNATURE_INVALID", label);
    assert.equal(r.verificationCoverage, "none", label);
  }
});

test("F2: legacy engine authorization without `expiry` still verifies on `expires_at`", () => {
  const { engine, state, intent, auth } = issue(106n);
  const legacy = { ...auth } as Record<string, unknown>;
  delete legacy.expiry;
  const ok = engine.verifyAuthorization(intent, legacy as unknown as Authorization, state, auth.expires_at - 1);
  assert.equal(ok.valid, true);
  const expired = engine.verifyAuthorization(intent, legacy as unknown as Authorization, state, auth.expires_at);
  assert.equal(expired.valid, false);
  assert.equal(expired.reason, "AUTH_EXPIRED");
});
