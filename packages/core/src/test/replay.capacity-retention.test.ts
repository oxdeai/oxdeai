// SPDX-License-Identifier: Apache-2.0
/**
 * replay.capacity-retention.test.ts
 *
 * Replay protection must hold for every intent that can still pass the
 * trusted-time freshness gate:
 *
 *  1. RETENTION — a nonce stays retained for at least
 *     maxIntentAgeSeconds + maxClockSkewSeconds, whatever window is configured.
 *  2. CAPACITY  — a still-retained nonce is never evicted to make room; when
 *     live entries exhaust `max_nonces_per_agent` the evaluation fails closed.
 *  3. CONFIG    — a capacity below 1, or a NaN/negative window, never silently
 *     disables replay protection.
 *  4. DENY      — a denied evaluation leaves replay state unchanged, so a
 *     failed competing intent cannot weaken protection of retained entries.
 *
 * Every test drives the public `PolicyEngine.evaluatePure` path.
 */
import test from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { PolicyEngine } from "../policy/PolicyEngine.js";
import type { Intent } from "../types/intent.js";
import type { State } from "../types/state.js";

const AGENT = "agent-1";
const T = 1_730_000_000;
const AGE = 300;
const SKEW = 300;

function engine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v1",
    engine_secret: "s".repeat(32),
    authorization_ttl_seconds: 60,
    maxClockSkewSeconds: SKEW,
    maxIntentAgeSeconds: AGE,
  });
}

function state(windowSeconds: number, cap: number): State {
  return {
    policy_version: "v1",
    period_id: "p1",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: { budget_limit: { [AGENT]: 10n ** 12n }, spent_in_period: { [AGENT]: 0n } },
    max_amount_per_action: { [AGENT]: 10n ** 9n },
    velocity: { config: { window_seconds: 60, max_actions: 100_000 }, counters: {} },
    replay: { window_seconds: windowSeconds, max_nonces_per_agent: cap, nonces: {} },
    concurrency: { max_concurrent: { [AGENT]: 100_000 }, active: {}, active_auths: {} },
    recursion: { max_depth: { [AGENT]: 5 } },
    tool_limits: { window_seconds: 60, max_calls: { [AGENT]: 100_000 }, calls: {} },
  };
}

function intent(nonce: number, timestamp: number): Intent {
  return {
    intent_id: `intent-${nonce}`,
    agent_id: AGENT,
    action_type: "PAYMENT",
    amount: 1n,
    target: "merchant",
    timestamp,
    metadata_hash: "0".repeat(64),
    nonce: BigInt(nonce),
    signature: "sig",
    depth: 0,
    type: "EXECUTE",
  };
}

type Step = { decision: "ALLOW" | "DENY"; reasons: readonly string[]; next: State };

function step(e: PolicyEngine, s: State, it: Intent, now: number): Step {
  const out = e.evaluatePure(it, s, now, { mode: "fail-fast" });
  if (out.decision === "DENY") return { decision: "DENY", reasons: out.reasons, next: s };
  return { decision: "ALLOW", reasons: [], next: out.nextState };
}

test("retention covers the freshness horizon even when the window is shorter", () => {
  const e = engine();
  // Window 300 < AGE + SKEW = 600. The intent is dated at the maximum future
  // skew, so it is first admissible at T and still admissible at T + 600.
  const it = intent(1, T + SKEW);
  const first = step(e, state(300, 256), it, T);
  assert.equal(first.decision, "ALLOW");

  for (const now of [T + 301, T + 450, T + AGE + SKEW]) {
    const again = step(e, first.next, it, now);
    assert.equal(again.decision, "DENY", `replay admitted at +${now - T}s`);
    assert.deepEqual(again.reasons, ["REPLAY_NONCE"]);
  }

  // One second later the intent itself is stale; freshness, not replay
  // retention, is what stops it.
  const late = step(e, first.next, it, T + AGE + SKEW + 1);
  assert.deepEqual(late.reasons, ["INTENT_STALE"]);
});

test("a window longer than the horizon is still honoured", () => {
  const e = engine();
  const first = step(e, state(5_000, 256), intent(2, T), T);
  const fresh = intent(3, T + 4_000);
  const s1 = step(e, first.next, fresh, T + 4_000);
  assert.equal(s1.decision, "ALLOW");
  const retained = s1.next.replay.nonces[AGENT]!.map((x) => x.nonce);
  assert.ok(retained.includes("2"), "entry inside the configured window was pruned");
});

test("a live entry is never evicted when capacity is exhausted", () => {
  const e = engine();
  let s = state(100_000, 2);
  const protectedIntent = intent(10, T);
  s = step(e, s, protectedIntent, T).next;
  s = step(e, s, intent(11, T + 1), T + 1).next;

  const before = structuredClone(s);
  const competing = step(e, s, intent(12, T + 2), T + 2);
  assert.equal(competing.decision, "DENY");
  assert.deepEqual(competing.reasons, ["VELOCITY_EXCEEDED"]);
  assert.deepEqual(competing.next, before, "a DENY must not change replay state");

  const replay = step(e, competing.next, protectedIntent, T + 3);
  assert.equal(replay.decision, "DENY");
  assert.deepEqual(replay.reasons, ["REPLAY_NONCE"]);
});

test("capacity frees once entries leave the retention interval", () => {
  const e = engine();
  let s = state(60, 1);
  s = step(e, s, intent(20, T), T).next;
  // Retention is max(60, 600) = 600: still full one second before expiry.
  assert.deepEqual(step(e, s, intent(21, T + 599), T + 599).reasons, ["VELOCITY_EXCEEDED"]);
  assert.deepEqual(step(e, s, intent(21, T + 600), T + 600).reasons, ["VELOCITY_EXCEEDED"]);
  const freed = step(e, s, intent(21, T + 601), T + 601);
  assert.equal(freed.decision, "ALLOW");
  assert.deepEqual(freed.next.replay.nonces[AGENT]!.map((x) => x.nonce), ["21"]);
});

for (const cap of [0, -1, Number.NaN, 0.5]) {
  test(`capacity ${cap} fails closed instead of disabling replay protection`, () => {
    const e = engine();
    const it = intent(30, T);
    const first = step(e, state(100_000, cap), it, T);
    assert.equal(first.decision, "DENY");
    assert.deepEqual(first.reasons, ["STATE_INVALID"]);
  });
}

for (const windowSeconds of [Number.NaN, -1]) {
  test(`window ${windowSeconds} fails closed instead of pruning every entry`, () => {
    const e = engine();
    const first = step(e, state(windowSeconds, 256), intent(40, T), T);
    assert.equal(first.decision, "DENY");
    assert.deepEqual(first.reasons, ["STATE_INVALID"]);
  });
}

test("a failed competing intent leaves the retained nonce protected", () => {
  const e = engine();
  let s = state(100_000, 1);
  const original = intent(50, T);
  s = step(e, s, original, T).next;
  for (let i = 0; i < 5; i++) {
    const competing = step(e, s, intent(60 + i, T + 1 + i), T + 1 + i);
    assert.equal(competing.decision, "DENY");
    s = competing.next;
  }
  assert.deepEqual(step(e, s, original, T + 10).reasons, ["REPLAY_NONCE"]);
});

test("property: no nonce is admitted twice while its intent is still fresh", () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 0, max: 900 }),
      fc.integer({ min: 1, max: 6 }),
      fc.array(
        fc.record({
          nonce: fc.integer({ min: 0, max: 7 }),
          lead: fc.integer({ min: -AGE, max: SKEW }),
          dt: fc.integer({ min: 0, max: 200 }),
        }),
        { minLength: 1, maxLength: 40 }
      ),
      (windowSeconds, cap, ops) => {
        const e = engine();
        let s = state(windowSeconds, cap);
        let now = T;
        // Each nonce is bound to one fixed intent, as a replayed intent would be.
        const bound = new Map<number, Intent>();
        const admitted = new Map<number, number>();
        for (const op of ops) {
          now += op.dt;
          const it = bound.get(op.nonce) ?? intent(op.nonce, now + op.lead);
          bound.set(op.nonce, it);
          const r = step(e, s, it, now);
          if (r.decision === "ALLOW") {
            assert.ok(!admitted.has(op.nonce), `nonce ${op.nonce} admitted twice (window ${windowSeconds}, cap ${cap})`);
            admitted.set(op.nonce, now);
          }
          s = r.next;
        }
      }
    ),
    { numRuns: 400, seed: 48 }
  );
});
