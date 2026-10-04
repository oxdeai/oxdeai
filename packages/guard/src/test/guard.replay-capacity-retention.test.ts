// SPDX-License-Identifier: Apache-2.0
/**
 * Core -> Guard: one protected intent must not reach the upstream executor
 * twice because replay state was evicted (capacity), never retained
 * (capacity below 1), or pruned before the intent stopped being fresh
 * (retention shorter than the trusted-time freshness horizon).
 *
 * The guard samples `Date.now()` for `evaluationTime`; each step pins it.
 * Every authorization is genuinely signed and verified; each replay attempt
 * would otherwise receive a fresh auth_id, so the guard's auth_id replay store
 * does not by itself stop a second evaluation of the same intent.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { PolicyEngine } from "@oxdeai/core";
import type { Intent, KeySet, State } from "@oxdeai/core";

import { OxDeAIGuard } from "../guard.js";

const KEYS = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const AGENT = "agent-1";
const T = 1_730_000_000;
const KEYSET: KeySet = {
  issuer: "replay-issuer",
  version: "1",
  keys: [{ kid: "k1", alg: "Ed25519", public_key: KEYS.publicKey }],
};

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

function intent(label: string, nonce: number, timestamp: number): Intent {
  return {
    intent_id: label,
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

type Attempt = { label: string; nonce: number; timestamp: number; now: number };

async function run(windowSeconds: number, cap: number, attempts: Attempt[]): Promise<Record<string, number>> {
  const engine = new PolicyEngine({
    policy_version: "v1",
    engine_secret: "s".repeat(32),
    authorization_ttl_seconds: 60,
    maxClockSkewSeconds: 300,
    maxIntentAgeSeconds: 300,
    authorization_issuer: "replay-issuer",
    authorization_audience: "aud",
    authorization_signing_alg: "Ed25519",
    authorization_signing_kid: "k1",
    authorization_private_key_pem: KEYS.privateKey,
  });
  let current = { state: state(windowSeconds, cap), version: 0 };
  const bound = new Map<string, Intent>();
  const guard = OxDeAIGuard({
    engine,
    expectedAudience: "aud",
    trustedKeySets: KEYSET,
    getState: () => current,
    setState: (next, expected) => {
      if (expected !== current.version) return false;
      current = { state: next, version: current.version + 1 };
      return true;
    },
    mapActionToIntent: (action) => bound.get(action.name)!,
  });

  const executions: Record<string, number> = {};
  const realNow = Date.now;
  try {
    for (const a of attempts) {
      if (!bound.has(a.label)) bound.set(a.label, intent(a.label, a.nonce, a.timestamp));
      Date.now = () => a.now * 1000;
      try {
        await guard({ name: a.label, args: {} }, async () => {
          executions[a.label] = (executions[a.label] ?? 0) + 1;
        });
      } catch {
        // A refusal is the expected outcome for every replay attempt.
      }
    }
  } finally {
    Date.now = realNow;
  }
  return executions;
}

test("capacity exhaustion cannot evict a live entry and re-admit its intent", async () => {
  const executions = await run(100_000, 2, [
    { label: "X", nonce: 1, timestamp: T, now: T },
    { label: "Y", nonce: 2, timestamp: T + 1, now: T + 1 },
    { label: "Z", nonce: 3, timestamp: T + 2, now: T + 2 },
    { label: "X", nonce: 1, timestamp: T, now: T + 3 },
  ]);
  assert.equal(executions.X, 1);
  assert.equal(executions.Y, 1);
  assert.equal(executions.Z, undefined, "capacity exhaustion must fail closed");
});

test("capacity 0 cannot disable replay protection", async () => {
  const executions = await run(100_000, 0, [
    { label: "X", nonce: 1, timestamp: T, now: T },
    { label: "X", nonce: 1, timestamp: T, now: T + 1 },
  ]);
  assert.equal(executions.X, undefined, "capacity 0 must fail closed");
});

test("retention shorter than the freshness horizon cannot re-admit a fresh intent", async () => {
  const executions = await run(300, 256, [
    { label: "X", nonce: 1, timestamp: T + 300, now: T },
    { label: "X", nonce: 1, timestamp: T + 300, now: T + 301 },
    { label: "X", nonce: 1, timestamp: T + 300, now: T + 600 },
  ]);
  assert.equal(executions.X, 1);
});
