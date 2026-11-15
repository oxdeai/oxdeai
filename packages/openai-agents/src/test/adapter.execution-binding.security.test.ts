// SPDX-License-Identifier: Apache-2.0
//
// ACT-1 adapter execution binding: the protected tool must receive the exact,
// immutable action the guard verified, even when the caller-owned framework
// input changes while authorization is awaited. Synthetic keys, synthetic
// policy, mock tools.
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";
import type { KeySet, State } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";
import { createInMemoryReplayStore, OxDeAIDenyError, OxDeAINormalizationError } from "@oxdeai/guard";
import type { ProposedAction, ReplayStore } from "@oxdeai/guard";

import { createOpenAIAgentsGuard } from "../adapter.js";
import type { OpenAIAgentsToolCall, OpenAIAgentsGuardConfig } from "../types.js";

const AGENT_ID = "openai-agents-binding-agent";
const NOW = Math.floor(Date.now() / 1000);
const KP = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const KEYSET: KeySet = {
  issuer: "binding-issuer",
  version: "v1",
  keys: [{ kid: "k1", alg: "Ed25519", public_key: KP.publicKey.toString() }],
};

// Policy: PROVISION allowed with a 10-unit per-action cap; nothing else allowed.
function makeState(): State {
  return buildState({
    agent_id: AGENT_ID,
    allow_action_types: ["PROVISION"],
    budget_limit: 1_000_000_000_000n,
    max_amount_per_action: 10_000_000n,
    velocity_max_actions: 1000,
    max_concurrent: 16,
  });
}

type Hooks = { onConsume?: () => void | Promise<void>; onSetState?: () => void | Promise<void> };
type Counters = { consumes: number; setState: number };

function makeConfig(hooks: Hooks = {}, overrides: Partial<OpenAIAgentsGuardConfig> = {}): { config: OpenAIAgentsGuardConfig; counters: Counters } {
  const counters: Counters = { consumes: 0, setState: 0 };
  const inner = createInMemoryReplayStore();
  const replayStore: ReplayStore = {
    consumeAuthId: async (id, o) => {
      counters.consumes++;
      const r = await inner.consumeAuthId(id, o);
      await hooks.onConsume?.();
      return r;
    },
    // The adapters expose no delegation path, so only auth ids are consumed.
  };
  let state = makeState();
  let version = 0;
  const config: OpenAIAgentsGuardConfig = {
    engine: new PolicyEngine({
      policy_version: "v1",
      engine_secret: "binding-test-secret-at-least-32-chars!!",
      authorization_signing_alg: "Ed25519",
      authorization_signing_kid: "k1",
      authorization_issuer: KEYSET.issuer,
      authorization_audience: AGENT_ID,
      authorization_ttl_seconds: 600,
      authorization_private_key_pem: KP.privateKey.toString(),
      ...RECOMMENDED_TRUSTED_TIME_PROFILE,
    }),
    agentId: AGENT_ID,
    trustedKeySets: [KEYSET],
    replayStore,
    getState: async () => ({ state, version }),
    setState: async (next, expected) => {
      counters.setState++;
      await hooks.onSetState?.();
      if (expected !== version) return false;
      state = next;
      version++;
      return true;
    },
    ...overrides,
  };
  return { config, counters };
}

function makeInput(): OpenAIAgentsToolCall {
  return {
    name: "provision_gpu",
    input: { asset: "a100", spec: { gpus: 1, region: "eu" } },
    call_id: "call-binding-1",
    estimatedCost: 1,
    timestampSeconds: NOW,
  };
}

type Seen = { name: string; cost: unknown; asset: unknown; gpus: unknown; region: unknown };
function view(a: ProposedAction): Seen {
  const spec = a.args.spec as Record<string, unknown> | undefined;
  return { name: a.name, cost: a.estimatedCost, asset: a.args.asset, gpus: spec?.gpus, region: spec?.region };
}
const AUTHORIZED: Seen = { name: "provision_gpu", cost: 1, asset: "a100", gpus: 1, region: "eu" };

function deepFrozen(value: unknown): boolean {
  if (value === null || typeof value !== "object") return true;
  return Object.isFrozen(value) && Reflect.ownKeys(value).every((k) => deepFrozen((value as Record<PropertyKey, unknown>)[k]));
}

async function runWithArgument(input: OpenAIAgentsToolCall, hooks: Hooks = {}) {
  const { config, counters } = makeConfig(hooks);
  const guard = createOpenAIAgentsGuard(config);
  const seen: Seen[] = [];
  await guard(input, async (verified) => { seen.push(view(verified)); return "ok"; });
  return { seen, counters };
}

async function assertRejectedBeforeAnything(input: OpenAIAgentsToolCall, callerCode: () => number) {
  const { config, counters } = makeConfig();
  const guard = createOpenAIAgentsGuard(config);
  let executions = 0;
  await assert.rejects(
    guard(input, async () => { executions++; }),
    (err: unknown) => err instanceof OxDeAINormalizationError,
  );
  assert.equal(executions, 0, "tool must not execute");
  assert.equal(counters.consumes, 0, "no replay id may be consumed");
  assert.equal(counters.setState, 0, "no state may be written");
  assert.equal(callerCode(), 0, "no caller code (getter / trap) may run");
}

test("execute receives the verified action: deep-frozen, mapped from the input, same object as beforeExecute and onDecision", async () => {
  let hookArg: ProposedAction | undefined;
  let decisionArg: unknown;
  const { config } = makeConfig({}, {
    beforeExecute: (a) => { hookArg = a; },
    onDecision: (r) => { decisionArg = (r as { action?: unknown }).action; },
  });
  const input = makeInput();
  let got: ProposedAction | undefined;
  await createOpenAIAgentsGuard(config)(input, async (verified) => { got = verified; });
  assert.ok(got);
  assert.deepEqual(view(got), AUTHORIZED);
  assert.equal(got.context?.agent_id, AGENT_ID);
  assert.equal(got.context?.intent_id, "call-binding-1");
  assert.ok(deepFrozen(got), "verified action must be deep-frozen");
  assert.notEqual(got.args, input.input, "verified args must not alias the caller's object");
  assert.equal(hookArg, got, "beforeExecute receives the same object");
  assert.equal(decisionArg, got, "onDecision receives the same object");
});

test("controls: the mutated values presented directly are denied", async () => {
  for (const mutate of [
    (x: OpenAIAgentsToolCall) => { x.name = "send_payment"; },
    (x: OpenAIAgentsToolCall) => { x.estimatedCost = 900; },
  ]) {
    const { config } = makeConfig();
    const input = makeInput();
    mutate(input);
    let executions = 0;
    await assert.rejects(createOpenAIAgentsGuard(config)(input, async () => { executions++; }), OxDeAIDenyError);
    assert.equal(executions, 0);
  }
});

test("tool name mutated during replay consume: the tool receives the authorized name", async () => {
  const input = makeInput();
  const { seen } = await runWithArgument(input, { onConsume: () => { input.name = "send_payment"; } });
  assert.deepEqual(seen, [AUTHORIZED]);
  assert.equal(input.name, "send_payment", "the caller's object did change");
});

test("amount mutated during the CAS state write: the tool receives the authorized amount", async () => {
  const input = makeInput();
  const { seen } = await runWithArgument(input, { onSetState: () => { input.estimatedCost = 900; } });
  assert.deepEqual(seen, [AUTHORIZED]);
});

test("nested args mutated during replay consume: the tool receives the authorized args", async () => {
  const input = makeInput();
  const spec = input.input.spec as Record<string, unknown>;
  const { seen } = await runWithArgument(input, {
    onConsume: () => { spec.gpus = 64; spec.region = "us"; input.input.asset = "h100x8"; },
  });
  assert.deepEqual(seen, [AUTHORIZED]);
});

test("args object replaced during replay consume: the tool receives the authorized args", async () => {
  const input = makeInput();
  const { seen } = await runWithArgument(input, {
    onConsume: () => { input.input = { asset: "h100x8", spec: { gpus: 64, region: "us" } }; },
  });
  assert.deepEqual(seen, [AUTHORIZED]);
});

test("input mutated synchronously after the call starts: the tool receives exactly what was verified", async () => {
  const input = makeInput();
  let verifiedArgs: unknown;
  const { config } = makeConfig({}, { beforeExecute: (a) => { verifiedArgs = a.args; } });
  const seen: Seen[] = [];
  let toolArgs: unknown;
  const pending = createOpenAIAgentsGuard(config)(input, async (verified) => { seen.push(view(verified)); toolArgs = verified.args; });
  input.name = "send_payment";
  input.estimatedCost = 900;
  (input.input.spec as Record<string, unknown>).gpus = 2;
  await pending;
  // Top-level fields were copied by the adapter when the call started.
  assert.equal(seen.length, 1);
  assert.equal(seen[0].name, "provision_gpu");
  assert.equal(seen[0].cost, 1);
  // Nested args are captured when the guard snapshots the action (after the
  // awaited state load), so this earlier mutation is part of what was verified.
  // Whatever was verified is exactly what the tool receives.
  assert.equal(seen[0].gpus, 2);
  assert.equal(toolArgs, verifiedArgs);
});

test("the tool cannot modify the verified action", async () => {
  const { config } = makeConfig();
  let after: Seen | undefined;
  await createOpenAIAgentsGuard(config)(makeInput(), async (verified) => {
    assert.throws(() => { (verified as { estimatedCost?: number }).estimatedCost = 900; }, TypeError);
    assert.throws(() => { (verified.args.spec as Record<string, unknown>).gpus = 64; }, TypeError);
    after = view(verified);
  });
  assert.deepEqual(after, AUTHORIZED);
});

test("accessor in args is rejected before execution, replay consumption and state writes", async () => {
  const input = makeInput();
  let getterCalls = 0;
  Object.defineProperty(input.input.spec as object, "gpus", { enumerable: true, get: () => { getterCalls++; return 1; } });
  await assertRejectedBeforeAnything(input, () => getterCalls);
});

test("Proxy in args is rejected before execution, replay consumption and state writes", async () => {
  const input = makeInput();
  let traps = 0;
  const handler: ProxyHandler<Record<string, unknown>> = {
    get: (t, p, r) => { traps++; return Reflect.get(t, p, r); },
    ownKeys: (t) => { traps++; return Reflect.ownKeys(t); },
    getOwnPropertyDescriptor: (t, p) => { traps++; return Reflect.getOwnPropertyDescriptor(t, p); },
  };
  input.input = new Proxy(input.input, handler);
  await assertRejectedBeforeAnything(input, () => traps);
});

test("non-plain values in args are rejected before execution, replay consumption and state writes", async () => {
  class Spec { gpus = 1; }
  for (const value of [new Spec(), new Date(0), new Map(), Buffer.from("x"), () => 1]) {
    const input = makeInput();
    input.input.extra = value;
    await assertRejectedBeforeAnything(input, () => 0);
  }
});

test("legacy zero-argument executor still runs, but it reads caller-owned input and is not covered by the binding", async () => {
  const input = makeInput();
  const { config } = makeConfig({ onConsume: () => { input.estimatedCost = 900; } });
  let legacySaw: unknown;
  await createOpenAIAgentsGuard(config)(input, async () => { legacySaw = input.estimatedCost; });
  // Backward compatible: the call succeeds and the callback runs.
  // Not security-equivalent: the closure observes a value that was never authorized.
  assert.equal(legacySaw, 900);
});
