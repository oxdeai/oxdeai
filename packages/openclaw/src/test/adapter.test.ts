// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";
import type { Authorization, KeySet, State } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";
import { OxDeAIDenyError, OxDeAIAuthorizationError, OxDeAINormalizationError } from "@oxdeai/guard";

import { createOpenClawGuard } from "../adapter.js";
import type { OpenClawAction, OpenClawGuardConfig } from "../types.js";

// ── fixtures ──────────────────────────────────────────────────────────────────

const AGENT_ID = "openclaw-agent-001";
const ENGINE_SECRET = "test-secret-must-be-at-least-32-chars!!";

const TEST_KEYPAIR = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding:  { format: "pem", type: "spki" },
});

const TEST_KEYSET: KeySet = {
  issuer: "test-issuer",
  version: "v1",
  keys: [{ kid: "k1", alg: "Ed25519", public_key: TEST_KEYPAIR.publicKey.toString() }],
};

function makeEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v1",
    engine_secret: ENGINE_SECRET,
    authorization_signing_alg: "Ed25519",
    authorization_signing_kid: "k1",
    authorization_issuer: TEST_KEYSET.issuer,
    authorization_audience: AGENT_ID,
    authorization_ttl_seconds: 600,
    authorization_private_key_pem: TEST_KEYPAIR.privateKey.toString(),
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

function makeState(agentId = AGENT_ID): State {
  return buildState({
    agent_id: agentId,
    allow_action_types: ["PROVISION", "PAYMENT", "PURCHASE", "ONCHAIN_TX"],
    budget_limit: 1_000_000_000n,
    max_amount_per_action: 1_000_000_000n,
    velocity_max_actions: 1000,
    max_concurrent: 16,
  });
}

const baseAction: OpenClawAction = {
  name: "provision_gpu",
  args: { asset: "a100", region: "us-east-1" },
  step_id: "step-abc-123",
  workflow_id: "openclaw-gpu-demo",
  estimatedCost: 0.5,
  resourceType: "gpu",
  timestampSeconds: Math.floor(Date.now() / 1000),
};

function makeGuardConfig(overrides: Partial<OpenClawGuardConfig> = {}): OpenClawGuardConfig {
  let currentState = makeState();
  return {
    engine: makeEngine(),
    agentId: AGENT_ID,
    getState: () => ({ state: currentState, version: 0 }),
    setState: (s) => { currentState = s; return true; },
    trustedKeySets: [TEST_KEYSET],
    ...overrides,
  };
}

// ── mock engine helpers ───────────────────────────────────────────────────────

function makeDenyEngine(): PolicyEngine {
  return {
    evaluatePure: () => ({ decision: "DENY" as const, reasons: ["KILL_SWITCH_GLOBAL"] }),
    computePolicyId: () => "p".repeat(64),
    verifyAuthorization: () => ({ valid: true }),
  } as unknown as PolicyEngine;
}

function makeNoAuthEngine(state: State): PolicyEngine {
  return {
    evaluatePure: () => ({
      decision: "ALLOW" as const,
      reasons: [] as [],
      authorization: undefined as unknown as Authorization,
      nextState: state,
    }),
    computePolicyId: () => "p".repeat(64),
    verifyAuthorization: () => ({ valid: true }),
  } as unknown as PolicyEngine;
}

// ── 1. Basic ALLOW path ───────────────────────────────────────────────────────

test("adapter: ALLOW executes and returns the result", async () => {
  const guard = createOpenClawGuard(makeGuardConfig());
  const result = await guard(baseAction, async () => "gpu-provisioned");
  assert.equal(result, "gpu-provisioned");
});

// ── 2. DENY propagates ────────────────────────────────────────────────────────

test("adapter: DENY throws OxDeAIDenyError and does not call execute", async () => {
  let currentState: State = { ...makeState(), kill_switch: { global: true, agents: {} } };
  let executeCalled = false;

  const guard = createOpenClawGuard({
    engine: makeEngine(),
    agentId: AGENT_ID,
    getState: () => ({ state: currentState, version: 0 }),
    setState: (s) => { currentState = s; return true; },
    trustedKeySets: [TEST_KEYSET],
  });

  await assert.rejects(
    () => guard(baseAction, async () => { executeCalled = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDenyError);
      assert.ok((err as OxDeAIDenyError).reasons.length > 0);
      return true;
    }
  );

  assert.ok(!executeCalled);
});

// ── 3. agentId injection ──────────────────────────────────────────────────────

test("adapter: agentId from config is injected into ProposedAction.context.agent_id", async () => {
  const CUSTOM_AGENT = "my-openclaw-agent";
  let capturedAgentId: unknown;

  const guard = createOpenClawGuard({
    ...makeGuardConfig({ agentId: CUSTOM_AGENT }),
    mapActionToIntent(action) {
      capturedAgentId = action.context?.agent_id;
      throw new Error("capture-only");
    },
  });

  await assert.rejects(() => guard(baseAction, async () => {}), OxDeAINormalizationError);
  assert.equal(capturedAgentId, CUSTOM_AGENT);
});

// ── 4. step_id → context.intent_id ───────────────────────────────────────────

test("adapter: action.step_id is injected as context.intent_id", async () => {
  let capturedIntentId: unknown;

  const guard = createOpenClawGuard({
    ...makeGuardConfig(),
    mapActionToIntent(action) {
      capturedIntentId = action.context?.intent_id;
      throw new Error("capture-only");
    },
  });

  await assert.rejects(() => guard(baseAction, async () => {}), OxDeAINormalizationError);
  assert.equal(capturedIntentId, "step-abc-123");
});

// ── 5. workflow_id → context.workflow_id ─────────────────────────────────────

test("adapter: action.workflow_id is carried in context.workflow_id", async () => {
  let capturedWorkflowId: unknown;

  const guard = createOpenClawGuard({
    ...makeGuardConfig(),
    mapActionToIntent(action) {
      capturedWorkflowId = (action.context as Record<string, unknown>)?.workflow_id;
      throw new Error("capture-only");
    },
  });

  await assert.rejects(() => guard(baseAction, async () => {}), OxDeAINormalizationError);
  assert.equal(capturedWorkflowId, "openclaw-gpu-demo");
});

// ── 6. Missing step_id: no intent_id in context ───────────────────────────────

test("adapter: missing step_id results in no intent_id in context", async () => {
  let capturedIntentId: unknown = "sentinel";

  const guard = createOpenClawGuard({
    ...makeGuardConfig(),
    mapActionToIntent(action) {
      capturedIntentId = action.context?.intent_id;
      throw new Error("capture-only");
    },
  });

  const actionWithoutStep: OpenClawAction = { name: "provision_gpu", args: {} };
  await assert.rejects(() => guard(actionWithoutStep, async () => {}), OxDeAINormalizationError);
  assert.equal(capturedIntentId, undefined);
});

// ── 7. action.args propagates ─────────────────────────────────────────────────

test("adapter: action.args propagates to ProposedAction.args", async () => {
  let capturedArgs: unknown;

  const guard = createOpenClawGuard({
    ...makeGuardConfig(),
    mapActionToIntent(action) {
      capturedArgs = action.args;
      throw new Error("capture-only");
    },
  });

  const expectedArgs = { asset: "h100", region: "eu-west-1", count: 3 };
  await assert.rejects(
    () => guard({ name: "provision_gpu", args: expectedArgs }, async () => {}),
    OxDeAINormalizationError
  );
  assert.deepEqual(capturedArgs, expectedArgs);
});

// ── 8. estimatedCost and resourceType propagate ───────────────────────────────

test("adapter: estimatedCost and resourceType propagate to ProposedAction", async () => {
  let capturedCost: unknown;
  let capturedResourceType: unknown;

  const guard = createOpenClawGuard({
    ...makeGuardConfig(),
    mapActionToIntent(action) {
      capturedCost = action.estimatedCost;
      capturedResourceType = action.resourceType;
      throw new Error("capture-only");
    },
  });

  const a: OpenClawAction = {
    name: "provision_gpu",
    args: { asset: "a100" },
    estimatedCost: 123.45,
    resourceType: "gpu",
  };

  await assert.rejects(() => guard(a, async () => {}), OxDeAINormalizationError);
  assert.equal(capturedCost, 123.45);
  assert.equal(capturedResourceType, "gpu");
});

// ── 9. timestampSeconds propagates ───────────────────────────────────────────

test("adapter: timestampSeconds from action propagates to ProposedAction", async () => {
  let capturedTimestamp: unknown;

  const guard = createOpenClawGuard({
    ...makeGuardConfig(),
    mapActionToIntent(action) {
      capturedTimestamp = action.timestampSeconds;
      throw new Error("capture-only");
    },
  });

  const FIXED_TS = 1_700_000_000;
  const a: OpenClawAction = { name: "provision_gpu", args: {}, timestampSeconds: FIXED_TS };
  await assert.rejects(() => guard(a, async () => {}), OxDeAINormalizationError);
  assert.equal(capturedTimestamp, FIXED_TS);
});

// ── 10. action.name propagates ────────────────────────────────────────────────

test("adapter: action.name propagates to ProposedAction.name", async () => {
  let capturedName: unknown;

  const guard = createOpenClawGuard({
    ...makeGuardConfig(),
    mapActionToIntent(action) {
      capturedName = action.name;
      throw new Error("capture-only");
    },
  });

  await assert.rejects(
    () => guard({ name: "my_openclaw_skill", args: {} }, async () => {}),
    OxDeAINormalizationError
  );
  assert.equal(capturedName, "my_openclaw_skill");
});

// ── 11. Missing authorization blocks execution (security invariant) ────────────

test("adapter: ALLOW without authorization artifact throws OxDeAIAuthorizationError", async () => {
  const state = makeState();
  let executeCalled = false;

  const guard = createOpenClawGuard({
    engine: makeNoAuthEngine(state),
    agentId: AGENT_ID,
    getState: () => ({ state, version: 0 }),
    setState: () => true,
    trustedKeySets: [TEST_KEYSET],
  });

  await assert.rejects(
    () => guard(baseAction, async () => { executeCalled = true; }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      return true;
    }
  );

  assert.ok(!executeCalled);
});

// ── 12. setState is called on ALLOW ──────────────────────────────────────────

test("adapter: setState is called after successful execution", async () => {
  let storedState: State | undefined;

  const guard = createOpenClawGuard({
    engine: makeEngine(),
    agentId: AGENT_ID,
    getState: () => ({ state: makeState(), version: 0 }),
    setState: (s) => { storedState = s; return true; },
    trustedKeySets: [TEST_KEYSET],
  });

  await guard(baseAction, async () => "ok");
  assert.ok(storedState !== undefined);
  assert.ok(typeof storedState!.policy_version === "string");
});

// ── 13. setState is NOT called on DENY ───────────────────────────────────────

test("adapter: setState is NOT called on DENY", async () => {
  let setStateCalled = false;

  const guard = createOpenClawGuard({
    engine: makeDenyEngine(),
    agentId: AGENT_ID,
    getState: () => ({ state: makeState(), version: 0 }),
    setState: () => { setStateCalled = true; return true; },
    trustedKeySets: [TEST_KEYSET],
  });

  await assert.rejects(() => guard(baseAction, async () => {}), OxDeAIDenyError);
  assert.ok(!setStateCalled);
});

// ── 14. onDecision hooks ──────────────────────────────────────────────────────

test("adapter: onDecision receives ALLOW after successful execution", async () => {
  let decision: string | undefined;
  const guard = createOpenClawGuard({
    ...makeGuardConfig(),
    onDecision({ decision: d }) { decision = d; },
  });

  await guard(baseAction, async () => {});
  assert.equal(decision, "ALLOW");
});

test("adapter: onDecision receives DENY when blocked", async () => {
  let decision: string | undefined;
  let currentState: State = { ...makeState(), kill_switch: { global: true, agents: {} } };

  const guard = createOpenClawGuard({
    engine: makeEngine(),
    agentId: AGENT_ID,
    getState: () => ({ state: currentState, version: 0 }),
    setState: (s) => { currentState = s; return true; },
    onDecision({ decision: d }) { decision = d; },
    trustedKeySets: [TEST_KEYSET],
  });

  await assert.rejects(() => guard(baseAction, async () => {}));
  assert.equal(decision, "DENY");
});

// ── 15. Guard is reusable across sequential calls ─────────────────────────────

test("adapter: guard is reusable — multiple sequential calls work", async () => {
  let currentState = makeState();
  const guard = createOpenClawGuard({
    engine: makeEngine(),
    agentId: AGENT_ID,
    getState: () => ({ state: currentState, version: 0 }),
    setState: (s) => { currentState = s; return true; },
    trustedKeySets: [TEST_KEYSET],
  });

  const r1 = await guard(baseAction, async () => "first");
  const r2 = await guard(baseAction, async () => "second");
  assert.equal(r1, "first");
  assert.equal(r2, "second");
});

// ── H-1 compatibility: an indeterminate execution is surfaced once ────────────
// The adapter does not consume the PEP gateway response contract. When the
// execute callback fails after dispatch (the side effect may have happened),
// the adapter must surface that failure exactly once: no automatic retry and
// no automatic re-authorization. Reconciliation belongs to the caller.

test("adapter (H-1): a failure after dispatch propagates once, with no automatic retry or re-authorization", async () => {
  let executions = 0;
  let evaluations = 0;
  const failure = Object.assign(new Error("ECONNRESET"), { code: "ECONNRESET" });

  const engine = makeEngine();
  const evaluate = engine.evaluatePure.bind(engine);
  engine.evaluatePure = ((...args: Parameters<typeof evaluate>) => {
    evaluations += 1;
    return evaluate(...args);
  }) as typeof engine.evaluatePure;

  const guard = createOpenClawGuard(makeGuardConfig({ engine }));

  await assert.rejects(
    () => guard(baseAction, async () => { executions += 1; throw failure; }),
    (err: unknown) => {
      assert.equal(err, failure, "the original post-dispatch failure must reach the caller unchanged");
      return true;
    }
  );

  assert.equal(executions, 1, "execute must run exactly once");
  assert.equal(evaluations, 1, "the policy engine must be evaluated exactly once");
});
