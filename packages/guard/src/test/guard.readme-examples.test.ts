// SPDX-License-Identifier: Apache-2.0
/**
 * Executable coverage for the security-relevant examples in README.md.
 *
 * The fixtures below use the same public API calls, configuration shape and
 * mapper as the README's "Custom action-to-intent mapping" and "Delegation
 * execution path" sections, so the README's claims are exercised against the
 * real guard rather than asserted in prose. The final tests check that the
 * README and CHANGELOG keep the corrected statements and do not reintroduce the
 * unsafe patterns they replaced.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  PolicyEngine,
  RECOMMENDED_TRUSTED_TIME_PROFILE,
  createDelegation,
  signAuthorizationEd25519,
} from "@oxdeai/core";
import type { AuthorizationAuthority, AuthorizationV1, DelegationScope, Intent, KeySet, State } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import {
  createSecureGuard,
  createTrustedExecutionContext,
  defaultNormalizeAction,
  OxDeAIAuthorityError,
  OxDeAIDelegationError,
  OxDeAIDenyError,
  OxDeAIGuardConfigurationError,
  OxDeAINormalizationError,
  OxDeAIProvenanceConflictError,
  type OxDeAIGuardConfig,
  type ProposedAction,
  type ReplayStore,
  type StateVersion,
} from "../index.js";

// ── README "Custom action-to-intent mapping" mapper, verbatim ────────────────

// Deployer-controlled pricing in fixed-point micro-units (1 unit = 1_000_000n).
// Never read from the request.
const GPU_PRICE_MICROS = new Map<string, bigint>([
  ["a100", 2_500_000_000n],
  ["h100", 4_000_000_000n],
]);
const REGIONS = new Set(["us-east-1", "eu-west-1"]);

function toIntent(action: ProposedAction): Intent {
  const { asset, region } = action.args;
  const price = typeof asset === "string" ? GPU_PRICE_MICROS.get(asset) : undefined;
  if (action.name !== "provision_gpu" || price === undefined || typeof region !== "string" || !REGIONS.has(region)) {
    throw new OxDeAINormalizationError("provision_gpu requires a known asset and region");
  }
  // defaultNormalizeAction supplies agent_id (reconciled against the
  // TrustedExecutionContext by createSecureGuard), a fresh intent_id and nonce,
  // and metadata_hash = sha256 of the sorted args, which binds every argument.
  return { ...defaultNormalizeAction(action), action_type: "PROVISION", amount: price, target: region };
}

// ── Shared fixtures ─────────────────────────────────────────────────────────

function keyPair() {
  return generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
}

const PDP = keyPair();
const AGENT_A = keyPair();
const PDP_ISSUER = "oxdeai.policy-engine"; // PolicyEngine's default authorization issuer
const POLICY_ID = "policy-readme";
const T_NOW = Math.floor(Date.now() / 1000);

const pdpKeySet: KeySet = { issuer: PDP_ISSUER, version: "1", keys: [{ kid: "k1", alg: "Ed25519", public_key: PDP.publicKey }] };
const agentAKeySet: KeySet = { issuer: "agent-A", version: "1", keys: [{ kid: "agent-A-k1", alg: "Ed25519", public_key: AGENT_A.publicKey }] };
const AUTHORITIES: readonly AuthorizationAuthority[] = [{ issuer: PDP_ISSUER, policyId: POLICY_ID }];
const PARENT_SCOPE: DelegationScope = { tools: ["provision_gpu"], max_amount: 10_000_000_000n };

function engineFor(audience: string) {
  return new PolicyEngine({
    policy_version: "v1",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    authorization_signing_alg: "Ed25519",
    authorization_signing_kid: "k1",
    authorization_private_key_pem: PDP.privateKey,
    authorization_audience: audience,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

/** Versioned in-memory state with real CAS, recording writes. */
function stateStore(state: State) {
  let current: { state: State; version: StateVersion } = { state, version: 0 };
  const writes: StateVersion[] = [];
  return {
    getState: () => current,
    setState: (next: State, expected: StateVersion) => {
      if (current.version !== expected) return false;
      current = { state: next, version: (current.version as number) + 1 };
      writes.push(expected);
      return true;
    },
    writes,
  };
}

/** A replay store that records every consume so tests can assert its absence. */
function observableReplayStore(calls: string[]) {
  const auth = new Set<string>();
  const deleg = new Set<string>();
  const store: ReplayStore = {
    async consumeAuthId(id) { calls.push("consumeAuthId"); if (auth.has(id)) return false; auth.add(id); return true; },
    async consumeDelegationId(id) { calls.push("consumeDelegationId"); if (deleg.has(id)) return false; deleg.add(id); return true; },
  };
  return { store, auth, deleg };
}

function context(agentId: string, depth = 0) {
  return createTrustedExecutionContext({ principalId: `principal-${agentId}`, agentId, adapterId: "http-adapter", depth });
}

// ── Delegation fixture: the README's parent side, child-side PEP and call ────

function delegationSetup(over: Partial<OxDeAIGuardConfig> = {}) {
  const calls: string[] = [];
  const replay = observableReplayStore(calls);
  // Policy state that would DENY everything if the engine were consulted.
  const state = buildState({ agent_id: "agent-B", allow_action_types: [], budget_limit: 0n, max_amount_per_action: 0n });
  state.kill_switch.global = true;
  const store = stateStore(state);

  const engine = engineFor("agent-A");
  engine.evaluatePure = () => { calls.push("evaluatePure"); throw new Error("delegation path must not evaluate policy"); };

  const parentAuth: AuthorizationV1 = signAuthorizationEd25519(
    {
      auth_id: `parent-${Math.random()}`, issuer: PDP_ISSUER, audience: "agent-A",
      intent_hash: "a".repeat(64), state_hash: "b".repeat(64), policy_id: POLICY_ID, decision: "ALLOW",
      issued_at: T_NOW - 10, expiry: T_NOW + 600, kid: "k1",
    } as never,
    PDP.privateKey
  );

  // README: parent side.
  const delegation = createDelegation(
    parentAuth,
    {
      delegatee: "agent-B",
      scope: { tools: ["provision_gpu"], max_amount: 3_000_000_000n },
      expiry: parentAuth.expiry,
      kid: "agent-A-k1",
    },
    AGENT_A.privateKey
  );

  // README: child side.
  const guard = createSecureGuard(
    {
      engine,
      getState: store.getState,
      setState: (s, v) => { calls.push("setState"); return store.setState(s, v); },
      expectedAudience: "agent-A",
      trustedKeySets: [pdpKeySet, agentAKeySet],
      trustedDelegationAuthorities: AUTHORITIES,
      mapActionToIntent: toIntent,
      replayStore: replay.store,
      beforeExecute: () => { calls.push("beforeExecute"); },
      ...over,
    },
    { tenancy: "single-tenant" }
  );

  const executed: Readonly<Record<string, unknown>>[] = [];
  async function present(agentId: string, args: Record<string, unknown>, proposerContext?: Record<string, unknown>) {
    const request = Object.freeze({ ...args });
    return guard(
      context(agentId, 1),
      { name: "provision_gpu", args: request, ...(proposerContext ? { context: proposerContext } : {}) },
      async () => { calls.push("execute"); executed.push(request); return "provisioned"; },
      { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } }
    );
  }
  return { calls, replay, store, delegation, parentAuth, present, executed };
}

const A100 = { asset: "a100", region: "us-east-1" };

test("A: README delegation example executes for the intended delegatee", async () => {
  const d = delegationSetup();
  assert.equal(await d.present("agent-B", A100), "provisioned");
  assert.deepEqual(d.executed, [A100]);
  assert.deepEqual(d.calls, ["consumeDelegationId", "consumeAuthId", "beforeExecute", "execute"]);
  assert.ok(d.replay.deleg.has(d.delegation.delegation_id));
  assert.ok(d.replay.auth.has(d.parentAuth.auth_id));
});

test("B, C, D: a substituted delegatee is rejected before execution, state write or replay consumption; the delegatee can still use the artifact", async () => {
  const d = delegationSetup();
  await assert.rejects(d.present("agent-C", A100), (err: unknown) => {
    assert.ok(err instanceof OxDeAIDelegationError);
    assert.ok(err.violations.some((v) => v.includes("delegatee does not match expectedDelegatee")));
    return true;
  });
  assert.deepEqual(d.calls, [], "no evaluation, consumption, state write, hook or execution");
  assert.equal(d.replay.auth.size, 0);
  assert.equal(d.replay.deleg.size, 0);
  assert.equal(d.store.writes.length, 0);
  assert.equal(d.executed.length, 0);

  assert.equal(await d.present("agent-B", A100), "provisioned");
  assert.deepEqual(d.executed, [A100]);
});

test("E: missing, empty or non-matching delegation authority fails closed before consumption or execution", async () => {
  const cases: Array<[string, Partial<OxDeAIGuardConfig>, new (...a: never[]) => Error]> = [
    ["undefined", { trustedDelegationAuthorities: undefined }, OxDeAIGuardConfigurationError],
    ["empty", { trustedDelegationAuthorities: [] }, OxDeAIAuthorityError],
    ["other pair", { trustedDelegationAuthorities: [{ issuer: PDP_ISSUER, policyId: "some-other-policy" }] }, OxDeAIAuthorityError],
  ];
  for (const [label, over, errorClass] of cases) {
    const d = delegationSetup(over);
    await assert.rejects(d.present("agent-B", A100), errorClass, label);
    assert.deepEqual(d.calls, [], label);
    assert.equal(d.executed.length, 0, label);
  }
});

test("F: a proposer agent_id that conflicts with the TrustedExecutionContext fails closed", async () => {
  const d = delegationSetup();
  // The request claims to be the delegatee; the authenticated identity is agent-C.
  await assert.rejects(d.present("agent-C", A100, { agent_id: "agent-B" }), OxDeAIProvenanceConflictError);
  assert.deepEqual(d.calls, []);
  assert.equal(d.executed.length, 0);
});

test("G: a delegated amount above scope.max_amount fails closed before consumption or execution", async () => {
  const d = delegationSetup();
  // h100 is priced at 4000 units; the delegation allows 3000.
  await assert.rejects(d.present("agent-B", { asset: "h100", region: "us-east-1" }), (err: unknown) => {
    assert.ok(err instanceof OxDeAIDelegationError);
    assert.ok(err.violations.some((v) => v.includes("exceeds delegation scope.max_amount")));
    return true;
  });
  assert.deepEqual(d.calls, []);
  assert.equal(d.executed.length, 0);
});

test("README claim: the delegation path does not evaluate the PolicyEngine or commit state", async () => {
  // delegationSetup's state has the global kill switch on, zero budget and no
  // allowed action types, and its engine throws if evaluated. The delegated call
  // still executes: the chain and delegation scope are the only constraints.
  const d = delegationSetup();
  assert.equal(await d.present("agent-B", A100), "provisioned");
  assert.ok(!d.calls.includes("evaluatePure"));
  assert.ok(!d.calls.includes("setState"));
  assert.equal(d.store.writes.length, 0);
});

// ── README custom mapper on the standard (non-delegation) path ───────────────

function mapperSetup() {
  const calls: string[] = [];
  const store = stateStore(buildState({
    agent_id: "agent-xyz",
    allow_action_types: ["PROVISION"],
    budget_limit: 3_000_000_000n, // 3000 units: one a100 fits, two do not
    max_amount_per_action: 5_000_000_000n,
  }));
  const engine = engineFor("agent-xyz");
  const evaluate = engine.evaluatePure.bind(engine);
  engine.evaluatePure = (...args: Parameters<typeof evaluate>) => { calls.push("evaluatePure"); return evaluate(...args); };

  const authorized: Intent[] = [];
  const guard = createSecureGuard(
    {
      engine,
      getState: store.getState,
      setState: (s, v) => { calls.push("setState"); return store.setState(s, v); },
      expectedAudience: "agent-xyz",
      trustedKeySets: [pdpKeySet],
      mapActionToIntent: (a) => { const intent = toIntent(a); authorized.push(intent); return intent; },
    },
    { tenancy: "single-tenant" }
  );
  const trustedContext = context("agent-xyz");
  const executed: Readonly<Record<string, unknown>>[] = [];
  async function provision(args: Record<string, unknown>) {
    const request = Object.freeze({ ...args });
    return guard(trustedContext, { name: "provision_gpu", args: request }, async () => {
      calls.push("execute");
      executed.push(request);
      return "provisioned";
    });
  }
  return { calls, authorized, executed, provision, store };
}

function sortedArgsHash(args: Record<string, unknown>): string {
  const sorted = Object.fromEntries(Object.keys(args).sort().map((k) => [k, args[k]]));
  return createHash("sha256").update(JSON.stringify(sorted)).digest("hex");
}

test("H: the README mapper authorizes exactly what the callback executes, priced from the trusted table", async () => {
  const m = mapperSetup();
  assert.equal(await m.provision(A100), "provisioned");
  const [intent] = m.authorized;
  const [executed] = m.executed;
  assert.deepEqual(executed, A100);
  assert.equal(intent.amount, GPU_PRICE_MICROS.get(executed["asset"] as string));
  assert.equal(intent.action_type, "PROVISION");
  assert.equal(intent.agent_id, "agent-xyz", "identity comes from the trusted context");
  assert.equal(intent.target, executed["region"]);
  assert.equal(intent.metadata_hash, sortedArgsHash(executed as Record<string, unknown>), "metadata_hash binds the executed args");
  assert.notEqual(intent.metadata_hash, sortedArgsHash({ ...A100, region: "eu-west-1" }));

  // A second a100 exceeds the 3000-unit budget: no silent zero-cost path.
  await assert.rejects(m.provision(A100), (err: unknown) => {
    assert.ok(err instanceof OxDeAIDenyError);
    assert.ok(err.reasons.includes("BUDGET_EXCEEDED"));
    return true;
  });
  assert.equal(m.executed.length, 1);
});

test("I: missing or malformed cost-bearing inputs fail normalization before evaluation or execution", async () => {
  const malformed: Record<string, unknown>[] = [
    {},
    { region: "us-east-1" },
    { asset: "a100" },
    { asset: "tpu", region: "us-east-1" },
    { asset: "a100", region: "mars-1" },
    { asset: 100, region: "us-east-1" },
    { asset: "constructor", region: "us-east-1" },
    { asset: "__proto__", region: "us-east-1" },
  ];
  for (const args of malformed) {
    const m = mapperSetup();
    await assert.rejects(m.provision(args), OxDeAINormalizationError, JSON.stringify(args));
    assert.deepEqual(m.calls, [], JSON.stringify(args));
    assert.equal(m.store.writes.length, 0);
  }
});

// ── J: documentation drift ──────────────────────────────────────────────────

const packageRoot = fileURLToPath(new URL("../../", import.meta.url));
const flat = (s: string) => s.replace(/\s+/g, " ");

function section(markdown: string, heading: string): string {
  const start = markdown.indexOf(`## ${heading}`);
  assert.ok(start >= 0, `README is missing the "${heading}" section`);
  const end = markdown.indexOf("\n## ", start + 3);
  return markdown.slice(start, end < 0 ? undefined : end);
}

test("J: README keeps the corrected delegation and mapper guidance", () => {
  const readme = readFileSync(packageRoot + "README.md", "utf8");

  // Unsafe or false patterns that were removed must not return.
  assert.doesNotMatch(readme, /before policy evaluation/);
  assert.doesNotMatch(readme, /delegation:\s*\{\s*delegation:\s*delegationChain,\s*parentAuth\s*\}/);
  assert.doesNotMatch(readme, /agent_id:\s*action\.context\?\.agent_id/);
  assert.doesNotMatch(readme, /estimatedCost \?\? 0/);
  assert.doesNotMatch(readme, /provisionGpu\("a100", "us-east-1"\)/);

  // The README mapper is the one exercised above.
  const mapper = flat(section(readme, "Custom action-to-intent mapping"));
  for (const line of [
    'const GPU_PRICE_MICROS = new Map<string, bigint>([',
    'const price = typeof asset === "string" ? GPU_PRICE_MICROS.get(asset) : undefined;',
    'throw new OxDeAINormalizationError("provision_gpu requires a known asset and region");',
    'return { ...defaultNormalizeAction(action), action_type: "PROVISION", amount: price, target: region };',
    "mapActionToIntent: toIntent,",
    "async () => provisionGpu(request)",
  ]) {
    assert.ok(mapper.includes(flat(line)), `mapper section lost: ${line}`);
  }

  const delegation = flat(section(readme, "Delegation execution path"));
  for (const needle of [
    "createSecureGuard(",
    "createTrustedExecutionContext(",
    "trustedDelegationAuthorities:",
    "parentScope:",
    "delegation.delegatee === trusted execution identity",
    "It does **not** evaluate the `PolicyEngine`",
    "`@oxdeai/guard@2.0.0` does not bind `delegatee` to the acting agent",
  ]) {
    assert.ok(delegation.includes(flat(needle)), `delegation section lost: ${needle}`);
  }
  assert.doesNotMatch(delegation, /OxDeAIGuard\(/, "the primary delegation example must use createSecureGuard");
});

test("J: CHANGELOG ordering matches the implementation and does not overclaim rollback", () => {
  const changelog = flat(readFileSync(packageRoot + "CHANGELOG.md", "utf8"));
  assert.ok(changelog.includes(
    "strict verification → `intent_hash` binding → `state_hash` binding → consume `auth_id` → CAS commit"
  ));
  assert.doesNotMatch(changelog, /consume `auth_id` → strict verification/);
  assert.doesNotMatch(changelog, /Any failure blocks execution with no side effects committed/);
  assert.ok(changelog.includes("Consumption is irreversible"));
});
