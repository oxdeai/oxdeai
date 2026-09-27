// SPDX-License-Identifier: Apache-2.0
/**
 * Executable fixtures for the three integration examples on the public
 * website (`website/index.html`, section `#code`).
 *
 * Each fixture mirrors its snippet's configuration and call shape, so the
 * security claims the site makes are exercised against the real engine,
 * guard and verifiers rather than asserted in prose:
 *
 *   guard setup          - the authorized amount/type is the executed amount/type
 *   strict verification  - "ok" on an envelope implies a verified trusted signature
 *   delegation           - the delegatee is bound to the trusted acting identity
 *
 * The final test checks that the website still shows the load-bearing lines,
 * so the page cannot silently drift back to the unsafe forms these fixtures
 * replaced.
 *
 * RELEASE NOTE: the guard-enforced delegatee binding (#350) exists on main and
 * is NOT in the published @oxdeai/guard@2.0.0. The delegation tests below that
 * call the guard WITHOUT the snippet's explicit pre-check prove current main
 * behavior only.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  PolicyEngine,
  RECOMMENDED_TRUSTED_TIME_PROFILE,
  createDelegation,
  encodeCanonicalState,
  encodeEnvelope,
  signAuthorizationEd25519,
  signEnvelopeEd25519,
  verifyAuthorization,
  verifyEnvelope,
} from "@oxdeai/core";
import type { AuthorizationAuthority, AuthorizationV1, DelegationV1, Intent, KeySet, State } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { createSecureGuard } from "../secureGuard.js";
import { createTrustedExecutionContext } from "../trustedContext.js";
import type { TrustedExecutionContext } from "../trustedContext.js";
import { defaultNormalizeAction } from "../normalizeAction.js";
import type { ReplayStore } from "../replayStore.js";
import type { ProposedAction, StateVersion } from "../types.js";
import {
  OxDeAIAuthorizationError,
  OxDeAIDelegationError,
  OxDeAIDenyError,
  OxDeAINormalizationError,
  OxDeAIProvenanceConflictError,
} from "../errors.js";

function keyPair() {
  return generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
}

const PDP_KEY = keyPair();
const PARENT_AGENT_KEY = keyPair();
const ROGUE_KEY = keyPair();
const T_NOW = Math.floor(Date.now() / 1000);

// PolicyEngine's default authorization issuer; the website engine sets none.
const PDP_ISSUER = "oxdeai.policy-engine";
const pdpKeySet: KeySet = {
  issuer: PDP_ISSUER, version: "1",
  keys: [{ kid: "k1", alg: "Ed25519", public_key: PDP_KEY.publicKey }],
};

/** Versioned in-memory state with real compare-and-set, so budget accumulates. */
function stateStore(state: State) {
  let current = { state, version: 0 as StateVersion };
  let writes = 0;
  return {
    getState: () => current,
    setState: (next: State, expected: StateVersion) => {
      if (current.version !== expected) return false;
      current = { state: next, version: (current.version as number) + 1 };
      writes += 1;
      return true;
    },
    writes: () => writes,
  };
}

function websiteEngine(): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v1.0.0",
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 60,
    authorization_signing_alg: "Ed25519",
    authorization_signing_kid: "k1",
    authorization_private_key_pem: PDP_KEY.privateKey,
    authorization_audience: "agent-001",
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

// ── Guard setup tab ──────────────────────────────────────────────────────────

/** Mirrors `toIntent` on the website: amount and type come from the executed args. */
function toIntent(action: ProposedAction): Intent {
  const amount = action.args["amount_micros"];
  if (action.name !== "charge_wallet" || typeof amount !== "string" || !/^[1-9][0-9]*$/.test(amount)) {
    throw new OxDeAINormalizationError("charge_wallet requires a positive integer amount_micros string");
  }
  return { ...defaultNormalizeAction(action), action_type: "PAYMENT", amount: BigInt(amount) };
}

function guardSetup() {
  const store = stateStore(buildState({
    agent_id: "agent-001",
    policy_version: "v1.0.0",            // must match the engine's policy_version
    allow_action_types: ["PAYMENT"],
    budget_limit: 150_000_000n,          // 150.00 USD
    max_amount_per_action: 150_000_000n,
  }));
  const authorized: Intent[] = [];
  const guard = createSecureGuard(
    {
      engine: websiteEngine(),
      getState: store.getState,
      setState: store.setState,
      trustedKeySets: [pdpKeySet],
      expectedAudience: "agent-001",
      // Capture the normalized intent so the test can compare it to execution.
      mapActionToIntent: (a) => {
        const intent = toIntent(a);
        authorized.push(intent);
        return intent;
      },
    },
    { tenancy: "single-tenant" }
  );
  const trustedContext = createTrustedExecutionContext({
    principalId: "principal-001", agentId: "agent-001", adapterId: "http-pep", depth: 0,
  });
  const executed: Readonly<Record<string, unknown>>[] = [];
  const chargeWallet = async (args: Readonly<Record<string, unknown>>) => {
    executed.push(args);
    return "charged";
  };
  async function charge(args: Record<string, unknown>) {
    const charge = Object.freeze({ ...args });
    return guard(trustedContext, { name: "charge_wallet", args: charge }, async () => chargeWallet(charge));
  }
  return { charge, authorized, executed, store };
}

test("website guard: the authorized amount and type are exactly what executes", async () => {
  const g = guardSetup();
  const args = { wallet_id: "w-1", amount_micros: "100000000", currency: "usd" };
  assert.equal(await g.charge(args), "charged");

  assert.equal(g.authorized.length, 1);
  assert.equal(g.executed.length, 1);
  assert.equal(g.authorized[0].action_type, "PAYMENT");
  assert.equal(g.authorized[0].amount, 100_000_000n);
  // Execution received the identical validated value that was authorized.
  assert.equal(BigInt(g.executed[0]["amount_micros"] as string), g.authorized[0].amount);
  assert.deepEqual(g.executed[0], args);
  assert.equal(g.store.writes(), 1);
});

test("website guard: an amount beyond the remaining budget is denied and never executes", async () => {
  const g = guardSetup();
  await g.charge({ wallet_id: "w-1", amount_micros: "100000000", currency: "usd" });
  // 100 + 100 > 150 budget.
  await assert.rejects(g.charge({ wallet_id: "w-1", amount_micros: "100000000", currency: "usd" }), OxDeAIDenyError);
  // 200 > 150 per-action ceiling on a fresh budget.
  const fresh = guardSetup();
  await assert.rejects(fresh.charge({ wallet_id: "w-1", amount_micros: "200000000", currency: "usd" }), OxDeAIDenyError);

  assert.equal(g.executed.length, 1);
  assert.equal(fresh.executed.length, 0);
  assert.equal(fresh.store.writes(), 0);
});

test("website guard: missing or non-integer amounts fail closed before evaluation", async () => {
  for (const amount_micros of [undefined, 100, "0", "100.5", "-1", "1e8"]) {
    const g = guardSetup();
    await assert.rejects(g.charge({ wallet_id: "w-1", amount_micros, currency: "usd" }), OxDeAINormalizationError);
    assert.equal(g.executed.length, 0);
    assert.equal(g.store.writes(), 0);
  }
});

test("regression: the previous website action normalized to a zero-cost PROVISION intent", () => {
  // Previous snippet: { name: "charge_wallet", args: { amount: 100, currency: "usd" } }
  // executed as chargeWallet(100). The default normalizer authorizes neither
  // the amount nor the payment type, which is why the site now uses toIntent.
  const intent = defaultNormalizeAction({
    name: "charge_wallet",
    args: { amount: 100, currency: "usd" },
    context: { agent_id: "agent-001" },
  });
  assert.equal(intent.amount, 0n);
  assert.equal(intent.action_type, "PROVISION");
});

// ── Strict verification tab ──────────────────────────────────────────────────

const ENVELOPE_ISSUER = "oxdeai-pdp";
const envelopeKeySet: KeySet = {
  issuer: ENVELOPE_ISSUER, version: "1",
  keys: [{ kid: "k1", alg: "Ed25519", public_key: PDP_KEY.publicKey }],
};

function envelopeParts() {
  const engine = websiteEngine();
  const policyId = engine.computePolicyId();
  const snapshot = encodeCanonicalState(engine.exportState(buildState({ agent_id: "agent-001" })));
  const events: Parameters<typeof encodeEnvelope>[0]["events"] = [
    { type: "INTENT_RECEIVED", intent_hash: "ih-1", agent_id: "agent-001", timestamp: 100, policyId },
    { type: "DECISION", intent_hash: "ih-1", decision: "ALLOW", reasons: [], policy_version: "v1.0.0", timestamp: 101, policyId },
    { type: "STATE_CHECKPOINT", stateHash: "a".repeat(64), timestamp: 102, policyId },
  ];
  return { policyId, envelope: { formatVersion: 1 as const, snapshot, events } };
}

/** Mirrors the website envelope call. */
function verifyAuditEnvelope(envelopeBytes: Uint8Array, expectedPolicyId: string) {
  return verifyEnvelope(envelopeBytes, {
    mode: "strict",
    trustedKeySets: [envelopeKeySet],
    expectedIssuer: ENVELOPE_ISSUER,
    requireSignatureVerification: true,
    expectedPolicyId,
  });
}

test("website verification: a trusted signed envelope verifies", () => {
  const { policyId, envelope } = envelopeParts();
  const signed = signEnvelopeEd25519(envelope, { issuer: ENVELOPE_ISSUER, kid: "k1", privateKeyPem: PDP_KEY.privateKey });
  const result = verifyAuditEnvelope(encodeEnvelope(signed), policyId);
  assert.equal(result.status, "ok");
});

test("website verification: an unsigned envelope is rejected", () => {
  const { policyId, envelope } = envelopeParts();
  const bytes = encodeEnvelope(envelope);
  const result = verifyAuditEnvelope(bytes, policyId);
  assert.equal(result.status, "invalid");
  assert.ok(result.violations.some((v) => v.code === "ENVELOPE_SIGNATURE_MISSING"));

  // Why the website sets requireSignatureVerification: strict mode plus trusted
  // keys alone still accepts the same unsigned bytes as "ok".
  const structuralOnly = verifyEnvelope(bytes, { mode: "strict", trustedKeySets: [envelopeKeySet], expectedPolicyId: policyId });
  assert.equal(structuralOnly.status, "ok");
});

test("website verification: wrong-key and untrusted-issuer envelopes are rejected", () => {
  const { policyId, envelope } = envelopeParts();
  const forged = signEnvelopeEd25519(envelope, { issuer: ENVELOPE_ISSUER, kid: "k1", privateKeyPem: ROGUE_KEY.privateKey });
  const forgedResult = verifyAuditEnvelope(encodeEnvelope(forged), policyId);
  assert.equal(forgedResult.status, "invalid");
  assert.ok(forgedResult.violations.some((v) => v.code === "ENVELOPE_SIGNATURE_INVALID"));

  const foreign = signEnvelopeEd25519(envelope, { issuer: "someone-else", kid: "k1", privateKeyPem: ROGUE_KEY.privateKey });
  const foreignResult = verifyAuditEnvelope(encodeEnvelope(foreign), policyId);
  assert.equal(foreignResult.status, "invalid");
  assert.ok(foreignResult.violations.some((v) => v.code === "ENVELOPE_KID_UNKNOWN"));
});

test("website verification: strict authorization requires a verified trusted signature", () => {
  const artifact = signAuthorizationEd25519(
    {
      auth_id: "auth-website-1", issuer: PDP_ISSUER, audience: "agent-001",
      intent_hash: "a".repeat(64), state_hash: "b".repeat(64),
      policy_id: "policy-production-v1", decision: "ALLOW",
      issued_at: T_NOW - 10, expiry: T_NOW + 60, kid: "k1",
    } as never,
    PDP_KEY.privateKey
  );
  const opts = { mode: "strict" as const, trustedKeySets: [pdpKeySet], expectedPolicyId: "policy-production-v1" };

  const ok = verifyAuthorization(artifact, opts);
  assert.equal(ok.status, "ok");
  assert.equal(ok.signatureVerified, true);

  const forged = signAuthorizationEd25519({ ...artifact, signature: undefined } as never, ROGUE_KEY.privateKey);
  const forgedResult = verifyAuthorization(forged, opts);
  assert.notEqual(forgedResult.status, "ok");
  assert.equal(forgedResult.signatureVerified, false);

  const noTrust = verifyAuthorization(artifact, { mode: "strict", expectedPolicyId: "policy-production-v1" });
  assert.ok(noTrust.violations.some((v) => v.code === "TRUSTED_KEYSETS_REQUIRED"));
});

// ── Delegation tab ───────────────────────────────────────────────────────────

const parentAgentKeySet: KeySet = {
  issuer: "agent-001", version: "1",
  keys: [{ kid: "agent-001-k1", alg: "Ed25519", public_key: PARENT_AGENT_KEY.publicKey }],
};
const trustedDelegationAuthorities: readonly AuthorizationAuthority[] = [
  { issuer: PDP_ISSUER, policyId: "policy-production-v1" },
];
const parentScope = { tools: ["provision_gpu"], max_amount: 1_000_000_000n };

function issueParentAuth(authId: string): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      auth_id: authId, issuer: PDP_ISSUER, audience: "agent-001",
      intent_hash: "c".repeat(64), state_hash: "d".repeat(64),
      policy_id: "policy-production-v1", decision: "ALLOW",
      issued_at: T_NOW - 10, expiry: T_NOW + 600, kid: "k1",
    } as never,
    PDP_KEY.privateKey
  );
}

/** Mirrors `toGpuIntent`: amount comes from the executed args. */
function toGpuIntent(action: ProposedAction): Intent {
  const amount = action.args["cost_micros"];
  if (action.name !== "provision_gpu" || typeof amount !== "string" || !/^[1-9][0-9]*$/.test(amount)) {
    throw new OxDeAINormalizationError("provision_gpu requires a positive integer cost_micros string");
  }
  return { ...defaultNormalizeAction(action), action_type: "PROVISION", amount: BigInt(amount) };
}

function delegationSetup() {
  const calls: string[] = [];
  const auth = new Set<string>();
  const deleg = new Set<string>();
  const replayStore: ReplayStore = {
    async consumeAuthId(id) { calls.push("consumeAuthId"); if (auth.has(id)) return false; auth.add(id); return true; },
    async consumeDelegationId(id) { calls.push("consumeDelegationId"); if (deleg.has(id)) return false; deleg.add(id); return true; },
  };
  const store = stateStore(buildState({ agent_id: "child-agent-002", policy_version: "v1.0.0" }));

  const parentAuth = issueParentAuth(`parent-${Math.random()}`);
  const delegation: DelegationV1 = createDelegation(
    parentAuth,
    {
      delegatee: "child-agent-002",
      scope: { tools: ["provision_gpu"], max_amount: 300_000_000n },
      expiry: parentAuth.expiry,
      kid: "agent-001-k1",
    },
    PARENT_AGENT_KEY.privateKey
  );

  const guard = createSecureGuard(
    {
      engine: websiteEngine(),
      getState: store.getState,
      setState: (s, v) => { calls.push("setState"); return store.setState(s, v); },
      trustedKeySets: [pdpKeySet, parentAgentKeySet],
      expectedAudience: "agent-001",
      trustedDelegationAuthorities,
      mapActionToIntent: toGpuIntent,
      replayStore,
      beforeExecute: () => { calls.push("beforeExecute"); },
    },
    { tenancy: "single-tenant" }
  );

  const contextFor = (agentId: string) => createTrustedExecutionContext({
    principalId: `principal-for-${agentId}`, agentId, adapterId: "http-pep", depth: 1,
  });

  const provisioned: Readonly<Record<string, unknown>>[] = [];
  async function callGuard(ctx: TrustedExecutionContext, args: Record<string, unknown>, context?: Record<string, unknown>) {
    const gpuRequest = Object.freeze({ ...args });
    return guard(
      ctx,
      { name: "provision_gpu", args: gpuRequest, ...(context ? { context } : {}) },
      async () => { calls.push("execute"); provisioned.push(gpuRequest); return "provisioned"; },
      { delegation: { delegation, parentAuth, parentScope } }
    );
  }
  /** The full website flow: explicit recipient pre-check, then the guard. */
  async function websiteFlow(ctx: TrustedExecutionContext, args: Record<string, unknown>) {
    if (delegation.delegatee !== ctx.agentId) {
      throw new Error("Delegation was not issued to this agent");
    }
    return callGuard(ctx, args);
  }
  return { calls, auth, deleg, store, delegation, parentAuth, contextFor, callGuard, websiteFlow, provisioned };
}

const GPU = { gpu: "a100", cost_micros: "250000000" };

test("website delegation: the intended delegate executes within the delegated scope", async () => {
  const d = delegationSetup();
  assert.equal(await d.websiteFlow(d.contextFor("child-agent-002"), GPU), "provisioned");
  assert.deepEqual(d.provisioned, [GPU]);
  assert.deepEqual(d.calls, ["consumeDelegationId", "consumeAuthId", "beforeExecute", "execute"]);
  assert.equal(d.store.writes(), 0, "delegation path never commits state");
});

test("website delegation (main only, #350): a different acting identity is rejected by the guard before replay, state or execution", async () => {
  const d = delegationSetup();
  // Called WITHOUT the snippet's pre-check, to prove the guard itself binds
  // delegatee to TrustedExecutionContext.agentId. Not true of guard@2.0.0.
  await assert.rejects(d.callGuard(d.contextFor("child-agent-003"), GPU), (err: unknown) => {
    assert.ok(err instanceof OxDeAIDelegationError);
    assert.ok(err.violations.some((v) => v.includes("delegatee does not match expectedDelegatee")));
    return true;
  });
  assert.deepEqual(d.calls, []);
  assert.equal(d.auth.size, 0);
  assert.equal(d.deleg.size, 0);
  assert.equal(d.provisioned.length, 0);

  // The unconsumed artifact still works for its real recipient.
  assert.equal(await d.callGuard(d.contextFor("child-agent-002"), GPU), "provisioned");
});

test("website delegation: the explicit pre-check rejects a different identity before the guard runs (any version)", async () => {
  const d = delegationSetup();
  await assert.rejects(d.websiteFlow(d.contextFor("child-agent-003"), GPU), /not issued to this agent/);
  assert.deepEqual(d.calls, []);
  assert.equal(d.provisioned.length, 0);
});

test("website delegation: a proposer-claimed agent_id cannot override the trusted identity", async () => {
  const d = delegationSetup();
  await assert.rejects(
    d.callGuard(d.contextFor("child-agent-003"), GPU, { agent_id: "child-agent-002" }),
    OxDeAIProvenanceConflictError
  );
  assert.deepEqual(d.calls, []);
});

test("website delegation: amount above the delegated max_amount and replay are rejected", async () => {
  const d = delegationSetup();
  await assert.rejects(
    d.websiteFlow(d.contextFor("child-agent-002"), { gpu: "a100", cost_micros: "400000000" }),
    OxDeAIDelegationError
  );
  assert.deepEqual(d.calls, []);

  await d.websiteFlow(d.contextFor("child-agent-002"), GPU);
  await assert.rejects(d.websiteFlow(d.contextFor("child-agent-002"), GPU), OxDeAIAuthorizationError);
  assert.equal(d.provisioned.length, 1);
});

// ── Website drift check ──────────────────────────────────────────────────────

test("website: code panels show the load-bearing lines exercised above", () => {
  const html = readFileSync(fileURLToPath(new URL("../../../../website/index.html", import.meta.url)), "utf8");
  const panel = (id: string): string => {
    const start = html.indexOf(`<div id="${id}"`);
    assert.ok(start >= 0, `missing panel ${id}`);
    const end = html.indexOf("</pre>", start);
    return html
      .slice(start, end)
      .replace(/<[^>]+>/g, "")
      .replace(/&gt;/g, ">")
      .replace(/&lt;/g, "<")
      .replace(/&amp;/g, "&");
  };

  const guardTab = panel("tab-guard");
  assert.match(guardTab, /mapActionToIntent: toIntent/);
  assert.match(guardTab, /action_type: "PAYMENT", amount: BigInt\(amount\)/);
  assert.match(guardTab, /async \(\) => chargeWallet\(charge\)/);
  assert.doesNotMatch(guardTab, /chargeWallet\(\d/);

  const verifyTab = panel("tab-verify");
  assert.match(verifyTab, /requireSignatureVerification: true/);
  assert.match(verifyTab, /!result\.signatureVerified/);
  assert.doesNotMatch(verifyTab, /cryptographically verified/);

  const delegationTab = panel("tab-delegation");
  assert.match(delegationTab, /createSecureGuard\(/);
  assert.match(delegationTab, /trustedDelegationAuthorities:/);
  assert.match(delegationTab, /createTrustedExecutionContext\(/);
  assert.match(delegationTab, /delegation\.delegatee !== childContext\.agentId/);
  assert.match(delegationTab, /@oxdeai\/guard@2\.0\.0/);
  assert.doesNotMatch(delegationTab, /OxDeAIGuard/);

  // Envelope signing is optional, so the page must not call every audit trail signed.
  assert.doesNotMatch(html, /Signed audit trail/);
  assert.match(html, /Envelope\s+signatures are optional/);
});
