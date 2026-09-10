#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { evidenceScope } from "./evidenceScope.mjs";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, sign as nodeSign } from "node:crypto";
import {
  encodeCanonicalState,
  encodeEnvelope,
  PolicyEngine,
  RECOMMENDED_TRUSTED_TIME_PROFILE,
  sha256HexFromJson,
  signAuthorizationEd25519,
  signEnvelopeEd25519,
  verifyAuthorization,
  verifyAuditEvents,
  verifyEnvelope,
  verifySnapshot,
  createDelegation,
  verifyDelegation,
  verifyDelegationChain,
  signEd25519,
  SIGNING_DOMAINS,
  signedKrlSigningPayload,
  verifySignedKrl,
} from "@oxdeai/core";
import type { AuthorizationV1, Intent, KeySet, KeySetKey, State, VerificationResult, DelegationV1, DelegationScope, VerifyDelegationOptions, SignedKRLV1 } from "@oxdeai/core";
import {
  TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION,
  TEST_ONLY_ED25519_PUBLIC_KEY_PEM_DO_NOT_USE_IN_PRODUCTION,
} from "./fixtures/ed25519.test-only.fixture.js";
import {
  KRL_TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION,
  KRL_TEST_ONLY_ED25519_PUBLIC_KEY_PEM_DO_NOT_USE_IN_PRODUCTION,
} from "./fixtures/krl-ed25519.test-only.fixture.js";
import { CONFORMANCE_ENGINE_SECRET } from "./fixtures/conformance-engine-secret.fixture.js";
import { runTrustedTimeConformance } from "./trustedTimeConformance.js";

type JsonRecord = Record<string, unknown>;

// Normative AuthorizationV1 supports both a bare signature string (legacy) and a
// nested signature object. This union mirrors AuthorizationV1.signature exactly so
// that Authorization (= AuthorizationLegacy & AuthorizationV1) is assignable here.
type AuthorizationSignatureLike =
  | string
  | { alg: "Ed25519" | "HMAC-SHA256"; kid: string; sig: string };

type AuthorizationLike = {
  auth_id: string;
  issuer: string;
  audience: string;
  intent_hash: string;
  state_hash: string;
  policy_id: string;
  decision: "ALLOW" | "DENY";
  issued_at: number;
  expiry: number;
  alg: "Ed25519" | "HMAC-SHA256";
  kid: string;
  signature: AuthorizationSignatureLike;
  state_snapshot_hash: string;
  expires_at: number;
  engine_signature: string;
};

type EnvelopeEvent = Parameters<typeof encodeEnvelope>[0]["events"][number];

type ConformanceAdapter = {
  name: string;
  canonicalJson(value: unknown): string;
  intentHash(intent: Intent): string;
  evaluateAuthorization(intent: Intent, evaluationTime: number): { authorization: AuthorizationLike; policyId: string };
  encodeSnapshot(state: State): { bytes: Uint8Array; policyId: string };
  verifySnapshot(bytes: Uint8Array, expectedPolicyId?: string): VerificationResult;
  verifyAuditEvents(
    events: unknown[],
    opts?: { expectedPolicyId?: string; mode?: "strict" | "best-effort"; requireStateAnchors?: boolean }
  ): VerificationResult;
  verifyEnvelope(bytes: Uint8Array, opts?: {
    expectedPolicyId?: string;
    mode?: "strict" | "best-effort";
    expectedIssuer?: string;
    trustedKeySets?: KeySet | readonly KeySet[];
    requireSignatureVerification?: boolean;
    now?: number;
  }): VerificationResult;
  verifyAuthorization(auth: AuthorizationV1, opts?: {
    now?: number;
    mode?: "strict" | "best-effort";
    expectedIssuer?: string;
    expectedAudience?: string;
    expectedPolicyId?: string;
    consumedAuthIds?: readonly string[];
    trustedKeySets?: KeySet | readonly KeySet[];
    requireSignatureVerification?: boolean;
    legacyHmacSecret?: string;
  }): VerificationResult;
};

const TEST_KEYSET: KeySet = {
  issuer: "oxdeai.policy-engine",
  version: "1",
  keys: [
    {
      kid: "2026-01",
      alg: "Ed25519",
      public_key: TEST_ONLY_ED25519_PUBLIC_KEY_PEM_DO_NOT_USE_IN_PRODUCTION
    }
  ]
};

const CORE_ENGINE_SECRET = CONFORMANCE_ENGINE_SECRET;

const CORE_POLICY_ID = "a".repeat(64);
const INTENT_BINDING_FIELDS = [
  "intent_id",
  "agent_id",
  "action_type",
  "depth",
  "amount",
  "asset",
  "target",
  "timestamp",
  "metadata_hash",
  "nonce",
  "type",
  "authorization_id",
  "tool",
  "tool_call"
] as const;

function makeEngine(authorizationTtlSeconds = 60): PolicyEngine {
  return new PolicyEngine({
    policy_version: "v1.0.0",
    engine_secret: CORE_ENGINE_SECRET, // now typed as string
    authorization_ttl_seconds: authorizationTtlSeconds,
    policyId: CORE_POLICY_ID,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
}

function makeBaseState(): State {
  return {
    policy_version: "v1.0.0",
    period_id: "period-1",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: {
      budget_limit: { "agent-1": 5_000_000n },
      spent_in_period: { "agent-1": 0n }
    },
    max_amount_per_action: { "agent-1": 2_000_000n },
    velocity: {
      config: { window_seconds: 60, max_actions: 10 },
      counters: {}
    },
    replay: {
      window_seconds: 300,
      max_nonces_per_agent: 256,
      nonces: {}
    },
    concurrency: {
      max_concurrent: { "agent-1": 3 },
      active: {},
      active_auths: {}
    },
    recursion: {
      max_depth: { "agent-1": 5 }
    },
    tool_limits: {
      window_seconds: 60,
      max_calls: { "agent-1": 50 },
      calls: {}
    }
  };
}

function asRecord(value: unknown): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("expected object");
  }
  return value as JsonRecord;
}

function parseIntent(input: unknown): Intent {
  const r = asRecord(input);
  const maybeType = r.type;
  const type = maybeType === "RELEASE" ? "RELEASE" : "EXECUTE";

  const base = {
    intent_id: String(r.intent_id),
    agent_id: String(r.agent_id),
    action_type: String(r.action_type) as Intent["action_type"],
    amount: BigInt(String(r.amount)),
    asset: r.asset === undefined ? undefined : String(r.asset),
    target: String(r.target),
    timestamp: Number(r.timestamp),
    metadata_hash: String(r.metadata_hash),
    nonce: BigInt(String(r.nonce)),
    signature: String(r.signature),
    depth: r.depth === undefined ? undefined : Number(r.depth),
    tool: r.tool === undefined ? undefined : String(r.tool),
    tool_call: r.tool_call === undefined ? undefined : Boolean(r.tool_call)
  };

  if (type === "RELEASE") {
    return {
      ...base,
      type: "RELEASE",
      authorization_id: String(r.authorization_id)
    };
  }

  return {
    ...base,
    type: "EXECUTE",
    authorization_id: r.authorization_id === undefined ? undefined : String(r.authorization_id)
  };
}

function parseState(input: unknown): State {
  const r = asRecord(input);
  const budget = asRecord(r.budget);
  const budget_limit = asRecord(budget.budget_limit);
  const spent_in_period = asRecord(budget.spent_in_period);

  const max_amount_per_action = asRecord(r.max_amount_per_action);

  const toBigintRecord = (rec: JsonRecord): Record<string, bigint> => {
    const out: Record<string, bigint> = {};
    for (const [k, v] of Object.entries(rec)) out[k] = BigInt(String(v));
    return out;
  };

  const state = makeBaseState();
  state.policy_version = String(r.policy_version);
  state.period_id = String(r.period_id);

  state.kill_switch = {
    global: Boolean(asRecord(r.kill_switch).global),
    agents: asRecord(asRecord(r.kill_switch).agents) as Record<string, boolean>
  };
  state.allowlists = asRecord(r.allowlists) as State["allowlists"];
  state.budget = {
    budget_limit: toBigintRecord(budget_limit),
    spent_in_period: toBigintRecord(spent_in_period)
  };
  state.max_amount_per_action = toBigintRecord(max_amount_per_action);
  state.velocity = asRecord(r.velocity) as State["velocity"];
  state.replay = asRecord(r.replay) as State["replay"];
  state.concurrency = asRecord(r.concurrency) as State["concurrency"];
  state.recursion = asRecord(r.recursion) as State["recursion"];
  state.tool_limits = asRecord(r.tool_limits) as State["tool_limits"];

  return state;
}

function b64ToBytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "base64"));
}

function hexSha256Utf8(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

// Returns the raw signature bytes string regardless of which shape is present.
// Used wherever the conformance layer needs to inspect or compare signature material.
function getSignatureBytes(signature: AuthorizationSignatureLike): string {
  return typeof signature === "string" ? signature : signature.sig;
}

// Corrupts the signature bytes by replacing the last two characters with "aa".
// Works for both the legacy bare-string shape and the normative nested-object shape.
// All mutation-test sites must go through this helper; no direct .slice() on signature.
function mutateSignature<T extends { signature: AuthorizationSignatureLike }>(auth: T): T {
  if (typeof auth.signature === "string") {
    return { ...auth, signature: auth.signature.slice(0, -2) + "aa" };
  }
  return {
    ...auth,
    signature: { ...auth.signature, sig: auth.signature.sig.slice(0, -2) + "aa" },
  };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function canonicalize(value: unknown): unknown {
  if (value === undefined) return null;
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(canonicalize);
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value).sort()) out[k] = canonicalize(value[k]);
    return out;
  }
  return value;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

const coreAdapter: ConformanceAdapter = {
  name: "@oxdeai/core",
  canonicalJson,
  intentHash(intent: Intent): string {
    const src = intent as unknown as Record<string, unknown>;
    const binding: Record<string, unknown> = {};
    for (const key of INTENT_BINDING_FIELDS) {
      const value = src[key];
      if (value !== undefined) binding[key] = value;
    }
    return sha256HexFromJson(binding);
  },
  evaluateAuthorization(intent: Intent, evaluationTime: number) {
    const engine = makeEngine();
    const out = engine.evaluatePure(intent, makeBaseState(), evaluationTime);
    if (out.decision !== "ALLOW") {
      throw new Error(`expected ALLOW, got DENY: ${out.reasons.join(",")}`);
    }
    // Cast to AuthorizationLike: runtime object retains internal engine fields
    // (state_snapshot_hash, expires_at, engine_signature) even though the
    // TypeScript type was narrowed to AuthorizationV1 at the evaluatePure boundary.
    return { authorization: out.authorization as unknown as AuthorizationLike, policyId: engine.computePolicyId() };
  },
  encodeSnapshot(state: State) {
    const engine = makeEngine();
    const snapshot = engine.exportState(state);
    return { bytes: encodeCanonicalState(snapshot), policyId: engine.computePolicyId() };
  },
  verifySnapshot(bytes: Uint8Array, expectedPolicyId?: string): VerificationResult {
    return verifySnapshot(bytes, expectedPolicyId ? { expectedPolicyId } : undefined);
  },
  verifyAuditEvents(events, opts) {
    return verifyAuditEvents(events as any, opts);
  },
  verifyEnvelope,
  verifyAuthorization
};

const here = fileURLToPath(new URL(".", import.meta.url));

const exercised = new Map<string, unknown>();
const caseResults = new Map<string, boolean>();
const jsonOutput = process.argv.includes("--json");

function recordCase(label: string, passed: boolean): void {
  const id = label.split(/[ :]/)[0]!;
  caseResults.set(id, (caseResults.get(id) ?? true) && passed);
}

function loadJson<T>(name: string): T {
  const p = resolve(here, "../../vectors", name);
  const data = JSON.parse(readFileSync(p, "utf8")) as T;
  exercised.set(`packages/conformance/vectors/${name}`, data);
  return data;
}

type VectorFile = { version: string; vectors: Array<JsonRecord> };

type CheckCtx = {
  failures: string[];
  passed: number;
};

function pass(ctx: CheckCtx, msg: string): void {
  ctx.passed += 1;
  recordCase(msg, true);
  if (!jsonOutput) console.log(`PASS ${msg}`);
}

function fail(ctx: CheckCtx, msg: string): void {
  ctx.failures.push(msg);
  recordCase(msg, false);
  console.error(`FAIL ${msg}`);
}

function eq(ctx: CheckCtx, label: string, actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(ctx, `${label}: expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
  } else {
    pass(ctx, label);
  }
}

function validateIntentHashVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("intent-hash.json");
  const vectors = file.vectors;
  const hashes: Record<string, string> = {};

  for (const v of vectors) {
    const id = String(v.id);
    const intent = parseIntent(v.input);
    const got = adapter.intentHash(intent);
    const want = String(asRecord(v.expected).hash);
    hashes[id] = got;
    eq(ctx, `${id} hash`, got, want);
  }

  eq(ctx, "intent-hash-002 invariant", hashes["intent-hash-002"], hashes["intent-hash-001"]);
  eq(ctx, "intent-hash-003 invariant", hashes["intent-hash-003"], hashes["intent-hash-001"]);
}

function validateAuthorizationVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("authorization-payload.json");

  for (const v of file.vectors) {
    const id = String(v.id);
    const input = asRecord(v.input);
    const intent = parseIntent(input.intent);
    const evaluationTime = Number(input.evaluation_time);
    const effectiveTtl = Number(input.effective_ttl);
    eq(ctx, `${id} intent_timestamp`, intent.timestamp, Number(input.intent_timestamp));
    const { authorization, policyId } = adapter.evaluateAuthorization(intent, evaluationTime);
    const expected = asRecord(v.expected);

    eq(ctx, `${id} intent_hash`, authorization.intent_hash, String(expected.intent_hash));
    if (expected.state_hash !== undefined) {
      eq(ctx, `${id} state_hash`, authorization.state_snapshot_hash, String(expected.state_hash));
    }
    eq(ctx, `${id} issued_at`, authorization.issued_at, Number(expected.expected_issued_at));
    eq(ctx, `${id} expiry`, authorization.expires_at, Number(expected.expected_expiry));
    eq(ctx, `${id} effective_ttl`, authorization.expires_at - authorization.issued_at, effectiveTtl);

    const payload = adapter.canonicalJson({
      expires_at: authorization.expires_at,
      intent_hash: authorization.intent_hash,
      policy_id: policyId,
      state_hash: authorization.state_snapshot_hash
    });
    eq(ctx, `${id} canonical_signing_payload`, payload, String(expected.canonical_signing_payload));
    eq(ctx, `${id} signature`, authorization.engine_signature, String(expected.signature));
  }
}

function validateAuthorizationVerificationVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("authorization-verification.json");

  for (const v of file.vectors) {
    const id = String(v.id);
    const input = asRecord(v.input);
    const auth = {
      alg: "HMAC-SHA256",
      kid: "legacy",
      signature: "legacy-placeholder",
      ...(asRecord(input.auth) as Record<string, unknown>)
    } as AuthorizationV1;
    const opts = (input.opts ? asRecord(input.opts) : {}) as {
      now?: number;
      expectedIssuer?: string;
      expectedAudience?: string;
      expectedPolicyId?: string;
      consumedAuthIds?: readonly string[];
    };
    const expected = asRecord(v.expected);
    const got = adapter.verifyAuthorization(auth, opts);

    eq(ctx, `${id} status`, got.status, String(expected.status));
    eq(ctx, `${id} violations`, got.violations, expected.violations ?? []);
  }
}

function validateClockSemanticsVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("clock-semantics-verification.json");

  for (const v of file.vectors) {
    const id = String(v.id);
    const input = asRecord(v.input);
    const auth = {
      alg: "HMAC-SHA256",
      kid: "legacy",
      signature: "legacy-placeholder",
      ...(asRecord(input.auth) as Record<string, unknown>)
    } as AuthorizationV1;
    const opts = (input.opts ? asRecord(input.opts) : {}) as { now?: number };
    const expected = asRecord(v.expected);
    const got = adapter.verifyAuthorization(auth, opts);

    eq(ctx, `${id} status`, got.status, String(expected.status));
    eq(ctx, `${id} violations`, got.violations, expected.violations ?? []);
  }
}

// ── Delegation conformance helpers ────────────────────────────────────────────

const DELEGATION_T_ISSUED  = 1_000_000;
const DELEGATION_T_NOW     = 1_001_000;
const DELEGATION_T_DEL_EXP = 1_002_000;
const DELEGATION_T_PAR_EXP = 1_003_000;

// Delegation signatures are verified against the delegating principal's KeySet.
// issuer = parent.audience = "parent-agent" (not the PDP issuer).
const DELEGATION_TEST_KEYSET: KeySet = {
  issuer: "parent-agent",
  version: "1",
  keys: [{
    kid: "2026-01",
    alg: "Ed25519",
    public_key: TEST_ONLY_ED25519_PUBLIC_KEY_PEM_DO_NOT_USE_IN_PRODUCTION,
  }],
};

function makeParentAuth(): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      auth_id:     "f".repeat(64),
      issuer:      "oxdeai.policy-engine",
      audience:    "parent-agent",
      intent_hash: "a".repeat(64),
      state_hash:  "b".repeat(64),
      policy_id:   "c".repeat(64),
      decision:    "ALLOW",
      issued_at:   DELEGATION_T_ISSUED,
      expiry:      DELEGATION_T_PAR_EXP,
      kid:         "2026-01",
    },
    TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION
  );
}

function makeSignedDelegationBase(parent: AuthorizationV1): DelegationV1 {
  return createDelegation(
    parent,
    {
      delegatee:    "child-agent",
      scope:        { tools: ["provision_gpu"] },
      expiry:       DELEGATION_T_DEL_EXP,
      kid:          "2026-01",
      delegationId: "d1d1d1d1-0000-0000-0000-c0nf0rm4nce",
      issuedAt:     DELEGATION_T_ISSUED,
    },
    TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION
  );
}

function parseDelegationScope(input: unknown): DelegationScope {
  if (input === undefined || input === null) return {};
  const r = asRecord(input);
  const scope: DelegationScope = {};
  if (r.tools !== undefined) scope.tools = r.tools as string[];
  if (r.max_amount !== undefined) scope.max_amount = BigInt(String(r.max_amount));
  if (r.max_actions !== undefined) scope.max_actions = Number(r.max_actions);
  if (r.max_depth !== undefined) scope.max_depth = Number(r.max_depth);
  return scope;
}

function parseDelegationInput(input: unknown): DelegationV1 {
  const r = asRecord(input);
  return {
    delegation_id:    String(r.delegation_id),
    issuer:           String(r.issuer),
    audience:         String(r.audience),
    parent_auth_hash: String(r.parent_auth_hash),
    delegator:        String(r.delegator),
    delegatee:        String(r.delegatee),
    scope:            parseDelegationScope(r.scope),
    policy_id:        String(r.policy_id),
    issued_at:        Number(r.issued_at),
    expiry:           Number(r.expiry),
    alg:              "Ed25519",
    kid:              String(r.kid),
    signature:        String(r.signature),
  };
}

function validateDelegationParentHashVectors(ctx: CheckCtx): void {
  const file = loadJson<VectorFile>("delegation-parent-hash.json");
  const seen: Record<string, string> = {};

  for (const v of file.vectors) {
    const id = String(v.id);
    const input = asRecord(v.input);
    const parent = asRecord(input.parent);
    const hash = hexSha256Utf8(canonicalJson(parent));
    const expected = String(asRecord(v.expected).parent_auth_hash);
    eq(ctx, `${id} parent_auth_hash`, hash, expected);
    seen[id] = hash;

    if (v.invariant) {
      const inv = String(v.invariant);
      if (inv.startsWith("equals ")) {
        const refId = inv.slice("equals ".length);
        if (refId in seen) {
          eq(ctx, `${id} invariant`, hash, seen[refId]);
        }
      }
    }
  }
}

function validateDelegationVerificationVectors(ctx: CheckCtx): void {
  const file = loadJson<VectorFile>("delegation-verification.json");

  for (const v of file.vectors) {
    const id = String(v.id);
    const input = asRecord(v.input);
    const delegation = parseDelegationInput(input.delegation);
    const optsRaw = input.opts ? asRecord(input.opts) : {};

    const opts: VerifyDelegationOptions = {};
    if (optsRaw.now !== undefined) opts.now = Number(optsRaw.now);
    if (optsRaw.expectedDelegatee !== undefined) opts.expectedDelegatee = String(optsRaw.expectedDelegatee);
    if (optsRaw.expectedPolicyId !== undefined) opts.expectedPolicyId = String(optsRaw.expectedPolicyId);
    if (optsRaw.requireSignatureVerification !== undefined) opts.requireSignatureVerification = Boolean(optsRaw.requireSignatureVerification);
    if (optsRaw.consumedDelegationIds !== undefined) opts.consumedDelegationIds = optsRaw.consumedDelegationIds as string[];
    if (optsRaw.parentScope !== undefined) opts.parentScope = parseDelegationScope(optsRaw.parentScope);

    const got = verifyDelegation(delegation, opts);
    const expected = asRecord(v.expected);
    eq(ctx, `${id} status`, got.status, String(expected.status));
    eq(ctx, `${id} violations`, got.violations, expected.violations ?? []);
  }
}

function buildDelegationChainCases(): Array<VerificationResult> {
  const parent = makeParentAuth();
  const delegation = makeSignedDelegationBase(parent);
  const opts = { now: DELEGATION_T_NOW };

  // valid
  const valid = verifyDelegationChain(delegation, parent, opts);

  // parent-hash-mismatch: different parent with same audience/policy so only hash differs
  const otherParent = signAuthorizationEd25519(
    {
      auth_id:     "e".repeat(64),  // different → different hash
      issuer:      "oxdeai.policy-engine",
      audience:    "parent-agent",  // same → delegator check passes
      intent_hash: "a".repeat(64),
      state_hash:  "b".repeat(64),
      policy_id:   "c".repeat(64),  // same → policy check passes
      decision:    "ALLOW",
      issued_at:   DELEGATION_T_ISSUED,
      expiry:      DELEGATION_T_PAR_EXP,
      kid:         "2026-01",
    },
    TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION
  );
  const hashMismatch = verifyDelegationChain(delegation, otherParent, opts);

  // delegator-mismatch: tamper delegator field after signing (chain check catches before sig)
  const delegatorMismatch = verifyDelegationChain(
    { ...delegation, delegator: "wrong-agent" },
    parent,
    opts
  );

  // parent-expired: now === parent.expiry → DELEGATION_PARENT_EXPIRED
  const parentExpired = verifyDelegationChain(delegation, parent, { now: DELEGATION_T_PAR_EXP });

  // expiry-exceeds-parent: delegation.expiry > parent.expiry
  const exceedsDelegation = createDelegation(
    parent,
    {
      delegatee: "child-agent",
      scope:     {},
      expiry:    DELEGATION_T_PAR_EXP + 1,
      kid:       "2026-01",
      issuedAt:  DELEGATION_T_ISSUED,
    },
    TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION
  );
  const expiryExceeds = verifyDelegationChain(exceedsDelegation, parent, opts);

  // multi-hop: delegation passed as its own parent (has delegation_id field)
  const multiHop = verifyDelegationChain(delegation, delegation as unknown as AuthorizationV1, opts);

  // policy-id-mismatch: tamper policy_id after signing (chain check catches before sig)
  const policyMismatch = verifyDelegationChain(
    { ...delegation, policy_id: "d".repeat(64) },
    parent,
    opts
  );

  return [valid, hashMismatch, delegatorMismatch, parentExpired, expiryExceeds, multiHop, policyMismatch];
}

function validateDelegationChainVectors(ctx: CheckCtx): void {
  const file = loadJson<VectorFile>("delegation-chain-verification.json");
  const actual = buildDelegationChainCases();

  for (let i = 0; i < file.vectors.length; i++) {
    const id = String(file.vectors[i].id);
    const expected = asRecord(file.vectors[i].expected);
    const got = actual[i];
    eq(ctx, `${id} status`, got.status, String(expected.status));
    eq(ctx, `${id} violations`, got.violations, expected.violations ?? []);
  }
}

function buildDelegationSignatureCases(): Array<VerificationResult> {
  const parent = makeParentAuth();
  const delegation = makeSignedDelegationBase(parent);
  const chainOpts = {
    now:                          DELEGATION_T_NOW,
    trustedKeySets:               DELEGATION_TEST_KEYSET,
    requireSignatureVerification: true,
  };

  // valid
  const valid = verifyDelegationChain(delegation, parent, chainOpts);

  // tampered-signature: corrupt last bytes
  const tamperedSig = verifyDelegationChain(
    { ...delegation, signature: delegation.signature.slice(0, -4) + "AAAA" },
    parent, chainOpts
  );

  // wrong-kid: key not found in trustedKeySets
  const wrongKid = verifyDelegationChain(
    { ...delegation, kid: "unknown-kid" },
    parent, chainOpts
  );

  // tampered-field: mutate delegatee after signing → sig covers original payload
  const tamperedField = verifyDelegationChain(
    { ...delegation, delegatee: "evil-agent" },
    parent, chainOpts
  );

  // expired: correctly signed but expiry already past
  const expiredDelegation = createDelegation(
    parent,
    {
      delegatee: "child-agent",
      scope:     {},
      expiry:    DELEGATION_T_NOW - 1,
      kid:       "2026-01",
      issuedAt:  DELEGATION_T_ISSUED,
    },
    TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION
  );
  const expired = verifyDelegationChain(expiredDelegation, parent, chainOpts);

  return [valid, tamperedSig, wrongKid, tamperedField, expired];
}

function validateDelegationSignatureVectors(ctx: CheckCtx): void {
  const file = loadJson<VectorFile>("delegation-signature-verification.json");
  const actual = buildDelegationSignatureCases();

  for (let i = 0; i < file.vectors.length; i++) {
    const id = String(file.vectors[i].id);
    const expected = asRecord(file.vectors[i].expected);
    const got = actual[i];
    eq(ctx, `${id} status`, got.status, String(expected.status));
    eq(ctx, `${id} violations`, got.violations, expected.violations ?? []);
  }
}

/**
 * Builds a signed AuthorizationV1 in Sift-compatible wire format:
 *   - alg = "ed25519" (lowercase, nested signature object)
 *   - expires_at (not expiry)
 *   - base64url-encoded signature bytes
 *   - signing preimage: canonicalJson(unsigned) with no domain prefix
 *
 * The verifier accepts this via the ed25519 branch + verifyEd25519Raw fallback
 * + base64url decoding in decodeSignatureBytes.
 */
function makeSiftWireFormatAuth(now = 1730000000): AuthorizationV1 {
  const unsigned: Record<string, unknown> = {
    auth_id:     "f".repeat(64),
    issuer:      "oxdeai.policy-engine",
    audience:    "merchant-gateway",
    intent_hash: "a".repeat(64),
    state_hash:  "b".repeat(64),
    policy_id:   "c".repeat(64),
    decision:    "ALLOW",
    issued_at:   now,
    expires_at:  now + 60,
    signature:   { alg: "ed25519", kid: "2026-01" },
  };
  const preimage = Buffer.from(canonicalJson(unsigned), "utf8");
  const sigBytes = nodeSign(null, preimage, TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION);
  return {
    ...unsigned,
    signature: { alg: "ed25519", kid: "2026-01", sig: sigBytes.toString("base64url") },
  } as unknown as AuthorizationV1;
}

function makeSignedAuthorizationBase(now = 1730000000): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      auth_id: "f".repeat(64),
      issuer: "oxdeai.policy-engine",
      audience: "merchant-gateway",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "c".repeat(64),
      decision: "ALLOW",
      issued_at: now,
      expiry: now + 60,
      kid: "2026-01"
    },
    TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION
  );
}

function validateAuthorizationSignatureVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("authorization-signature-verification.json");

  for (const v of file.vectors) {
    const id = String(v.id);
    const mode = String(v.mode);
    const expected = asRecord(v.expected);
    let auth = makeSignedAuthorizationBase();
    const opts: Parameters<ConformanceAdapter["verifyAuthorization"]>[1] = {
      now: 1730000010,
      expectedIssuer: "oxdeai.policy-engine",
      expectedAudience: "merchant-gateway",
      expectedPolicyId: "c".repeat(64),
      trustedKeySets: TEST_KEYSET,
      requireSignatureVerification: true,
      consumedAuthIds: []
    };

    if (mode === "invalid-signature") {
      auth = mutateSignature(auth);
    } else if (mode === "wrong-kid") {
      auth = { ...auth, kid: "unknown-kid" };
    } else if (mode === "wrong-issuer") {
      auth = { ...auth, issuer: "other-issuer" };
    } else if (mode === "wrong-audience") {
      const { signature: _sig, alg: _alg, ...unsigned } = auth;
      auth = signAuthorizationEd25519(
        {
          ...unsigned,
          audience: "other-audience"
        },
        TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION
      );
      opts.expectedAudience = "merchant-gateway";
    } else if (mode === "tampered-field") {
      auth = { ...auth, state_hash: "d".repeat(64) };
    } else if (mode === "expired") {
      const { signature: _sig, alg: _alg, ...unsigned } = auth;
      auth = signAuthorizationEd25519(
        {
          ...unsigned,
          issued_at: 100,
          expiry: 110
        },
        TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION
      );
      opts.now = 120;
    } else if (mode === "replay") {
      opts.consumedAuthIds = [auth.auth_id];
    } else if (mode === "unknown-alg") {
      auth = { ...auth, alg: "Unknown" as any };
    } else if (mode === "sift-wire-format") {
      auth = makeSiftWireFormatAuth();
    } else if (mode === "unsupported-alg-EdDSA") {
      auth = { ...auth, alg: "EdDSA" as any };
    } else if (mode === "unsupported-alg-ED25519") {
      auth = { ...auth, alg: "ED25519" as any };
    }

    const got = adapter.verifyAuthorization(auth, opts);
    eq(ctx, `${id} status`, got.status, String(expected.status));
    eq(ctx, `${id} violations`, got.violations, expected.violations ?? []);
  }
}

function validateSnapshotVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("snapshot-hash.json");

  for (const v of file.vectors) {
    const id = String(v.id);
    const expected = asRecord(v.expected);

    if (v.input_state !== undefined) {
      const state = parseState(v.input_state);
      const { bytes, policyId } = adapter.encodeSnapshot(state);
      const out = adapter.verifySnapshot(bytes, policyId);
      if (out.status !== "ok" || !out.stateHash) {
        fail(ctx, `${id} verifySnapshot expected ok`);
        continue;
      }
      eq(ctx, `${id} snapshot_base64`, Buffer.from(bytes).toString("base64"), String(expected.snapshot_base64));
      eq(ctx, `${id} state_hash`, out.stateHash, String(expected.state_hash));
    } else {
      const bytes = b64ToBytes(String(v.input_snapshot_base64));
      const out = adapter.verifySnapshot(bytes, CORE_POLICY_ID);
      if (out.status !== "ok" || !out.stateHash) {
        fail(ctx, `${id} verifySnapshot expected ok`);
        continue;
      }
      eq(ctx, `${id} state_hash`, out.stateHash, String(expected.state_hash));
    }
  }
}

function validateAuditChainVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("audit-chain.json");
  const [v1, v2, v3, v4] = file.vectors;

  const genesis = hexSha256Utf8(String(v1.input));
  eq(ctx, "audit-chain-001 genesis", genesis, String(asRecord(v1.expected).genesis_hex));

  const i2 = asRecord(v2.input);
  const e0 = i2.event_0;
  const head1 = hexSha256Utf8(`${String(i2.head_0)}\n${adapter.canonicalJson(e0)}`);
  eq(ctx, "audit-chain-002 head_1", head1, String(asRecord(v2.expected).head_1));

  const i3 = asRecord(v3.input);
  const events = (i3.events as unknown[]) ?? [];
  let head = String(i3.genesis);
  const heads: string[] = [];
  for (const ev of events) {
    head = hexSha256Utf8(`${head}\n${adapter.canonicalJson(ev)}`);
    heads.push(head);
  }
  const e3 = asRecord(v3.expected);
  eq(ctx, "audit-chain-003 head_1", heads[0], String(e3.head_1));
  eq(ctx, "audit-chain-003 head_2", heads[1], String(e3.head_2));
  eq(ctx, "audit-chain-003 head_3", heads[2], String(e3.head_3));

  const i4 = asRecord(v4.input);
  const mut = i4.mutated_event_0;
  const mutHead1 = hexSha256Utf8(`${String(i4.head_0)}\n${adapter.canonicalJson(mut)}`);
  const e4 = asRecord(v4.expected);
  eq(ctx, "audit-chain-004 original_head_1", String(e4.original_head_1), String(e4.original_head_1));
  eq(ctx, "audit-chain-004 mutated_head_1", mutHead1, String(e4.mutated_head_1));
  eq(ctx, "audit-chain-004 must differ", mutHead1 !== String(e4.original_head_1), true);
}

function buildEnvelopeCases(adapter: ConformanceAdapter): Array<{ status: string; violations: unknown[]; policyId?: string; stateHash?: string; auditHeadHash?: string }> {
  const engine = makeEngine();
  const state = makeBaseState();
  const intent = parseIntent({
    intent_id: "intent-300",
    agent_id: "agent-1",
    action_type: "PAYMENT",
    amount: "1000000",
    target: "merchant-1",
    timestamp: 1730000000,
    metadata_hash: "0".repeat(64),
    nonce: "300",
    signature: "sig-placeholder",
    depth: 0,
    tool: "openai.responses",
    tool_call: true,
    type: "EXECUTE"
  });

  const out = engine.evaluatePure(intent, state, intent.timestamp);
  if (out.decision !== "ALLOW") throw new Error("expected ALLOW for envelope cases");

  const events = engine.audit.snapshot();
  const snapshotBytes = encodeCanonicalState(engine.exportState(state));
  const snap = adapter.verifySnapshot(snapshotBytes, engine.computePolicyId());
  if (snap.status !== "ok" || !snap.stateHash) throw new Error("failed to build envelope cases");

  const valid = encodeEnvelope({ formatVersion: 1, snapshot: snapshotBytes, events });
  const withCheckpointEvents: EnvelopeEvent[] = [
    ...events,
    {
      type: "STATE_CHECKPOINT" as const,
      stateHash: snap.stateHash,
      timestamp: intent.timestamp,
      policyId: engine.computePolicyId()
    }
  ];
  const withCheckpoint = encodeEnvelope({
    formatVersion: 1,
    snapshot: snapshotBytes,
    events: withCheckpointEvents
  });
  const mismatchedEvents: EnvelopeEvent[] = events.map((e) => ({
    ...e,
    policyId: "c".repeat(64)
  }));
  const mismatched = encodeEnvelope({
    formatVersion: 1,
    snapshot: snapshotBytes,
    events: mismatchedEvents
  });
  const corrupt = new Uint8Array([1, 2, 3, 4, 5]);

  return [
    adapter.verifyEnvelope(withCheckpoint, { expectedPolicyId: engine.computePolicyId(), mode: "strict", trustedKeySets: TEST_KEYSET }),
    adapter.verifyEnvelope(valid, { expectedPolicyId: engine.computePolicyId(), mode: "best-effort" }),
    adapter.verifyEnvelope(mismatched, { expectedPolicyId: engine.computePolicyId(), mode: "best-effort" }),
    adapter.verifyEnvelope(corrupt, { expectedPolicyId: engine.computePolicyId(), mode: "best-effort" }),
    adapter.verifyEnvelope(valid, { expectedPolicyId: engine.computePolicyId(), mode: "strict", trustedKeySets: TEST_KEYSET })
  ];
}

function validateEnvelopeVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("envelope-verification.json");
  const actual = buildEnvelopeCases(adapter);

  for (let i = 0; i < file.vectors.length; i++) {
    const id = String(file.vectors[i].id);
    const expected = asRecord(file.vectors[i].expected);
    const got = actual[i];

    eq(ctx, `${id} status`, got.status, String(expected.status));
    if (expected.policyId !== undefined) eq(ctx, `${id} policyId`, got.policyId, String(expected.policyId));
    if (expected.stateHash !== undefined) eq(ctx, `${id} stateHash`, got.stateHash, String(expected.stateHash));
    if (expected.auditHeadHash !== undefined) eq(ctx, `${id} auditHeadHash`, got.auditHeadHash, String(expected.auditHeadHash));
    eq(ctx, `${id} violations`, got.violations, expected.violations ?? []);
  }
}

function validateEnvelopeSignatureVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("envelope-signature-verification.json");
  const engine = makeEngine();
  const state = makeBaseState();
  const bytes = encodeCanonicalState(engine.exportState(state));
  const policyId = engine.computePolicyId();
  const events = [
    {
      type: "INTENT_RECEIVED" as const,
      intent_hash: "11".repeat(32),
      agent_id: "agent-1",
      timestamp: 100,
      policyId
    },
    {
      type: "STATE_CHECKPOINT" as const,
      stateHash: verifySnapshot(bytes, { expectedPolicyId: policyId }).stateHash!,
      timestamp: 101,
      policyId
    }
  ];
  const signed = signEnvelopeEd25519(
    {
      formatVersion: 1,
      snapshot: bytes,
      events
    },
    { issuer: "oxdeai.policy-engine", kid: "2026-01", privateKeyPem: TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION }
  );

  for (const v of file.vectors) {
    const id = String(v.id);
    const mode = String(v.mode);
    const expected = asRecord(v.expected);
    let env = structuredClone(signed);
    const opts: Parameters<ConformanceAdapter["verifyEnvelope"]>[1] & {
      trustedKeySets?: KeySet;
      expectedIssuer?: string;
      requireSignatureVerification?: boolean;
      now?: number;
    } = {
      mode: "strict",
      expectedPolicyId: policyId,
      expectedIssuer: "oxdeai.policy-engine",
      trustedKeySets: TEST_KEYSET,
      requireSignatureVerification: true,
      now: 1730000010
    };

    if (mode === "tampered-envelope") {
      env = { ...env, events: [...env.events, { type: "DECISION", intent_hash: "11".repeat(32), decision: "ALLOW", reasons: [], policy_version: "v1", timestamp: 102, policyId }] as any };
    } else if (mode === "unknown-alg") {
      env = { ...env, alg: "Unknown" as any };
    } else if (mode === "unknown-kid") {
      env = { ...env, kid: "missing-kid" };
    } else if (mode === "malformed-signature") {
      env = { ...env, signature: "!!!not-base64!!!" };
    }

    const wire = encodeEnvelope(env as any);
    const got = adapter.verifyEnvelope(wire, opts as any);
    eq(ctx, `${id} status`, got.status, String(expected.status));
    eq(ctx, `${id} violations`, got.violations, expected.violations ?? []);
  }
}

function buildAuditVerificationCases(
  adapter: ConformanceAdapter
): Array<{ status: string; violations: unknown[] }> {
  const expectedPolicyId = "a".repeat(64);
  const mismatchPolicyId = "b".repeat(64);
  const altPolicyId = "c".repeat(64);

  const policyMismatch = adapter.verifyAuditEvents(
    [
      {
        type: "INTENT_RECEIVED",
        intent_hash: "11".repeat(32),
        agent_id: "agent-1",
        timestamp: 100,
        policyId: mismatchPolicyId
      }
    ],
    { expectedPolicyId, mode: "best-effort" }
  );

  const nonMonotonic = adapter.verifyAuditEvents(
    [
      {
        type: "INTENT_RECEIVED",
        intent_hash: "22".repeat(32),
        agent_id: "agent-1",
        timestamp: 200,
        policyId: expectedPolicyId
      },
      {
        type: "DECISION",
        intent_hash: "22".repeat(32),
        decision: "ALLOW",
        reasons: [],
        policy_version: "v1",
        timestamp: 100,
        policyId: expectedPolicyId
      }
    ],
    { mode: "best-effort" }
  );

  const mixedPolicy = adapter.verifyAuditEvents(
    [
      {
        type: "INTENT_RECEIVED",
        intent_hash: "33".repeat(32),
        agent_id: "agent-1",
        timestamp: 100,
        policyId: expectedPolicyId
      },
      {
        type: "DECISION",
        intent_hash: "33".repeat(32),
        decision: "ALLOW",
        reasons: [],
        policy_version: "v1",
        timestamp: 100,
        policyId: mismatchPolicyId
      }
    ],
    { mode: "best-effort" }
  );

  const strictMissingAnchor = adapter.verifyAuditEvents(
    [
      {
        type: "INTENT_RECEIVED",
        intent_hash: "44".repeat(32),
        agent_id: "agent-1",
        timestamp: 100,
        policyId: expectedPolicyId
      },
      {
        type: "DECISION",
        intent_hash: "44".repeat(32),
        decision: "ALLOW",
        reasons: [],
        policy_version: "v1",
        timestamp: 100,
        policyId: expectedPolicyId
      }
    ],
    { mode: "strict" }
  );

  const orderingCase = adapter.verifyAuditEvents(
    [
      {
        type: "INTENT_RECEIVED",
        intent_hash: "55".repeat(32),
        agent_id: "agent-1",
        timestamp: 300,
        policyId: altPolicyId
      },
      {
        type: "DECISION",
        intent_hash: "55".repeat(32),
        decision: "ALLOW",
        reasons: [],
        policy_version: "v1",
        timestamp: 100,
        policyId: mismatchPolicyId
      }
    ],
    { expectedPolicyId, mode: "strict" }
  );

  return [policyMismatch, nonMonotonic, mixedPolicy, strictMissingAnchor, orderingCase];
}

function validateAuditVerificationVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("audit-verification.json");
  const actual = buildAuditVerificationCases(adapter);

  for (let i = 0; i < file.vectors.length; i++) {
    const id = String(file.vectors[i].id);
    const expected = asRecord(file.vectors[i].expected);
    const got = actual[i];
    eq(ctx, `${id} status`, got.status, String(expected.status));
    eq(ctx, `${id} violations`, got.violations, expected.violations ?? []);
  }
}

// ── Profile C: Semantic State Verification ────────────────────────────────────
//
// Tests the guard's step 10 behavior: computeStateHash(liveState) must equal
// authorization.state_hash. Two hash strategies are modelled:
//   "core"     — sha256HexFromJson (standard OxDeAI; matches stateSnapshotHash for flat objects)
//   "provider" — SHA-256 of "PROVIDER:" + canonicalJson (simulates an external provider
//                algorithm such as siftCanonicalJsonHash; distinct from "core")
//   "throws"   — always throws (models a broken or unavailable hash implementation)
//
// Encoding B vectors additionally exercise selected Profile-C semantics: Sift-compatible wire format
// (alg="ed25519", expires_at, base64url sig) + live-state semantic verification.

function profileCCoreHash(state: unknown): string {
  return sha256HexFromJson(state as Record<string, unknown>);
}

function profileCProviderHash(state: unknown): string {
  // Deterministic but distinct from coreHash — simulates an external provider algorithm.
  return createHash("sha256")
    .update("PROVIDER:" + canonicalJson(state), "utf8")
    .digest("hex");
}

function profileCGetHashFn(strategy: string): (s: unknown) => string {
  if (strategy === "core")     return profileCCoreHash;
  if (strategy === "provider") return profileCProviderHash;
  if (strategy === "throws")   return (_s: unknown) => { throw new Error("hash backend unavailable"); };
  throw new Error(`unknown hash_strategy: ${strategy}`);
}

// ── Key lifecycle constants ───────────────────────────────────────────────────
const KL_SIGNING_NOW = 1730000000;
const KL_VERIFY_NOW  = 1730000010;
const KL_PAST        = KL_SIGNING_NOW - 7200;   // 2 h before signing
const KL_FUTURE      = KL_SIGNING_NOW + 7200;   // 2 h after signing

function makeKLAuth(): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      auth_id:     "e".repeat(64),
      issuer:      "kl.issuer",
      audience:    "kl.audience",
      intent_hash: "a".repeat(64),
      state_hash:  "b".repeat(64),
      policy_id:   "c".repeat(64),
      decision:    "ALLOW",
      issued_at:   KL_SIGNING_NOW,
      expiry:      KL_SIGNING_NOW + 300,
      kid:         "kl-key-001",
    },
    TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION
  );
}

function makeKLKeyEntry(overrides: Partial<KeySetKey> = {}): KeySetKey {
  return {
    kid:        "kl-key-001",
    alg:        "Ed25519",
    public_key: TEST_ONLY_ED25519_PUBLIC_KEY_PEM_DO_NOT_USE_IN_PRODUCTION,
    ...overrides,
  };
}

function makeKLKeyset(entry: KeySetKey): KeySet {
  return { issuer: "kl.issuer", version: "1", keys: [entry] };
}

function klVerifyOpts(keyset: KeySet): Parameters<ConformanceAdapter["verifyAuthorization"]>[1] {
  return {
    now:                         KL_VERIFY_NOW,
    expectedIssuer:              "kl.issuer",
    expectedAudience:            "kl.audience",
    expectedPolicyId:            "c".repeat(64),
    trustedKeySets:              keyset,
    requireSignatureVerification: true,
    consumedAuthIds:             [],
  };
}

function validateKeyLifecycleVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("key-lifecycle-verification.json");
  const auth = makeKLAuth();

  for (const v of file.vectors) {
    const id   = String(v.id);
    const mode = String(v.mode);
    const expected = asRecord(v.expected);

    let keyset: KeySet;

    if (mode === "key-active") {
      keyset = makeKLKeyset(makeKLKeyEntry({ status: "active" }));
    } else if (mode === "key-revoked") {
      keyset = makeKLKeyset(makeKLKeyEntry({ status: "revoked" }));
    } else if (mode === "key-not-before-future") {
      keyset = makeKLKeyset(makeKLKeyEntry({ status: "active", not_before: KL_FUTURE }));
    } else if (mode === "key-not-after-past") {
      keyset = makeKLKeyset(makeKLKeyEntry({ status: "active", not_after: KL_PAST }));
    } else if (mode === "key-valid-window") {
      keyset = makeKLKeyset(makeKLKeyEntry({ status: "active", not_before: KL_PAST, not_after: KL_FUTURE }));
    } else if (mode === "key-expired-window") {
      keyset = makeKLKeyset(makeKLKeyEntry({ status: "active", not_before: KL_PAST - 3600, not_after: KL_PAST }));
    } else if (mode === "key-retired-within-window") {
      keyset = makeKLKeyset(makeKLKeyEntry({ status: "retired", not_before: KL_PAST, not_after: KL_FUTURE }));
    } else if (mode === "key-retired-past-window") {
      keyset = makeKLKeyset(makeKLKeyEntry({ status: "retired", not_after: KL_PAST }));
    } else if (mode === "key-revoked-valid-window") {
      keyset = makeKLKeyset(makeKLKeyEntry({ status: "revoked", not_before: KL_PAST, not_after: KL_FUTURE }));
    } else if (mode === "wrong-kid-known-issuer") {
      keyset = makeKLKeyset(makeKLKeyEntry({ kid: "different-key-id", status: "active" }));
    } else {
      fail(ctx, `${id}: unknown mode "${mode}"`);
      continue;
    }

    const got = adapter.verifyAuthorization(auth, klVerifyOpts(keyset));
    eq(ctx, `${id} status`,     got.status,     String(expected.status));
    eq(ctx, `${id} violations`, got.violations, expected.violations ?? []);
  }
}

function validateProfileCStateVerificationVectors(ctx: CheckCtx, adapter: ConformanceAdapter): void {
  const file = loadJson<VectorFile>("profile-c-state-verification.json");
  for (const v of file.vectors) {
    const id    = String(v.id);
    const mode  = String(v.mode);
    const expected = asRecord(v.expected);
    const expectedStatus = String(expected.status);

    // ── Pure state-hash comparison modes ─────────────────────────────────────
    // These modes test the semantic comparison (step 10) in isolation.
    // They do not involve a real AuthorizationV1 artifact — they model the
    // guard's computeStateHash(liveState) == authorization.state_hash logic.
    if (mode === "live-state-match"    ||
        mode === "live-state-mismatch" ||
        mode === "hash-strategy-mismatch" ||
        mode === "toctou-stale-state") {

      const stateInput     = v.state_input;
      const liveStateInput = (v.live_state_input ?? v.state_input);
      const signingStrategy = String((v.signing_strategy ?? v.hash_strategy) ?? "core");
      const verifyStrategy  = String((v.verify_strategy  ?? v.hash_strategy) ?? "core");

      const signingHashFn = profileCGetHashFn(signingStrategy);
      const committedHash  = signingHashFn(stateInput);

      let liveHash: string | undefined;
      let threw = false;
      try {
        liveHash = profileCGetHashFn(verifyStrategy)(liveStateInput);
      } catch {
        threw = true;
      }

      if (threw) {
        eq(ctx, `${id} outcome`, "compute-error", expectedStatus);
      } else if (liveHash === committedHash) {
        eq(ctx, `${id} outcome`, "ok",                expectedStatus);
      } else {
        eq(ctx, `${id} outcome`, "state-hash-mismatch", expectedStatus);
      }
      continue;
    }

    // ── compute-throws mode ───────────────────────────────────────────────────
    if (mode === "compute-throws") {
      let threw = false;
      try {
        profileCGetHashFn("throws")(null);
      } catch {
        threw = true;
      }
      eq(ctx, `${id} throws`, threw, true);
      eq(ctx, `${id} outcome`, threw ? "compute-error" : "ok", expectedStatus);
      continue;
    }

    // ── Encoding B modes ──────────────────────────────────────────────────────
    // These consume a committed Sift-compatible (Encoding B) AuthorizationV1 artifact
    // with state_hash = signingHashFn(state_input), verify the signature
    // (exercising the ed25519/expires_at/base64url path), then simulate
    // Profile C step 10: computeStateHash(live_state_input) == authorization.state_hash.
    if (mode === "encoding-b-live-state-match"    ||
        mode === "encoding-b-live-state-mismatch" ||
        mode === "encoding-b-hash-strategy-mismatch") {

      const stateInput      = v.state_input;
      const liveStateInput  = (v.live_state_input ?? v.state_input);
      const signingStrategy = String((v.signing_strategy ?? v.hash_strategy) ?? "provider");
      const verifyStrategy  = String((v.verify_strategy  ?? v.hash_strategy) ?? "provider");

      const committedHash = profileCGetHashFn(signingStrategy)(stateInput);

      // Consume the committed authority fixture preserved by the one-way projection.
      // Do not synthesize/re-sign an artifact: Go and Python verify these same bytes.
      const auth = v.auth as unknown as AuthorizationV1;
      const opts = asRecord(v.opts);
      const trustedKey = asRecord(opts.trustedKey);
      eq(ctx, `${id} committed state hash`, auth.state_hash, committedHash);
      const sigResult = adapter.verifyAuthorization(auth, {
        now: Number(opts.now),
        expectedIssuer: "oxdeai.policy-engine",
        expectedAudience: "merchant-gateway",
        trustedKeySets: {
          issuer: "oxdeai.policy-engine",
          version: "1",
          keys: [{ kid: String(trustedKey.kid), alg: trustedKey.alg as KeySetKey["alg"], public_key: String(trustedKey.public_key) }],
        },
        requireSignatureVerification: true,
        consumedAuthIds: [],
      });

      if (sigResult.status !== "ok") {
        fail(ctx, `${id} signature: expected ok, got ${sigResult.status} — ${JSON.stringify(sigResult.violations)}`);
        continue;
      }
      pass(ctx, `${id} signature`);

      // Step 2: semantic state verification (Profile C step 10).
      let liveHash: string | undefined;
      let threw = false;
      try {
        liveHash = profileCGetHashFn(verifyStrategy)(liveStateInput);
      } catch {
        threw = true;
      }

      let outcome: string;
      if (threw) {
        outcome = "compute-error";
      } else if (liveHash === committedHash) {
        outcome = "ok";
      } else {
        outcome = "state-hash-mismatch";
      }
      eq(ctx, `${id} outcome`, outcome, expectedStatus);
      continue;
    }

    fail(ctx, `${id}: unknown mode "${mode}"`);
  }
}

// ── SignedKRLV1 verification ───────────────────────────────────────────────────

const KRL_ISSUER     = "krl.issuer";
const KRL_KID        = "krl-2026-01";
const KRL_T_ISSUED   = 1_730_000_000;
const KRL_T_NOW      = 1_730_000_010;
const KRL_T_NOT_AFTER = 1_730_003_600;

const KRL_TRUSTED_KEYSET: KeySet = {
  issuer: KRL_ISSUER,
  version: "1",
  keys: [{
    kid:        KRL_KID,
    alg:        "Ed25519",
    public_key: KRL_TEST_ONLY_ED25519_PUBLIC_KEY_PEM_DO_NOT_USE_IN_PRODUCTION,
  }],
};

function buildValidKrlBase(): Omit<SignedKRLV1, "signature"> {
  return {
    version:      "SignedKRLV1",
    issuer:       KRL_ISSUER,
    krl_version:  1,
    issued_at:    KRL_T_ISSUED,
    not_after:    KRL_T_NOT_AFTER,
    revoked_kids: ["kid-provider-1", "kid-provider-2"],
  };
}

function signValidKrl(override?: Partial<Omit<SignedKRLV1, "signature">>): SignedKRLV1 {
  const base = { ...buildValidKrlBase(), ...override };
  const envelope: SignedKRLV1 = {
    ...base,
    signature: { alg: "Ed25519", kid: KRL_KID, sig: "" },
  };
  const payload = signedKrlSigningPayload(envelope);
  const sig = signEd25519(SIGNING_DOMAINS.KRL_V1, payload, KRL_TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION);
  return { ...envelope, signature: { alg: "Ed25519", kid: KRL_KID, sig } };
}

function validateSignedKrlVectors(ctx: CheckCtx): void {
  const file = loadJson<VectorFile>("signed-krl-verification.json");

  for (const v of file.vectors) {
    const id   = String(v.id);
    const mode = String(v.mode);
    const expected = asRecord(v.expected);

    let result: VerificationResult;

    if (mode === "valid") {
      // Valid KRL — signature verifies, not expired
      const krl = signValidKrl();
      result = verifySignedKrl(krl, { now: KRL_T_NOW, trustedKeySets: KRL_TRUSTED_KEYSET });

    } else if (mode === "invalid-signature") {
      // Tamper last 4 base64 characters of the signature
      const krl = signValidKrl();
      const tampered: SignedKRLV1 = {
        ...krl,
        signature: { ...krl.signature, sig: krl.signature.sig.slice(0, -4) + "AAAA" },
      };
      result = verifySignedKrl(tampered, { now: KRL_T_NOW, trustedKeySets: KRL_TRUSTED_KEYSET });

    } else if (mode === "expired") {
      // Verification time is one second past not_after
      const krl = signValidKrl();
      result = verifySignedKrl(krl, { now: KRL_T_NOT_AFTER + 1, trustedKeySets: KRL_TRUSTED_KEYSET });

    } else if (mode === "malformed-revoked-kids") {
      // revoked_kids is a string, not an array — structural malformation
      const raw = {
        ...buildValidKrlBase(),
        revoked_kids: "not-an-array",
        signature: { alg: "Ed25519", kid: KRL_KID, sig: "placeholder" },
      };
      result = verifySignedKrl(raw, { now: KRL_T_NOW, trustedKeySets: KRL_TRUSTED_KEYSET });

    } else if (mode === "duplicate-revoked-kids") {
      // Valid signature but revoked_kids has duplicate entries
      const krl = signValidKrl({ revoked_kids: ["kid-1", "kid-1"] });
      result = verifySignedKrl(krl, { now: KRL_T_NOW, trustedKeySets: KRL_TRUSTED_KEYSET });

    } else if (mode === "unknown-signing-kid") {
      // kid tampered after signing — not found in trusted key sets
      const krl = signValidKrl();
      const wrongKid: SignedKRLV1 = {
        ...krl,
        signature: { ...krl.signature, kid: "unknown-kid" },
      };
      result = verifySignedKrl(wrongKid, { now: KRL_T_NOW, trustedKeySets: KRL_TRUSTED_KEYSET });

    } else if (mode === "signing-key-inactive") {
      // The correct kid exists in the trusted set but is marked revoked
      const krl = signValidKrl();
      const revokedKeyset: KeySet = {
        ...KRL_TRUSTED_KEYSET,
        keys: [{ ...KRL_TRUSTED_KEYSET.keys[0], status: "revoked" }],
      };
      result = verifySignedKrl(krl, { now: KRL_T_NOW, trustedKeySets: revokedKeyset });

    } else if (mode === "unsupported-alg") {
      // signature.alg is not "Ed25519" — structural KRL_UNSUPPORTED_ALG before sig check
      const raw = {
        ...buildValidKrlBase(),
        signature: { alg: "HMAC-SHA256" as any, kid: KRL_KID, sig: "placeholder" },
      };
      result = verifySignedKrl(raw, { now: KRL_T_NOW, trustedKeySets: KRL_TRUSTED_KEYSET });

    } else if (mode === "version-regression") {
      // krl_version=1 but caller knows previous version was 5
      const krl = signValidKrl(); // krl_version = 1
      result = verifySignedKrl(krl, {
        now: KRL_T_NOW,
        trustedKeySets: KRL_TRUSTED_KEYSET,
        previousKrlVersionByIssuer: { [KRL_ISSUER]: 5 },
      });

    } else {
      fail(ctx, `${id}: unknown mode "${mode}"`);
      continue;
    }

    eq(ctx, `${id} status`,     result.status,     String(expected.status));
    eq(ctx, `${id} violations`, result.violations, expected.violations ?? []);
  }
}

function main(): void {
  const ctx: CheckCtx = { failures: [], passed: 0 };
  const adapter = coreAdapter;

  if (!jsonOutput) console.log(`Running conformance validation with ${adapter.name}`);

  try {
    validateIntentHashVectors(ctx, adapter);
    validateAuthorizationVectors(ctx, adapter);
    const trustedTime = runTrustedTimeConformance(loadJson<unknown>("trusted-time.json"), line => {
      const match = /^(PASS|FAIL) ([^ :]+)/.exec(line);
      if (match) recordCase(match[2]!, match[1] === "PASS");
      if (!jsonOutput) console.log(line);
    });
    ctx.passed += trustedTime.passed;
    ctx.failures.push(...trustedTime.failures);
    validateAuthorizationVerificationVectors(ctx, adapter);
    validateAuthorizationSignatureVectors(ctx, adapter);
    validateSnapshotVectors(ctx, adapter);
    validateAuditChainVectors(ctx, adapter);
    validateAuditVerificationVectors(ctx, adapter);
    validateEnvelopeVectors(ctx, adapter);
    validateEnvelopeSignatureVectors(ctx, adapter);
    validateDelegationParentHashVectors(ctx);
    validateDelegationVerificationVectors(ctx);
    validateDelegationChainVectors(ctx);
    validateDelegationSignatureVectors(ctx);
    validateKeyLifecycleVectors(ctx, adapter);
    validateClockSemanticsVectors(ctx, adapter);
    validateProfileCStateVerificationVectors(ctx, adapter);
    validateSignedKrlVectors(ctx);

  } catch (error) {
    ctx.failures.push(error instanceof Error ? error.message : String(error));
  }
  const scope = evidenceScope({ consumer: "packages/conformance/src/validate.ts", runtime: "TypeScript", selections: [...exercised].map(([representation, data]) => {
    const ids = (data as VectorFile).vectors.map(v => String(v.id)).filter(id => caseResults.has(id));
    return { representation, data, consumer: "packages/conformance/src/validate.ts", runtime: "TypeScript", caseIds: ids, passedCaseIds: ids.filter(id => caseResults.get(id)) };
  }) });
  console.log(JSON.stringify({ result: ctx.failures.length ? "FAIL" : "PASS", passed: ctx.passed, failures: ctx.failures, evidenceScope: scope }));
  if (ctx.failures.length > 0) {
    console.error(`\nConformance failed: ${ctx.failures.length} assertion(s)`);
    process.exitCode = 1;
    return;
  }

  if (!jsonOutput) console.log(`\nConformance passed: ${ctx.passed} assertions (declared evidenceScope only)`);
}

main();
