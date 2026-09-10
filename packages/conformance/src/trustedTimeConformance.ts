// SPDX-License-Identifier: Apache-2.0
import { evidenceScope } from "./evidenceScope.mjs";
import {
  PolicyEngine,
  signAuthorizationEd25519,
  verifyAuthorization,
  verifyTrustedTime,
} from "@oxdeai/core";
import type { AuthorizationV1, Intent, KeySet, ReasonCode, State } from "@oxdeai/core";
import {
  TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION,
  TEST_ONLY_ED25519_PUBLIC_KEY_PEM_DO_NOT_USE_IN_PRODUCTION,
} from "./fixtures/ed25519.test-only.fixture.js";
import { CONFORMANCE_ENGINE_SECRET } from "./fixtures/conformance-engine-secret.fixture.js";

export const TRUSTED_TIME_SCHEMA_VERSION = "1.0.0";
export const TRUSTED_TIME_CATEGORIES = [
  "intent_freshness", "authorization_issuance", "replay", "velocity",
  "authorization_verification", "determinism", "malformed_configuration",
  "protocol_seconds_validation", "tool_window",
] as const;

type Category = (typeof TRUSTED_TIME_CATEGORIES)[number];
type RecordValue = Record<string, unknown>;
export type TrustedTimeVector = {
  id: string;
  category: Category;
  status: "active" | "pending";
  description: string;
  blocked_by?: string;
  comparison_group?: string;
  input: RecordValue;
  expected: RecordValue;
};
export type TrustedTimeFile = {
  schema_version: string;
  description: string;
  vectors: TrustedTimeVector[];
};
export type TrustedTimeSummary = {
  active: number;
  passed: number;
  failed: number;
  pending: number;
  failures: string[];
  evidenceScope: ReturnType<typeof evidenceScope>;
};

const CATEGORY_SET = new Set<string>(TRUSTED_TIME_CATEGORIES);
// The package root currently exposes ReasonCode as a public type rather than a
// runtime value. `satisfies` keeps this registry compile-time checked against
// that public union while providing strict runtime validation for vector data.
const PUBLIC_REASON_CODES = [
  "KILL_SWITCH", "ALLOWLIST_ACTION", "ALLOWLIST_ASSET", "ALLOWLIST_TARGET",
  "POLICY_VERSION_MISMATCH", "STATE_INVALID", "INTENT_AMOUNT_INVALID", "BUDGET_EXCEEDED",
  "PER_ACTION_CAP_EXCEEDED", "VELOCITY_EXCEEDED", "CONCURRENCY_LIMIT_EXCEEDED",
  "RECURSION_DEPTH_EXCEEDED", "REPLAY_NONCE", "REPLAY_DETECTED", "AUTH_EXPIRED",
  "AUTH_SIGNATURE_INVALID", "AUTH_INTENT_MISMATCH", "INTERNAL_ERROR",
  "CONCURRENCY_RELEASE_INVALID", "TOOL_CALL_LIMIT_EXCEEDED",
  "INTENT_FRESHNESS_FUTURE", "INTENT_STALE",
] as const satisfies readonly ReasonCode[];
type MissingPublicReasonCode = Exclude<ReasonCode, (typeof PUBLIC_REASON_CODES)[number]>;
const ALL_PUBLIC_REASON_CODES_COVERED: MissingPublicReasonCode extends never ? true : never = true;
void ALL_PUBLIC_REASON_CODES_COVERED;
const REASON_CODES = new Set<string>(PUBLIC_REASON_CODES);
const VERIFICATION_CODES = new Set(["AUTH_EXPIRED", "AUTH_ISSUED_AT_IMPLAUSIBLE"]);
const COMMON_KEYS = new Set(["id", "category", "status", "description", "blocked_by", "comparison_group", "input", "expected"]);
const INPUT_KEYS: Record<Category, Set<string>> = {
  intent_freshness: new Set(["intent_timestamp", "evaluation_time", "max_clock_skew_seconds", "max_intent_age_seconds"]),
  authorization_issuance: new Set(["intent_timestamp", "evaluation_time", "effective_ttl", "authorization_action"]),
  replay: new Set(["replay_window_seconds", "max_nonces_per_agent", "initial_nonce_state", "steps"]),
  velocity: new Set(["window_seconds", "max_actions", "initial_velocity", "steps"]),
  authorization_verification: new Set(["authorization_issued_at", "authorization_expiry", "verifier_time", "max_future_issued_at_skew_seconds"]),
  determinism: new Set(["kind", "repeat", "intent_timestamp", "evaluation_time", "effective_ttl", "window_seconds", "max_actions", "initial_velocity", "steps"]),
  malformed_configuration: new Set(["configuration_field", "configuration_value"]),
  protocol_seconds_validation: new Set(["case", "intent_timestamp", "evaluation_time", "effective_ttl"]),
  tool_window: new Set(["window_seconds", "max_calls", "max_calls_by_tool", "initial_tool_calls", "steps"]),
};
const EXPECTED_KEYS: Record<Category, Set<string>> = {
  intent_freshness: new Set(["decision", "reasons"]),
  authorization_issuance: new Set(["decision", "reasons", "authorization_issued_at", "authorization_expiry"]),
  replay: new Set(["steps"]),
  velocity: new Set(["steps"]),
  authorization_verification: new Set(["status", "violation_codes"]),
  determinism: new Set(["decision", "reasons", "authorization_issued_at", "authorization_expiry", "identical_output"]),
  malformed_configuration: new Set(["throws", "error_includes"]),
  protocol_seconds_validation: new Set(["decision", "reasons", "throws", "error_includes"]),
  tool_window: new Set(["steps"]),
};

function object(value: unknown, where: string): RecordValue {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${where}: expected object`);
  return value as RecordValue;
}
function exactKeys(value: RecordValue, allowed: Set<string>, where: string): void {
  for (const key of Object.keys(value)) if (!allowed.has(key)) throw new Error(`${where}: unknown field ${key}`);
}
function text(value: unknown, where: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${where}: expected non-empty string`);
  return value;
}
function array(value: unknown, where: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${where}: expected array`);
  return value;
}
function safeSeconds(value: unknown, where: string, positive = false): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < (positive ? 1 : 0)) {
    throw new Error(`${where}: expected ${positive ? "positive" : "non-negative"} safe-integer protocol seconds`);
  }
  return value;
}
function nonNegativeCount(value: unknown, where: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new Error(`${where}: expected non-negative safe integer`);
  return value;
}
function validateReasons(value: unknown, id: string, where: string): void {
  for (const [index, reason] of array(value, `${id} ${where}`).entries()) {
    if (typeof reason !== "string" || !REASON_CODES.has(reason)) throw new Error(`${id} ${where}[${index}]: unsupported ReasonCode ${String(reason)}`);
  }
}
function validateDecisionExpected(expected: RecordValue, id: string): void {
  if (expected.decision !== "ALLOW" && expected.decision !== "DENY") throw new Error(`${id} expected.decision: expected ALLOW or DENY`);
  validateReasons(expected.reasons, id, "expected.reasons");
  if (expected.decision === "ALLOW" && (expected.reasons as unknown[]).length !== 0) throw new Error(`${id} expected.reasons: ALLOW must have no reasons`);
}
function validateNonceState(value: unknown, id: string, where: string): void {
  for (const [i, raw] of array(value, `${id} ${where}`).entries()) {
    const item = object(raw, `${id} ${where}[${i}]`);
    exactKeys(item, new Set(["nonce", "nonce_first_seen_time"]), `${id} ${where}[${i}]`);
    text(item.nonce, `${id} ${where}[${i}].nonce`);
    safeSeconds(item.nonce_first_seen_time, `${id} ${where}[${i}].nonce_first_seen_time`);
  }
}
function validateToolCalls(value: unknown, id: string, where: string): void {
  for (const [i, raw] of array(value, `${id} ${where}`).entries()) {
    const item = object(raw, `${id} ${where}[${i}]`);
    exactKeys(item, new Set(["tool_call_time", "tool"]), `${id} ${where}[${i}]`);
    if (typeof item.tool_call_time !== "number" || !Number.isSafeInteger(item.tool_call_time)) {
      throw new Error(`${id} ${where}[${i}].tool_call_time: expected safe integer`);
    }
    text(item.tool, `${id} ${where}[${i}].tool`);
  }
}

function validateSteps(vector: TrustedTimeVector): void {
  const steps = array(vector.input.steps, `${vector.id} input.steps`);
  if (steps.length === 0) throw new Error(`${vector.id} input.steps: must not be empty`);
  for (const [i, raw] of steps.entries()) {
    const step = object(raw, `${vector.id} input.steps[${i}]`);
    exactKeys(step, new Set(["intent_timestamp", "evaluation_time", "nonce"]), `${vector.id} input.steps[${i}]`);
    safeSeconds(step.intent_timestamp, `${vector.id} input.steps[${i}].intent_timestamp`);
    safeSeconds(step.evaluation_time, `${vector.id} input.steps[${i}].evaluation_time`);
    text(step.nonce, `${vector.id} input.steps[${i}].nonce`);
  }
  if (vector.category === "determinism") return;
  const expectedSteps = array(vector.expected.steps, `${vector.id} expected.steps`);
  if (expectedSteps.length !== steps.length) throw new Error(`${vector.id} expected.steps: expected ${steps.length} entries`);
  for (const [i, raw] of expectedSteps.entries()) {
    const step = object(raw, `${vector.id} expected.steps[${i}]`);
    const allowed = vector.category === "replay"
      ? new Set(["decision", "reasons", "nonce_state"])
      : vector.category === "tool_window"
        ? new Set(["decision", "reasons", "tool_calls"])
        : new Set(["decision", "reasons", "velocity_window_start", "velocity_count"]);
    exactKeys(step, allowed, `${vector.id} expected.steps[${i}]`);
    validateDecisionExpected(step, `${vector.id} step ${i + 1}`);
    if (vector.category === "replay") validateNonceState(step.nonce_state, vector.id, `expected.steps[${i}].nonce_state`);
    else if (vector.category === "tool_window") validateToolCalls(step.tool_calls, vector.id, `expected.steps[${i}].tool_calls`);
    else {
      // Negative starts are permitted only as an expected preservation value for the malformed-state vector.
      if (typeof step.velocity_window_start !== "number" || !Number.isSafeInteger(step.velocity_window_start)) throw new Error(`${vector.id} expected.steps[${i}].velocity_window_start: expected safe integer`);
      nonNegativeCount(step.velocity_count, `${vector.id} expected.steps[${i}].velocity_count`);
    }
  }
}

export function parseTrustedTimeFile(raw: unknown): TrustedTimeFile {
  const file = object(raw, "trusted-time");
  exactKeys(file, new Set(["schema_version", "description", "vectors"]), "trusted-time");
  if (file.schema_version !== TRUSTED_TIME_SCHEMA_VERSION) throw new Error(`trusted-time schema_version: expected ${TRUSTED_TIME_SCHEMA_VERSION}`);
  text(file.description, "trusted-time description");
  const seen = new Set<string>();
  const vectors = array(file.vectors, "trusted-time vectors") as unknown as TrustedTimeVector[];
  for (const rawVector of vectors) {
    const vector = object(rawVector, "trusted-time vector") as unknown as TrustedTimeVector;
    exactKeys(vector as unknown as RecordValue, COMMON_KEYS, `trusted-time vector ${String(vector.id ?? "(missing)")}`);
    const id = text(vector.id, "trusted-time vector id");
    if (seen.has(id)) throw new Error(`${id}: duplicate vector ID`);
    seen.add(id);
    if (!CATEGORY_SET.has(String(vector.category))) throw new Error(`${id}: unknown category ${String(vector.category)}`);
    if (vector.status !== "active" && vector.status !== "pending") throw new Error(`${id}: malformed status ${String(vector.status)}`);
    text(vector.description, `${id} description`);
    if (vector.status === "pending") text(vector.blocked_by, `${id} blocked_by`);
    else if (vector.blocked_by !== undefined) throw new Error(`${id}: active vector must not define blocked_by`);
    if (vector.comparison_group !== undefined) text(vector.comparison_group, `${id} comparison_group`);
    const input = object(vector.input, `${id} input`);
    const expected = object(vector.expected, `${id} expected`);
    exactKeys(input, INPUT_KEYS[vector.category], `${id} input`);
    exactKeys(expected, EXPECTED_KEYS[vector.category], `${id} expected`);

    if (vector.category === "intent_freshness") {
      safeSeconds(input.intent_timestamp, `${id} input.intent_timestamp`);
      safeSeconds(input.evaluation_time, `${id} input.evaluation_time`);
      safeSeconds(input.max_clock_skew_seconds, `${id} input.max_clock_skew_seconds`);
      safeSeconds(input.max_intent_age_seconds, `${id} input.max_intent_age_seconds`);
      validateDecisionExpected(expected, id);
    } else if (vector.category === "authorization_issuance") {
      safeSeconds(input.intent_timestamp, `${id} input.intent_timestamp`);
      safeSeconds(input.evaluation_time, `${id} input.evaluation_time`);
      safeSeconds(input.effective_ttl, `${id} input.effective_ttl`, true);
      if (input.authorization_action !== "EXECUTE" && input.authorization_action !== "RELEASE") throw new Error(`${id} input.authorization_action: unknown action`);
      validateDecisionExpected(expected, id);
      safeSeconds(expected.authorization_issued_at, `${id} expected.authorization_issued_at`);
      safeSeconds(expected.authorization_expiry, `${id} expected.authorization_expiry`);
    } else if (vector.category === "replay") {
      safeSeconds(input.replay_window_seconds, `${id} input.replay_window_seconds`, true);
      nonNegativeCount(input.max_nonces_per_agent, `${id} input.max_nonces_per_agent`);
      if (input.initial_nonce_state !== undefined) validateNonceState(input.initial_nonce_state, id, "input.initial_nonce_state");
      validateSteps(vector);
    } else if (vector.category === "velocity") {
      safeSeconds(input.window_seconds, `${id} input.window_seconds`, true);
      nonNegativeCount(input.max_actions, `${id} input.max_actions`);
      if (input.initial_velocity !== undefined) validateInitialVelocity(input.initial_velocity, id);
      validateSteps(vector);
    } else if (vector.category === "authorization_verification") {
      safeSeconds(input.authorization_issued_at, `${id} input.authorization_issued_at`);
      safeSeconds(input.authorization_expiry, `${id} input.authorization_expiry`);
      safeSeconds(input.verifier_time, `${id} input.verifier_time`);
      safeSeconds(input.max_future_issued_at_skew_seconds, `${id} input.max_future_issued_at_skew_seconds`);
      if (expected.status !== "ok" && expected.status !== "invalid") throw new Error(`${id} expected.status: unsupported verifier status`);
      for (const code of array(expected.violation_codes, `${id} expected.violation_codes`)) if (typeof code !== "string" || !VERIFICATION_CODES.has(code)) throw new Error(`${id} expected.violation_codes: unsupported verification code ${String(code)}`);
    } else if (vector.category === "determinism") {
      nonNegativeCount(input.repeat, `${id} input.repeat`);
      if ((input.repeat as number) < 2) throw new Error(`${id} input.repeat: must be at least 2`);
      if (input.kind === "velocity_sequence") {
        safeSeconds(input.window_seconds, `${id} input.window_seconds`, true);
        nonNegativeCount(input.max_actions, `${id} input.max_actions`);
        if (input.initial_velocity !== undefined) validateInitialVelocity(input.initial_velocity, id);
        validateSteps(vector);
      } else {
        if (input.kind !== undefined) throw new Error(`${id} input.kind: unsupported determinism kind`);
        safeSeconds(input.intent_timestamp, `${id} input.intent_timestamp`);
        safeSeconds(input.evaluation_time, `${id} input.evaluation_time`);
        safeSeconds(input.effective_ttl, `${id} input.effective_ttl`, true);
        validateDecisionExpected(expected, id);
      }
      if (expected.identical_output !== true) throw new Error(`${id} expected.identical_output: must be true`);
    } else if (vector.category === "malformed_configuration") {
      text(input.configuration_field, `${id} input.configuration_field`);
      if (expected.throws !== true) throw new Error(`${id} expected.throws: must be true`);
      text(expected.error_includes, `${id} expected.error_includes`);
    } else if (vector.category === "protocol_seconds_validation") {
      text(input.case, `${id} input.case`);
      if (expected.reasons !== undefined) validateDecisionExpected(expected, id);
      if (expected.throws !== undefined && expected.throws !== true) throw new Error(`${id} expected.throws: must be true`);
      if (expected.error_includes !== undefined) text(expected.error_includes, `${id} expected.error_includes`);
    } else if (vector.category === "tool_window") {
      safeSeconds(input.window_seconds, `${id} input.window_seconds`, true);
      nonNegativeCount(input.max_calls, `${id} input.max_calls`);
      if (input.max_calls_by_tool !== undefined) nonNegativeCount(input.max_calls_by_tool, `${id} input.max_calls_by_tool`);
      if (input.initial_tool_calls !== undefined) validateToolCalls(input.initial_tool_calls, id, "input.initial_tool_calls");
      validateSteps(vector);
    }
  }
  return file as unknown as TrustedTimeFile;
}

function validateInitialVelocity(raw: unknown, id: string): void {
  const value = object(raw, `${id} input.initial_velocity`);
  exactKeys(value, new Set(["velocity_window_start", "velocity_count"]), `${id} input.initial_velocity`);
  if (typeof value.velocity_window_start !== "number" || !Number.isSafeInteger(value.velocity_window_start)) throw new Error(`${id} input.initial_velocity.velocity_window_start: expected safe integer`);
  nonNegativeCount(value.velocity_count, `${id} input.initial_velocity.velocity_count`);
}

function makeState(): State {
  return {
    policy_version: "v1.0.0", period_id: "period-1",
    kill_switch: { global: false, agents: {} }, allowlists: {},
    budget: { budget_limit: { "agent-1": 5_000_000n }, spent_in_period: { "agent-1": 0n } },
    max_amount_per_action: { "agent-1": 2_000_000n },
    velocity: { config: { window_seconds: 60, max_actions: 10 }, counters: {} },
    replay: { window_seconds: 600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { "agent-1": 10 }, active: {}, active_auths: {} },
    recursion: { max_depth: { "agent-1": 10 } },
    tool_limits: { window_seconds: 600, max_calls: { "agent-1": 100 }, calls: {} },
  };
}
function makeEngine(ttl = 60, skew = 300, age = 300): PolicyEngine {
  return new PolicyEngine({ policy_version: "v1.0.0", engine_secret: CONFORMANCE_ENGINE_SECRET, authorization_ttl_seconds: ttl, maxClockSkewSeconds: skew, maxIntentAgeSeconds: age, policyId: "a".repeat(64) });
}
function intent(id: string, timestamp: number, nonce: string, action: "EXECUTE" | "RELEASE" = "EXECUTE"): Intent {
  const nonceValue = /^\d+$/.test(nonce)
    ? BigInt(nonce)
    : BigInt([...nonce].reduce((n, c) => n + c.charCodeAt(0), 10_000));
  return {
    intent_id: `${id}-${nonce}`, agent_id: "agent-1", action_type: "PAYMENT", amount: 100n,
    asset: "wallet", target: "merchant-1", timestamp, metadata_hash: "0".repeat(64),
    nonce: nonceValue, signature: "sig", depth: 0,
    ...(action === "RELEASE" ? { type: "RELEASE" as const, authorization_id: "release-id" } : { type: "EXECUTE" as const }),
  };
}
function normalize(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value, (_key, item) => typeof item === "bigint" ? `${item}n` : item));
}
function equal(actual: unknown, expected: unknown): boolean { return JSON.stringify(normalize(actual)) === JSON.stringify(normalize(expected)); }

function runSequence(vector: TrustedTimeVector, category: "replay" | "velocity" | "tool_window"): unknown[] {
  const input = vector.input;
  let state = makeState();
  if (category === "replay") {
    state.replay.window_seconds = input.replay_window_seconds as number;
    state.replay.max_nonces_per_agent = input.max_nonces_per_agent as number;
    state.replay.nonces["agent-1"] = ((input.initial_nonce_state ?? []) as RecordValue[]).map(x => ({ nonce: x.nonce as string, ts: x.nonce_first_seen_time as number }));
  } else if (category === "velocity") {
    state.velocity.config = { window_seconds: input.window_seconds as number, max_actions: input.max_actions as number };
    if (input.initial_velocity) {
      const initial = input.initial_velocity as RecordValue;
      state.velocity.counters["agent-1"] = { window_start: initial.velocity_window_start as number, count: initial.velocity_count as number };
    }
  } else {
    state.tool_limits.window_seconds = input.window_seconds as number;
    state.tool_limits.max_calls["agent-1"] = input.max_calls as number;
    if (input.max_calls_by_tool !== undefined) {
      state.tool_limits.max_calls_by_tool = { "agent-1": { search: input.max_calls_by_tool as number } };
    }
    state.tool_limits.calls["agent-1"] = ((input.initial_tool_calls ?? []) as RecordValue[]).map(x => ({ ts: x.tool_call_time as number, tool: x.tool as string }));
  }
  const observations: unknown[] = [];
  for (const [index, rawStep] of (input.steps as RecordValue[]).entries()) {
    const before = structuredClone(state);
    const stepIntent = {
      ...intent(vector.id, rawStep.intent_timestamp as number, rawStep.nonce as string),
      ...(category === "tool_window" ? { tool: "search", tool_call: true } : {}),
    };
    const out = makeEngine().evaluatePure(stepIntent, state, rawStep.evaluation_time as number);
    if (out.decision === "ALLOW") state = out.nextState;
    else state = before;
    const base = { decision: out.decision, reasons: [...out.reasons] };
    observations.push(category === "replay"
      ? { ...base, nonce_state: (state.replay.nonces["agent-1"] ?? []).map(x => ({ nonce: x.nonce, nonce_first_seen_time: x.ts })) }
      : category === "velocity"
        ? { ...base, velocity_window_start: state.velocity.counters["agent-1"]?.window_start, velocity_count: state.velocity.counters["agent-1"]?.count }
        : { ...base, tool_calls: (state.tool_limits.calls["agent-1"] ?? []).map(x => ({ tool_call_time: x.ts, tool: x.tool })) });
    void index;
  }
  return observations;
}

const KEYSET: KeySet = { issuer: "issuer", version: "1", keys: [{ kid: "k1", alg: "Ed25519", public_key: TEST_ONLY_ED25519_PUBLIC_KEY_PEM_DO_NOT_USE_IN_PRODUCTION }] };
function runVector(vector: TrustedTimeVector): unknown {
  const input = vector.input;
  if (vector.category === "intent_freshness") {
    return verifyTrustedTime({ intentTimestamp: input.intent_timestamp as number, evaluationTime: input.evaluation_time as number, maxClockSkewSeconds: input.max_clock_skew_seconds as number, maxIntentAgeSeconds: input.max_intent_age_seconds as number });
  }
  if (vector.category === "authorization_issuance") {
    const action = input.authorization_action as "EXECUTE" | "RELEASE";
    const state = makeState();
    if (action === "RELEASE") { state.concurrency.active["agent-1"] = 1; state.concurrency.active_auths["agent-1"] = { "release-id": { expires_at: (input.evaluation_time as number) + 600 } }; }
    const out = makeEngine(input.effective_ttl as number).evaluatePure(intent(vector.id, input.intent_timestamp as number, "1", action), state, input.evaluation_time as number);
    return out.decision === "ALLOW" ? { decision: out.decision, reasons: out.reasons, authorization_issued_at: out.authorization.issued_at, authorization_expiry: out.authorization.expiry } : { decision: out.decision, reasons: out.reasons };
  }
  if (vector.category === "replay" || vector.category === "velocity") return { steps: runSequence(vector, vector.category) };
  if (vector.category === "tool_window") {
    const first = { steps: runSequence(vector, "tool_window") };
    const second = { steps: runSequence(vector, "tool_window") };
    if (!equal(first, second)) throw new Error(`${vector.id}: repeated tool-window execution was not deterministic`);
    return first;
  }
  if (vector.category === "authorization_verification") {
    const unsigned = { auth_id: vector.id, issuer: "issuer", audience: "aud", intent_hash: "1".repeat(64), state_hash: "2".repeat(64), policy_id: "3".repeat(64), decision: "ALLOW" as const, issued_at: input.authorization_issued_at as number, expiry: input.authorization_expiry as number, kid: "k1" };
    const auth = signAuthorizationEd25519(unsigned, TEST_ONLY_ED25519_PRIVATE_KEY_PEM_DO_NOT_USE_IN_PRODUCTION);
    const result = verifyAuthorization(auth, { now: input.verifier_time as number, mode: "strict", expectedIssuer: "issuer", expectedAudience: "aud", trustedKeySets: KEYSET, maxFutureIssuedAtSkewSeconds: input.max_future_issued_at_skew_seconds as number });
    return { status: result.status, violation_codes: result.violations.map(v => v.code) };
  }
  if (vector.category === "malformed_configuration") {
    try {
      if (input.configuration_field === "authorization_ttl_seconds") makeEngine(input.configuration_value as number);
      else verifyAuthorization({} as AuthorizationV1, { maxFutureIssuedAtSkewSeconds: input.configuration_value as number });
      return { throws: false, error_includes: "" };
    } catch (error) { return { throws: true, error_includes: error instanceof Error ? error.message : String(error) }; }
  }
  if (vector.category === "protocol_seconds_validation") {
    try {
      if (input.case === "intent_timestamp") {
        return verifyTrustedTime({ intentTimestamp: input.intent_timestamp as number, evaluationTime: input.evaluation_time as number, maxClockSkewSeconds: 300, maxIntentAgeSeconds: 300 });
      }
      const out = makeEngine(input.effective_ttl as number | undefined ?? 60).evaluatePure(intent(vector.id, input.intent_timestamp as number, "1"), makeState(), input.evaluation_time as number);
      return { decision: out.decision, reasons: out.reasons };
    } catch (error) { return { throws: true, error_includes: error instanceof Error ? error.message : String(error) }; }
  }
  if (vector.category === "determinism") {
    const outputs: unknown[] = [];
    for (let i = 0; i < (input.repeat as number); i++) {
      if (input.kind === "velocity_sequence") outputs.push({ steps: runSequence(vector, "velocity") });
      else {
        const out = makeEngine(input.effective_ttl as number).evaluatePure(intent(vector.id, input.intent_timestamp as number, "1"), makeState(), input.evaluation_time as number);
        outputs.push(out.decision === "ALLOW" ? { decision: out.decision, reasons: out.reasons, authorization_issued_at: out.authorization.issued_at, authorization_expiry: out.authorization.expiry, full: normalize(out) } : normalize(out));
      }
    }
    const first = outputs[0];
    const identical = outputs.every(x => equal(x, first));
    if (input.kind === "velocity_sequence") return { identical_output: identical };
    const base = first as RecordValue;
    return { decision: base.decision, reasons: base.reasons, authorization_issued_at: base.authorization_issued_at, authorization_expiry: base.authorization_expiry, identical_output: identical };
  }
  throw new Error(`${vector.id}: active category ${vector.category} has no executor`);
}

function matches(actual: unknown, expected: RecordValue): boolean {
  if (expected.throws === true) return (actual as RecordValue).throws === true && String((actual as RecordValue).error_includes).includes(String(expected.error_includes));
  return equal(actual, expected);
}

function mismatchDetail(vector: TrustedTimeVector, actual: unknown): string | undefined {
  if (vector.category !== "replay" && vector.category !== "velocity" && vector.category !== "tool_window") return undefined;
  const actualSteps = (actual as { steps: unknown[] }).steps;
  const expectedSteps = vector.expected.steps as unknown[];
  const inputSteps = vector.input.steps as RecordValue[];
  for (let index = 0; index < expectedSteps.length; index++) {
    if (!equal(actualSteps[index], expectedSteps[index])) {
      const input = inputSteps[index]!;
      return `step ${index + 1} intent_timestamp=${String(input.intent_timestamp)} evaluation_time=${String(input.evaluation_time)} expected=${JSON.stringify(expectedSteps[index])} actual=${JSON.stringify(actualSteps[index])}`;
    }
  }
  return undefined;
}

export function runTrustedTimeConformance(raw: unknown, log: (line: string) => void = console.log): TrustedTimeSummary {
  const file = parseTrustedTimeFile(raw);
  const passedCaseIds: string[] = [];
  const summary = { active: 0, passed: 0, failed: 0, pending: 0, failures: [] as string[] };
  for (const vector of file.vectors) {
    if (vector.status === "pending") { summary.pending++; log(`PENDING ${vector.id} blocked_by=${vector.blocked_by}`); continue; }
    summary.active++;
    try {
      const actual = runVector(vector);
      if (!matches(actual, vector.expected)) throw new Error(mismatchDetail(vector, actual) ?? `expected=${JSON.stringify(vector.expected)} actual=${JSON.stringify(actual)}`);
      passedCaseIds.push(vector.id);
      summary.passed++; log(`PASS ${vector.id}`);
    } catch (error) {
      summary.failed++;
      const detail = error instanceof Error ? error.message : String(error);
      const message = `${vector.id}: ${detail}`;
      summary.failures.push(message); log(`FAIL ${message}`);
    }
  }
  return { ...summary, evidenceScope: evidenceScope({ consumer: "packages/conformance/src/trustedTimeConformance.ts", runtime: "TypeScript", selections: [{
    representation: "packages/conformance/vectors/trusted-time.json", data: raw,
    consumer: "packages/conformance/src/trustedTimeConformance.ts", runtime: "TypeScript",
    caseIds: file.vectors.filter(v => v.status === "active").map(v => v.id), passedCaseIds,
  }] }) };
}

export function trustedTimeExitCode(summary: TrustedTimeSummary): 0 | 1 {
  return summary.failed === 0 ? 0 : 1;
}
