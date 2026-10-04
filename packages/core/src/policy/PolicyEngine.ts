// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";
import type { Intent } from "../types/intent.js";
import type { State, CanonicalState } from "../types/state.js";
import type { Authorization, AuthorizationV1 } from "../types/authorization.js";
import type { ReasonCode, PolicyModule } from "../types/policy.js";
import type { VerificationMode, VerificationCoverage } from "../verification/types.js";

import { canonicalJson, intentHash, sha256HexFromJson } from "../crypto/hashes.js";
import { engineSignHmac } from "../crypto/sign.js";
import { engineVerifyHmac } from "../crypto/verify.js";
import { SIGNING_DOMAINS, signEd25519, signHmacDomain } from "../crypto/signatures.js";
import { runDecisionModules } from "./decision/index.js";

import { HashChainedLog } from "../audit/HashChainedLog.js";
import type { AuditEvent } from "../audit/AuditLog.js";
import { isRuntimeState, validateNumericLeaves } from "./stateGuards.js";
import { assertProtocolSeconds } from "./trustedTimeValidation.js";
import { verifyTrustedTime } from "./verifyTrustedTime.js";
import { KillSwitchModule } from "./modules/KillSwitchModule.js";
import { AllowlistModule } from "./modules/AllowlistModule.js";
import { BudgetModule } from "./modules/BudgetModule.js";
import { VelocityModule } from "./modules/VelocityModule.js";

import { ReplayModule } from "./modules/ReplayModule.js";
import { ConcurrencyModule, computeConcurrencyLeases } from "./modules/ConcurrencyModule.js";
import { RecursionDepthModule } from "./modules/RecursionDepthModule.js";
import { ToolAmplificationModule } from "./modules/ToolAmplificationModule.js";
import type { StateStore, AuditSink } from "../adapters/types.js";
import { stableStringify } from "../utils/stableStringify.js";
import { createCanonicalState, withModuleState } from "../snapshot/CanonicalState.js";
import { MODULE_CODECS } from "./modules/registry.js";

/** @public */
export type EngineEvalOptions = {
  mode?: "fail-fast" | "collect-all";
};

/**
 * Result of {@link PolicyEngine.verifyAuthorization}.
 *
 * ⚠️ LIMITED SCOPE — NOT full authorization verification. This method
 * authenticates only the engine-HMAC field subset (`intent_hash`,
 * `policy_version`, `state_snapshot_hash`, `decision`, `expires_at`). A
 * `valid: true` result therefore means only that the engine-HMAC subset is
 * authentic; it is NOT equivalent to full `AuthorizationV1` verification, and
 * fields OUTSIDE the subset (e.g. `audience`, `capability`, `state_hash`) are
 * not authenticated by this check. Relying parties enforcing an authorization
 * MUST use the strict standalone {@link verifyAuthorization} instead.
 *
 * The #172 verification-surface descriptors are ALWAYS populated here (they are
 * required, not merely inherited as optional fields from the shared
 * {@link VerificationResult}), so a caller can never mistake this limited-scope
 * check for full cryptographic verification:
 *
 *   - `signatureVerified` is `true` ONLY when the engine HMAC actually ran and
 *     passed; a failed or unperformed HMAC never reports `true`.
 *   - `verificationMode` is always `"permissive"` — this helper has no strict
 *     posture.
 *   - `verificationCoverage` is `"engine-hmac-subset"` once the HMAC check is
 *     engaged (whether it passes or is rejected), and `"none"` when no HMAC
 *     check ran (e.g. an earlier structural check short-circuited).
 *     It NEVER reports `"authorization-v1-full"` — that surface is only
 *     produced by the strict standalone verifier.
 *
 * @public
 */
export type EngineAuthorizationVerificationResult = {
  valid: boolean;
  reason?: ReasonCode;
  signatureVerified: boolean;
  verificationMode: VerificationMode;
  verificationCoverage: VerificationCoverage;
};

/** @public */
export type EvaluateOutput =
  | { decision: "ALLOW"; reasons: []; authorization: AuthorizationV1 }
  | { decision: "DENY"; reasons: ReasonCode[] };

/** @public */
export type EvaluatePureOutput =
  | { decision: "ALLOW"; reasons: []; authorization: AuthorizationV1; nextState: State }
  | { decision: "DENY"; reasons: ReasonCode[] };

/** @public */
export type SimulationResult = {
  outputs: EvaluatePureOutput[];
  finalState: State;
};

/** @public */
export type EngineOptions = {
  policy_version: string;
  engine_secret: string;
  authorization_ttl_seconds?: number;
  authorization_issuer?: string;
  authorization_audience?: string;
  /**
   * Algorithm used to sign emitted `AuthorizationV1` artifacts.
   *
   * Defaults to `"HMAC-SHA256"` for backward compatibility. **This default is
   * deprecated.** New deployments SHOULD set this to `"Ed25519"` and provide
   * `authorization_private_key_pem`. `"HMAC-SHA256"` will be removed as a valid
   * default in a future major release.
   *
   * @deprecated Pass `"Ed25519"` explicitly for all new integrations.
   */
  authorization_signing_alg?: "Ed25519" | "HMAC-SHA256";
  authorization_signing_kid?: string;
  authorization_private_key_pem?: string;
  /**
   * Trusted-time freshness tolerance (docs/spec/core/trusted-time-v1.md §5):
   * the max seconds `intent.timestamp` may lead the trusted `evaluationTime`
   * argument passed to `evaluate`/`evaluatePure` and still be considered
   * fresh. REQUIRED - there is no default inside `PolicyEngine`. Deployments
   * that have not chosen a policy should pass
   * `RECOMMENDED_TRUSTED_TIME_PROFILE` explicitly rather than relying on any
   * implicit fallback.
   */
  maxClockSkewSeconds: number;
  /**
   * Trusted-time freshness tolerance (docs/spec/core/trusted-time-v1.md §5):
   * the max seconds `intent.timestamp` may lag the trusted `evaluationTime`
   * argument and still be considered fresh. REQUIRED - see
   * `maxClockSkewSeconds`.
   */
  maxIntentAgeSeconds: number;
  deny_mode?: "collect-all" | "fail-fast";
  policyId?: string;
  strictDeterminism?: boolean;
  checkpoint_every_n_events?: number;
  stateStore?: StateStore;
  auditSink?: AuditSink;
  autoPersist?: boolean;
};

// Keep canonical snapshot hashes stable across host package managers/runners.
const ENGINE_VERSION = "unknown";
const DEFAULT_AUTHORIZATION_TTL_SECONDS = 60;

function resolveAuthorizationTtlSeconds(value: unknown): number {
  const ttl = value === undefined ? DEFAULT_AUTHORIZATION_TTL_SECONDS : value;
  if (typeof ttl !== "number" || !Number.isSafeInteger(ttl) || ttl <= 0) {
    throw new Error(
      "authorization_ttl_seconds must be a positive finite safe integer (seconds)"
    );
  }
  return ttl;
}

const RELEASE_MODULES: readonly PolicyModule[] = [
  { id: "KillSwitchModule", evaluate: KillSwitchModule, codec: MODULE_CODECS.KillSwitchModule },
  { id: "ReplayModule", evaluate: ReplayModule, codec: MODULE_CODECS.ReplayModule },
  { id: "ConcurrencyModule", evaluate: ConcurrencyModule, codec: MODULE_CODECS.ConcurrencyModule }
];

const EXECUTE_MODULES: readonly PolicyModule[] = [
  { id: "KillSwitchModule", evaluate: KillSwitchModule, codec: MODULE_CODECS.KillSwitchModule },
  { id: "AllowlistModule", evaluate: AllowlistModule, codec: MODULE_CODECS.AllowlistModule },
  { id: "ReplayModule", evaluate: ReplayModule, codec: MODULE_CODECS.ReplayModule },
  { id: "RecursionDepthModule", evaluate: RecursionDepthModule, codec: MODULE_CODECS.RecursionDepthModule },
  { id: "ConcurrencyModule", evaluate: ConcurrencyModule, codec: MODULE_CODECS.ConcurrencyModule },
  { id: "ToolAmplificationModule", evaluate: ToolAmplificationModule, codec: MODULE_CODECS.ToolAmplificationModule },
  { id: "BudgetModule", evaluate: BudgetModule, codec: MODULE_CODECS.BudgetModule },
  { id: "VelocityModule", evaluate: VelocityModule, codec: MODULE_CODECS.VelocityModule }
];

/** @public */
export class PolicyEngine {
  private readonly opts: EngineOptions;
  private readonly authorizationTtl: number;
  private currentState?: State;
  private auditEventCount = 0;
  // Adapter writes are sequenced here so evaluate/evaluatePure remain synchronous.
  private auditSinkChain: Promise<void> = Promise.resolve();
  private stateStoreChain: Promise<void> = Promise.resolve();
  private auditSinkError: unknown | null = null;
  private stateStoreError: unknown | null = null;
  public readonly audit: HashChainedLog = new HashChainedLog();

  constructor(opts: EngineOptions) {
    if (typeof opts.engine_secret !== "string" || opts.engine_secret.length < 32) {
      throw new Error(
        `engine_secret must be a string of at least 32 characters (got ${
          typeof opts.engine_secret === "string"
            ? `${opts.engine_secret.length} chars`
            : typeof opts.engine_secret
        })`
      );
    }
    assertProtocolSeconds(opts.maxClockSkewSeconds, "EngineOptions.maxClockSkewSeconds");
    assertProtocolSeconds(opts.maxIntentAgeSeconds, "EngineOptions.maxIntentAgeSeconds");
    this.authorizationTtl = resolveAuthorizationTtlSeconds(opts.authorization_ttl_seconds);
    this.opts = opts;
  }

  private authorizationTtlSeconds(): number {
    return this.authorizationTtl;
  }

  private authorizationIssuer(): string {
    return this.opts.authorization_issuer ?? "oxdeai.policy-engine";
  }

  private authorizationAudience(): string {
    return this.opts.authorization_audience ?? "oxdeai.relying-party";
  }

  private authorizationSigningAlg(): "Ed25519" | "HMAC-SHA256" {
    // Default is "HMAC-SHA256" for backward compatibility only.
    // New configurations should pass authorization_signing_alg: "Ed25519".
    return this.opts.authorization_signing_alg ?? "HMAC-SHA256";
  }

  private authorizationSigningKid(): string {
    return this.opts.authorization_signing_kid ?? (this.authorizationSigningAlg() === "Ed25519" ? "ed25519-default" : "hmac-default");
  }

  /**
   * validateState(): explicit runtime validation for fail-closed semantics.
   * Goal: structural corruption should return STATE_INVALID (not INTERNAL_ERROR).
   * Note: per-agent configuration is validated for the current intent.agent_id only.
   */
  private validateStateForIntent(state: unknown, intent: Intent): { ok: true } | { ok: false; reason: ReasonCode } {
    if (!isRuntimeState(state)) return { ok: false, reason: "STATE_INVALID" };

    const leaves = validateNumericLeaves(state, intent.agent_id);
    if (!leaves.ok) return { ok: false, reason: "STATE_INVALID" };

    return { ok: true };
  }

  private validateIntent(intent: Intent): { ok: true } | { ok: false; reason: ReasonCode } {
    if (intent.amount < 0n) {
      return { ok: false, reason: "INTENT_AMOUNT_INVALID" };
    }
    if (intent.type === "RELEASE" && !intent.authorization_id) {
      return { ok: false, reason: "STATE_INVALID" };
    }
    return { ok: true };
  }

  private emitAudit(event: AuditEvent): void {
    this.audit.append(event);
    this.auditEventCount += 1;
    if (!this.opts.auditSink) return;

    const sink = this.opts.auditSink;
    const queuedEvent = structuredClone(event);
    this.auditSinkChain = this.auditSinkChain
      .then(() => Promise.resolve(sink.append(queuedEvent)))
      .catch((error) => {
        this.auditSinkError ??= error;
      });
  }

  private maybeEmitCheckpoint(policyId: string, timestamp: number, state: State): void {
    const every = this.opts.checkpoint_every_n_events;
    if (every === undefined) return;
    if (!Number.isInteger(every) || every <= 0) return;
    if (this.auditEventCount % every !== 0) return;

    this.emitAudit({
      type: "STATE_CHECKPOINT",
      stateHash: this.computeStateHashFor(state),
      timestamp,
      policyId
    });
  }

  async flushAudit(): Promise<void> {
    await this.auditSinkChain;
    if (this.opts.auditSink?.flush) {
      await this.opts.auditSink.flush();
    }
    if (this.auditSinkError !== null) {
      const err = this.auditSinkError;
      this.auditSinkError = null;
      throw err;
    }
  }

  commitState(state: State): void {
    if (!this.opts.stateStore) return;
    const snapshot = this.exportState(state);
    const store = this.opts.stateStore;
    this.stateStoreChain = this.stateStoreChain
      .then(() => Promise.resolve(store.set(snapshot)))
      .catch((error) => {
        this.stateStoreError ??= error;
      });
  }

  async flushState(): Promise<void> {
    await this.stateStoreChain;
    if (this.stateStoreError !== null) {
      const err = this.stateStoreError;
      this.stateStoreError = null;
      throw err;
    }
  }

  /**
   * Interval during which one intent remains admissible under the trusted-time
   * freshness gate. Replay retention must cover it in full; an unrepresentable
   * sum retains every entry rather than pruning any.
   */
  private freshnessHorizonSeconds(): number {
    const horizon = this.opts.maxIntentAgeSeconds + this.opts.maxClockSkewSeconds;
    return Number.isSafeInteger(horizon) ? horizon : Number.POSITIVE_INFINITY;
  }

  /**
   * `evaluationTime` is the trusted PEP clock (unix seconds), sampled once
   * per evaluation by the caller (docs/spec/core/trusted-time-v1.md §2.1).
   * It is REQUIRED and never defaulted or derived from `intent.timestamp` or
   * an ambient clock - see `evaluatePure` for the full freshness-gate
   * contract, which this method inherits unchanged (always in `fail-fast`
   * mode).
   */
  evaluate(intent: Intent, state: State, evaluationTime: number): EvaluateOutput {
    const out = this.evaluatePure(intent, state, evaluationTime, { mode: "fail-fast" });

    if (out.decision === "DENY") {
      this.currentState = structuredClone(state);
      if (this.opts.autoPersist === true) {
        this.commitState(state);
      }
      return out;
    }

    Object.assign(state, out.nextState);
    this.currentState = structuredClone(state);
    if (this.opts.autoPersist === true) {
      this.commitState(state);
    }

    return { decision: "ALLOW", reasons: [], authorization: out.authorization };
  }

  /**
   * ⚠️ LIMITED SCOPE — authenticates ONLY the engine-HMAC field subset
   * (`intent_hash`, `policy_version`, `state_snapshot_hash`, `decision`,
   * `expires_at`). A `valid: true` result is NOT equivalent to full
   * `AuthorizationV1` verification: fields outside that subset (e.g.
   * `audience`, `capability`, `state_hash`) are not authenticated here, so a
   * mutation to one of them leaves this result `valid`. Relying parties
   * enforcing an authorization MUST use the strict standalone
   * {@link verifyAuthorization} instead. See
   * {@link EngineAuthorizationVerificationResult}.
   */
  verifyAuthorization(
    intent: Intent,
    authorization: Authorization,
    state: State,
    now?: number
  ): EngineAuthorizationVerificationResult {
    // This helper has no strict posture; its configured mode is always
    // "permissive". Whether an engine-HMAC check actually ran and passed is
    // conveyed orthogonally by `signatureVerified` / `verificationCoverage`
    // (#172), never by the mode.
    const verificationMode: VerificationMode = "permissive";
    try {
      const t =
        now ??
        (() => {
          if (this.opts.strictDeterminism) {
            throw new Error("strictDeterminism: 'now' must be provided (no Date.now fallback)");
          }
          return Math.floor(Date.now() / 1000);
        })();

      // Structural checks below run BEFORE any cryptographic check; a failure
      // here means no engine HMAC was ever engaged, so coverage stays "none".
      const intent_hash = intentHash(intent);
      if (intent_hash !== authorization.intent_hash)
        return { valid: false, reason: "AUTH_INTENT_MISMATCH", signatureVerified: false, verificationMode, verificationCoverage: "none" };
      const expiry = authorization.expiry ?? authorization.expires_at;
      if (t > expiry)
        return { valid: false, reason: "AUTH_EXPIRED", signatureVerified: false, verificationMode, verificationCoverage: "none" };
      if (authorization.decision !== "ALLOW")
        return { valid: false, reason: "AUTH_SIGNATURE_INVALID", signatureVerified: false, verificationMode, verificationCoverage: "none" };
      if (state.policy_version !== authorization.policy_version)
        return { valid: false, reason: "POLICY_VERSION_MISMATCH", signatureVerified: false, verificationMode, verificationCoverage: "none" };

      const authPayload = {
        intent_hash: authorization.intent_hash,
        policy_version: authorization.policy_version,
        state_snapshot_hash: authorization.state_snapshot_hash,
        decision: "ALLOW" as const,
        expires_at: authorization.expires_at
      };

      // The engine-HMAC subset check is engaged here. Coverage records the
      // surface actually evaluated (the engine-HMAC subset — NEVER the full
      // AuthorizationV1 surface) and is set the moment the check runs,
      // independent of its outcome; `signatureVerified` flips true only if the
      // check passes.
      const verificationCoverage: VerificationCoverage = "engine-hmac-subset";
      const ok = engineVerifyHmac(authPayload, authorization.engine_signature, this.opts.engine_secret);
      if (!ok)
        return { valid: false, reason: "AUTH_SIGNATURE_INVALID", signatureVerified: false, verificationMode, verificationCoverage };

      return { valid: true, signatureVerified: true, verificationMode, verificationCoverage };
    } catch {
      return { valid: false, reason: "INTERNAL_ERROR", signatureVerified: false, verificationMode, verificationCoverage: "none" };
    }
  }

  /**
   * evaluatePure - pure, deterministic evaluation of (intent, state, policy, evaluationTime).
   *
   * The input `state` is never mutated. deepMerge creates new object copies at
   * every level touched by a module delta, so passing the same state reference
   * across sequential calls is safe.
   *
   * For concurrent evaluation in multi-threaded environments (e.g. worker
   * threads sharing a SharedArrayBuffer), callers should still provide
   * structuredClone(state) to each invocation for full isolation.
   *
   * `evaluationTime` is the trusted PEP clock (unix seconds), sampled once
   * per evaluation by the caller and passed explicitly
   * (docs/spec/core/trusted-time-v1.md §2.1). It is REQUIRED: there is no
   * default, no fallback to `Date.now()`, and no derivation from
   * `intent.timestamp`. A malformed `evaluationTime` (NaN, Infinity,
   * non-integer, negative, or unsafe magnitude) is a trusted-caller
   * precondition violation, not policy data - `evaluatePure` throws
   * synchronously, before entering its evaluation `try` block, rather than
   * returning any `EvaluatePureOutput` (no decision, no `nextState`, no
   * audit event is produced for a rejected precondition).
   * The same validated value drives freshness, module evaluation, and every
   * emitted authorization validity window: `issued_at = evaluationTime` and
   * `expiry = evaluationTime + authorization_ttl_seconds` (default 60 only
   * when the option is undefined).
   *
   * Trusted-time freshness is evaluated before module execution - before
   * `ReplayModule` and (on EXECUTE) `VelocityModule`. When freshness denies,
   * no module evaluation occurs, regardless of `opts.mode`. In
   * `collect-all` mode, a freshness denial therefore returns only its own
   * reason code; module reasons (e.g. `REPLAY_NONCE`, `VELOCITY_EXCEEDED`)
   * are never collected for a non-fresh intent. This is a security
   * property, not a bug - see docs/spec/core/trusted-time-v1.md §6-§7.
   */
  evaluatePure(intent: Intent, state: State, evaluationTime: number, opts?: EngineEvalOptions): EvaluatePureOutput {

    const mode = opts?.mode ?? "fail-fast";

    const iv = this.validateIntent(intent);
    if (!iv.ok) return { decision: "DENY", reasons: [iv.reason] };

    // Fail-closed + explicit runtime validation
    const v = this.validateStateForIntent(state as unknown, intent);
    if (!v.ok) return { decision: "DENY", reasons: [v.reason] };

    if (state.policy_version !== this.opts.policy_version) {
      return { decision: "DENY", reasons: ["POLICY_VERSION_MISMATCH"] };
    }

    // Trusted precondition - refuses to evaluate rather than proceeding on a
    // coerced or attacker-influenced value (spec §5.1). Deliberately outside
    // the try block below: this must never be caught and converted into a
    // DENY/INTERNAL_ERROR policy result.
    assertProtocolSeconds(evaluationTime, "evaluationTime");
    const effectiveTtl = this.authorizationTtlSeconds();
    if (evaluationTime > Number.MAX_SAFE_INTEGER - effectiveTtl) {
      throw new Error(
        "evaluationTime + authorization_ttl_seconds must be a safe integer (unix seconds)"
      );
    }

    try {
      const intent_hash = intentHash(intent);
      const policyId = this.computePolicyId();
      this.emitAudit({
        type: "INTENT_RECEIVED",
        intent_hash,
        agent_id: intent.agent_id,
        timestamp: evaluationTime,
        policyId
      });

      // ── Trusted-time freshness gate ───────────────────────────────────────
      // Evaluated before any module (before Replay, before Velocity), per
      // docs/spec/core/trusted-time-v1.md §6-§7. intent.timestamp is the one
      // attacker-controlled input this gate reads; a malformed value denies
      // with STATE_INVALID rather than being compared against the bounds.
      // On DENY, no module in EXECUTE_MODULES/RELEASE_MODULES ever runs -
      // this mirrors the existing module-pipeline DENY handling below
      // exactly (same audit shape, same checkpoint behavior).
      const freshness = verifyTrustedTime({
        intentTimestamp: intent.timestamp,
        evaluationTime,
        maxClockSkewSeconds: this.opts.maxClockSkewSeconds,
        maxIntentAgeSeconds: this.opts.maxIntentAgeSeconds
      });

      if (freshness.decision === "DENY") {
        this.emitAudit({
          type: "DECISION",
          intent_hash,
          decision: "DENY",
          reasons: freshness.reasons,
          policy_version: state.policy_version,
          timestamp: evaluationTime,
          policyId
        });
        this.maybeEmitCheckpoint(policyId, evaluationTime, state);
        return { decision: "DENY", reasons: freshness.reasons };
      }

      const t = intent.type ?? "EXECUTE";
      const modules = t === "RELEASE" ? RELEASE_MODULES : EXECUTE_MODULES;

      // ── Decision phase ──────────────────────────────────────────────────
      // (intent + state + module policies) → ALLOW | DENY + nextState
      const decisionResult = runDecisionModules(
        { intent, state, evaluationTime, freshnessHorizonSeconds: this.freshnessHorizonSeconds(), mode },
        modules
      );

      if (decisionResult.decision === "DENY") {
        this.emitAudit({
          type: "DECISION",
          intent_hash,
          decision: "DENY",
          reasons: decisionResult.reasons,
          policy_version: state.policy_version,
          timestamp: evaluationTime,
          policyId
        });
        this.maybeEmitCheckpoint(policyId, evaluationTime, state);
        return { decision: "DENY", reasons: decisionResult.reasons };
      }

      // Authorization is bound to the post-decision state snapshot.
      // working carries all module deltas from the decision phase.
      let working = decisionResult.nextState;

      // Materialize the concurrency lease decision as a replacement assignment.
      //
      // Module deltas are deep-merged, and deepMerge is additive: a lease map
      // returned by ConcurrencyModule with an entry omitted merges back onto the
      // prior map and the omitted entry survives. Reclaiming an expired lease -
      // and removing a cleanly released one - therefore cannot be expressed from
      // inside a module without giving the delta protocol generic deletion
      // semantics, which would change the state transition contract for every
      // module.
      //
      // Instead ConcurrencyModule keeps the decision and the engine assigns the
      // resulting map here, replacing rather than merging that one path. This
      // runs inside the same evaluated transition as the triggering operation
      // and is committed by the same exact-version CAS below, so `active` and
      // `active_auths` move atomically.
      //
      // Computed from `state`, the same pre-delta input the module evaluated
      // against, and with the same trusted `evaluationTime` - engine and module
      // cannot diverge because there is only one definition of the decision.
      const concurrencyLeases = computeConcurrencyLeases(intent, state, evaluationTime);
      if (concurrencyLeases !== null) {
        const leaseAgent = intent.agent_id;
        working = {
          ...working,
          concurrency: {
            ...working.concurrency,
            active_auths: {
              ...working.concurrency.active_auths,
              [leaseAgent]: concurrencyLeases.auths
            }
          }
        };
      }

      const state_snapshot_hash = this.computeStateHashFor(working);
      const issued_at = evaluationTime;
      const expires_at = issued_at + effectiveTtl;
      const policy_id = policyId;
      const issuer = this.authorizationIssuer();
      const audience = this.authorizationAudience();
      const alg = this.authorizationSigningAlg();
      const kid = this.authorizationSigningKid();

      const authPayload = {
        intent_hash,
        policy_version: state.policy_version,
        state_snapshot_hash,
        decision: "ALLOW" as const,
        expires_at
      };

      const engine_signature = engineSignHmac(authPayload, this.opts.engine_secret);
      // state_hash binds the authorization to the evaluation-time input state.
      // Uses computeStateHashFor (module-codec canonical hash) rather than a raw
      // JSON hash so it is insensitive to key-insertion order and missing optional
      // fields - the same guarantee the engine already provides for state_snapshot_hash.
      // This allows the PEP boundary to verify the current state matches the state
      // the engine evaluated against via engine.computeStateHash(state).
      const state_hash = this.computeStateHashFor(state);

      const authorizationCorePayload: Record<string, unknown> = {
        auth_id: "",
        issuer,
        audience,
        intent_hash,
        state_hash,
        policy_id,
        decision: "ALLOW" as const,
        issued_at,
        expiry: expires_at,
        alg,
        kid,
        nonce: intent.nonce.toString()
      };
      if (intent.action_type !== undefined) authorizationCorePayload.capability = intent.action_type;

      // Derive a stable auth_id before signature attachment.
      const authorization_id = sha256HexFromJson({ ...authorizationCorePayload, engine_signature });
      const authCore = { ...authorizationCorePayload, auth_id: authorization_id };
      let signature: string;
      if (alg === "Ed25519") {
        if (!this.opts.authorization_private_key_pem) {
          throw new Error("authorization_private_key_pem is required for Ed25519 signing");
        }
        signature = signEd25519(SIGNING_DOMAINS.AUTH_V1, authCore, this.opts.authorization_private_key_pem);
      } else {
        signature = signHmacDomain(SIGNING_DOMAINS.AUTH_V1, authCore, this.opts.engine_secret);
      }

      const authorization: Authorization = {
        authorization_id,
        auth_id: authorization_id,
        issuer,
        audience,
        intent_hash,
        state_hash,
        policy_id,
        policy_version: state.policy_version,
        state_snapshot_hash,
        decision: "ALLOW",
        issued_at,
        expiry: expires_at,
        alg,
        kid,
        nonce: intent.nonce.toString(),
        signature,
        expires_at,
        engine_signature
      };
      if (intent.action_type !== undefined) authorization.capability = intent.action_type;

      if (t === "EXECUTE") {
        const agent = intent.agent_id;
        // `working` already carries the reclaimed map assigned above, so the new
        // lease is added to the post-reclamation set rather than to the stale one.
        const current = working.concurrency.active_auths?.[agent] ?? {};

        working = {
          ...working,
          concurrency: {
            ...working.concurrency,
            active_auths: {
              ...working.concurrency.active_auths,
              [agent]: {
                ...current,
                [authorization.auth_id]: { expires_at: authorization.expiry }
              }
            }
          }
        };
      }

      this.emitAudit({
        type: "DECISION",
        intent_hash,
        decision: "ALLOW",
        reasons: [],
        policy_version: state.policy_version,
        timestamp: issued_at,
        policyId
      });

      this.emitAudit({
        type: "AUTH_EMITTED",
        authorization_id,
        intent_hash,
        expires_at,
        timestamp: issued_at,
        policyId
      });
      this.maybeEmitCheckpoint(policyId, issued_at, working);

      return { decision: "ALLOW", reasons: [], authorization, nextState: working };
    } catch {
      return { decision: "DENY", reasons: ["INTERNAL_ERROR"] };
    }

    
  }

  computePolicyId(): string {
    if (this.opts.policyId) return this.opts.policyId;
    const describeModules = (mods: readonly PolicyModule[]) =>
      [...mods]
        .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
        .map((m) => ({ id: m.id, version: (m as any).version ?? null }));
    const payload = stableStringify({
      engine: "PolicyEngine",
      engineVersion: ENGINE_VERSION,
      modules: {
        execute: describeModules(EXECUTE_MODULES),
        release: describeModules(RELEASE_MODULES)
      },
      opts: {
        policy_version: this.opts.policy_version ?? null,
        authorization_ttl_seconds: this.authorizationTtlSeconds(),
        deny_mode: this.opts.deny_mode ?? "fail-fast",
        strict: this.opts.strictDeterminism ?? false
      }
    });
    return createHash("sha256").update(payload, "utf8").digest("hex");
  }

  exportState(): CanonicalState;
  exportState(state: State): CanonicalState;
  exportState(state?: State): CanonicalState {
    const current = state ?? this.currentState;
    if (!current) throw new Error("exportState: engine has no current state");

    let snapshot = createCanonicalState({
      formatVersion: 1,
      engineVersion: ENGINE_VERSION,
      policyId: this.computePolicyId(),
      modules: {}
    });

    const ids = Object.keys(MODULE_CODECS).sort();
    for (const id of ids) {
      snapshot = withModuleState(snapshot, id, MODULE_CODECS[id].serializeState(current));
    }

    return snapshot;
  }

  importState(state: CanonicalState): void;
  importState(target: State, state: CanonicalState): void;
  importState(arg1: State | CanonicalState, arg2?: CanonicalState): void {
    const state = (arg2 ?? arg1) as CanonicalState;
    if (state.formatVersion !== 1) {
      throw new Error(`importState: unsupported formatVersion=${String((state as any).formatVersion)}`);
    }
    const expected = this.computePolicyId();
    if (state.policyId !== expected) {
      throw new Error(`importState: policyId mismatch (state=${state.policyId}, engine=${expected})`);
    }

    const target = arg2 ? (arg1 as State) : structuredClone(this.currentState);
    if (!target) throw new Error("importState: engine has no mutable state target");

    const ids = Object.keys(MODULE_CODECS).sort();
    for (const id of ids) {
      const codec = MODULE_CODECS[id];
      codec.deserializeState(target, state.modules[id]);
    }

    this.currentState = structuredClone(target);
  }

  computeStateHash(): string;
  computeStateHash(state: State): string;
  computeStateHash(state?: State): string {
    const current = state ?? this.currentState;
    if (!current) throw new Error("computeStateHash: engine has no current state");
    return this.computeStateHashFor(current);
  }

  /**
   * The entire sequence is evaluated against one fixed trusted
   * `evaluationTime`. `simulateSequence` is a what-if simulation at a fixed
   * instant, not a historical replay - every intent in `intents` sees the
   * same trusted clock reading, regardless of `intent.timestamp`.
   */
  simulateSequence(intents: Intent[], evaluationTime: number, opts?: EngineEvalOptions): SimulationResult {
    const base = this.currentState;
    if (!base) throw new Error("simulateSequence: engine has no current state");

    let working = structuredClone(base);
    const outputs: EvaluatePureOutput[] = [];
    for (const intent of intents) {
      const out = this.evaluatePure(intent, working, evaluationTime, opts);
      outputs.push(out);
      if (out.decision === "ALLOW") {
        working = out.nextState;
      }
    }

    return { outputs, finalState: working };
  }

  private computeStateHashFor(state: State): string {
    const ids = Object.keys(MODULE_CODECS).sort();
    const moduleHashes: Record<string, string> = {};
    for (const id of ids) {
      moduleHashes[id] = MODULE_CODECS[id].stateHash(state);
    }

    const bytes = new TextEncoder().encode(
      canonicalJson({
        formatVersion: 1,
        engineVersion: ENGINE_VERSION,
        policyId: this.computePolicyId(),
        modules: moduleHashes
      })
    );
    return createHash("sha256").update(bytes).digest("hex");
  }
  
}
