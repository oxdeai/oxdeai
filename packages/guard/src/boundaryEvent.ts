// SPDX-License-Identifier: Apache-2.0
/**
 * Unified guard-boundary audit emission (#235).
 *
 * `onDecision` reports a completed `GuardDecisionRecord`. It therefore cannot
 * report a request the guard refused without emitting one — an unbranded
 * trusted context, a provenance conflict, a delegation replay, a state-hash
 * mismatch, a CAS conflict. Those rejections were previously visible only as a
 * thrown error, so a deployment whose only audit sink was `onDecision` could
 * not see attempted identity or tool substitutions at all.
 *
 * "No decision record" is not the same as "no decision". A boundary rejection
 * may occur before the engine ran (`policyEvaluated === false`), or after it
 * returned a valid ALLOW (`policyEvaluated === true`): authorization
 * verification, replay consumption, hash binding and the CAS commit all run
 * after the ALLOW and before `execute()`. On the ALLOW path `onDecision` fires
 * only once the protected callback has returned, so a rejection anywhere in
 * that window yields a boundary event and no decision record at all.
 *
 * This module carries the second stream. Every rejection raised at the guard
 * boundary is emitted once, as a structured {@link GuardBoundaryAuditEvent},
 * to the optional `onBoundaryEvent` hook — without changing any error type,
 * message, or control flow.
 *
 * ## Stream semantics (disjoint by construction)
 *
 * ```text
 * valid DENY                              → onDecision only      (decision record emitted)
 * guard rejection before execute() starts → onBoundaryEvent only (no decision record)
 * ALLOW, execute() starts, callback threw → neither              (current contract, #238)
 * ```
 *
 * The invariant is that no single rejection is ever reported on both streams.
 * A valid `OxDeAIDenyError` is the engine's decision, is reported to
 * `onDecision`, and returns early here; every other guard-boundary rejection
 * emits no decision record, whether or not the engine had already returned an
 * ALLOW. A malformed DENY — one whose `reasons` fail the guard's structural
 * check before `OxDeAIDenyError` is constructed (#247) — is not a decision:
 * it never reaches `onDecision`, is classified `POLICY_EVALUATION` /
 * `ENGINE_FAILURE` at the throw site, and is reported here like any other
 * pre-execution guard-boundary rejection.
 *
 * ## Failure contract
 *
 * `onBoundaryEvent` is a best-effort audit sink. A hook that throws, rejects,
 * or hangs on a rejected promise must never change what the caller sees: the
 * ORIGINAL error is always re-thrown, unwrapped and unreplaced. A deployment
 * that needs delivery guarantees must provide them inside the hook.
 */
import { OxDeAIDenyError } from "./errors.js";
import type { ProvenanceRecord } from "./provenance.js";

/**
 * The enforcement stage a request was rejected at.
 *
 * Ordered the way a request traverses the boundary. `TRUSTED_CONTEXT` is
 * reachable only on the Tier 1 secure path; every other stage is shared.
 *
 * @public
 */
export type GuardBoundaryStage =
  | "TRUSTED_CONTEXT"
  | "STATE_LOAD"
  | "NORMALIZATION"
  | "PROVENANCE"
  | "DELEGATION"
  | "POLICY_EVALUATION"
  | "AUTHORIZATION_VERIFICATION"
  | "REPLAY"
  | "STATE_COMMIT"
  | "EXECUTION_GATE";

/**
 * Why the request was rejected, as a stable machine-readable category.
 *
 * Categories are deliberately coarser than the error messages: a message is
 * free to change wording, a category is what an audit pipeline groups on.
 * `UNCLASSIFIED` is the honest fallback for a rejection that escaped an
 * unannotated throw site (typically a deployment-supplied `getState`,
 * `setState`, or `beforeExecute` callback failing) — it is never a synonym for
 * "allowed".
 *
 * @public
 */
export type GuardBoundaryFailure =
  | "UNTRUSTED_CONTEXT"
  | "MISSING_TENANT_ID"
  | "STATE_VERSION_MISSING"
  | "NORMALIZATION_FAILURE"
  | "PROVENANCE_CONFLICT"
  | "DELEGATION_INPUT_INVALID"
  | "DELEGATION_VERIFICATION_FAILED"
  | "DELEGATION_REVOKED"
  | "DELEGATION_REVOCATION_UNAVAILABLE"
  | "DELEGATION_REPLAY"
  | "AUTHORIZATION_MISSING"
  | "AUTHORIZATION_VERIFICATION_FAILED"
  | "AUTHORIZATION_AUTHORITY_DENIED"
  | "AUTHORIZATION_REPLAY"
  | "REPLAY_STORE_UNAVAILABLE"
  | "INTENT_HASH_MISMATCH"
  | "STATE_HASH_MISMATCH"
  | "CAS_CONFLICT"
  | "ENGINE_FAILURE"
  | "UNCLASSIFIED";

/**
 * One guard-boundary rejection, as seen by an audit sink.
 *
 * The boolean block is the point of the record: it states exactly how far the
 * request got before it was refused, so that a reader can tell a request that
 * never reached the engine from one that was authorized and then failed its
 * state binding. Every flag is reported for every event — a rejection is
 * described by the flags that are `false` as much as by the ones that are
 * `true`.
 *
 * There is deliberately no `policyDecision` field. A valid `DENY` is not
 * reachable here: it is an `OxDeAIDenyError`, which is reported on
 * `onDecision` and returns early from emission. That leaves `ALLOW` as the only value the
 * field could ever carry, and it would carry it exactly when
 * `policyEvaluated` is already `true` — no information that
 * {@link GuardBoundaryAuditEvent.policyEvaluated} does not already give.
 *
 * @public
 */
export type GuardBoundaryAuditEvent = {
  /** Stage the request was refused at. */
  readonly stage: GuardBoundaryStage;
  /** Category of the refusal. */
  readonly boundaryFailure: GuardBoundaryFailure;
  /** `true` once `engine.evaluatePure` has returned. Always `false` on the delegation path, which does not call the engine. */
  readonly policyEvaluated: boolean;
  /** `true` once the engine has returned an ALLOW carrying an authorization artifact. */
  readonly authorizationIssued: boolean;
  /** `true` once an `auth_id` was consumed from the replay store by this request. */
  readonly authorizationConsumed: boolean;
  /** `true` once a `delegation_id` was consumed from the replay store by this request. */
  readonly delegationConsumed: boolean;
  /** `true` once the CAS `setState` commit succeeded. */
  readonly stateCommitted: boolean;
  /**
   * `true` once control has been handed to the protected callback.
   *
   * An event is never emitted with this flag set: past this point the guard has
   * permitted the action, so a later failure belongs to the callback and is not
   * a guard-boundary rejection. The flag is on the record so that the invariant
   * is legible to an audit reader rather than implicit.
   */
  readonly executionStarted: boolean;
  /** `intent_id` of the normalized intent, once normalization has succeeded. */
  readonly intentId?: string;
  /**
   * Per-field trusted-vs-proposer outcome, on a provenance conflict.
   *
   * Reuses the type the reconciliation boundary already exports, so an audit
   * reader parses one provenance vocabulary rather than an opaque string map.
   */
  readonly provenance?: ProvenanceRecord;
  /** Conflicting fields, in declaration order, on a provenance conflict. */
  readonly conflictingFields?: readonly string[];
};

/**
 * Audit sink for guard-boundary rejections.
 *
 * Disjoint from `onDecision`: a valid policy `DENY` is reported there and
 * never here, and a guard rejection that emits no decision record is reported
 * here and never there — whether it happened before the engine ran or after a
 * valid ALLOW. A failure thrown by the protected callback after the guard
 * permitted execution is reported on neither — the guard's answer was ALLOW,
 * and the callback's outcome belongs to the caller (#238).
 *
 * Best effort. Anything this hook throws or rejects with is swallowed; the
 * caller always receives the original guard error, unwrapped and unreplaced.
 * A slow hook does delay the rejection, because the guard awaits it before
 * re-throwing — return promptly and do durable work out of band.
 *
 * @public
 */
export type GuardBoundaryEventHook = (event: GuardBoundaryAuditEvent) => void | Promise<void>;

// ── internal: per-request lifecycle ───────────────────────────────────────────

/**
 * Mutable per-request progress record. Internal: it is written as the request
 * advances and read only when building an event.
 */
export type GuardLifecycle = {
  /** Stage currently being executed; the fallback stage for an unannotated throw. */
  stage: GuardBoundaryStage;
  policyEvaluated: boolean;
  authorizationIssued: boolean;
  authorizationConsumed: boolean;
  delegationConsumed: boolean;
  stateCommitted: boolean;
  executionStarted: boolean;
  intentId?: string;
  /**
   * Set once control has been handed to the shared enforcement body, which
   * runs its own catch and has therefore already accounted for anything raised
   * beyond this point.
   *
   * The {@link EMITTED} set covers that case for thrown objects; this flag
   * covers it for a non-object throw, which cannot be tracked in a WeakSet. It
   * is what stops the secure path's outer catch from re-reporting a callback
   * failure — the inner body's `executionStarted` short-circuit is invisible to
   * the outer lifecycle.
   */
  sharedBodyEntered: boolean;
};

/** Start a lifecycle at the stage the enclosing layer begins with. */
export function createLifecycle(stage: GuardBoundaryStage): GuardLifecycle {
  return {
    stage,
    policyEvaluated: false,
    authorizationIssued: false,
    authorizationConsumed: false,
    delegationConsumed: false,
    stateCommitted: false,
    executionStarted: false,
    sharedBodyEntered: false,
  };
}

// ── internal: classification ──────────────────────────────────────────────────

/** Extra evidence a throw site can attach to its rejection. */
type BoundaryDetails = {
  readonly conflictingFields?: readonly string[];
  readonly provenance?: ProvenanceRecord;
};

type BoundaryAnnotation = {
  readonly stage: GuardBoundaryStage;
  readonly failure: GuardBoundaryFailure;
  readonly details?: BoundaryDetails;
};

/**
 * Classification is held beside the error, never on it: attaching properties to
 * the error would change a public error shape that callers already match on.
 */
const ANNOTATIONS = new WeakMap<object, BoundaryAnnotation>();

/**
 * Errors already accounted for, so that two nested catches (secure wrapper and
 * shared body) report one event rather than two.
 *
 * A WeakSet, not a Set: entries must not keep a rejected request's error — and
 * everything it retains — alive for the lifetime of the process.
 */
const EMITTED = new WeakSet<object>();

/**
 * Whether a thrown value can key a WeakMap/WeakSet.
 *
 * `throw "boom"` is legal, and a third-party normalizer or callback may do it.
 * Every weak-collection operation is guarded by this, so a non-object rejection
 * still surfaces unchanged instead of being replaced by a `TypeError` raised
 * inside the audit path. It loses only cross-layer de-duplication.
 */
function isWeakKey(value: unknown): value is object {
  return (typeof value === "object" && value !== null) || typeof value === "function";
}

/**
 * Classify a rejection at its throw site and return it unchanged, so a call
 * site reads `throw reject(STAGE, CATEGORY, new SomeError(...))`.
 *
 * The error's type and message are untouched — this only records how the
 * rejection should be described to an audit sink. The first annotation wins:
 * an inner layer that knows more about the rejection than an outer one keeps
 * its classification.
 */
export function reject<E>(
  stage: GuardBoundaryStage,
  failure: GuardBoundaryFailure,
  error: E,
  details?: BoundaryDetails
): E {
  if (isWeakKey(error) && !ANNOTATIONS.has(error)) {
    ANNOTATIONS.set(error, details ? { stage, failure, details } : { stage, failure });
  }
  return error;
}

function buildEvent(
  annotation: BoundaryAnnotation | undefined,
  lifecycle: GuardLifecycle
): GuardBoundaryAuditEvent {
  const details = annotation?.details;
  return Object.freeze({
    stage: annotation?.stage ?? lifecycle.stage,
    boundaryFailure: annotation?.failure ?? "UNCLASSIFIED",
    policyEvaluated: lifecycle.policyEvaluated,
    authorizationIssued: lifecycle.authorizationIssued,
    authorizationConsumed: lifecycle.authorizationConsumed,
    delegationConsumed: lifecycle.delegationConsumed,
    stateCommitted: lifecycle.stateCommitted,
    executionStarted: lifecycle.executionStarted,
    ...(lifecycle.intentId !== undefined ? { intentId: lifecycle.intentId } : {}),
    ...(details?.provenance ? { provenance: details.provenance } : {}),
    ...(details?.conflictingFields
      ? { conflictingFields: Object.freeze([...details.conflictingFields]) }
      : {}),
  });
}

/**
 * Emit one guard-boundary audit event for a rejection, if it is one.
 *
 * Every emission rule lives here, so both catch sites are identical and
 * unconditional and neither can drift into deciding policy of its own:
 *
 *  1. no hook          → nothing to do;
 *  2. valid `OxDeAIDenyError` → a policy decision; `onDecision` reported it;
 *  3. execution began  → the guard permitted the action, so this is a callback
 *                        failure, not a boundary rejection;
 *  4. already handled  → a nested catch one layer down accounted for it.
 *
 * The caller re-throws the ORIGINAL error regardless of what happens here.
 */
export async function emitBoundaryEvent(
  hook: GuardBoundaryEventHook | undefined,
  err: unknown,
  lifecycle: GuardLifecycle
): Promise<void> {
  if (!hook) return;

  // A valid denial is a decision, not a boundary rejection: it is reported on
  // onDecision, and reporting it here as well would double-count every DENY.
  if (err instanceof OxDeAIDenyError) return;

  if (lifecycle.executionStarted) {
    // Past the execution gate the guard has already permitted the action. Mark
    // the error handled so an OUTER catch, whose lifecycle never saw the gate
    // open, cannot re-report a callback failure as a guard rejection.
    if (isWeakKey(err)) EMITTED.add(err);
    return;
  }

  // Already accounted for one layer down — by identity for a thrown object, and
  // by the shared-body flag for a non-object throw that cannot be tracked.
  if (lifecycle.sharedBodyEntered) return;
  if (isWeakKey(err)) {
    if (EMITTED.has(err)) return;
    EMITTED.add(err);
  }

  const event = buildEvent(isWeakKey(err) ? ANNOTATIONS.get(err) : undefined, lifecycle);

  try {
    await hook(event);
  } catch {
    // Best effort: an audit sink failure must never change what the caller
    // sees, and must never mask the rejection it was reporting.
  }
}
