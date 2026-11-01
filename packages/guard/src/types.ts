// SPDX-License-Identifier: Apache-2.0
import type { AuthorizationAuthority, AuthorizationV1, DelegationScope, DelegationV1, Intent, KeySet, PolicyEngine, State } from "@oxdeai/core";
import type { ReplayStore } from "./replayStore.js";
import type { ReplayProtection } from "./replayProtection.js";
import type { GuardBoundaryEventHook } from "./boundaryEvent.js";

/**
 * A runtime-agnostic description of an action an agent wants to perform.
 * Runtimes map their tool-call or action objects to this type before
 * passing them to the guard.
 */
export type ProposedAction = {
  /** Name of the action / tool being invoked (e.g. "provision_gpu"). */
  name: string;
  /** Arguments passed to the action. */
  args: Record<string, unknown>;
  /** Optional ambient context — agent_id and target are read from here by the default normalizer. */
  context?: Record<string, unknown>;
  /** Estimated monetary cost of the action in whole units (e.g. USD). Used to set the intent amount. */
  estimatedCost?: number;
  /** Resource category (e.g. "gpu", "payment"). Used to infer action_type. */
  resourceType?: string;
  /** Unix timestamp in seconds. Defaults to Date.now() / 1000 when omitted. */
  timestampSeconds?: number;
};

/**
 * Delegation credentials presented by a child agent to execute within a
 * delegated scope. The guard verifies the full chain before execution.
 */
export type GuardDelegationInput = {
  /** The DelegationV1 artifact issued by the parent agent. */
  delegation: DelegationV1;
  /** The parent AuthorizationV1 that the delegation was derived from. */
  parentAuth: AuthorizationV1;
  /**
   * The scope granted to the parent agent — the authority ceiling for this
   * delegation chain. Required for scope narrowing verification.
   * Absence or structural invalidity fails closed before chain verification.
   */
  parentScope: DelegationScope;
};

/**
 * Per-call options passed as the optional third argument to the guard function.
 * When `delegation` is present, the guard takes the delegation verification path
 * instead of the standard policy-evaluation path.
 */
export type GuardCallOptions = {
  /**
   * Delegation credentials for child-agent execution.
   * When provided, the guard skips engine.evaluatePure() and instead
   * verifies the delegation chain locally.
   */
  delegation?: GuardDelegationInput;
};

/** Structured record of the guard's decision, passed to the onDecision hook. */
export type GuardDecisionRecord = {
  action: ProposedAction;
  decision: "ALLOW" | "DENY";
  authorization?: AuthorizationV1;
  /** Present when the decision was made via the delegation verification path. */
  delegation?: DelegationV1;
  reasons?: string[];
  /**
   * Per-field trusted-vs-proposer outcome. Present only on the Tier 1 secure
   * guard path, so that an audit reader can tell a guard-filled premise apart
   * from a proposer assertion that happened to be correct.
   */
  provenance?: Readonly<Record<string, string>>;
};

/**
 * Opaque version token associated with a state snapshot.
 * Returned by getState() and passed back to setState() to enforce CAS semantics.
 * Use a monotonically-increasing integer, ETag, or any comparable value.
 */
export type StateVersion = string | number;

/**
 * A state snapshot paired with its version token.
 * Returned by getState() so the guard can detect concurrent modifications.
 */
export type VersionedState = {
  state: State;
  version: StateVersion;
};

/** Configuration for OxDeAIGuard. */
export type OxDeAIGuardConfig = {
  /** The PolicyEngine instance that evaluates intent policy. */
  engine: PolicyEngine;
  /**
   * Load the current policy state together with its version token.
   * The version is passed back to setState() to enforce CAS semantics.
   * May be async.
   */
  getState: () => VersionedState | Promise<VersionedState>;
  /**
   * Persist the next state using compare-and-set semantics.
   * Must atomically verify that the persisted version still equals
   * `expectedVersion` before committing `state`. Return `true` on
   * success, `false` on version mismatch (concurrent modification).
   * The guard throws OxDeAIConflictError and blocks execution on `false`.
   * May be async.
   */
  setState: (state: State, expectedVersion: StateVersion) => boolean | Promise<boolean>;

  /**
   * Optional custom mapping from a ProposedAction to an OxDeAI Intent.
   * When omitted, the default normalizer is used.
   */
  mapActionToIntent?: (action: ProposedAction) => Intent;

  /**
   * Optional hook called after authorization succeeds but before the
   * side-effecting execute() callback is invoked.
   */
  beforeExecute?: (
    action: ProposedAction,
    authorization: AuthorizationV1
  ) => void | Promise<void>;

  /**
   * Optional audit hook called after every decision (ALLOW and DENY).
   * Errors thrown here are swallowed so they cannot block execution.
   */
  onDecision?: (result: GuardDecisionRecord) => void | Promise<void>;

  /**
   * Optional audit hook for rejections raised at the guard boundary — an
   * unbranded trusted context, a provenance conflict, a delegation replay, a
   * hash-binding failure, a CAS conflict.
   *
   * Disjoint from {@link OxDeAIGuardConfig.onDecision}, by construction:
   *
   * ```text
   * valid DENY                              → onDecision only      (decision record emitted)
   * guard rejection before execute() starts → onBoundaryEvent only (no decision record)
   * ALLOW, execute() starts, callback threw → neither              (current contract, #238)
   * ```
   *
   * No rejection is reported on both streams. A valid denial is the engine's
   * decision and is reported to `onDecision`; every other guard-boundary
   * rejection emits no decision record, which is precisely why a deployment
   * auditing only `onDecision` could not see attempted identity or tool
   * substitutions.
   *
   * A boundary rejection is not necessarily pre-decision: it may occur before
   * the engine ran (`policyEvaluated === false`) or after a valid ALLOW
   * (`policyEvaluated === true`), because authorization verification, replay
   * consumption, hash binding and the CAS commit all run after the ALLOW and
   * before `execute()`, while the ALLOW record is only emitted once the
   * protected callback has returned.
   *
   * Best effort, exactly like `onDecision`: anything this hook throws or
   * rejects with is swallowed, and the caller always receives the original
   * guard error, unwrapped and unreplaced. It is awaited before the rejection
   * propagates, so a slow hook delays the caller — do durable work out of band.
   */
  onBoundaryEvent?: GuardBoundaryEventHook;

  /**
   * The audience this guard instance expects in every AuthorizationV1 artifact.
   *
   * Must equal the `authorization_audience` value configured in the PolicyEngine
   * (typically the agent's identity string). Every authorization issued by the
   * engine carries this audience; the guard rejects tokens whose audience field
   * does not exactly match.
   *
   * For adapter packages (openclaw, langgraph, crewai, etc.) this is derived
   * automatically from `config.agentId` — callers do not set it directly.
   *
   * Enforcement: `validateConfig` throws `OxDeAIGuardConfigurationError` when
   * absent. There is no default or fallback.
   */
  expectedAudience: string;

  /**
   * KeySets used to verify Ed25519 signatures on authorization artifacts.
   * Required; `validateConfig` throws when absent or empty.
   */
  trustedKeySets?: KeySet | readonly KeySet[];

  /**
   * Deployer-configured (issuer, policyId) pairs authorized to act as a
   * DELEGATION ROOT at this boundary.
   *
   * Required whenever a call supplies `opts.delegation`. `parentAuth` arrives
   * from the caller, so a valid signature under {@link trustedKeySets} proves
   * only that a trusted key for the *claimed* issuer signed it — never that the
   * issuer may issue for the claimed `policy_id`. Without an independent
   * authority list there is nothing to check that against, so the guard fails
   * closed rather than accepting the parent's own claim.
   *
   * ```text
   * undefined  -> delegation call fails closed (missing required configuration)
   * []         -> valid configuration authorizing no delegation root
   * ```
   *
   * `undefined` is NOT "accept any issuer/policy". The distinction between
   * absent and empty is deliberate and must not be collapsed.
   *
   * Optional in the type because the ordinary `guard(action, execute)` path
   * never reads it: there, the authorization is the untouched return value of
   * `engine.evaluatePure()` in the same call, and its expectations come from
   * the engine's own trusted configuration. Framework adapters do not expose
   * delegation and therefore need not configure this.
   *
   * Authority is a complete pair. Do not decompose it into separate issuer and
   * policy allow-lists — that authorizes their Cartesian product.
   */
  trustedDelegationAuthorities?: readonly AuthorizationAuthority[];

  /**
   * Pluggable replay store for durable auth_id and delegation_id tracking.
   *
   * When omitted, an in-memory store is created per guard instance (equivalent
   * to the previous single-process behavior). Provide a backend-backed
   * implementation (e.g. Redis, DynamoDB) for multi-process or
   * restart-durable replay prevention.
   *
   * The store MUST be fail-closed: throw rather than return a permissive
   * result when unavailable. The guard treats any thrown error as DENY.
   *
   * @deprecated P2-1: prefer `replayProtection`. Setting both is rejected at
   * construction. A bare `replayStore` is still honored for back-compat.
   */
  replayStore?: ReplayStore;

  /**
   * P2-1: explicit replay-protection posture. Makes the deployment's replay
   * domain intent explicit. `{mode:"process-local"}` acknowledges a
   * single-process in-memory store; `{mode:"shared", store}` declares a
   * caller-provided durable, cross-instance backend. When omitted (and no
   * `replayStore` is given), the transitional default is a process-local store
   * plus a one-time migration warning. OxDeAI enforces this configuration
   * contract; it does not verify that a `shared` store is genuinely durable,
   * atomic, or shared - that is a deployment obligation. Mutually exclusive
   * with `replayStore`.
   */
  replayProtection?: ReplayProtection;

  /**
   * P2-1 STRICT MODE (opt-in). When true, construction FAILS CLOSED with a
   * deterministic OxDeAIGuardConfigurationError if no replay posture is
   * declared (neither `replayProtection` nor the deprecated `replayStore`).
   * A deliberately-declared {mode:'process-local'} remains accepted. Default
   * false (transitional: undeclared uses a process-local store + one-time
   * warning). A future major release makes strict the effective default.
   */
  requireExplicitReplayProtection?: boolean;

  /**
   * Optional custom function for computing the live-state hash used in
   * state_hash binding verification (guard step 6c).
   *
   * When provided, this function is called instead of
   * `config.engine.computeStateHash(state)` to produce the hash that is
   * compared against `authorization.state_hash`.
   *
   * Required when authorizations are produced by an external provider that
   * uses a different state canonicalization algorithm. For example:
   *   - Sift adapter: uses siftCanonicalJsonHash(state)
   *   - Core PolicyEngine: uses engine.computeStateHash(state) (default)
   *
   * Using the wrong function for the authorization's committed hash algorithm
   * produces a deterministic state_hash mismatch — execution is blocked,
   * fail-closed. There is no fallback or partial acceptance.
   *
   * Fail-closed: any exception thrown by this function blocks execution
   * with OxDeAIAuthorizationError.
   */
  computeStateHash?: (state: State) => string;
};
