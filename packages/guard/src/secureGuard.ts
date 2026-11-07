// SPDX-License-Identifier: Apache-2.0
import type { Intent, KeySet } from "@oxdeai/core";
import { OxDeAIGuard, resolveDelegationRevocation, resolveDelegationSigners } from "./guard.js";
import { resolveRevocationConfig } from "./revocation.js";
import { assertIntrinsicsUnpolluted, captureSecureGuardConfig, isCapturedEphemeralReplayStore } from "./secureConfig.js";
import { defaultNormalizeAction } from "./normalizeAction.js";
import { resolveReplayProtection, strictFromConfig } from "./replayProtection.js";
import { OxDeAIAuthorizationError, OxDeAIGuardConfigurationError } from "./errors.js";
import { isTrustedExecutionContext, type TrustedExecutionContext } from "./trustedContext.js";
import { reconcileWithTrustedContext, type ProvenanceRecord } from "./provenance.js";
import { createLifecycle, emitBoundaryEvent, reject } from "./boundaryEvent.js";
import type { GuardLifecycle } from "./boundaryEvent.js";
import type { OxDeAIGuardConfig, ProposedAction, GuardCallOptions } from "./types.js";

/**
 * Deployment-level configuration for the Tier 1 secure path.
 *
 * @public
 */
export type SecureGuardOptions = {
  /**
   * Whether this deployment serves one tenant or many.
   *
   * REQUIRED and never defaulted. Tier 1 permits an absent `tenantId` only when
   * the deployment is explicitly single-tenant; without a declared posture a
   * multi-tenant integration whose route has not been wired for tenant identity
   * is indistinguishable from a legitimate single-tenant one, and would silently
   * evaluate in an ambiguous namespace.
   *
   *  - `"single-tenant"` — a context without `tenantId` is valid.
   *  - `"multi-tenant"`  — a context without `tenantId` fails closed before
   *                        evaluation; a proposer tenant claim that conflicts
   *                        with the trusted one is a provenance conflict.
   */
  readonly tenancy: "single-tenant" | "multi-tenant";
};

/**
 * Tier 1 secure guard entry point.
 *
 * The secure path differs from {@link OxDeAIGuard} in exactly one respect: how
 * the evaluated intent's provenance is established. Everything after that —
 * state read, evaluation, authorization verification, replay consumption,
 * intent/state hash binding, CAS, execution ordering — is the SAME enforcement
 * body, reached by delegating to `OxDeAIGuard` rather than by reimplementing
 * it. Two entry points that share one body cannot drift apart.
 *
 * ```text
 * authenticate                       (caller, before this function)
 * → resolve trusted context          (createTrustedExecutionContext)
 * → normalize proposal → reconcile   (here; conflicts fail closed)
 * → read state → evaluate → verify → CAS → execute   (shared body)
 * ```
 *
 * Trusted context is a separate positional argument and never a field on
 * {@link ProposedAction}: there is no place to put it in the request payload,
 * so "trusted context is not accepted from request JSON" holds structurally
 * rather than by convention.
 *
 * ⚠️ Only this path, or an integration independently enforcing the same
 * boundary, may claim Tier 1 evaluator-input provenance. `OxDeAIGuard` remains
 * available and unchanged, and carries no such guarantee.
 *
 * SCOPE — this entry point establishes trusted *evaluator inputs* only. It does
 * NOT make state or policy authoritative: `getState` / `setState` and the
 * engine's policy configuration are still supplied by the deployment. An
 * authoritative versioned StateProvider and PolicyProvider are separate work.
 *
 * ⚠️ AUDIT CONTRACT — where provenance appears:
 *
 * ```text
 * ALLOW / evaluated paths      → provenance on GuardDecisionRecord (onDecision)
 * pre-evaluation conflict      → provenance on GuardBoundaryAuditEvent
 *                                (onBoundaryEvent) and on the thrown
 *                                OxDeAIProvenanceConflictError, NOT on onDecision
 * ```
 *
 * A provenance conflict is rejected before the shared enforcement body reaches
 * a policy decision, so there is no decision record to attach it to. It is
 * deliberately NOT emitted through `onDecision` as a synthetic DENY: that hook
 * reports `PolicyEngine` decisions, and manufacturing one would misreport a
 * boundary rejection as a policy outcome. It is instead emitted once on the
 * disjoint guard-boundary stream — `config.onBoundaryEvent` — carrying the
 * conflicting fields and the full provenance map, so a deployment no longer has
 * to catch `OxDeAIProvenanceConflictError` itself to see attempted identity or
 * tool substitutions. A deployment that wires NEITHER hook still sees only the
 * thrown error.
 *
 * @public
 */
export function createSecureGuard(config: OxDeAIGuardConfig, options: SecureGuardOptions) {
  const tenancy = options?.tenancy;
  if (tenancy !== "single-tenant" && tenancy !== "multi-tenant") {
    throw new OxDeAIGuardConfigurationError(
      'Secure guard requires an explicit tenancy posture: "single-tenant" or "multi-tenant". ' +
        "It is not defaulted, because a multi-tenant deployment that has not wired tenant identity " +
        "would otherwise be indistinguishable from a legitimate single-tenant one."
    );
  }
  // ── F4-AUD-01: construction-time configuration capture ────────────────────
  //
  // The shared body is rebuilt per call (below) so that each call's provenance
  // capture is isolated. It used to be rebuilt from the deployer's LIVE config
  // object, so every option OxDeAIGuard resolves at construction (signer
  // authority, F4-C revocation, SignedKRLV1 revocation, …) was in fact re-read
  // per call: pushing a pair into the caller's signer array, reassigning
  // `config.revocation = undefined` or replacing `provider.check` after
  // construction widened authority or disabled enforcement.
  //
  // The caller's config is now read ONCE, here. Every option is read once,
  // by name, through ordinary property access (REV-R1/REV-R2: own, inherited,
  // non-enumerable, accessor and Proxy-provided values alike, exactly as
  // OxDeAIGuard reads them; a `{ ...config }` copy silently dropped all but own
  // enumerable ones, downgrading shared replay protection and disabling signer
  // and revocation enforcement). A read that throws is a configuration error,
  // never "not configured". Every security option OxDeAIGuard resolves at
  // construction is then resolved, with the same resolvers, into frozen data
  // or bound callables, and per-call shared bodies are built only from that
  // frozen template. What deliberately stays live is what OxDeAIGuard itself
  // treats as live: the retained `trustedKeySets` array and KeySet objects
  // (in-place rotation), and the internal state behind captured callables
  // (provider and store state, engine state). See secureConfig.ts and README
  // "Secure guard configuration".
  const raw: OxDeAIGuardConfig = captureSecureGuardConfig(config);

  const baseNormalize: (action: ProposedAction) => Intent =
    raw.mapActionToIntent ?? defaultNormalizeAction;

  // Resolve the replay store ONCE through the shared replay-protection contract
  // (P2-1). A per-call default store would give every call a fresh replay
  // namespace, silently disabling replay protection across calls.
  // Unsafe/ambiguous config fails closed at construction. `raw` holds exactly
  // the values read once above, so the posture validated here is the posture
  // enforced. A deployer-supplied store (`shared` or legacy) was captured by
  // secureConfig.ts BEFORE resolution, with its methods read once and bound to
  // it (RV-02, F4-AUD-01): the resolver validates that snapshot, the store's
  // identity and state stay live and shared, and replacing its methods later
  // is not observed. A `process-local` or implicit store is created by the
  // resolver itself and is reachable from nowhere else.
  const resolvedReplay = resolveReplayProtection(raw, { strict: strictFromConfig(raw.requireExplicitReplayProtection) });
  if (resolvedReplay.source === "explicit-shared" && isCapturedEphemeralReplayStore(resolvedReplay.store)) {
    // The resolver applies this rule by object identity, which it can no
    // longer see through the snapshot; same rule, same message.
    throw new OxDeAIGuardConfigurationError(
      "replayProtection mode 'shared' requires a durable backend, but the OxDeAI built-in in-memory " +
        "store is process-local. Provide an external shared store (e.g. Redis/DynamoDB) or use " +
        "replayProtection:{mode:'process-local'} if a single-process store is intended."
    );
  }
  const replayStore = resolvedReplay.store;

  // AUD-OBS-02: hand the per-call body exactly ONE replay source, the store
  // resolved above (the same object for `shared` and legacy `replayStore`; one
  // instance-lifetime in-memory store for `process-local`). Forwarding the
  // caller's `replayProtection` alongside it made every call fail with
  // "Ambiguous replay configuration". `replayProtection` is removed rather than
  // re-validated: it was validated once above, and re-resolving
  // `{mode:'process-local'}` per call would mint a fresh store each time.
  const { replayProtection: _validatedReplayPosture, ...rawWithoutReplayPosture } = raw;
  void _validatedReplayPosture;
  // `replayProtection: undefined` stays an OWN property (RV-01): every option
  // in the per-call config is own, so no option read can reach a prototype
  // polluted after construction.
  const unresolved: OxDeAIGuardConfig = { ...rawWithoutReplayPosture, replayProtection: undefined, replayStore };

  // Validate the whole configuration NOW (F4-AUD-01: invalid configuration
  // fails at construction, as it does for OxDeAIGuard), with OxDeAIGuard's own
  // validation and error messages. The instance is discarded.
  OxDeAIGuard(unresolved);

  // Capture each construction-resolved security option as frozen data.
  const normalizedKeySets: readonly KeySet[] = Array.isArray(raw.trustedKeySets)
    ? raw.trustedKeySets
    : [raw.trustedKeySets as KeySet];
  const signedKrl = resolveRevocationConfig(raw.revocation, normalizedKeySets);
  const delegationRevocation = resolveDelegationRevocation(raw);
  const template: OxDeAIGuardConfig = Object.freeze({
    ...unresolved,
    // Frozen copy of validated (delegator, issuer) pairs.
    trustedDelegationSigners: resolveDelegationSigners(raw.trustedDelegationSigners),
    // Read per request by OxDeAIGuard. Already a frozen copy (secureConfig.ts),
    // so a later mutation of the caller's list can neither add nor remove a
    // parent authority for this instance. `undefined` (not configured) and
    // `[]` (authorizes nothing) stay distinct.
    trustedDelegationAuthorities: raw.trustedDelegationAuthorities,
    // `check` bound to the original provider object at construction: replacing
    // `provider.check` later is not observed, while the provider's own
    // revocation state (whatever `check` consults) is.
    delegationRevocationProvider: delegationRevocation.provider,
    requireDelegationRevocation: delegationRevocation.required,
    // Already validated and frozen: KRL trust copied, scopes copied, the KRL
    // provider function and the watermark store's bound `accept` captured.
    revocation: signedKrl as unknown as OxDeAIGuardConfig["revocation"],
  });
  OxDeAIGuard(template); // the captured form must itself be valid.
  // IR-01: resolution and validation above can still run deployer code (e.g.
  // getters on the live `trustedKeySets` entries). Refuse to return a guard if
  // an intrinsic prototype was polluted at any point during construction.
  assertIntrinsicsUnpolluted();

  /**
   * The secure prelude plus delegation to the shared body. Extracted so that
   * every rejection raised before the shared body is reached leaves through the
   * one catch in `secureGuard` below.
   */
  async function runSecure(
    trustedContext: TrustedExecutionContext,
    action: ProposedAction,
    execute: () => Promise<unknown>,
    opts: GuardCallOptions | undefined,
    lifecycle: GuardLifecycle
  ): Promise<unknown> {
    if (!isTrustedExecutionContext(trustedContext)) {
      throw reject(
        "TRUSTED_CONTEXT",
        "UNTRUSTED_CONTEXT",
        new OxDeAIAuthorizationError(
          "Secure guard requires a TrustedExecutionContext built by createTrustedExecutionContext(). " +
            "A plain object — including one deserialized from request JSON — is not accepted. Execution blocked."
        )
      );
    }

    // Deployment-level tenancy posture, enforced before evaluation, authorization
    // issuance, state mutation or execution. A multi-tenant deployment whose
    // route did not resolve a tenant fails closed rather than evaluating in an
    // ambiguous namespace; treating the absence as "probably single tenant" is
    // exactly the migration hazard this posture exists to remove.
    if (tenancy === "multi-tenant" && trustedContext.tenantId === undefined) {
      throw reject(
        "TRUSTED_CONTEXT",
        "MISSING_TENANT_ID",
        new OxDeAIAuthorizationError(
          "Deployment is configured multi-tenant but the trusted execution context carries no tenantId. " +
            "Execution blocked."
        )
      );
    }

    let provenance: ProvenanceRecord | undefined;

    // Per-call fields only. Everything else comes from the frozen construction
    // template, never from the caller's config object.
    const secureConfig: OxDeAIGuardConfig = {
      ...template,
      // Reconciliation runs on the OUTPUT of the deployment's normalizer, so a
      // custom mapActionToIntent cannot overwrite a trusted premise.
      mapActionToIntent: (a: ProposedAction): Intent => {
        // `defaultNormalizeAction` requires `context.agent_id` and throws before
        // reconciliation could fill it, so an absent proposer identity would
        // never reach the "absent claim → derived premise" rule. Supply the
        // derived identity for normalization ONLY when the proposer omitted it,
        // and reconcile against the ORIGINAL proposer claims so the fill is
        // audited as `absent` rather than as a claim the proposer made.
        const claimedAgentId = a.context?.["agent_id"];
        const synthesizedFields = new Set<string>();
        let forNormalization = a;
        if (claimedAgentId === undefined || claimedAgentId === null) {
          synthesizedFields.add("agent_id");
          forNormalization = {
            ...a,
            context: { ...a.context, agent_id: trustedContext.agentId },
          };
        }

        const proposed = baseNormalize(forNormalization);
        const reconciled = reconcileWithTrustedContext(proposed, trustedContext, a.context, {
          synthesized: synthesizedFields,
        });
        provenance = reconciled.provenance;
        return reconciled.intent;
      },
      onDecision: template.onDecision
        ? (record) => template.onDecision!({ ...record, ...(provenance ? { provenance } : {}) })
        : undefined,
    };

    // Factory-time configuration errors are still this layer's to report; from
    // the invocation onward the shared body runs its own catch, so anything it
    // raises is already accounted for and must not be reported twice.
    const sharedBody = OxDeAIGuard(secureConfig);
    lifecycle.sharedBodyEntered = true;
    return await sharedBody(action, execute, opts);
  }

  return async function secureGuard(
    trustedContext: TrustedExecutionContext,
    action: ProposedAction,
    execute: () => Promise<unknown>,
    opts?: GuardCallOptions
  ): Promise<unknown> {
    const outerLifecycle = createLifecycle("TRUSTED_CONTEXT");
    try {
      return await runSecure(trustedContext, action, execute, opts, outerLifecycle);
    } catch (err) {
      // Identical and unconditional to the shared body's catch: the rules for
      // what is emitted live only in emitBoundaryEvent, and the ORIGINAL error
      // is re-thrown regardless of what the audit sink does.
      await emitBoundaryEvent(template.onBoundaryEvent, err, outerLifecycle);
      throw err;
    }
  };
}
