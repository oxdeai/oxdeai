// SPDX-License-Identifier: Apache-2.0
import type { Intent } from "@oxdeai/core";
import { OxDeAIGuard } from "./guard.js";
import { defaultNormalizeAction } from "./normalizeAction.js";
import { resolveReplayProtection } from "./replayProtection.js";
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
  const baseNormalize: (action: ProposedAction) => Intent =
    config.mapActionToIntent ?? defaultNormalizeAction;

  // Resolve the replay store ONCE through the shared replay-protection contract
  // (P2-1). The guard closure is rebuilt per call so that each call's provenance
  // capture is isolated, and a per-call default store would otherwise give every
  // call a fresh replay namespace — silently disabling replay protection across
  // calls. Unsafe/ambiguous config fails closed at construction.
  const replayStore = resolveReplayProtection(config).store;

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

    const secureConfig: OxDeAIGuardConfig = {
      ...config,
      replayStore,
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
      onDecision: config.onDecision
        ? (record) => config.onDecision!({ ...record, ...(provenance ? { provenance } : {}) })
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
      await emitBoundaryEvent(config.onBoundaryEvent, err, outerLifecycle);
      throw err;
    }
  };
}
