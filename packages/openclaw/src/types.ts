// SPDX-License-Identifier: Apache-2.0
import type { PolicyEngine } from "@oxdeai/core";
import type { OxDeAIGuardConfig, ProposedAction } from "@oxdeai/guard";

/**
 * An OpenClaw action/skill call.
 *
 * Structurally compatible with the action shape produced by the OpenClaw
 * runtime (workflow planner → action dispatcher). No import from the OpenClaw
 * library is required.
 *
 * OpenClaw-specific fields:
 *   - `workflow_id`  identifies the parent workflow (carried as context)
 *   - `step_id`      identifies this step within the workflow - used as `intent_id`
 */
export type OpenClawAction = {
  /** Skill or tool name dispatched by the OpenClaw action dispatcher. */
  name: string;
  /** Action arguments - parsed key/value pairs from the workflow step. */
  args: Record<string, unknown>;
  /** Step identifier within the workflow - used as `intent_id` when present. */
  step_id?: string;
  /** Parent workflow identifier - carried in `context.workflow_id` when present. */
  workflow_id?: string;
  /** Estimated monetary cost in whole units (e.g. USD). Passed to the default normalizer as `estimatedCost`. */
  estimatedCost?: number;
  /** Resource type hint (e.g. `"gpu"`, `"payment"`). Used to infer `action_type` by the default normalizer. */
  resourceType?: string;
  /** Unix timestamp in seconds. Defaults to `Date.now() / 1000` when absent. */
  timestampSeconds?: number;
};

/**
 * Configuration for `createOpenClawGuard`.
 *
 * Extends `OxDeAIGuardConfig` with a required `agentId` field.
 * OpenClaw action calls do not carry agent identity - the adapter injects it
 * from this config into every `ProposedAction` it builds.
 */
export type OpenClawGuardConfig = {
  /** The PolicyEngine instance that evaluates intent policy. */
  engine: PolicyEngine;
  /** Load current state with its version token. The version is passed back to setState for CAS. May be async. */
  getState: OxDeAIGuardConfig["getState"];
  /** Persist next state using compare-and-set. Return true on success, false on version mismatch. May be async. */
  setState: OxDeAIGuardConfig["setState"];

  /**
   * Identity of the acting agent. Injected as `context.agent_id` on every
   * `ProposedAction` derived from an action call.
   */
  agentId: string;

  /**
   * Optional custom mapping from a `ProposedAction` (built from the action call)
   * to an OxDeAI `Intent`. When omitted, the guard's default normalizer is used.
   *
   * The `ProposedAction` passed here always has:
   *   - `name`    from `action.name`
   *   - `args`    from `action.args`
   *   - `context.agent_id`    from `config.agentId`
   *   - `context.intent_id`   from `action.step_id` (when present)
   *   - `context.workflow_id` from `action.workflow_id` (when present)
   *   - `estimatedCost`       from `action.estimatedCost`
   *   - `resourceType`        from `action.resourceType`
   *   - `timestampSeconds`    from `action.timestampSeconds` (or now)
   */
  mapActionToIntent?: OxDeAIGuardConfig["mapActionToIntent"];

  /** Called after authorization succeeds but before the execute callback. */
  beforeExecute?: OxDeAIGuardConfig["beforeExecute"];

  /**
   * Audit hook fired after every decision (ALLOW and DENY).
   * Errors thrown here are swallowed.
   */
  onDecision?: OxDeAIGuardConfig["onDecision"];

  /**
   * Audit hook for guard-boundary rejections raised before `execute()` starts —
   * provenance conflicts, replay rejections, hash-binding failures, CAS conflicts.
   *
   * Disjoint from {@link onDecision}: a boundary rejection produces no decision
   * record, so a deployment wiring only `onDecision` cannot observe one.
   */
  onBoundaryEvent?: OxDeAIGuardConfig["onBoundaryEvent"];

  /** Trusted keysets required for strict authorization verification. */
  trustedKeySets?: OxDeAIGuardConfig["trustedKeySets"];

  /**
   * Replay store used for durable `auth_id` / `delegation_id` tracking.
   *
   * When omitted the guard creates a per-instance in-memory store, which is
   * single-process only. Multi-process or restart-durable deployments must
   * supply a shared backend such as `createRedisReplayStore` from `@oxdeai/guard`.
   */
  replayStore?: OxDeAIGuardConfig["replayStore"];

  /**
   * Custom live-state hash strategy used for `state_hash` binding verification.
   *
   * Required when authorizations are issued by an external provider whose state
   * canonicalization differs from the core PolicyEngine's.
   */
  computeStateHash?: OxDeAIGuardConfig["computeStateHash"];
};

/**
 * The guard function returned by `createOpenClawGuard`.
 * Call it with an OpenClaw action and the execute callback.
 *
 * `execute` receives the verified action (ACT-1): the deep-frozen
 * `ProposedAction` snapshot that the guard evaluated and bound to the
 * authorization, with `args` taken from `action.args`. The same object is passed
 * to `beforeExecute` and `onDecision`. The protected tool must read its name and
 * arguments from this argument.
 *
 * A callback that ignores the argument and reads the original input instead
 * (for example `() => executeAction(action)`) still type-checks and runs, for
 * backward compatibility, but it is NOT covered by this binding: the input is
 * caller-owned and can change while authorization is awaited.
 */
export type OpenClawGuardFn = <T>(
  action: OpenClawAction,
  execute: (verified: ProposedAction) => Promise<T>
) => Promise<T>;
