// SPDX-License-Identifier: Apache-2.0
import type { PolicyEngine } from "@oxdeai/core";
import type { OxDeAIGuardConfig, ProposedAction } from "@oxdeai/guard";

/**
 * A CrewAI-style tool/action call.
 *
 * Structurally compatible with the tool call shape produced by CrewAI agents.
 * No import from the CrewAI library is required — attach OxDeAI fields
 * (`estimatedCost`, `resourceType`, `timestampSeconds`) when constructing
 * calls in your agent executor.
 */
export type CrewAIToolCall = {
  /** Tool name — matches the tool's registered name in the CrewAI crew. */
  name: string;
  /** Tool arguments — parsed key/value pairs passed to the tool. */
  args: Record<string, unknown>;
  /** Optional task or call identifier — used as `intent_id` when present. */
  id?: string;
  /** Estimated monetary cost in whole units (e.g. USD). Passed to the default normalizer as `estimatedCost`. */
  estimatedCost?: number;
  /** Resource type hint (e.g. `"gpu"`, `"payment"`). Used to infer `action_type` by the default normalizer. */
  resourceType?: string;
  /** Unix timestamp in seconds. Defaults to `Date.now() / 1000` when absent. */
  timestampSeconds?: number;
};

/**
 * Configuration for `createCrewAIGuard`.
 *
 * Extends `OxDeAIGuardConfig` with a required `agentId` field.
 * CrewAI tool calls do not carry agent identity — the adapter injects it
 * from this config into every `ProposedAction` it builds.
 */
export type CrewAIGuardConfig = {
  /** The PolicyEngine instance that evaluates intent policy. */
  engine: PolicyEngine;
  /** Load current state with its version token. The version is passed back to setState for CAS. May be async. */
  getState: OxDeAIGuardConfig["getState"];
  /** Persist next state using compare-and-set. Return true on success, false on version mismatch. May be async. */
  setState: OxDeAIGuardConfig["setState"];

  /**
   * Identity of the acting agent. Injected as `context.agent_id` on every
   * `ProposedAction` derived from a tool call.
   */
  agentId: string;

  /**
   * Optional custom mapping from a `ProposedAction` (built from the tool call)
   * to an OxDeAI `Intent`. When omitted, the guard's default normalizer is used.
   *
   * The `ProposedAction` passed here always has:
   *   - `name`    from `toolCall.name`
   *   - `args`    from `toolCall.args`
   *   - `context.agent_id`   from `config.agentId`
   *   - `context.intent_id`  from `toolCall.id` (when present)
   *   - `estimatedCost`      from `toolCall.estimatedCost`
   *   - `resourceType`       from `toolCall.resourceType`
   *   - `timestampSeconds`   from `toolCall.timestampSeconds` (or now)
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
 * The guard function returned by `createCrewAIGuard`.
 * Call it with a CrewAI tool call and the execute callback.
 *
 * `execute` receives the verified action (ACT-1): the deep-frozen
 * `ProposedAction` snapshot that the guard evaluated and bound to the
 * authorization, with `args` taken from `toolCall.args`. The same object is passed
 * to `beforeExecute` and `onDecision`. The protected tool must read its name and
 * arguments from this argument.
 *
 * A callback that ignores the argument and reads the original input instead
 * (for example `() => executeTool(toolCall)`) still type-checks and runs, for
 * backward compatibility, but it is NOT covered by this binding: the input is
 * caller-owned and can change while authorization is awaited.
 */
export type CrewAIGuardFn = <T>(
  toolCall: CrewAIToolCall,
  execute: (verified: ProposedAction) => Promise<T>
) => Promise<T>;
