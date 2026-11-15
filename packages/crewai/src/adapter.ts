// SPDX-License-Identifier: Apache-2.0
import { OxDeAIGuard } from "@oxdeai/guard";
import type { ProposedAction } from "@oxdeai/guard";
import type { CrewAIToolCall, CrewAIGuardConfig, CrewAIGuardFn } from "./types.js";

/**
 * Convert a CrewAI tool call into an OxDeAI `ProposedAction`.
 *
 * - `name`               ← toolCall.name
 * - `args`               ← toolCall.args
 * - `context.agent_id`  ← config.agentId  (injected — tool calls carry no agent identity)
 * - `context.intent_id` ← toolCall.id     (when present)
 * - `estimatedCost`      ← toolCall.estimatedCost
 * - `resourceType`       ← toolCall.resourceType
 * - `timestampSeconds`   ← toolCall.timestampSeconds ?? now
 */
function toProposedAction(toolCall: CrewAIToolCall, agentId: string): ProposedAction {
  return {
    name: toolCall.name,
    args: toolCall.args,
    estimatedCost: toolCall.estimatedCost,
    resourceType: toolCall.resourceType,
    timestampSeconds: toolCall.timestampSeconds ?? Math.floor(Date.now() / 1000),
    context: {
      agent_id: agentId,
      ...(toolCall.id !== undefined ? { intent_id: toolCall.id } : {}),
    },
  };
}

/**
 * createCrewAIGuard — thin CrewAI binding for `@oxdeai/guard`.
 *
 * Returns a guard function that accepts a CrewAI tool call and an execute
 * callback. All authorization logic is delegated to `@oxdeai/guard` — this
 * adapter only handles the CrewAI ToolCall → ProposedAction translation.
 *
 * @example
 * ```ts
 * import { createCrewAIGuard } from "@oxdeai/crewai";
 *
 * const guard = createCrewAIGuard({ engine, getState, setState, agentId: "my-agent" });
 *
 * // The tool receives the verified, frozen action. Read the tool name and
 * // arguments from it, not from `toolCall` (ACT-1).
 * const result = await guard(toolCall, (verified) => executeTool(verified.name, verified.args));
 * ```
 */
export function createCrewAIGuard(config: CrewAIGuardConfig): CrewAIGuardFn {
  const guard = OxDeAIGuard({
    engine: config.engine,
    getState: config.getState,
    setState: config.setState,
    mapActionToIntent: config.mapActionToIntent,
    beforeExecute: config.beforeExecute,
    onDecision: config.onDecision,
    onBoundaryEvent: config.onBoundaryEvent,
    expectedAudience: config.agentId,
    trustedKeySets: config.trustedKeySets,
    replayStore: config.replayStore,
    computeStateHash: config.computeStateHash,
  });

  return async function crewAIGuard<T>(
    toolCall: CrewAIToolCall,
    execute: (verified: ProposedAction) => Promise<T>
  ): Promise<T> {
    const action = toProposedAction(toolCall, config.agentId);
    // ACT-1: the fields of `toolCall` are read once, above. The guard takes a
    // deep-frozen snapshot of this action, verifies that snapshot and passes the
    // same object to `execute`. Executors that read `toolCall` instead are not
    // covered: it is caller-owned and can change while authorization is awaited.
    return guard(action, execute) as Promise<T>;
  };
}
