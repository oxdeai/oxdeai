// SPDX-License-Identifier: Apache-2.0
import { OxDeAIGuard } from "@oxdeai/guard";
import type { ProposedAction } from "@oxdeai/guard";
import type { AutoGenToolCall, AutoGenGuardConfig, AutoGenGuardFn } from "./types.js";

/**
 * Convert an AutoGen function/tool call into an OxDeAI `ProposedAction`.
 *
 * - `name`               ← toolCall.name
 * - `args`               ← toolCall.args
 * - `context.agent_id`  ← config.agentId  (injected — function calls carry no agent identity)
 * - `context.intent_id` ← toolCall.id     (when present)
 * - `estimatedCost`      ← toolCall.estimatedCost
 * - `resourceType`       ← toolCall.resourceType
 * - `timestampSeconds`   ← toolCall.timestampSeconds ?? now
 */
function toProposedAction(toolCall: AutoGenToolCall, agentId: string): ProposedAction {
  const name = toolCall.name;
  const args = toolCall.args;
  const estimatedCost = toolCall.estimatedCost;
  const resourceType = toolCall.resourceType;
  const timestampSeconds = toolCall.timestampSeconds ?? Math.floor(Date.now() / 1000);
  const identifier = toolCall.id;
  return {
    name,
    args,
    estimatedCost,
    resourceType,
    timestampSeconds,
    context: {
      agent_id: agentId,
      ...(identifier !== undefined ? { intent_id: identifier } : {}),
    },
  };
}

/**
 * createAutoGenGuard — thin AutoGen binding for `@oxdeai/guard`.
 *
 * Returns a guard function that accepts an AutoGen function/tool call and an
 * execute callback. All authorization logic is delegated to `@oxdeai/guard` —
 * this adapter only handles the AutoGen ToolCall → ProposedAction translation.
 *
 * @example
 * ```ts
 * import { createAutoGenGuard } from "@oxdeai/autogen";
 *
 * const guard = createAutoGenGuard({ engine, getState, setState, agentId: "my-agent" });
 *
 * // The tool receives the verified, frozen action. Read the tool name and
 * // arguments from it, not from `toolCall` (ACT-1).
 * const result = await guard(toolCall, (verified) => executeTool(verified.name, verified.args));
 * ```
 */
export function createAutoGenGuard(config: AutoGenGuardConfig): AutoGenGuardFn {
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

  return async function autoGenGuard<T>(
    toolCall: AutoGenToolCall,
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
