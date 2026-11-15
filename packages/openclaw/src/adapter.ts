// SPDX-License-Identifier: Apache-2.0
import { OxDeAIGuard } from "@oxdeai/guard";
import type { ProposedAction } from "@oxdeai/guard";
import type { OpenClawAction, OpenClawGuardConfig, OpenClawGuardFn } from "./types.js";

/**
 * Convert an OpenClaw action into an OxDeAI `ProposedAction`.
 *
 * - `name`                    ← action.name
 * - `args`                    ← action.args
 * - `context.agent_id`       ← config.agentId   (injected - action calls carry no agent identity)
 * - `context.intent_id`      ← action.step_id   (when present; step_id is the per-action identifier)
 * - `context.workflow_id`    ← action.workflow_id (when present; passed as extra context)
 * - `estimatedCost`           ← action.estimatedCost
 * - `resourceType`            ← action.resourceType
 * - `timestampSeconds`        ← action.timestampSeconds ?? now
 */
function toProposedAction(action: OpenClawAction, agentId: string): ProposedAction {
  return {
    name: action.name,
    args: action.args,
    estimatedCost: action.estimatedCost,
    resourceType: action.resourceType,
    timestampSeconds: action.timestampSeconds ?? Math.floor(Date.now() / 1000),
    context: {
      agent_id: agentId,
      ...(action.step_id !== undefined ? { intent_id: action.step_id } : {}),
      ...(action.workflow_id !== undefined ? { workflow_id: action.workflow_id } : {}),
    },
  };
}

/**
 * createOpenClawGuard - thin OpenClaw binding for `@oxdeai/guard`.
 *
 * Returns a guard function that accepts an OpenClaw action and an execute
 * callback. All authorization logic is delegated to `@oxdeai/guard` - this
 * adapter only handles the OpenClaw Action → ProposedAction translation.
 *
 * @example
 * ```ts
 * import { createOpenClawGuard } from "@oxdeai/openclaw";
 *
 * const guard = createOpenClawGuard({ engine, getState, setState, agentId: "my-agent" });
 *
 * // The tool receives the verified, frozen action. Read the tool name and
 * // arguments from it, not from `action` (ACT-1).
 * const result = await guard(action, (verified) => executeAction(verified.name, verified.args));
 * ```
 */
export function createOpenClawGuard(config: OpenClawGuardConfig): OpenClawGuardFn {
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

  return async function openClawGuard<T>(
    action: OpenClawAction,
    execute: (verified: ProposedAction) => Promise<T>
  ): Promise<T> {
    const proposed = toProposedAction(action, config.agentId);
    // ACT-1: the fields of `action` are read once, above. The guard takes a
    // deep-frozen snapshot of this action, verifies that snapshot and passes the
    // same object to `execute`. Executors that read `action` instead are not
    // covered: it is caller-owned and can change while authorization is awaited.
    return guard(proposed, execute) as Promise<T>;
  };
}
