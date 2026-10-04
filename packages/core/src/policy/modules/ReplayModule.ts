// SPDX-License-Identifier: Apache-2.0
import type { Intent } from "../../types/intent.js";
import type { State } from "../../types/state.js";
import type { PolicyEvaluationContext, PolicyResult, ReasonCode } from "../../types/policy.js";
import { statelessModuleCodec } from "./_codec.js";

/**
 * Internal evaluation context for the replay module. The engine adds the
 * trusted-time freshness horizon so retention can never be shorter than the
 * interval during which the same intent remains admissible. Not part of the
 * public `PolicyEvaluationContext` type in the 2.0.x line.
 *
 * @internal
 */
export type ReplayEvaluationContext = PolicyEvaluationContext & {
  freshnessHorizonSeconds?: number;
};

/**
 * Reason emitted when live replay entries exhaust `max_nonces_per_agent`.
 * The 2.0.x line reuses an existing code so the public `ReasonCode` union is
 * unchanged in a patch release.
 *
 * @internal
 */
export const REPLAY_CAPACITY_EXHAUSTED_REASON: ReasonCode = "VELOCITY_EXCEEDED";

function nonceKey(intent: Intent): string {
  // keep consistent formatting across versions
  return intent.nonce.toString();
}

/**
 * Replay-window eviction is driven exclusively by the trusted evaluation
 * clock (`context.evaluationTime`), never by `intent.timestamp`,
 * `issued_at`, `expiry`, or an ambient `Date.now()`.
 *
 * `intent.timestamp` is attacker-controlled, and sourcing the window from it
 * is a replay bypass. Entries are retained while `entry.ts >= windowStart`,
 * so POSTdating an intent pushes `windowStart` forward, prunes the caller's
 * own previously recorded nonce, and lets the replay through. (Backdating
 * moves `windowStart` earlier and therefore retains more; it is not an
 * eviction bypass, though it does inflate replay-state pressure.)
 *
 * Persisted-state compatibility (no migration, self-healing):
 *  - legacy replay entries may have been stamped from `intent.timestamp`;
 *  - they are interpreted as existing persisted timestamps, without conversion;
 *  - all new entries are stamped from `evaluationTime`;
 *  - pruning is driven exclusively by `evaluationTime`;
 *  - no persisted-state schema migration or version bump is required;
 *  - legacy entries self-heal as they expire under the trusted evaluation
 *    clock. The transition completes within one replay retention window plus
 *    the maximum positive legacy timestamp skew permitted by the freshness
 *    policy — a legacy entry may have been stamped from an `intent.timestamp`
 *    running ahead of trusted time by up to the configured future-skew
 *    tolerance, so it survives that much longer than the window alone.
 *
 * This is safe because the trusted-time freshness gate in
 * `PolicyEngine.evaluatePure` already bounds how far `intent.timestamp` may
 * deviate from `evaluationTime`, which is what makes that overhang finite.
 *
 * @public
 */
export function ReplayModule(
  intent: Intent,
  state: State,
  context: ReplayEvaluationContext,
): PolicyResult {
  const agent = intent.agent_id;

  const cfg = state.replay;
  if (!cfg || typeof cfg.window_seconds !== "number" || typeof cfg.max_nonces_per_agent !== "number") {
    return { decision: "DENY", reasons: ["STATE_INVALID"] };
  }
  // Fail closed on configurations that would silently disable replay
  // protection: a NaN or negative window prunes every entry, and a capacity
  // below 1 (or NaN) retains nothing.
  if (Number.isNaN(cfg.window_seconds) || cfg.window_seconds < 0) {
    return { decision: "DENY", reasons: ["STATE_INVALID"] };
  }
  if (Number.isNaN(cfg.max_nonces_per_agent) || cfg.max_nonces_per_agent < 1) {
    return { decision: "DENY", reasons: ["STATE_INVALID"] };
  }

  const now = context.evaluationTime;
  // A nonce must stay retained for as long as the same intent can still pass
  // the trusted-time freshness gate. The engine supplies that horizon
  // (maxIntentAgeSeconds + maxClockSkewSeconds); a configured window shorter
  // than it is widened, never trusted as-is.
  const horizon = context.freshnessHorizonSeconds;
  const retention = horizon === undefined ? cfg.window_seconds : Math.max(cfg.window_seconds, horizon);
  const windowStart = now - retention;

  const list = state.replay.nonces[agent] ?? [];

  // prune deterministically: only entries outside the retention interval
  const pruned = list.filter((x) => x.ts >= windowStart);

  const n = nonceKey(intent);
  if (pruned.some((x) => x.nonce === n)) {
    return { decision: "DENY", reasons: ["REPLAY_NONCE"] };
  }

  // Never evict a still-retained nonce to make room. When capacity is
  // exhausted by live entries, fail closed; the DENY carries no state delta,
  // so every retained entry stays protected.
  if (pruned.length >= cfg.max_nonces_per_agent) {
    return { decision: "DENY", reasons: [REPLAY_CAPACITY_EXHAUSTED_REASON] };
  }

  const next = [...pruned, { nonce: n, ts: now }];

  return {
    decision: "ALLOW",
    reasons: [],
    stateDelta: {
      replay: {
        ...state.replay,
        nonces: {
          ...state.replay.nonces,
          [agent]: next
        }
      }
    }
  };
}

/** @public */
export const ReplayModuleCodec = statelessModuleCodec("ReplayModule");
