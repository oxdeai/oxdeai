// SPDX-License-Identifier: Apache-2.0
/**
 * replayProtection.ts - P2-1 transitional replay-protection contract.
 *
 * A single resolver, shared by all three guard entry points (guard.ts,
 * secureGuard.ts, gateway.ts), turns the deployer's declared replay posture
 * into a concrete ReplayStore and makes an unsafe configuration non-silent.
 *
 * TRANSITIONAL release: when nothing is declared, the historical process-local
 * in-memory default is preserved and a one-time migration warning is emitted.
 * This does NOT fully close P2-1; a separately approved strict release will
 * reject an undeclared posture. OxDeAI enforces the CONFIGURATION contract
 * below; it never verifies that a caller-provided `shared` store is actually
 * atomic, shared across instances, or restart-durable - that remains an
 * external operational obligation.
 */
import { createInMemoryReplayStore, isEphemeralReplayStore } from "./replayStore.js";
import type { ReplayStore } from "./replayStore.js";
import { OxDeAIGuardConfigurationError } from "./errors.js";

/**
 * Declared replay-protection posture.
 *
 * - `process-local`: an explicit, documented in-memory store scoped to one
 *   process lifetime. Correct for single-process and development; NOT safe for
 *   multi-instance or restart-durable deployments.
 * - `shared`: a caller-provided backend declared to span the deployment's
 *   replay domain. OxDeAI uses the store as given; it cannot verify the store's
 *   durability, atomicity, or sharing - that is the deployment's obligation.
 *
 * @public
 */
export type ReplayProtection =
  | { readonly mode: "process-local" }
  | { readonly mode: "shared"; readonly store: ReplayStore };

/** How the active store was resolved (for deterministic testing + warning). */
export type ReplayResolutionSource =
  | "explicit-shared"
  | "explicit-process-local"
  | "legacy-replay-store"
  | "implicit-default";

export type ReplayResolution = {
  readonly store: ReplayStore;
  readonly source: ReplayResolutionSource;
};

/** The migration warning text. Contains no credentials, ids, or payloads. */
export const REPLAY_MIGRATION_WARNING =
  "[oxdeai] No replayProtection configured; using a process-local in-memory replay store. " +
  "This is unsafe for multi-instance or restart-durable deployments (a consumed authorization " +
  "can be accepted again on another instance or after a restart). Declare an explicit posture: " +
  "replayProtection:{mode:'process-local'} to acknowledge the local default, or " +
  "replayProtection:{mode:'shared',store} with a durable backend. A future release will require this.";

let warned = false;
/** Reset the one-time warning latch. Test-only; not part of the public API. */
export function __resetReplayMigrationWarningForTests(): void {
  warned = false;
}

/**
 * Resolve the replay store from a config that may carry the new
 * `replayProtection` contract and/or the deprecated `replayStore`.
 *
 * Enforced (configuration):
 *  - both fields set            -> OxDeAIGuardConfigurationError (ambiguous)
 *  - {mode:'shared'} w/o store  -> OxDeAIGuardConfigurationError (also a TS error)
 *  - {mode:'shared'} w/ builtin -> OxDeAIGuardConfigurationError (process-local in shared mode)
 *  - {mode:'shared', store}     -> use the store (a declaration; durability not verified)
 *  - {mode:'process-local'}     -> fresh in-memory store, no warning
 *  - legacy replayStore alone   -> use it (back-compat), no warning
 *  - neither                    -> in-memory store + one-time migration warning (transitional)
 *
 * `warn` defaults to a one-time `console.warn`; injectable for tests.
 */
export function resolveReplayProtection(
  config: { replayProtection?: ReplayProtection; replayStore?: ReplayStore },
  warn: (message: string) => void = defaultWarnOnce
): ReplayResolution {
  // Transitional compatibility: an explicitly undefined optional field is treated as absent.
  // This preserves JS/TS callers that forward optional properties; it is not an explicit posture.
  const hasNew = config.replayProtection !== undefined;
  const hasLegacy = config.replayStore !== undefined;

  if (hasNew && hasLegacy) {
    throw new OxDeAIGuardConfigurationError(
      "Ambiguous replay configuration: set either replayProtection or the deprecated replayStore, not both."
    );
  }

  if (hasNew) {
    // B1-1: validate the shape at runtime. The TypeScript type is advisory;
    // a JS caller or a deserialized config can carry any value. Everything
    // here fails closed with the deterministic guard configuration error.
    const rpRaw = config.replayProtection as unknown;
    if (rpRaw === null || typeof rpRaw !== "object" || Array.isArray(rpRaw)) {
      throw new OxDeAIGuardConfigurationError(
        "replayProtection must be an object: {mode:'process-local'} or {mode:'shared', store}."
      );
    }
    const rp = rpRaw as { mode?: unknown; store?: unknown };
    // B1-1: explicit allowlist. An unknown mode is NEVER interpreted as 'shared'.
    if (rp.mode !== "process-local" && rp.mode !== "shared") {
      throw new OxDeAIGuardConfigurationError(
        "replayProtection.mode must be exactly 'process-local' or 'shared' (got " +
          describe(rp.mode) + ")."
      );
    }

    if (rp.mode === "process-local") {
      // B1-2: a store alongside process-local contradicts the declared intent.
      if ("store" in rp) {
        throw new OxDeAIGuardConfigurationError(
          "replayProtection mode 'process-local' must not carry a store; use {mode:'shared', store} " +
            "to supply a backend, or drop the store property."
        );
      }
      return { store: createInMemoryReplayStore(), source: "explicit-process-local" };
    }

    // mode === "shared" (B1-3): require a structurally valid store.
    const store = rp.store;
    if (store === undefined || store === null) {
      throw new OxDeAIGuardConfigurationError(
        "replayProtection mode 'shared' requires a store (a durable, cross-instance replay backend)."
      );
    }
    if (typeof store !== "object" || typeof (store as ReplayStore).consumeAuthId !== "function") {
      throw new OxDeAIGuardConfigurationError(
        "replayProtection mode 'shared' requires a store implementing an async consumeAuthId(id, {expiry}) method."
      );
    }
    // Optional method, when present, must be callable (ReplayStore contract).
    const delFn = (store as { consumeDelegationId?: unknown }).consumeDelegationId;
    if (delFn !== undefined && typeof delFn !== "function") {
      throw new OxDeAIGuardConfigurationError(
        "replayProtection store exposes a consumeDelegationId that is not callable."
      );
    }
    // Structural validation only: this does NOT prove durability, atomicity, or
    // cross-instance sharing - those remain an external deployment obligation.
    if (isEphemeralReplayStore(store as ReplayStore)) {
      throw new OxDeAIGuardConfigurationError(
        "replayProtection mode 'shared' requires a durable backend, but the OxDeAI built-in in-memory " +
          "store is process-local. Provide an external shared store (e.g. Redis/DynamoDB) or use " +
          "replayProtection:{mode:'process-local'} if a single-process store is intended."
      );
    }
    return { store: store as ReplayStore, source: "explicit-shared" };
  }

  if (hasLegacy) {
    // Back-compat: the deployer deliberately provided a store. Honor it as-is.
    return { store: config.replayStore as ReplayStore, source: "legacy-replay-store" };
  }

  // Neither declared: transitional process-local default with a one-time warning.
  warn(REPLAY_MIGRATION_WARNING);
  return { store: createInMemoryReplayStore(), source: "implicit-default" };
}

/** A short, safe description of an invalid `mode` value for error messages. */
function describe(value: unknown): string {
  if (value === undefined) return "missing";
  if (value === null) return "null";
  if (typeof value === "string") return `string ${JSON.stringify(value)}`;
  if (Array.isArray(value)) return "array";
  return typeof value;
}

function defaultWarnOnce(message: string): void {
  if (warned) return;
  warned = true;
  // eslint-disable-next-line no-console
  console.warn(message);
}
