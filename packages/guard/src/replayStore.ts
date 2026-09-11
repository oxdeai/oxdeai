// SPDX-License-Identifier: Apache-2.0

/**
 * ReplayStore — pluggable replay-prevention backend for the OxDeAI guard.
 *
 * The guard authenticates/verifies before calling consumeAuthId (and optionally
 * consumeDelegationId), and consumes before protected execution. Implementations
 * MUST be fail-closed: if the store is
 * unavailable, throw rather than returning a permissive result. Any thrown
 * error is caught by the guard and re-raised as OxDeAIAuthorizationError,
 * blocking execution.
 *
 * Normative store contract (verification-v1 §4.3):
 *   At most one concurrent consume may succeed for an identifier in its declared
 *   replay domain. Consumed IDs MUST remain unavailable while the protected
 *   authorization could otherwise still be accepted. An indeterminate result
 *   MUST NOT be reported as successful consumption. No backend is mandated.
 *
 * Consumption spends the replay entitlement; it does not record a completed
 * effect. A crash or failure after consume may spend an authorization without
 * execution. Multiple consume calls are not one transaction with the effect.
 *
 * Deployment boundary:
 *   The caller declares/configures the replay domain through store selection and
 *   namespace/routing. Local code cannot infer every valid deployment boundary.
 *   In-memory stores lose state on restart. External backends can support shared
 *   retention, but restart persistence, replica visibility, topology, backend
 *   persistence settings and HA/recovery guarantees require deployment evidence.
 *   Generic implementation conformance does not prove these properties.
 */
export interface ReplayStore {
  /**
   * Atomically check-and-consume an auth_id.
   *
   * @param authId        The auth_id from the AuthorizationV1 artifact.
   * @param opts.expiry   Unix timestamp (seconds) when the auth expires.
   *                      Backends may garbage-collect only after the identifier
   *                      can no longer authorize reuse anywhere in the declared
   *                      domain, accounting for its verifier clocks/acceptance rules.
   * @returns `true`  if the auth_id was successfully consumed (first use).
   * @returns `false` if the auth_id was already consumed (replay detected).
   * @throws             if the store is unavailable — the guard will DENY.
   */
  consumeAuthId(authId: string, opts: { expiry: number }): Promise<boolean>;

  /**
   * Atomically check-and-consume a delegation_id.
   *
   * Optional. When absent, delegation replay is still prevented by
   * consumeAuthId on the parent authorization: consuming the parentAuth
   * once prevents the same delegation chain from being replayed.
   *
   * Implement this method when separate delegation-ID tracking is required by
   * the declared profile/domain. The current guard always consumes parentAuth
   * as well; adding this method does not enable multiple uses of that parent.
   *
   * @param delegationId  The delegation_id from the DelegationV1 artifact.
   * @param opts.expiry   Unix timestamp (seconds) when the delegation expires.
   * @returns `true`  if the delegation_id was successfully consumed (first use).
   * @returns `false` if the delegation_id was already consumed (replay detected).
   * @throws             if the store is unavailable — the guard will DENY.
   */
  consumeDelegationId?(delegationId: string, opts: { expiry: number }): Promise<boolean>;
}

/**
 * createInMemoryReplayStore — default single-process replay store.
 *
 * Uses two in-memory Sets to track consumed IDs. Each factory call produces
 * an independent store instance, mirroring the prior per-guard-instance Sets.
 *
 * Suitable for:
 *   - Single-process deployments
 *   - Testing and development
 *
 * NOT suitable for:
 *   - Multi-process / horizontally-scaled deployments
 *   - Scenarios where replay prevention must survive process restarts
 *
 * Where the declared replay domain spans restarts or processes, use a backend
 * and deployment configuration that preserve the contract across that domain.
 * A backend's technology name alone does not demonstrate that guarantee.
 */
export function createInMemoryReplayStore(): ReplayStore {
  const consumedAuthIds = new Set<string>();
  const consumedDelegationIds = new Set<string>();

  return {
    async consumeAuthId(authId: string): Promise<boolean> {
      if (consumedAuthIds.has(authId)) return false;
      consumedAuthIds.add(authId);
      return true;
    },
    async consumeDelegationId(delegationId: string): Promise<boolean> {
      if (consumedDelegationIds.has(delegationId)) return false;
      consumedDelegationIds.add(delegationId);
      return true;
    },
  };
}
