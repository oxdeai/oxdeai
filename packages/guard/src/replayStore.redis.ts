// SPDX-License-Identifier: Apache-2.0
/**
 * replayStore.redis.ts
 *
 * Redis-backed ReplayStore; deployment durability is not certified here.
 *
 * Atomicity guarantee:
 *   SET key value NX EX ttl is a single atomic Redis command.
 *   Within one authoritative Redis keyspace, at most one concurrent caller can
 *   receive "OK" for a retained key. Store errors can leave no successful caller.
 *   This avoids a read-then-write race; it does not prove retention through
 *   failover, independent replicas, restart, eviction or recovery.
 *
 * Key schema:
 *   replay:auth:<auth_id>           — AuthorizationV1 single-use tokens
 *   replay:delegation:<delegation_id> — DelegationV1 single-use tokens
 *
 * TTL policy:
 *   ttl = max(1, expiry - now)
 *   Safe eviction requires alignment with every verifier's acceptance window
 *   in the declared replay domain; the formula alone does not prove alignment.
 *   A minimum of 1 second is enforced so that already-expired artifacts
 *   never create zero-TTL or infinite-TTL keys.
 *
 * Fail-closed:
 *   Any Redis error (network failure, timeout, cluster failover) is re-thrown.
 *   The guard catches this and raises OxDeAIAuthorizationError, blocking execution.
 *   There is no fallback, no best-effort path, no silent memory store.
 *
 * Client compatibility:
 *   The RedisClient interface matches the ioredis positional argument style:
 *     client.set(key, value, "NX", "EX", ttlSeconds) → Promise<"OK" | null>
 *
 *   node-redis v4 adapter:
 *     const client: RedisClient = {
 *       set: (k, v, _nx, _ex, ttl) =>
 *         nodeRedisClient.set(k, v, { NX: true, EX: ttl }),
 *     };
 *
 * Replay domain and clocks:
 *   The caller configures the authoritative keyspace through the supplied client;
 *   fixed key prefixes do not discover deployment boundaries. TTL uses the local
 *   wall clock, which may differ from injected verifier time or other hosts.
 *   No generic clock-skew allowance is established here. Deployments must ensure
 *   a consumed key cannot expire or be lost while any verifier in that domain
 *   could still accept the authorization. Uncertain required replay state must
 *   block execution. Backend persistence, replication and recovery need separate
 *   validation; a consume result is not evidence that the effect occurred.
 */

import type { ReplayStore } from "./replayStore.js";

// ---------------------------------------------------------------------------
// Minimal Redis client interface
// ---------------------------------------------------------------------------

/**
 * Minimal Redis client interface required by createRedisReplayStore.
 *
 * Intentionally narrow — only the SET NX EX command is required.
 * Compatible natively with ioredis and @redis/client (node-redis v4 wrapper).
 *
 * The caller owns the client lifecycle (connection, reconnection, shutdown).
 * The store does NOT create, pool, or close connections.
 */
export interface RedisClient {
  /**
   * SET key value NX EX seconds
   *
   * @returns "OK"  if the key was set (first use — consume allowed)
   * @returns null  if the key already existed (replay — consume denied)
   * @throws        on any Redis or network error
   */
  set(
    key: string,
    value: string,
    nx: "NX",
    ex: "EX",
    seconds: number
  ): Promise<"OK" | null>;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface RedisReplayStoreConfig {
  /** Pre-connected Redis client. The store does not manage its lifecycle. */
  client: RedisClient;
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/** Returns the Redis key for an auth_id. Not user-overridable. */
function authKey(authId: string): string {
  return `replay:auth:${authId}`;
}

/** Returns the Redis key for a delegation_id. Not user-overridable. */
function delegationKey(delegationId: string): string {
  return `replay:delegation:${delegationId}`;
}

/**
 * Compute the TTL (seconds) to assign to a Redis key.
 *
 * Always at least 1 second to avoid invalid/non-positive Redis TTLs.
 * Authorization expiry is enforced by the verifier independently. This minimum
 * is not a clock-skew buffer or proof of retention across the replay domain.
 */
function computeTtl(expiry: number): number {
  const now = Math.floor(Date.now() / 1000);
  return Math.max(1, expiry - now);
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * createRedisReplayStore — atomic consume within the configured Redis keyspace.
 * Restart resistance and cross-instance visibility depend on deployment setup.
 *
 * Usage:
 *
 *   import { createClient } from "ioredis"; // or node-redis v4
 *   import { createRedisReplayStore } from "@oxdeai/guard/replayStore.redis";
 *
 *   const redis = new Redis({ host: "redis.internal", port: 6379 });
 *
 *   const guard = OxDeAIGuard({
 *     // ...
 *     replayStore: createRedisReplayStore({ client: redis }),
 *   });
 *
 * @param config.client  Pre-connected Redis client. Must remain connected for
 *                       the lifetime of the guard. The caller is responsible
 *                       for reconnection and graceful shutdown.
 */
export function createRedisReplayStore(config: RedisReplayStoreConfig): ReplayStore {
  const { client } = config;

  if (!client || typeof client.set !== "function") {
    throw new TypeError(
      "createRedisReplayStore: config.client must implement RedisClient (set method required)."
    );
  }

  return {
    async consumeAuthId(authId: string, opts: { expiry: number }): Promise<boolean> {
      const ttl = computeTtl(opts.expiry);
      const result = await client.set(authKey(authId), "1", "NX", "EX", ttl);
      return result === "OK";
    },

    async consumeDelegationId(delegationId: string, opts: { expiry: number }): Promise<boolean> {
      const ttl = computeTtl(opts.expiry);
      const result = await client.set(delegationKey(delegationId), "1", "NX", "EX", ttl);
      return result === "OK";
    },
  };
}
