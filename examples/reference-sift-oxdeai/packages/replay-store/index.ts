// SPDX-License-Identifier: Apache-2.0
/**
 * Replay protection store.
 *
 * The interface is designed for durable backends (Redis, DynamoDB, Postgres)
 * where `consumeAuthId` is atomic (check-and-set). The in-memory implementation
 * below is suitable only for single-process deployments and tests.
 *
 * PRODUCTION WARNING: replace MemoryReplayStore with a durable, distributed
 * implementation before deploying to a horizontally-scaled environment.
 *
 * Interface contract:
 *   consumeAuthId MUST be atomic — the check and the mark must happen in a
 *   single operation with no race window. Any implementation that does a
 *   separate read then write is incorrect and allows replay under concurrency.
 */

// ─── Interface ────────────────────────────────────────────────────────────────

export interface ReplayStore {
  /**
   * Atomically checks whether `authId` has been consumed.
   * - If NOT consumed: marks it as consumed and returns true (allowed).
   * - If already consumed: returns false (replay detected → DENY).
   *
   * `expiresAt` is a Unix timestamp (seconds). Implementations MAY use it
   * to schedule TTL-based eviction of consumed entries; they MUST NOT use
   * it to skip the replay check for expired entries.
   *
   * Implementations MUST throw on store errors. The PEP treats any thrown
   * error as a hard failure (REPLAY_STORE_ERROR, HTTP 500) — fail-closed.
   */
  consumeAuthId(authId: string, expiresAt: number): Promise<boolean>;
}

// ─── In-memory implementation ─────────────────────────────────────────────────

export class MemoryReplayStore implements ReplayStore {
  // Maps auth_id → expires_at (Unix seconds). Entries are pruned lazily.
  private readonly consumed = new Map<string, number>();

  async consumeAuthId(authId: string, expiresAt: number): Promise<boolean> {
    this.pruneExpired();
    if (this.consumed.has(authId)) return false;
    this.consumed.set(authId, expiresAt);
    return true;
  }

  private pruneExpired(): void {
    const now = Math.floor(Date.now() / 1000);
    for (const [id, exp] of this.consumed) {
      if (exp < now) this.consumed.delete(id);
    }
  }
}

// ─── Map-backed implementation (shared only within one process) ───

/**
 * A `ReplayStore` backed by an external `Map<string, number>`.
 *
 * Passing the same `Map` instance to multiple `MapBackedReplayStore` instances
 * (e.g. after a simulated process restart) preserves records within a single
 * process, not across process restarts — any auth_id consumed by the first instance is visible to the second.
 *
 * This implementation is a stand-in for a Redis `SET NX EX` backend:
 * - First call for an auth_id: writes the entry and returns `true`.
 * - Subsequent calls for the same auth_id: returns `false` (replay detected).
 *
 * PRODUCTION NOTE: Replace this with a Redis-backed implementation that uses
 * `SET key 1 NX EX <ttl>` for true distributed atomicity across processes/hosts.
 */
export class MapBackedReplayStore implements ReplayStore {
  constructor(private readonly store: Map<string, number>) {}

  async consumeAuthId(authId: string, expiresAt: number): Promise<boolean> {
    if (this.store.has(authId)) return false;
    this.store.set(authId, expiresAt);
    return true;
  }
}
