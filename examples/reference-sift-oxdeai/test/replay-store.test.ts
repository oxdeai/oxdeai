// SPDX-License-Identifier: Apache-2.0
/**
 * Replay store tests.
 *
 * Unit: MapBackedReplayStore semantics (NX, records shared within one process).
 * Integration: PEP fail-closed on replay store error (REPLAY_STORE_ERROR, HTTP 500).
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { MapBackedReplayStore, type ReplayStore } from "../packages/replay-store/index.js";
import { startTestHarness, type TestContext } from "./harness.js";
import { fetchSiftReceipt, callPepGateway } from "../apps/agent/client.js";

// ─── Unit: MapBackedReplayStore ───────────────────────────────────────────────

const FUTURE = Math.floor(Date.now() / 1000) + 3600;

test("MapBackedReplayStore: first consume returns true", async () => {
  const store = new MapBackedReplayStore(new Map());
  const result = await store.consumeAuthId("auth-001", FUTURE);
  assert.equal(result, true, "First consume must return true");
});

test("MapBackedReplayStore: second consume with same auth_id returns false", async () => {
  const store = new MapBackedReplayStore(new Map());
  await store.consumeAuthId("auth-002", FUTURE);
  const second = await store.consumeAuthId("auth-002", FUTURE);
  assert.equal(second, false, "Replay must return false");
});

test("MapBackedReplayStore: new instance with shared Map still denies (same process)", async () => {
  const sharedMap = new Map<string, number>();
  const first = new MapBackedReplayStore(sharedMap);
  await first.consumeAuthId("auth-003", FUTURE);

  // New wrapper in the same process; this does not simulate durable restart.
  const second = new MapBackedReplayStore(sharedMap);
  const result = await second.consumeAuthId("auth-003", FUTURE);
  assert.equal(result, false, "Replay must be denied across same-process wrappers");
});

test("MapBackedReplayStore: different auth_ids are independent", async () => {
  const store = new MapBackedReplayStore(new Map());
  const a = await store.consumeAuthId("auth-a", FUTURE);
  const b = await store.consumeAuthId("auth-b", FUTURE);
  assert.equal(a, true, "First auth_id must be allowed");
  assert.equal(b, true, "Second distinct auth_id must be allowed");
});

// ─── Integration: PEP fail-closed on replay store error ──────────────────────

class FaultyReplayStore implements ReplayStore {
  async consumeAuthId(_authId: string, _expiresAt: number): Promise<boolean> {
    throw new Error("simulated store failure");
  }
}

let ctx: TestContext;

before(async () => {
  ctx = await startTestHarness({ replayStore: new FaultyReplayStore() });
});

after(async () => {
  await ctx.close();
});

test("REPLAY_STORE_ERROR: store failure causes PEP to return 500 (fail-closed)", async () => {
  const envelope = await fetchSiftReceipt(ctx.mockSiftUrl, "transfer");

  const authResult = await ctx.adapter.adapt({
    kidAndReceipt: envelope,
    params: { amount: 100, destination: "safe_account" },
    state: ctx.readCounter(),
  });
  assert.ok(authResult.ok, "Adapter must succeed for REPLAY_STORE_ERROR setup");
  if (!authResult.ok) return;

  const { status, body } = await callPepGateway(
    ctx.pepUrl,
    authResult.intent,
    authResult.state,
    authResult.authorization
  );
  assert.deepEqual(ctx.readCounter(), { counter: 0 }, "Store failure must have no effect");
  assert.equal(status, 500, `Store error must return 500 — got ${status}`);
  assert.equal(
    (body as { code?: string }).code,
    "REPLAY_STORE_ERROR",
    `Expected code REPLAY_STORE_ERROR, got: ${(body as { code?: string }).code}`
  );
});
