// SPDX-License-Identifier: Apache-2.0
//
// RR-01 regression: the PEP gateway must treat the replay store's answer as a
// strict boolean. Only literal `true` permits forwarding to the upstream.
// `false` is a replay (403 REPLAY_DETECTED, unchanged). Any other answer
// violates the `Promise<boolean>` contract and fails closed like a store error
// (500 REPLAY_STORE_ERROR); previously any truthy value ("false", "OK", 1, {})
// executed. The upstream counter is the effect oracle.
import { test } from "node:test";
import assert from "node:assert/strict";
import { startTestHarness, type TestContext } from "./harness.js";
import type { ReplayStore } from "../packages/replay-store/index.js";
import { fetchSiftReceipt, callPepGateway } from "../apps/agent/client.js";

const PARAMS = { amount: 100, destination: "safe_account" };

class AnswerStore implements ReplayStore {
  calls = 0;
  constructor(private readonly answer: unknown) {}
  async consumeAuthId(_authId: string, _expiresAt: number): Promise<boolean> {
    this.calls++;
    return this.answer as boolean;
  }
}

async function attempt(answer: unknown) {
  const store = new AnswerStore(answer);
  const ctx: TestContext = await startTestHarness({ replayStore: store });
  try {
    const envelope = await fetchSiftReceipt(ctx.mockSiftUrl, "transfer");
    const state = ctx.readCounter();
    const auth = await ctx.adapter.adapt({ kidAndReceipt: envelope, params: PARAMS, state });
    assert.ok(auth.ok, !auth.ok ? auth.message : "");
    if (!auth.ok) throw new Error("unreachable");
    const response = await callPepGateway(ctx.pepUrl, auth.intent, auth.state, auth.authorization);
    return { response, counter: ctx.readCounter().counter, calls: store.calls };
  } finally {
    await ctx.close();
  }
}

test("RR-01 true: first consumption forwards once (counter 0 -> 1)", async () => {
  const r = await attempt(true);
  assert.equal(r.response.status, 200, JSON.stringify(r.response.body));
  assert.equal(r.counter, 1);
  assert.equal(r.calls, 1);
});

test("RR-01 false: replay denial keeps 403 REPLAY_DETECTED, no effect", async () => {
  const r = await attempt(false);
  assert.equal(r.response.status, 403);
  assert.equal((r.response.body as { code: string }).code, "REPLAY_DETECTED");
  assert.equal(r.counter, 0);
  assert.equal(r.calls, 1);
});

const MALFORMED: Array<[string, unknown]> = [
  ['"false"', "false"],
  ['"OK"', "OK"],
  ["1", 1],
  ["{}", {}],
  ["null", null],
  ["undefined", undefined],
];
for (const [label, value] of MALFORMED) {
  test(`RR-01 ${label}: malformed answer fails closed (500 REPLAY_STORE_ERROR), no effect`, async () => {
    const r = await attempt(value);
    assert.equal(r.response.status, 500, JSON.stringify(r.response.body));
    assert.equal((r.response.body as { ok: boolean }).ok, false);
    assert.equal((r.response.body as { code: string }).code, "REPLAY_STORE_ERROR");
    assert.equal(r.counter, 0, `upstream must not run for ${label}`);
    assert.equal(r.calls, 1);
  });
}
