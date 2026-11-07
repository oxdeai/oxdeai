// SPDX-License-Identifier: Apache-2.0
//
// RR-01 regression: the PEP must treat the replay store's answer as a strict
// boolean. Only literal `true` (first consumption) permits execution. `false`
// is a replay (AUTH_REPLAY, unchanged). Any other answer violates the
// `Promise<boolean>` contract and fails closed as REPLAY_STORE_UNAVAILABLE;
// previously any truthy value ("false", "OK", 1, {}) executed.

import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { sha256HexFromJson, signAuthorizationEd25519 } from "@oxdeai/core";
import type { AuthorizationV1 } from "@oxdeai/core";
import type { ReplayStore } from "@oxdeai/guard";
import type { PepConfig } from "../src/config.js";
import type { ActionEnvelope } from "../src/types.js";
import type { PlatformAdapter } from "../src/adapters/platform.js";
import { createPepServer } from "../src/server.js";
import { POLICY_ID } from "../src/policy.js";

const AUDIENCE = "PEP-frappe.lgf.oxdeai.dev";
const ISSUER = "oxdeai.lgf-frappe-pep";

function makeEnvelope(): ActionEnvelope {
  return {
    source_bench: "openwebui-dev",
    target_bench: "frappe",
    agent_or_tool_context: "erp-assistant",
    user_identity: "user@example.com",
    session_id: "rr01-session",
    action: {
      type: "EXECUTE",
      tool: "frappe.helpdesk.create_ticket",
      params: { subject: "RR-01 ticket", description: "Created by RR-01 test", priority: "Low" },
    },
  };
}

function issueAuthorization(envelope: ActionEnvelope, privateKeyPem: string): AuthorizationV1 {
  const now = Math.floor(Date.now() / 1000);
  return signAuthorizationEd25519(
    {
      auth_id: randomUUID(),
      issuer: ISSUER,
      audience: AUDIENCE,
      intent_hash: sha256HexFromJson(envelope.action),
      state_hash: sha256HexFromJson({}),
      policy_id: POLICY_ID,
      decision: "ALLOW",
      issued_at: now,
      expiry: now + 60,
      kid: "test-key-1",
      nonce: randomUUID(),
    },
    privateKeyPem,
  ) as AuthorizationV1;
}

async function postJson(url: string, body: unknown): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

describe("RR-01 strict replay-store result (lgf-frappe-pep)", () => {
  let baseUrl: string;
  let privateKeyPem: string;
  let frappeCalls = 0;
  let consumeCalls = 0;
  let answer: unknown = true;
  let close: () => Promise<void>;

  before(async () => {
    const keyPair = generateKeyPairSync("ed25519");
    privateKeyPem = keyPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    const publicKeyPem = keyPair.publicKey.export({ type: "spki", format: "pem" }) as string;

    const platformAdapter: PlatformAdapter = {
      name: "frappe",
      async execute() {
        frappeCalls++;
        return { resource_id: "T1", details: { ticket_id: "T1", name: "T1" } };
      },
    };
    // A store that violates the Promise<boolean> contract on demand.
    const store: ReplayStore = {
      async consumeAuthId() {
        consumeCalls++;
        return answer as boolean;
      },
    };
    const config: PepConfig = {
      mode: "enforce",
      expectedAudience: AUDIENCE,
      frappeBaseUrl: "https://frappe.lgf.oxdeai.dev",
      frappeApiKey: "test-key",
      frappeApiSecret: "test-secret",
      replayStore: { type: "memory" },
      port: 0,
      signingPrivateKey: keyPair.privateKey,
      signingPublicKeyPem: publicKeyPem,
      signingKid: "test-key-1",
      issuer: ISSUER,
      trustedAuthorizationAuthorities: [{ issuer: ISSUER, policyId: POLICY_ID }],
      authorizationTtlSeconds: 60,
    };
    const server = createPepServer({ config, replayStore: store, platformAdapter });
    await new Promise<void>((resolve, reject) => {
      server.on("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server.address();
    if (!addr || typeof addr === "string") throw new Error("Unexpected address");
    baseUrl = `http://127.0.0.1:${(addr as { port: number }).port}`;
    close = () => {
      server.closeAllConnections();
      return new Promise((res, rej) => server.close((e) => (e ? rej(e) : res())));
    };
  });

  after(async () => {
    await close();
  });

  async function run(value: unknown) {
    answer = value;
    frappeCalls = 0;
    consumeCalls = 0;
    const envelope = makeEnvelope();
    const result = await postJson(`${baseUrl}/execute`, { envelope, authorization: issueAuthorization(envelope, privateKeyPem) });
    assert.equal(consumeCalls, 1, "the replay store was consulted exactly once");
    return result;
  }

  test("true: first consumption executes once", async () => {
    const r = await run(true);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body["ok"], true);
    assert.equal(frappeCalls, 1);
  });

  test("false: replay denial keeps the AUTH_REPLAY classification", async () => {
    const r = await run(false);
    assert.equal(r.status, 403);
    assert.equal(r.body["decision"], "DENY");
    assert.equal(r.body["reason"], "AUTH_REPLAY");
    assert.equal(frappeCalls, 0);
  });

  const malformed: Array<[string, unknown]> = [
    ['"false"', "false"],
    ['"OK"', "OK"],
    ["1", 1],
    ["{}", {}],
    ["null", null],
    ["undefined", undefined],
  ];
  for (const [label, value] of malformed) {
    test(`${label}: malformed answer fails closed (REPLAY_STORE_UNAVAILABLE), Frappe never called`, async () => {
      const r = await run(value);
      assert.equal(r.status, 403, JSON.stringify(r.body));
      assert.equal(r.body["ok"], false);
      assert.equal(r.body["decision"], "DENY");
      assert.equal(r.body["reason"], "REPLAY_STORE_UNAVAILABLE");
      assert.equal(frappeCalls, 0, `Frappe must not be called for ${label}`);
    });
  }
});
