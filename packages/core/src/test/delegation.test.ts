// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { signAuthorizationEd25519 } from "../verification/verifyAuthorization.js";
import { createDelegation as createDelegationAtWallClock } from "../delegation/createDelegation.js";
import {
  verifyDelegation,
  verifyDelegationChain,
  delegationParentHash,
} from "../verification/verifyDelegation.js";
import type { KeySet } from "../types/keyset.js";
import type { AuthorizationV1 } from "../types/authorization.js";

// ── Test fixtures ─────────────────────────────────────────────────────────────

const KEYS = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

// Delegation is signed by the delegating principal (parent.audience = "agent-A")
const KEYSET: KeySet = {
  issuer: "agent-A",
  version: "1",
  keys: [{ kid: "k1", alg: "Ed25519", public_key: KEYS.publicKey }],
};

function makeParent(overrides?: { expiry?: number; auth_id?: string }): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      auth_id: overrides?.auth_id ?? "f".repeat(64),
      issuer: "issuer-A",
      audience: "agent-A",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "policy-1",
      decision: "ALLOW",
      issued_at: 1000,
      expiry: overrides?.expiry ?? 2000,
      kid: "k1",
    },
    KEYS.privateKey
  );
}

const NOW = 1500;

// Lot A (F4-R6-03/R8-02): verifyDelegation now rejects an issued_at more than
// maxFutureIssuedAtSkewSeconds ahead of the verification time. These fixtures
// verify at a fixed clock, so issue at that clock too (createDelegation would
// otherwise stamp the real wall clock, decades after the fixed `now`). An
// explicit `issuedAt` in a call still takes precedence.
const createDelegation: typeof createDelegationAtWallClock = (parent, params, key) =>
  createDelegationAtWallClock(parent, { issuedAt: 1000, ...params }, key);

// ── delegationParentHash ──────────────────────────────────────────────────────

test("delegationParentHash: stable across calls", () => {
  const parent = makeParent();
  assert.equal(delegationParentHash(parent), delegationParentHash(parent));
});

test("delegationParentHash: changes when parent changes", () => {
  const a = makeParent();
  const b = makeParent({ auth_id: "e".repeat(64) });
  assert.notEqual(delegationParentHash(a), delegationParentHash(b));
});

// ── verifyDelegation (isolated) ───────────────────────────────────────────────

test("ok: valid delegation, no signature verification", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: { tools: ["tool-A"] }, expiry: 1800, kid: "k1" },
    KEYS.privateKey
  );
  const result = verifyDelegation(d, { now: NOW });
  assert.equal(result.ok, true);
  assert.equal(result.status, "ok");
});

test("ok: valid delegation with signature verification", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: { tools: ["tool-A"] }, expiry: 1800, kid: "k1" },
    KEYS.privateKey
  );
  const result = verifyDelegation(d, {
    now: NOW,
    trustedKeySets: KEYSET,
    requireSignatureVerification: true,
  });
  assert.equal(result.ok, true);
  assert.equal(result.policyId, "policy-1");
});

test("invalid: expired delegation", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: 1200, kid: "k1" },
    KEYS.privateKey
  );
  const result = verifyDelegation(d, { now: 1300 });
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_EXPIRED"));
});

test("invalid: delegation_id in consumed set", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: 1800, kid: "k1", delegationId: "d-fixed" },
    KEYS.privateKey
  );
  const result = verifyDelegation(d, { now: NOW, consumedDelegationIds: ["d-fixed"] });
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_REPLAY"));
});

test("invalid: expectedDelegatee mismatch", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: 1800, kid: "k1" },
    KEYS.privateKey
  );
  const result = verifyDelegation(d, { now: NOW, expectedDelegatee: "agent-C" });
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_AUDIENCE_MISMATCH"));
});

test("invalid: expectedPolicyId mismatch", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: 1800, kid: "k1" },
    KEYS.privateKey
  );
  const result = verifyDelegation(d, { now: NOW, expectedPolicyId: "other-policy" });
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_POLICY_MISMATCH"));
});

test("invalid: signature tampered", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: 1800, kid: "k1" },
    KEYS.privateKey
  );
  const tampered = { ...d, delegatee: "agent-EVIL" };
  const result = verifyDelegation(tampered, {
    now: NOW,
    trustedKeySets: KEYSET,
    requireSignatureVerification: true,
  });
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_SIGNATURE_INVALID"));
});

test("invalid: missing required field", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: 1800, kid: "k1" },
    KEYS.privateKey
  );
  const result = verifyDelegation({ ...d, delegation_id: "" }, { now: NOW });
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_MISSING_FIELD"));
});

// ── Scope narrowing ───────────────────────────────────────────────────────────

test("invalid: scope.tools not subset of parentScope", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: { tools: ["tool-A", "tool-B"] }, expiry: 1800, kid: "k1" },
    KEYS.privateKey
  );
  const result = verifyDelegation(d, {
    now: NOW,
    parentScope: { tools: ["tool-A"] },
  });
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_SCOPE_VIOLATION"));
});

test("ok: scope.tools is subset of parentScope", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: { tools: ["tool-A"] }, expiry: 1800, kid: "k1" },
    KEYS.privateKey
  );
  const result = verifyDelegation(d, {
    now: NOW,
    parentScope: { tools: ["tool-A", "tool-B"] },
  });
  assert.equal(result.ok, true);
});

test("invalid: scope.max_amount exceeds parentScope", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: { max_amount: 500n }, expiry: 1800, kid: "k1" },
    KEYS.privateKey
  );
  const result = verifyDelegation(d, {
    now: NOW,
    parentScope: { max_amount: 300n },
  });
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_SCOPE_VIOLATION"));
});

// ── verifyDelegationChain ────────────────────────────────────────────────────

test("ok: valid chain with parent", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: 1800, kid: "k1" },
    KEYS.privateKey
  );
  const result = verifyDelegationChain(d, parent, {
    now: NOW,
    trustedKeySets: KEYSET,
    requireSignatureVerification: true,
  });
  assert.equal(result.ok, true);
});

test("invalid: parent hash mismatch", () => {
  const parent = makeParent();
  const otherParent = makeParent({ auth_id: "e".repeat(64) });
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: 1800, kid: "k1" },
    KEYS.privateKey
  );
  const result = verifyDelegationChain(d, otherParent, { now: NOW });
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_PARENT_HASH_MISMATCH"));
});

test("invalid: parent expired", () => {
  const parent = makeParent({ expiry: 1200 });
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: 1200, kid: "k1" },
    KEYS.privateKey
  );
  const result = verifyDelegationChain(d, parent, { now: 1300 });
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_PARENT_EXPIRED"));
});

test("invalid: delegator does not match parent.audience", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: 1800, kid: "k1" },
    KEYS.privateKey
  );
  // Tamper delegator
  const tampered = { ...d, delegator: "agent-EVIL" };
  const result = verifyDelegationChain(tampered, parent, { now: NOW });
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_DELEGATOR_MISMATCH"));
});

test("invalid: delegation expiry exceeds parent expiry", () => {
  const parent = makeParent({ expiry: 1800 });
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: 3000, kid: "k1" },
    KEYS.privateKey
  );
  const result = verifyDelegationChain(d, parent, { now: NOW });
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_EXPIRY_EXCEEDS_PARENT"));
});

test("invalid: multi-hop delegation denied", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: 1800, kid: "k1" },
    KEYS.privateKey
  );
  // Try using a DelegationV1 as parent (multi-hop)
  const result = verifyDelegationChain(d, d as unknown as AuthorizationV1, { now: NOW });
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_MULTIHOP_DENIED"));
});

test("invalid: policy_id mismatch with parent", () => {
  const parent = makeParent();
  const d = createDelegation(
    parent,
    { delegatee: "agent-B", scope: {}, expiry: 1800, kid: "k1" },
    KEYS.privateKey
  );
  // Tamper policy_id
  const tampered = { ...d, policy_id: "wrong-policy" };
  const result = verifyDelegationChain(tampered, parent, { now: NOW });
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.code === "DELEGATION_POLICY_ID_MISMATCH"));
});
