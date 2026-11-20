// SPDX-License-Identifier: Apache-2.0
// R-03 / R-04 regression (authorization-v1.md §5 "Signed field set",
// "Expiry field resolution", §13).
//
// R-03: authorization validity must never derive from an unsigned expiry.
// R-04: the artifact is a closed field set; fields not covered by the
//       signature are rejected (except the enumerated PolicyEngine legacy
//       fields, which are equality-bound or engine-HMAC only).
//
// Artifacts are signed here directly with node:crypto over the documented
// preimages so the tests do not rely on the signing helpers under test.
import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync, sign } from "node:crypto";
import { canonicalJson } from "../crypto/hashes.js";
import { verifyAuthorization } from "../verification/verifyAuthorization.js";
import { createDelegation } from "../delegation/createDelegation.js";
import { verifyDelegationChain } from "../verification/verifyDelegation.js";
import type { AuthorizationV1 } from "../types/authorization.js";

const kp = generateKeyPairSync("ed25519");
const PUB = kp.publicKey.export({ format: "pem", type: "spki" }).toString();
const PRIV = kp.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
const NOW = 1_730_000_000;
const KS = { issuer: "iss", version: "1", keys: [{ kid: "k1", alg: "Ed25519" as const, public_key: PUB }] };
const OPTS = { now: NOW, mode: "strict" as const, requireSignatureVerification: true, trustedKeySets: [KS], expectedAudience: "aud" };

const signA = (payload: object) =>
  sign(null, Buffer.concat([Buffer.from("OXDEAI_AUTH_V1\n"), Buffer.from(canonicalJson(payload))]), kp.privateKey).toString("base64");
const signB = (payload: object) => sign(null, Buffer.from(canonicalJson(payload)), kp.privateKey).toString("base64url");

const common = {
  auth_id: "a".repeat(64), issuer: "iss", audience: "aud", decision: "ALLOW", intent_hash: "1".repeat(64),
  state_hash: "2".repeat(64), policy_id: "p", issued_at: NOW - 10,
};
/** Encoding A, flat: signs every given field (caller passes the signed set). */
function flatA(signed: Record<string, unknown>, unsigned: Record<string, unknown> = {}): AuthorizationV1 {
  const f = { ...common, alg: "Ed25519", kid: "k1", ...signed };
  return { ...f, signature: signA(f), ...unsigned } as unknown as AuthorizationV1;
}
/** Encoding B, nested Sift form: signs fields + signature:{alg,kid}. */
function nestedB(signed: Record<string, unknown>, unsigned: Record<string, unknown> = {}): AuthorizationV1 {
  const meta = { alg: "ed25519", kid: "k1" };
  const f = { ...common, ...signed };
  return { ...f, signature: { ...meta, sig: signB({ ...f, signature: meta }) }, ...unsigned } as unknown as AuthorizationV1;
}
const codes = (a: AuthorizationV1, opts = OPTS) => {
  const r = verifyAuthorization(a, opts);
  return { status: r.status, codes: r.violations.map((v) => v.code as string), sig: r.signatureVerified };
};
function assertOk(a: AuthorizationV1, label: string) {
  const r = codes(a);
  assert.equal(r.status, "ok", `${label}: ${JSON.stringify(r.codes)}`);
  assert.equal(r.sig, true, label);
}
function assertRejected(a: AuthorizationV1, code: string, label: string) {
  const r = codes(a);
  assert.equal(r.status, "invalid", label);
  assert.ok(r.codes.includes(code), `${label}: expected ${code} in ${JSON.stringify(r.codes)}`);
}

// ── Valid baselines (must remain accepted) ───────────────────────────────────
test("R-03/R-04 baseline: Encoding A flat with signed expiry is accepted", () => {
  assertOk(flatA({ expiry: NOW + 60 }), "flat A");
});
test("R-03/R-04 baseline: Encoding A flat with optional signed version/nonce/capability is accepted", () => {
  assertOk(flatA({ expiry: NOW + 60, version: "AuthorizationV1", nonce: "7", capability: "exec" }), "flat A optional fields");
});
test("R-03/R-04 baseline: PolicyEngine-shaped artifact (equality-bound legacy fields) is accepted", () => {
  assertOk(flatA({ expiry: NOW + 60 }, {
    authorization_id: common.auth_id, expires_at: NOW + 60, policy_version: "v1",
    state_snapshot_hash: "3".repeat(64), engine_signature: "4".repeat(64),
  }), "engine shape");
});
test("R-03/R-04 baseline: Encoding B nested with signed expires_at is accepted", () => {
  assertOk(nestedB({ expires_at: NOW + 60 }), "nested B");
});
test("R-03/R-04 baseline: nested artifact with BOTH expiry and expires_at signed and equal is accepted", () => {
  assertOk(nestedB({ expiry: NOW + 60, expires_at: NOW + 60 }), "nested both equal");
});

// ── R-03: expiry ─────────────────────────────────────────────────────────────
test("R-03: flat signed expiry:null + unsigned future expires_at is rejected (AUTH_MISSING_FIELD)", () => {
  const a = flatA({ expiry: null }, { expires_at: NOW + 10 * 365 * 86400 });
  assertRejected(a, "AUTH_MISSING_FIELD", "expiry null");
  // and stays rejected far in the future
  const later = verifyAuthorization(a, { ...OPTS, now: NOW + 5 * 365 * 86400 });
  assert.equal(later.status, "invalid");
});
test("R-03: flat signed non-integer expiry (string) + unsigned expires_at is rejected", () => {
  assertRejected(flatA({ expiry: String(NOW + 60) }, { expires_at: NOW + 60 }), "AUTH_MISSING_FIELD", "expiry string");
});
test("R-03: flat artifact without expiry but with (unsigned) expires_at is rejected", () => {
  assertRejected(flatA({ expires_at: NOW + 60 }), "AUTH_MISSING_FIELD", "flat expires_at only");
});
test("R-03: flat unsigned expires_at that differs from signed expiry is rejected (AUTH_SIGNATURE_INVALID)", () => {
  assertRejected(flatA({ expiry: NOW + 60 }, { expires_at: NOW + 99999 }), "AUTH_SIGNATURE_INVALID", "flat conflict");
});
test("R-03: flat unsigned non-integer expires_at beside a valid expiry is rejected", () => {
  assertRejected(flatA({ expiry: NOW + 60 }, { expires_at: "soon" }), "AUTH_MISSING_FIELD", "flat expires_at malformed");
});
test("R-03: nested signed expiry:null + signed expires_at does not fall back (AUTH_MISSING_FIELD)", () => {
  assertRejected(nestedB({ expiry: null, expires_at: NOW + 60 }), "AUTH_MISSING_FIELD", "nested expiry null");
});
test("R-03: nested conflicting signed expiry/expires_at is rejected; signed expiry precedence still reports expiry", () => {
  assertRejected(nestedB({ expiry: NOW + 60, expires_at: NOW - 100 }), "AUTH_SIGNATURE_INVALID", "nested conflict (expiry future)");
  const r = codes(nestedB({ expiry: NOW - 100, expires_at: NOW + 9999 }));
  assert.equal(r.status, "invalid");
  assert.ok(r.codes.includes("AUTH_SIGNATURE_INVALID") && r.codes.includes("AUTH_EXPIRED"), JSON.stringify(r.codes));
});
test("R-03: missing expiry and expires_at is rejected", () => {
  assertRejected(nestedB({}), "AUTH_MISSING_FIELD", "nested none");
});
test("R-03: nested non-integer expires_at is rejected", () => {
  assertRejected(nestedB({ expires_at: "9999999999" }), "AUTH_MISSING_FIELD", "nested expires_at string");
});
test("R-03: expiry boundary unchanged (now == expiry -> AUTH_EXPIRED; expiry-1 -> ok)", () => {
  assertRejected(flatA({ expiry: NOW }), "AUTH_EXPIRED", "boundary");
  assertOk(flatA({ expiry: NOW + 1 }), "last valid second");
});
test("R-03: delegation from a parent without a valid integer expiry fails closed (DELEGATION_MISSING_FIELD)", () => {
  const parent = flatA({ expiry: null, audience: "agent-a" }) as AuthorizationV1;
  const del = createDelegation(parent, { delegatee: "agent-b", scope: { tools: ["t"] }, expiry: NOW + 20 * 365 * 86400, kid: "k1", issuer: "iss", issuedAt: NOW }, PRIV);
  const r = verifyDelegationChain(del, parent, { now: NOW, trustedKeySets: [KS], requireSignatureVerification: true });
  assert.equal(r.status, "invalid");
  assert.ok(r.violations.some((v) => v.code === "DELEGATION_MISSING_FIELD"), JSON.stringify(r.violations));
});

// ── R-04: closed field set ───────────────────────────────────────────────────
for (const [label, extra] of [
  ["scope", { scope: { tools: ["*"], max_amount: "999999" } }],
  ["delegatee", { delegatee: "attacker" }],
  ["authority-related (trustedAuthorizationAuthorities)", { trustedAuthorizationAuthorities: [{ issuer: "x", policyId: "y" }] }],
  ["authority-related (policyId)", { policyId: "other-policy" }],
  ["parent_auth_hash", { parent_auth_hash: "0".repeat(64) }],
  ["arbitrary", { foo: "bar" }],
] as const) {
  test(`R-04: unsigned ${label} on Encoding A is rejected (AUTH_SIGNATURE_INVALID)`, () => {
    assertRejected(flatA({ expiry: NOW + 60 }, extra), "AUTH_SIGNATURE_INVALID", label);
  });
  test(`R-04: unsigned ${label} on Encoding B is rejected (AUTH_SIGNATURE_INVALID)`, () => {
    assertRejected(nestedB({ expires_at: NOW + 60 }, extra), "AUTH_SIGNATURE_INVALID", label);
  });
}
test("R-04: extra field inside the nested signature object is rejected", () => {
  const a = nestedB({ expires_at: NOW + 60 }) as unknown as { signature: Record<string, unknown> };
  a.signature.scope = "*";
  assertRejected(a as unknown as AuthorizationV1, "AUTH_SIGNATURE_INVALID", "signature.scope");
});
test("R-04: JSON '__proto__' own key is rejected as an unsigned field", () => {
  const a = JSON.parse(JSON.stringify(flatA({ expiry: NOW + 60 })).replace(/^\{/, '{"__proto__":{"admin":true},'));
  assertRejected(a, "AUTH_SIGNATURE_INVALID", "__proto__");
});
test("R-04: legacy authorization_id must equal the signed auth_id", () => {
  assertRejected(flatA({ expiry: NOW + 60 }, { authorization_id: "b".repeat(64) }), "AUTH_SIGNATURE_INVALID", "authorization_id mismatch");
});
test("R-04: legacy engine fields must be strings", () => {
  assertRejected(flatA({ expiry: NOW + 60 }, { policy_version: { v: 1 } }), "AUTH_SIGNATURE_INVALID", "policy_version object");
});

// ── Existing protections still apply ─────────────────────────────────────────
test("R-03/R-04: replay, audience, issuer-policy authority and state/policy tamper protections unchanged", () => {
  const a = flatA({ expiry: NOW + 60 });
  assert.ok(codes(a, { ...OPTS, consumedAuthIds: [common.auth_id] } as typeof OPTS).codes.includes("AUTH_REPLAY"));
  assert.ok(codes(a, { ...OPTS, expectedAudience: "other" }).codes.includes("AUTH_AUDIENCE_MISMATCH"));
  assert.ok(codes(a, { ...OPTS, trustedAuthorizationAuthorities: [{ issuer: "iss", policyId: "other" }] } as typeof OPTS).codes.includes("AUTH_ISSUER_POLICY_NOT_AUTHORIZED"));
  for (const field of ["state_hash", "policy_id", "intent_hash"] as const) {
    const t = { ...(a as unknown as Record<string, unknown>), [field]: "9".repeat(64) } as unknown as AuthorizationV1;
    assert.ok(codes(t).codes.includes("AUTH_SIGNATURE_INVALID"), field);
  }
});
