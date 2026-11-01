// S2 regression: authorization and delegation identifiers must have one
// canonical (Unicode NFC) representation at the verification trust boundary.
// A canonically-equivalent non-NFC identifier keeps a valid signature (the
// signing payload NFC-normalizes strings) but a distinct replay key, so it must
// be rejected, not silently normalized.
import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { verifyAuthorization } from "../verification/verifyAuthorization.js";
import { verifyDelegation } from "../verification/verifyDelegation.js";

// A structurally-valid synthetic keyset so strict verifyAuthorization proceeds
// past the TRUSTED_KEYSETS_REQUIRED gate to field validation. The signature in
// these fixtures is intentionally invalid; we assert only the canonical-id code.
const pub = generateKeyPairSync("ed25519", { publicKeyEncoding: { format: "pem", type: "spki" }, privateKeyEncoding: { format: "pem", type: "pkcs8" } }).publicKey.toString();
const keySet = { issuer: "iss", version: "1", keys: [{ kid: "k1", alg: "Ed25519", public_key: pub, status: "active" }] };

const NFC = "op-café-ñ";      // composed
const NFD = "op-café-ñ";      // decomposed, canonically equivalent
assert.notStrictEqual(NFC, NFD);
assert.strictEqual(NFC.normalize("NFC"), NFD.normalize("NFC"));

const codes = (r: { violations: { code: string }[] }) => r.violations.map((v) => v.code);

function baseAuth(auth_id: string) {
  return {
    auth_id, issuer: "iss", audience: "aud", intent_hash: "0".repeat(64),
    state_hash: "0".repeat(64), policy_id: "p1", decision: "ALLOW",
    issued_at: 1000, expiry: 9_999_999_999, alg: "Ed25519", kid: "k1",
    signature: "AA",
  } as any;
}
function baseDelegation(delegation_id: string) {
  return {
    delegation_id, issuer: "iss", audience: "aud", parent_auth_hash: "0".repeat(64),
    delegator: "d", delegatee: "e", policy_id: "p1", issued_at: 1000, expiry: 9_999_999_999,
    alg: "Ed25519", kid: "k1", signature: "AA",
  } as any;
}
const authOpts = { now: 2000, mode: "strict" as const, requireSignatureVerification: false, trustedKeySets: [keySet] } as any;
const delOpts = { now: 2000, mode: "strict" as const, requireSignatureVerification: false } as any;

test("S2 auth_id: a non-NFC auth_id is rejected as AUTH_ID_NONCANONICAL", () => {
  const r = verifyAuthorization(baseAuth(NFD), authOpts);
  assert.ok(codes(r).includes("AUTH_ID_NONCANONICAL"), "non-NFC auth_id must be flagged");
  assert.equal(r.ok, false);
});

test("S2 auth_id: an NFC auth_id is not flagged non-canonical", () => {
  const r = verifyAuthorization(baseAuth(NFC), authOpts);
  assert.ok(!codes(r).includes("AUTH_ID_NONCANONICAL"), "NFC auth_id must not be flagged");
});

test("S2 delegation_id: a non-NFC delegation_id is rejected as DELEGATION_ID_NONCANONICAL", () => {
  const r = verifyDelegation(baseDelegation(NFD), delOpts);
  assert.ok(codes(r).includes("DELEGATION_ID_NONCANONICAL"), "non-NFC delegation_id must be flagged");
  assert.equal(r.ok, false);
});

test("S2 delegation_id: an NFC delegation_id is not flagged non-canonical", () => {
  const r = verifyDelegation(baseDelegation(NFC), delOpts);
  assert.ok(!codes(r).includes("DELEGATION_ID_NONCANONICAL"), "NFC delegation_id must not be flagged");
});
