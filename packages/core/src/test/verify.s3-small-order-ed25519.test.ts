// SPDX-License-Identifier: Apache-2.0
//
// S3-R1: Ed25519 small-order public-key rejection. A small-order public key
// authenticates nothing - a crafted signature verifies against ANY message - so
// such keys must never yield a successful verification, on every path. The
// Edwards25519 small subgroup has 8 points; across canonical + non-canonical
// wire encodings there are 14 encodings, ALL accepted by OpenSSL's import. These
// tests assert rejection across the entry points and preservation of all
// legitimate behavior. Assertions fail the run automatically; exit code alone is
// not relied upon.

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  verifyEd25519,
  signEd25519,
  isSmallOrderEd25519Pem,
  SIGNING_DOMAINS,
} from "../crypto/signatures.js";
import { signAuthorizationEd25519, verifyAuthorization } from "../verification/verifyAuthorization.js";
import type { AuthorizationV1 } from "../types/authorization.js";
import type { KeySet } from "../types/keyset.js";

const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const pem = (raw32hex: string) =>
  `-----BEGIN PUBLIC KEY-----\n${Buffer.concat([SPKI_PREFIX, Buffer.from(raw32hex, "hex")]).toString("base64").replace(/(.{64})/g, "$1\n")}\n-----END PUBLIC KEY-----\n`;

// The complete 14 small-order Ed25519 public-key wire encodings (canonical +
// non-canonical), independently enumerated in the S3-R1 investigation.
const SMALL_ORDER_14 = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];
// The 8 canonical encodings explicitly named by the S3 investigation (subset).
const CANONICAL_8 = [
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
];
// Forged "universal" signature: R = identity, S = 0 (64 bytes, canonical base64).
const FORGED_SIG = Buffer.concat([
  Buffer.from("0100000000000000000000000000000000000000000000000000000000000000", "hex"),
  Buffer.alloc(32, 0),
]).toString("base64");

// ── 1-2. helper rejects all 14 encodings; verifyEd25519 rejects the forgery ───
test("isSmallOrderEd25519Pem flags all 14 small-order wire encodings", () => {
  for (const h of SMALL_ORDER_14) assert.equal(isSmallOrderEd25519Pem(pem(h)), true, `must flag ${h}`);
  assert.ok(CANONICAL_8.every((h) => SMALL_ORDER_14.includes(h)), "canonical 8 are a subset of the 14");
});
test("verifyEd25519 (Encoding A: auth/delegation/envelope/KRL primitive) rejects every small-order key", () => {
  const payload = { any: "payload" };
  for (const h of SMALL_ORDER_14) {
    assert.equal(verifyEd25519(SIGNING_DOMAINS.AUTH_V1, payload, FORGED_SIG, pem(h)), false, `A/auth must reject ${h}`);
    assert.equal(verifyEd25519(SIGNING_DOMAINS.DELEGATION_V1, payload, FORGED_SIG, pem(h)), false, `delegation must reject ${h}`);
    assert.equal(verifyEd25519(SIGNING_DOMAINS.KRL_V1, payload, FORGED_SIG, pem(h)), false, `KRL must reject ${h}`);
  }
});

// ── 3. end-to-end across verifyAuthorization (flat Encoding A + nested Encoding B)
const NOW = 1_700_000_000;
const smallOrderKeySet = (kidHex: string): KeySet => ({
  issuer: "iss", version: "1",
  keys: [{ kid: "k1", alg: "Ed25519", public_key: pem(kidHex), status: "active" }],
});
const strict = (ks: KeySet[] | []) => ({ now: NOW, mode: "strict" as const, trustedKeySets: ks, requireSignatureVerification: true, expectedAudience: "aud" });
const forgedFlatAuth = (): any => ({
  version: "AuthorizationV1", auth_id: "a".repeat(64), issuer: "iss", audience: "aud",
  intent_hash: "b".repeat(64), state_hash: "c".repeat(64), policy_id: "d".repeat(64),
  decision: "ALLOW", issued_at: NOW - 5, expiry: NOW + 600, alg: "Ed25519", kid: "k1", signature: FORGED_SIG,
});
const forgedNestedAuth = (): any => ({
  ...forgedFlatAuth(), signature: { alg: "Ed25519", kid: "k1", sig: FORGED_SIG },
});

test("verifyAuthorization rejects a forged ALLOW under a trusted small-order key (flat + nested), message-independent", () => {
  for (const h of SMALL_ORDER_14) {
    const rFlat = verifyAuthorization(forgedFlatAuth(), strict([smallOrderKeySet(h)]) as never);
    assert.equal(rFlat.ok, false, `flat forged ALLOW must be rejected under ${h}`);
    assert.equal(rFlat.signatureVerified, false);
    const rNested = verifyAuthorization(forgedNestedAuth(), strict([smallOrderKeySet(h)]) as never);
    assert.equal(rNested.ok, false, `nested (Encoding-B) forged ALLOW must be rejected under ${h}`);
    // message-independence: changing a bound field must not make it verify either
    const rMut = verifyAuthorization({ ...forgedFlatAuth(), intent_hash: "9".repeat(64) }, strict([smallOrderKeySet(h)]) as never);
    assert.equal(rMut.ok, false, `mutated forged ALLOW must still be rejected under ${h}`);
  }
});

// ── 4-5. legitimate keys: valid signatures verify, invalid ones do not ─────────
const KP = generateKeyPairSync("ed25519", { publicKeyEncoding: { format: "pem", type: "spki" }, privateKeyEncoding: { format: "pem", type: "pkcs8" } });
test("legitimate key: isSmallOrderEd25519Pem is false and valid signatures still verify (no regression)", () => {
  assert.equal(isSmallOrderEd25519Pem(KP.publicKey), false);
  const payload = { hello: "world", n: 42 };
  const sig = signEd25519(SIGNING_DOMAINS.AUTH_V1, payload, KP.privateKey);
  assert.equal(verifyEd25519(SIGNING_DOMAINS.AUTH_V1, payload, sig, KP.publicKey), true, "valid signature must verify");
  assert.equal(verifyEd25519(SIGNING_DOMAINS.AUTH_V1, { hello: "world", n: 43 }, sig, KP.publicKey), false, "wrong payload must fail");
});
test("legitimate trusted key: a real signed authorization verifies; a forged small-order sig does not", () => {
  const KS: KeySet = { issuer: "iss", version: "1", keys: [{ kid: "k1", alg: "Ed25519", public_key: KP.publicKey, status: "active" }] };
  const signed = signAuthorizationEd25519(
    { version: "AuthorizationV1", auth_id: "a".repeat(64), issuer: "iss", audience: "aud", intent_hash: "b".repeat(64), state_hash: "c".repeat(64), policy_id: "d".repeat(64), decision: "ALLOW", issued_at: NOW - 5, expiry: NOW + 600, kid: "k1" },
    KP.privateKey,
  ) as AuthorizationV1;
  assert.equal(verifyAuthorization(signed, strict([KS]) as never).ok, true, "genuine authorization must verify");
  assert.equal(verifyAuthorization(forgedFlatAuth(), strict([KS]) as never).ok, false, "forged small-order sig under a normal key must fail");
});

// ── 6. untrusted / inactive keys remain fail-closed ───────────────────────────
test("untrusted, unknown-kid, and inactive keys remain fail-closed", () => {
  const signed = signAuthorizationEd25519(
    { version: "AuthorizationV1", auth_id: "a".repeat(64), issuer: "iss", audience: "aud", intent_hash: "b".repeat(64), state_hash: "c".repeat(64), policy_id: "d".repeat(64), decision: "ALLOW", issued_at: NOW - 5, expiry: NOW + 600, kid: "k1" },
    KP.privateKey,
  ) as AuthorizationV1;
  // no trust config
  const r0 = verifyAuthorization(signed, strict([]) as never);
  assert.equal(r0.ok, false);
  assert.ok(r0.violations.some((v) => v.code === "TRUSTED_KEYSETS_REQUIRED"));
  // unknown kid
  const otherKid: KeySet = { issuer: "iss", version: "1", keys: [{ kid: "OTHER", alg: "Ed25519", public_key: KP.publicKey, status: "active" }] };
  const r1 = verifyAuthorization(signed, strict([otherKid]) as never);
  assert.equal(r1.ok, false);
  assert.ok(r1.violations.some((v) => v.code === "AUTH_KID_UNKNOWN"));
  // inactive (revoked) key
  const revoked: KeySet = { issuer: "iss", version: "1", keys: [{ kid: "k1", alg: "Ed25519", public_key: KP.publicKey, status: "revoked" }] };
  const r2 = verifyAuthorization(signed, strict([revoked]) as never);
  assert.equal(r2.ok, false);
  assert.ok(r2.violations.some((v) => v.code === "AUTH_KEY_INACTIVE"));
});

// ── 7. S4 canonical-signature validation preserved under a legitimate key ──────
test("S4 canonical-signature validation is preserved (non-canonical sig rejected under a valid key)", () => {
  const payload = { s4: "preserved" };
  const sig = signEd25519(SIGNING_DOMAINS.AUTH_V1, payload, KP.privateKey);
  assert.equal(verifyEd25519(SIGNING_DOMAINS.AUTH_V1, payload, sig, KP.publicKey), true, "canonical sig verifies");
  assert.equal(verifyEd25519(SIGNING_DOMAINS.AUTH_V1, payload, sig + "\n", KP.publicKey), false, "trailing newline (non-canonical) rejected");
  assert.equal(verifyEd25519(SIGNING_DOMAINS.AUTH_V1, payload, "", KP.publicKey), false, "empty signature rejected");
});
