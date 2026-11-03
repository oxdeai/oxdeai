// S4 regression: Ed25519 signatures verify only in a canonical Base64 encoding.
// Encoding A = standard base64 (crypto verifyEd25519, used by delegation/envelope/
// KRL/auth-primary). Encoding B = base64url (auth fallback). Empty input included.
import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { signEd25519, verifyEd25519, SIGNING_DOMAINS } from "../crypto/signatures.js";
import { signAuthorizationEd25519, verifyAuthorization, canonicalSignatureBytes } from "../verification/verifyAuthorization.js";
import type { KeySet } from "../types/keyset.js";

const kp = generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
const dom = SIGNING_DOMAINS.AUTH_V1;
const payload = { a: 1, b: "x" };
const sigStd = signEd25519(dom, payload, kp.privateKey);
const raw = Buffer.from(sigStd, "base64");

// ── Encoding A: crypto verifyEd25519 (standard base64 only) ───────────────────
test("S4-A canonical standard signature verifies", () => {
  assert.equal(verifyEd25519(dom, payload, sigStd, kp.publicKey), true);
});
test("S4-A trailing whitespace is rejected", () => {
  assert.equal(verifyEd25519(dom, payload, sigStd + "\n", kp.publicKey), false);
});
test("S4-A mutated final character (same bytes) is rejected", () => {
  const ab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const ch = sigStd.split(""); let i = ch.length - 1; while (ch[i] === "=") i--;
  const idx = ab.indexOf(ch[i]); let mut: string | null = null;
  for (let d = 1; d < 64; d++) { const c = ab[(idx + d) % 64]; const t = ch.slice(); t[i] = c; const s = t.join(""); const b = Buffer.from(s, "base64"); if (b.length === 64 && Buffer.compare(b, raw) === 0 && s !== sigStd) { mut = s; break; } }
  assert.ok(mut, "constructed a non-canonical variant"); assert.equal(verifyEd25519(dom, payload, mut as string, kp.publicKey), false);
});
test("S4-A base64url form is rejected by the standard-only path", () => {
  assert.equal(verifyEd25519(dom, payload, raw.toString("base64url"), kp.publicKey), false);
});
test("S4-A empty string is rejected", () => {
  assert.equal(verifyEd25519(dom, payload, "", kp.publicKey), false);
});
test("S4-A wrong length (63/65 bytes) is rejected", () => {
  assert.equal(verifyEd25519(dom, payload, Buffer.alloc(63, 1).toString("base64"), kp.publicKey), false);
  assert.equal(verifyEd25519(dom, payload, Buffer.alloc(65, 1).toString("base64"), kp.publicKey), false);
});
test("S4-A a tampered payload still fails (no regression)", () => {
  assert.equal(verifyEd25519(dom, { a: 2, b: "x" }, sigStd, kp.publicKey), false);
});

// ── Encoding B: authorization accepts canonical base64url, rejects non-canonical ─
const KS: KeySet = { issuer: "iss", version: "1", keys: [{ kid: "k1", alg: "Ed25519", public_key: kp.publicKey.toString(), status: "active" }] };
const NOW = Math.floor(Date.now() / 1000);
const action = { type: "EXECUTE", tool: "t", params: { amount: 1 } };
function signedAuth() {
  return signAuthorizationEd25519({ auth_id: "a1", issuer: "iss", audience: "aud", intent_hash: "0".repeat(64), state_hash: "0".repeat(64), policy_id: "p1", decision: "ALLOW", issued_at: NOW - 5, expiry: NOW + 600, kid: "k1" }, kp.privateKey) as any;
}
const vopts = { now: NOW, mode: "strict" as const, trustedKeySets: [KS], requireSignatureVerification: true, expectedAudience: "aud" } as any;

test("S4-B canonical standard authorization verifies ok", () => {
  const a = signedAuth();
  assert.equal(verifyAuthorization(a, vopts).ok, true);
});
// Encoding B (base64url) acceptance is a per-encoding canonical rule in the
// authorization fallback. Proven directly on canonicalSignatureBytes (the
// fallback's decoder) because a valid Encoding-B signature uses a different
// (domain-less) preimage that cannot be synthesised from an Encoding-A artifact.
test("S4-B canonicalSignatureBytes accepts canonical standard AND canonical base64url of 64 bytes", () => {
  const stdCanon = raw.toString("base64");       // padded, 88 chars
  const urlCanon = raw.toString("base64url");     // unpadded, 86 chars
  assert.notEqual(stdCanon, urlCanon);
  assert.ok(canonicalSignatureBytes(stdCanon) !== null, "canonical standard accepted");
  assert.ok(canonicalSignatureBytes(urlCanon) !== null, "canonical base64url accepted (Encoding B preserved)");
  // Encoding-A rule is NOT applied to an Encoding-B string: the base64url form
  // is accepted as base64url, not rejected for lacking standard padding.
});
test("S4-B canonicalSignatureBytes rejects non-canonical and malformed encodings", () => {
  const stdCanon = raw.toString("base64");
  const urlCanon = raw.toString("base64url");
  assert.equal(canonicalSignatureBytes(stdCanon + "\n"), null, "trailing newline");
  assert.equal(canonicalSignatureBytes(urlCanon + "A"), null, "extra char (wrong length)");
  // A base64url string that contains url-specific chars ('-'/'_'), padded with '=',
  // is canonical under NEITHER alphabet, so it is rejected. Use a fixed 64-byte value
  // (all 0xff) whose base64url is guaranteed to contain '_'; a random signature's
  // base64url sometimes has no url-specific char, in which case url+"==" IS the
  // canonical standard encoding and is (correctly) accepted - that is not the case here.
  const urlSpecial = Buffer.alloc(64, 0xff).toString("base64url");
  assert.ok(/[-_]/.test(urlSpecial), "fixture contains a url-specific char");
  assert.equal(canonicalSignatureBytes(urlSpecial + "=="), null, "padded base64url is non-canonical");
  assert.equal(canonicalSignatureBytes(""), null, "empty string");
  assert.equal(canonicalSignatureBytes(Buffer.alloc(63, 1).toString("base64")), null, "short");
  assert.equal(canonicalSignatureBytes(Buffer.alloc(65, 1).toString("base64")), null, "long");
});
test("S4-B non-canonical standard (trailing newline) authorization is rejected", () => {
  const a = signedAuth();
  a.signature = a.signature + "\n";
  assert.equal(verifyAuthorization(a, vopts).ok, false);
});
test("S4-B empty signature authorization is rejected", () => {
  const a = signedAuth(); a.signature = "";
  assert.equal(verifyAuthorization(a, vopts).ok, false);
});

// ── Encoding B END-TO-END through verifyAuthorization ─────────────────────────
// A real Encoding-B signature is over the DOMAIN-LESS preimage
// canonicalJson(authorizationSigningPayload(auth)) consumed by verifyEd25519Raw,
// in nested-signature form. We sign that exact preimage with node:crypto and run
// it through verifyAuthorization to prove canonical base64url is accepted and
// non-canonical is rejected - without altering production behavior.
import { sign as nodeSign } from "node:crypto";
import { canonicalJson } from "../crypto/hashes.js";
import { authorizationSigningPayload } from "../verification/verifyAuthorization.js";

let encBAuthId = "b1";
function nestedAuth(sigEncoded: string): any {
  return {
    auth_id: encBAuthId, issuer: "iss", audience: "aud", intent_hash: "0".repeat(64),
    state_hash: "0".repeat(64), policy_id: "p1", decision: "ALLOW",
    issued_at: NOW - 5, expiry: NOW + 600, alg: "Ed25519", kid: "k1",
    signature: { alg: "Ed25519", kid: "k1", sig: sigEncoded },
  };
}
// Select a valid signature containing a base64url-specific character.
// Otherwise, adding "==" may produce canonical standard base64.
let encBRaw: Buffer | undefined;
for (let i = 0; i < 1000; i++) {
  encBAuthId = `b1-${i}`;
  const payload = authorizationSigningPayload(nestedAuth(""));
  const preimage = Buffer.from(canonicalJson(payload), "utf8");
  const candidate = nodeSign(null, preimage, kp.privateKey);
  if (/[-_]/.test(candidate.toString("base64url"))) {
    encBRaw = candidate;
    break;
  }
}
assert.ok(encBRaw, "could not construct Encoding-B signature with URL-specific characters");

test("S4-B e2e: canonical base64url Encoding-B signature verifies via verifyAuthorization", () => {
  const r = verifyAuthorization(nestedAuth(encBRaw.toString("base64url")), vopts);
  assert.equal(r.ok, true, "canonical base64url Encoding-B must verify");
  assert.equal(r.signatureVerified, true);
});
test("S4-B e2e: canonical standard Encoding-B signature also verifies", () => {
  const r = verifyAuthorization(nestedAuth(encBRaw.toString("base64")), vopts);
  assert.equal(r.ok, true);
});
test("S4-B e2e: non-canonical base64url (extra char) Encoding-B is rejected", () => {
  const r = verifyAuthorization(nestedAuth(encBRaw.toString("base64url") + "A"), vopts);
  assert.equal(r.ok, false);
});
test("S4-B e2e: padded base64url Encoding-B (non-canonical) is rejected", () => {
  const r = verifyAuthorization(nestedAuth(encBRaw.toString("base64url") + "=="), vopts);
  assert.equal(r.ok, false);
});
test("S4-B e2e: trailing-newline Encoding-B is rejected", () => {
  const r = verifyAuthorization(nestedAuth(encBRaw.toString("base64") + "\n"), vopts);
  assert.equal(r.ok, false);
});
