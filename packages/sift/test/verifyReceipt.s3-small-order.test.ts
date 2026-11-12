// SPDX-License-Identifier: Apache-2.0
//
// S3-R2: Sift receipt-verification small-order Ed25519 rejection. A small-order
// public key authenticates nothing, so a forged ALLOW receipt must never be
// accepted under one, whether supplied as PEM or raw. These assert actual
// verification results (not key parsing), and discriminate against the baseline.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { verifyReceipt } from "../src/verifyReceipt.js";
import { SMALL_ORDER_ED25519 } from "../src/smallOrderEd25519.js";

// ── canonical JSON + receipt helpers (mirror verifyReceipt.property.test.ts) ──
function canonicalize(value: unknown): unknown {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as object).sort()) out[k] = canonicalize((value as Record<string, unknown>)[k]);
    return out;
  }
  return value;
}
const canonicalBytes = (v: unknown) => Buffer.from(JSON.stringify(canonicalize(v)), "utf-8");
const computeHash = (receipt: Record<string, unknown>) => {
  const { signature: _s, receipt_hash: _h, ...payload } = receipt;
  return createHash("sha256").update(canonicalBytes(payload)).digest("hex");
};
const FIXED_NOW = new Date("2026-04-14T12:00:00.000Z");
const BASELINE_TS = FIXED_NOW.toISOString();

function baseReceipt(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    receipt_version: "1.0", tenant_id: "tenant-test", agent_id: "agent-test",
    action: "transfer_funds", tool: "payments_api", decision: "ALLOW", risk_tier: 1,
    timestamp: BASELINE_TS, nonce: "11111111-1111-1111-1111-111111111111",
    policy_matched: "payments-policy-v1", ...overrides,
  };
}
// A receipt whose body + receipt_hash are well-formed (passes integrity) but
// whose signature is the universal small-order forgery R=identity,S=0.
const FORGED_SIG_B64URL = Buffer.concat([
  Buffer.from("0100000000000000000000000000000000000000000000000000000000000000", "hex"),
  Buffer.alloc(32, 0),
]).toString("base64url"); // 86 base64url chars
function forgedReceipt(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const base = baseReceipt(overrides);
  const withHash = { ...base, receipt_hash: computeHash(base) };
  return { ...withHash, signature: FORGED_SIG_B64URL };
}

const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const smallOrderPem = (hex: string) =>
  `-----BEGIN PUBLIC KEY-----\n${Buffer.concat([SPKI_PREFIX, Buffer.from(hex, "hex")]).toString("base64").replace(/(.{64})/g, "$1\n")}\n-----END PUBLIC KEY-----\n`;
const smallOrderRaw = (hex: string) => Buffer.from(hex, "hex").toString("base64url"); // publicKeyFromRaw accepts base64url

// ── 1-3. all 14 small-order encodings rejected via PEM and raw, forged ALLOW ──
test("S3-R2: forged ALLOW receipt rejected under every small-order key (PEM and raw)", () => {
  for (const hex of SMALL_ORDER_ED25519) {
    const rPem = verifyReceipt(forgedReceipt(), { publicKeyPem: smallOrderPem(hex), now: FIXED_NOW });
    assert.equal(rPem.ok, false, `PEM small-order ${hex} must reject forged receipt`);
    assert.equal(rPem.code, "UNSUPPORTED_PUBLIC_KEY", `PEM ${hex} must fail with UNSUPPORTED_PUBLIC_KEY, got ${rPem.code}`);

    const rRaw = verifyReceipt(forgedReceipt(), { publicKeyRaw: smallOrderRaw(hex), now: FIXED_NOW });
    assert.equal(rRaw.ok, false, `raw small-order ${hex} must reject forged receipt`);
    assert.equal(rRaw.code, "UNSUPPORTED_PUBLIC_KEY", `raw ${hex} must fail with UNSUPPORTED_PUBLIC_KEY, got ${rRaw.code}`);
  }
});
test("S3-R2: rejection is message-independent (changing a bound field still rejects)", () => {
  for (const hex of SMALL_ORDER_ED25519) {
    const r = verifyReceipt(forgedReceipt({ action: "drain_account", risk_tier: 4 }), { publicKeyPem: smallOrderPem(hex), now: FIXED_NOW });
    assert.equal(r.ok, false, `mutated forged receipt must still reject under ${hex}`);
  }
});

// ── 4-5. legitimate key: valid verifies, tampered rejected (no regression) ────
function makeKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKeyPem: publicKey, privateKeyPem: privateKey };
}
function signedReceipt(kp: { privateKeyPem: string }, overrides: Record<string, unknown> = {}) {
  const base = baseReceipt(overrides);
  const withHash = { ...base, receipt_hash: computeHash(base) };
  const signature = cryptoSign(null, canonicalBytes(withHash), kp.privateKeyPem).toString("base64");
  return { ...withHash, signature };
}
test("S3-R2: legitimate signed receipt still verifies; tampered signature rejected (no regression)", () => {
  const kp = makeKeyPair();
  const ok = verifyReceipt(signedReceipt(kp), { publicKeyPem: kp.publicKeyPem, now: FIXED_NOW });
  assert.equal(ok.ok, true, `genuine receipt must verify; got ${JSON.stringify(ok)}`);
  // tamper the signature (flip one base64url char) -> invalid signature, not accepted
  const receipt = signedReceipt(kp);
  const sig = receipt.signature as string;
  receipt.signature = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
  const bad = verifyReceipt(receipt, { publicKeyPem: kp.publicKeyPem, now: FIXED_NOW });
  assert.equal(bad.ok, false, "tampered signature must be rejected");
});

// ── 6. malformed / missing key: fail closed ──────────────────────────────────
test("S3-R2: malformed and missing public keys fail closed", () => {
  const r1 = verifyReceipt(forgedReceipt(), { publicKeyPem: "-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----\n", now: FIXED_NOW } as never);
  assert.equal(r1.ok, false);
  const r2 = verifyReceipt(forgedReceipt(), { now: FIXED_NOW } as never);
  assert.equal(r2.ok, false);
  assert.equal(r2.code, "UNSUPPORTED_PUBLIC_KEY");
});

// ── 9. receipt-binding + expiration preserved (guard did not break checks) ────
test("S3-R2: receipt-hash binding and freshness checks still enforced (legitimate key)", () => {
  const kp = makeKeyPair();
  // wrong receipt_hash -> integrity failure (not accepted), proving binding intact
  const tampered = signedReceipt(kp);
  tampered.receipt_hash = "0".repeat(64);
  assert.equal(verifyReceipt(tampered, { publicKeyPem: kp.publicKeyPem, now: FIXED_NOW }).ok, false, "bad receipt_hash must reject");
  // stale timestamp with a tight maxAge -> freshness rejection still works
  const stale = verifyReceipt(signedReceipt(kp), { publicKeyPem: kp.publicKeyPem, now: new Date("2027-01-01T00:00:00Z"), maxAgeMs: 60000 } as never);
  assert.equal(stale.ok, false, "stale receipt must reject under maxAgeMs");
});

// ── equivalence: Sift's blocklist is exactly the independently-derived 14 ─────
// Re-derive from the 8 canonical small-order points (both sign bits; y+p when it
// still fits in 255 bits). This pins Sift's set to the same mathematical set as
// @oxdeai/core's guard; either set drifting from the true 14 fails this test.
// (Core's identical 14 is independently confirmed by the S3-R1 crypto review's
// compare_blocklist.py: 0 missing, 0 unexpected.)
test("S3-R2: Sift small-order set equals the derived 14 (Core/Sift equivalence)", () => {
  const P = (1n << 255n) - 19n;
  const toLE = (y: bigint, sign: number) => {
    const b = Buffer.alloc(32); let v = y;
    for (let i = 0; i < 32; i++) { b[i] = Number(v & 0xffn); v >>= 8n; }
    if (sign) b[31] |= 0x80;
    return b.toString("hex");
  };
  const parseY = (h: string) => { const b = Buffer.from(h, "hex"); const c = Buffer.from(b); c[31] &= 0x7f; let y = 0n; for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(c[i]); return y; };
  const CANON8 = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  ];
  const derived = new Set<string>();
  for (const h of CANON8) { const y = parseY(h); const ys = y + P < (1n << 255n) ? [y, y + P] : [y]; for (const yy of ys) for (const s of [0, 1]) derived.add(toLE(yy, s)); }
  assert.equal(derived.size, 14, "derivation must yield exactly 14");
  assert.deepEqual([...SMALL_ORDER_ED25519].sort(), [...derived].sort(), "Sift blocklist must equal the derived 14");
});
