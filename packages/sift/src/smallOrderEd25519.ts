// SPDX-License-Identifier: Apache-2.0
//
// S3-R2: reject Ed25519 small-order (low-order-subgroup) public keys before any
// signature verification in Sift's receipt path. A small-order key authenticates
// nothing - a crafted signature verifies against ANY message - so such a key in
// the Sift JWKS (or supplied directly) would let anyone forge an ALLOW receipt.
//
// This is a deliberate, self-contained copy of the complete small-order
// wire-encoding set used by @oxdeai/core's verification guard. Sift has no
// dependency on @oxdeai/core, and exposing core's internal guard would change
// core's public API, so the set is duplicated here. Drift is caught by two tests:
// test/smallOrderEd25519.core-equivalence.test.ts reads core's table from
// packages/core/src/crypto/signatures.ts and asserts set equality with this one,
// and test/verifyReceipt.s3-small-order.test.ts re-derives the 14 encodings from
// the 8 subgroup points and asserts equality with this one.
//
// The Edwards25519 small subgroup has exactly 8 points; across canonical and
// non-canonical wire encodings (sign-bit variant for the x=0 points; the `y + p`
// alternate for points with y < 19) there are 14 encodings, all accepted by
// OpenSSL without normalisation. The comparison is therefore against the raw
// 32-byte wire encoding (JWK `x`), not a re-canonicalised form.
import { createPublicKey } from "node:crypto";

/** Complete small-order Ed25519 public-key wire encodings (32-byte LE, hex). */
export const SMALL_ORDER_ED25519: ReadonlySet<string> = new Set([
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
]);

/**
 * The 32-byte Ed25519 public-key wire encoding (little-endian, as transmitted)
 * from a parsed key, or null if the key is not a usable Ed25519 public key. JWK
 * `x` preserves the exact wire bytes, including non-canonical ones.
 */
export function ed25519WireHex(key: ReturnType<typeof createPublicKey>): string | null {
  const jwk = key.export({ format: "jwk" }) as { kty?: string; crv?: string; x?: string };
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") return null;
  const raw = Buffer.from(jwk.x, "base64url");
  return raw.length === 32 ? raw.toString("hex") : null;
}

/**
 * True if the parsed key is an Ed25519 small-order public key, or is unreadable
 * as an Ed25519 public key. Fail closed: callers must treat `true` as "do not
 * trust any signature under this key".
 */
export function isSmallOrderEd25519Key(key: ReturnType<typeof createPublicKey>): boolean {
  try {
    const hex = ed25519WireHex(key);
    return hex === null ? true : SMALL_ORDER_ED25519.has(hex);
  } catch {
    return true;
  }
}
