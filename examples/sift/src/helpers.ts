// SPDX-License-Identifier: Apache-2.0
/**
 * Self-contained helpers for the Sift integration demo.
 *
 * Updated to match the live Sift staging verifier contract:
 *   - ensure_ascii=True canonicalization (Python json.dumps equivalent)
 *   - base64url-no-padding signatures
 *   - raw 32-byte Ed25519 public keys (JWKS `x` field format)
 *
 * Only public types are imported from @oxdeai/sift, plus one internal module:
 * the S3 small-order public-key guard (smallOrderEd25519.js), reused so the
 * 14-entry blocklist is not duplicated here.
 *
 * Preimage conventions matching packages/sift/src/verifyReceipt.ts:
 *
 *   receipt_hash preimage:  canonical( receipt  MINUS  signature  AND  receipt_hash )
 *   receipt signature:      canonical( receipt  MINUS  signature,  WITH receipt_hash )
 *
 * Preimage convention matching packages/sift/src/receiptToAuthorization.ts:
 *
 *   authorization signature:  canonical( signingPayload )
 *                             where signingPayload = authorization WITHOUT signature.sig
 *                             (signature.alg and signature.kid ARE present)
 */

import {
  createPublicKey,
  generateKeyPairSync,
  sign as nodeCryptoSign,
  verify as nodeCryptoVerify,
  createHash,
  randomUUID,
} from "node:crypto";
import type {
  SiftDecision,
  OxDeAIIntent,
  NormalizedState,
  AuthorizationV1Payload,
  SigningPayload,
} from "@oxdeai/sift";
import { isSmallOrderEd25519Key } from "@oxdeai/sift/dist/src/smallOrderEd25519.js";

// ─── Canonical JSON with ensure_ascii ────────────────────────────────────────
//
// Matches packages/sift/src/siftCanonical.ts exactly:
//   json.dumps(payload, sort_keys=True, separators=(",",":"), ensure_ascii=True)
//
// This is the function that hashes computed here (intent_hash, state_hash,
// receipt_hash) match those computed inside the @oxdeai/sift package.

type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [k: string]: JsonValue };

function canonicalize(value: unknown): JsonValue {
  if (value === null || value === undefined) return null;
  if (typeof value === "boolean") return value;
  if (typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError(`Non-finite number: ${value}`);
    return value;
  }
  if (Array.isArray(value)) return (value as unknown[]).map(canonicalize);
  if (typeof value === "object") {
    const keys = Object.keys(value as object).sort();
    const out = Object.create(null) as { [k: string]: JsonValue };
    for (const k of keys) out[k] = canonicalize((value as Record<string, unknown>)[k]);
    return out;
  }
  throw new TypeError(`Unsupported type: ${typeof value}`);
}

/**
 * Applies Python ensure_ascii=True semantics: every UTF-16 code unit above
 * U+007F is escaped as \uXXXX.  Supplementary characters (U+10000+) are
 * encoded as UTF-16 surrogate pairs, each individually escaped — matching
 * Python's behavior exactly.
 */
function applyEnsureAscii(json: string): string {
  let out = "";
  for (let i = 0; i < json.length; i++) {
    const code = json.charCodeAt(i);
    if (code > 0x7f) {
      out += "\\u" + code.toString(16).padStart(4, "0");
    } else {
      out += json[i];
    }
  }
  return out;
}

/**
 * UTF-8 bytes of the Sift-canonical JSON encoding of `value`.
 * Equivalent to Python:
 *   json.dumps(value, sort_keys=True, separators=(",",":"), ensure_ascii=True).encode("utf-8")
 */
export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(applyEnsureAscii(JSON.stringify(canonicalize(value))), "utf-8");
}

/** SHA-256 lowercase hex of `data`. */
export function sha256Hex(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/** SHA-256 lowercase hex of Sift-canonical JSON of `value`. */
export function canonicalHash(value: unknown): string {
  return sha256Hex(canonicalBytes(value));
}

// ─── base64url helpers ────────────────────────────────────────────────────────

/** Encodes a Buffer to base64url without padding (RFC 4648 §5). */
export function b64uEncode(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * Decodes a base64url-no-padding string to a Buffer.
 * Also accepts standard base64 input (normalises + → - and / → _ before
 * decoding) so both encodings produce identical bytes.
 */
export function b64uDecode(s: string): Buffer {
  const normalized = s
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
  return Buffer.from(normalized, "base64url");
}

// ─── Raw Ed25519 key import ───────────────────────────────────────────────────

// Ed25519 SPKI DER prefix (12 bytes):  30 2a 30 05 06 03 2b 65 70 03 21 00
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Creates a Node.js KeyObject from a raw 32-byte Ed25519 public key buffer. */
function publicKeyObjectFromRaw(raw: Buffer): ReturnType<typeof createPublicKey> {
  if (raw.length !== 32) {
    throw new TypeError(`Ed25519 public key must be 32 bytes, got ${raw.length}`);
  }
  const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

// ─── JWKS x decode helper ─────────────────────────────────────────────────────

/**
 * Decodes a JWKS `x` field value (base64url-no-padding) into a raw 32-byte
 * Ed25519 public key.
 *
 * In production the `x` value is fetched from the Sift JWKS endpoint.  The
 * caller then selects the entry whose `kid` matches the receipt's `kid` field
 * (and checks the KRL before trusting it).  Here the value is an inline demo
 * constant — no network call needed.
 *
 * Example JWKS entry shape (RFC 8037 OKP):
 *   {
 *     "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA",
 *     "use": "sig", "kid": "<key-id>", "x": "<base64url-raw-key>"
 *   }
 */
export function decodeJwksX(x: string): Buffer {
  const raw = b64uDecode(x);
  if (raw.length !== 32) {
    throw new TypeError(`JWKS x must decode to 32 bytes, got ${raw.length}`);
  }
  return raw;
}

// ─── Ed25519 key management ───────────────────────────────────────────────────

export interface DemoKeyPair {
  /** Raw 32-byte Ed25519 public key — what a JWKS `x` field encodes. */
  publicKeyRaw: Buffer;
  /**
   * Base64url-no-padding encoding of publicKeyRaw.
   * This is the `x` field value a JWKS endpoint would serve for this key.
   */
  publicKeyJwksX: string;
  /** PEM-encoded PKCS8 private key — used by Node.js signing helpers. */
  privateKeyPem: string;
}

export function makeKeyPair(): DemoKeyPair {
  // Generate as KeyObjects and export in the formats we need.
  const { publicKey: pubObj, privateKey: privObj } = generateKeyPairSync("ed25519");

  // Extract raw 32-byte key by stripping the 12-byte SPKI DER header.
  const spkiDer = pubObj.export({ type: "spki", format: "der" }) as Buffer;
  const publicKeyRaw = spkiDer.subarray(ED25519_SPKI_PREFIX.length); // last 32 bytes

  return {
    publicKeyRaw,
    publicKeyJwksX: b64uEncode(publicKeyRaw),
    privateKeyPem: privObj.export({ type: "pkcs8", format: "pem" }) as string,
  };
}

// ─── Signing and verification ─────────────────────────────────────────────────

/**
 * Signs Sift-canonical JSON bytes of `value` with the given Ed25519 private key.
 * Returns the signature as base64url without padding.
 */
export function signCanonical(value: unknown, privateKeyPem: string): string {
  return b64uEncode(nodeCryptoSign(null, canonicalBytes(value), privateKeyPem));
}

/**
 * Verifies an Ed25519 signature over Sift-canonical JSON bytes of `value`.
 *
 * `sigB64U` may be base64url-no-padding (Sift-native) or standard base64;
 * both are decoded to the same bytes.
 * `publicKeyRaw` is a raw 32-byte Buffer (JWKS `x` decoded).
 *
 * Returns false on any error rather than throwing, and for an Ed25519
 * small-order public key (S3: such a key authenticates nothing).
 */
export function verifyCanonical(
  value: unknown,
  sigB64U: string,
  publicKeyRaw: Buffer
): boolean {
  try {
    const pubKey = publicKeyObjectFromRaw(publicKeyRaw);
    // S3-R3: reject small-order keys on the exact KeyObject passed to verify.
    // Covers the Sift staging artifact check (liveStaging.ts) and pepVerify.
    if (isSmallOrderEd25519Key(pubKey)) return false;
    const sigBytes = b64uDecode(sigB64U);
    return nodeCryptoVerify(null, canonicalBytes(value), pubKey, sigBytes);
  } catch {
    return false;
  }
}

// ─── Mock Sift receipt builder ────────────────────────────────────────────────
//
// Produces a structurally valid receipt with a correctly-computed receipt_hash
// and a real Ed25519 signature using the Sift contract wire format.
//
// Preimage order (must match packages/sift/src/verifyReceipt.ts):
//   ① Build body (no receipt_hash, no signature)
//   ② receipt_hash = sha256( sift_canonical( ① ) )
//   ③ signed payload = ① + receipt_hash   (signature field absent)
//   ④ signature = sign( sift_canonical( ③ ) )   — base64url, no padding

export interface BuildReceiptOptions {
  decision: SiftDecision;
  keypair: DemoKeyPair;
  nonce?: string;
  tool?: string;
  action?: string;
  now?: Date;
}

export function buildMockReceipt(opts: BuildReceiptOptions): Record<string, unknown> {
  const {
    decision,
    keypair,
    nonce = randomUUID(),
    tool = "query_database",
    action = "call_tool",
    now = new Date(),
  } = opts;

  // ① Receipt body — no receipt_hash, no signature.
  const base = {
    receipt_version: "1.0",
    tenant_id: "demo-tenant",
    agent_id: "demo-agent",
    action,
    tool,
    decision,
    risk_tier: 1,
    timestamp: now.toISOString(),
    nonce,
    policy_matched: "policy-tools-v1",
  };

  // ② receipt_hash = SHA-256( sift_canonical( body ) )
  const receipt_hash = canonicalHash(base);

  // ③ Signed payload = body + receipt_hash  (signature still absent)
  const withHash = { ...base, receipt_hash };

  // ④ signature = sign( sift_canonical( ③ ) )  → base64url, no padding
  const signature = signCanonical(withHash, keypair.privateKeyPem);

  return { ...withHash, signature };
}

// ─── Authorization signing ────────────────────────────────────────────────────
//
// Fills the `sig` placeholder in authorization.signature by signing the
// signingPayload returned by receiptToAuthorization.
//
// The signingPayload is the correct preimage — it is the full authorization
// with signature.sig intentionally absent (signature.alg and signature.kid
// ARE present, as required by the contract).

export function signAuthorization(
  authorization: AuthorizationV1Payload,
  signingPayload: SigningPayload,
  issuerPrivateKeyPem: string
): AuthorizationV1Payload {
  const sig = signCanonical(signingPayload, issuerPrivateKeyPem);
  return { ...authorization, signature: { ...authorization.signature, sig } };
}

// ─── PEP simulation ───────────────────────────────────────────────────────────
//
// A minimal local Policy Enforcement Point.
//
// Sift is the decision layer — it evaluates policy and issues a receipt.
// OxDeAI is the authorization and enforcement boundary — it constructs a
// signed AuthorizationV1 artifact from the verified receipt, then the PEP
// enforces it here.
//
// This demo does not implement JWKS fetching or KRL checks.  In production:
//   - the issuer's kid is looked up in a JWKS endpoint
//   - the KRL is checked before trusting any key
//   - unknown kids trigger a JWKS refresh before failing
//
// Checks performed in order:
//   1. Audience exact match
//   2. Expiry (expires_at > floor(now / 1000))
//   3. Ed25519 signature on reconstructed signingPayload
//      (signature.alg and signature.kid included; signature.sig omitted)
//   4. intent_hash matches the provided intent
//   5. state_hash matches the provided state
//   6. Replay: auth_id must not have been seen before

export type PepResult =
  | { ok: true;  decision: "ALLOW"; executed: true;  auth_id: string }
  | { ok: false; decision: "DENY";  executed: false; reason: string };

// In-memory replay store — scoped to this demo process.
const pepReplayStore = new Set<string>();

export interface PepVerifyInput {
  authorization: AuthorizationV1Payload;
  intent: OxDeAIIntent;
  state: NormalizedState;
  audience: string;
  /**
   * Raw 32-byte Ed25519 public key for the issuer.
   * In production this is obtained by decoding the JWKS `x` field for the
   * matching `kid`, after consulting the KRL.
   */
  issuerPublicKeyRaw: Buffer;
  now: Date;
}

export function pepVerify(input: PepVerifyInput): PepResult {
  const { authorization, intent, state, audience, issuerPublicKeyRaw, now } = input;

  // 1. Audience
  if (authorization.audience !== audience) {
    return { ok: false, decision: "DENY", executed: false, reason: "AUDIENCE_MISMATCH" };
  }

  // 2. Expiry
  const nowSec = Math.floor(now.getTime() / 1000);
  if (authorization.expires_at <= nowSec) {
    return { ok: false, decision: "DENY", executed: false, reason: "EXPIRED" };
  }

  // 3. Signature — reconstruct signing payload (authorization without signature.sig).
  //    signature.alg and signature.kid are present; signature.sig is absent.
  //    This must produce the same canonical bytes that were signed by the issuer.
  const signingPayload: SigningPayload = {
    version:     authorization.version,
    auth_id:     authorization.auth_id,
    issuer:      authorization.issuer,
    audience:    authorization.audience,
    decision:    authorization.decision,
    intent_hash: authorization.intent_hash,
    state_hash:  authorization.state_hash,
    policy_id:   authorization.policy_id,
    issued_at:   authorization.issued_at,
    expires_at:  authorization.expires_at,
    signature: {
      alg: authorization.signature.alg,
      kid: authorization.signature.kid,
      // sig intentionally absent — this is the preimage
    },
  };
  if (!verifyCanonical(signingPayload, authorization.signature.sig, issuerPublicKeyRaw)) {
    return { ok: false, decision: "DENY", executed: false, reason: "INVALID_SIGNATURE" };
  }

  // 4. Intent hash — recompute from the provided intent and compare.
  if (authorization.intent_hash !== canonicalHash(intent)) {
    return { ok: false, decision: "DENY", executed: false, reason: "INTENT_HASH_MISMATCH" };
  }

  // 5. State hash — recompute from the provided state and compare.
  if (authorization.state_hash !== canonicalHash(state)) {
    return { ok: false, decision: "DENY", executed: false, reason: "STATE_HASH_MISMATCH" };
  }

  // 6. Replay — the auth_id must be consumed exactly once.
  if (pepReplayStore.has(authorization.auth_id)) {
    return { ok: false, decision: "DENY", executed: false, reason: "REPLAY" };
  }
  pepReplayStore.add(authorization.auth_id);

  return { ok: true, decision: "ALLOW", executed: true, auth_id: authorization.auth_id };
}
