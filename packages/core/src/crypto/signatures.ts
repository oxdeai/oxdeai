// SPDX-License-Identifier: Apache-2.0
import { createPrivateKey, createPublicKey, createHmac, sign, verify, timingSafeEqual } from "node:crypto";
import { canonicalJson } from "./hashes.js";
import type { KeySet, KeySetKey, SignatureAlgorithm } from "../types/keyset.js";

/** @public */
export const SIGNING_DOMAINS = {
  AUTH_V1:      "OXDEAI_AUTH_V1",
  ENVELOPE_V1:  "OXDEAI_ENVELOPE_V1",
  CHECKPOINT_V1: "OXDEAI_CHECKPOINT_V1",
  DELEGATION_V1: "OXDEAI_DELEGATION_V1",
  KRL_V1:       "OXDEAI_KRL_V1",
} as const;

/** @public */
export type SigningDomain = (typeof SIGNING_DOMAINS)[keyof typeof SIGNING_DOMAINS];

function canonicalBytes(payload: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJson(payload));
}

/** @public */
export function signatureInput(domain: SigningDomain, payload: unknown): Uint8Array {
  const prefix = new TextEncoder().encode(`${domain}\n`);
  const body = canonicalBytes(payload);
  const out = new Uint8Array(prefix.length + body.length);
  out.set(prefix, 0);
  out.set(body, prefix.length);
  return out;
}

function normalizePem(key: string): string {
  return key.includes("BEGIN") ? key : Buffer.from(key, "base64").toString("utf8");
}

/** @public */
export function signEd25519(domain: SigningDomain, payload: unknown, privateKeyPem: string): string {
  const key = createPrivateKey(normalizePem(privateKeyPem));
  const sig = sign(null, signatureInput(domain, payload), key);
  return sig.toString("base64");
}

/** @public */
export function verifyEd25519(
  domain: SigningDomain,
  payload: unknown,
  signatureBase64: string,
  publicKeyPem: string
): boolean {
  try {
    if (typeof signatureBase64 !== "string") return false;
    const sig = Buffer.from(signatureBase64, "base64");
    // S4: accept only the canonical standard-Base64 (Encoding A) encoding of an
    // exactly-64-byte Ed25519 signature. A lenient decode would admit several
    // distinct strings for the same bytes (trailing whitespace, a mutated final
    // character whose unused low bits differ, base64url with '-'/'_'); require
    // the supplied string to equal the standard re-encoding of the decoded bytes
    // and reject everything else. Fail closed (return false), never throw.
    // Note: this path is standard-Base64 only; the base64url (Encoding B)
    // tolerance lives in verifyAuthorization's verifyEd25519Raw, canonicalised
    // per-encoding there.
    if (sig.length !== 64 || sig.toString("base64") !== signatureBase64) return false;
    const key = createPublicKey(normalizePem(publicKeyPem));
    return verify(null, signatureInput(domain, payload), key, sig);
  } catch {
    return false;
  }
}

/** @public */
export function signHmacDomain(domain: SigningDomain, payload: unknown, secret: string): string {
  const msg = Buffer.from(signatureInput(domain, payload));
  return createHmac("sha256", secret).update(msg).digest("hex");
}

/** @public */
export function verifyHmacDomain(
  domain: SigningDomain,
  payload: unknown,
  signatureHex: string,
  secret: string
): boolean {
  try {
    const expected = signHmacDomain(domain, payload, secret);
    const a = Buffer.from(expected, "hex");
    const b = Buffer.from(signatureHex, "hex");
    if (a.length === 0 || a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/** @public */
export function findKeyInKeySets(
  keysets: readonly KeySet[],
  issuer: string,
  kid: string,
  alg: SignatureAlgorithm
): KeySetKey | undefined {
  const ks = keysets.find((k) => k.issuer === issuer);
  if (!ks) return undefined;
  return ks.keys.find((k) => k.kid === kid && k.alg === alg);
}

/** @public */
export function keyIsActiveAt(key: KeySetKey, now: number): boolean {
  if (key.status === "revoked") return false;
  if (key.not_before !== undefined && now < key.not_before) return false;
  if (key.not_after !== undefined && now > key.not_after) return false;
  return true;
}
