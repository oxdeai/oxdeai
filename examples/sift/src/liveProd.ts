// SPDX-License-Identifier: Apache-2.0
/**
 * Live Sift production network helpers.
 *
 * Responsibility: all network I/O for the prod path, nothing else.
 * run-prod.ts imports these and drives the adapter/PEP pipeline.
 *
 * Network path:
 *   fetchProdChallenge()     — POST /api/v1/auth/challenge → nonce
 *   buildProdAuthorizeRequest() — build + sign request body
 *   callProdAuthorize()      — POST /api/v1/authorize with X-Sift-Tenant header
 *   extractRawReceipt()      — unwrap Sift receipt from response JSON
 *   fetchProdVerifyKey()     — GET /api/v1/receipt/verify-key → Ed25519 public key bytes
 *
 * Adapter and PEP enforcement live in run-prod.ts, not here.
 *
 * ── Canonicalization note ──────────────────────────────────────────────────
 *
 * Sift request signing:  sorted keys, no whitespace, ensure_ascii=FALSE
 *   → siftRequestCanonicalBytes() below
 *
 * OxDeAI artifact hashes: sorted keys, no whitespace, ensure_ascii=TRUE
 *   → canonicalHash() / canonicalBytes() from helpers.ts (used in run-prod.ts)
 *
 * ── Response parsing ───────────────────────────────────────────────────────
 *
 *   /api/v1/receipt/verify-key returns receipt verification keys;
 *     verifySiftReceipt() selects keys[receipt.key_id].
 *   /api/v1/authorize may return a wrapped receipt or the receipt at the top level;
 *     verifySiftReceipt() performs the full shape and crypto validation.
 */

import { readFileSync } from "node:fs";
import {
  createPublicKey,
  sign as nodeCryptoSign,
  verify as nodeCryptoVerify,
  createHash,
  randomUUID,
} from "node:crypto";
import type { SiftReceipt } from "@oxdeai/sift";
import { isSmallOrderEd25519Key } from "@oxdeai/sift/dist/src/smallOrderEd25519.js";
import { b64uEncode, b64uDecode } from "./helpers.js";

// ─── Prod endpoints ───────────────────────────────────────────────────────────

export const PROD_BASE_URL       = "https://sift.walkosystems.com";
export const PROD_CHALLENGE_URL  = `${PROD_BASE_URL}/api/v1/auth/challenge`;
export const PROD_AUTHORIZE_URL  = `${PROD_BASE_URL}/api/v1/authorize`;
export const PROD_VERIFY_KEY_URL = `${PROD_BASE_URL}/api/v1/receipt/verify-key`;

// ─── Configuration ────────────────────────────────────────────────────────────

export interface ProdConfig {
  // Resolved by Sift contract
  tenantId:  string;  // "oxdeai_designpartner"
  agentId:   string;  // "oxdeai-boundary-demo-01"
  agentRole: string;  // "validation_agent"
  // Agent Ed25519 private key (PKCS8 PEM) — signs requests to Sift.
  // Also used as OxDeAI issuer key in the smoke test (dual use for simplicity).
  // Load via loadProdPrivateKey().
  privateKeyPem: string;
  // URL overrides (optional; default to PROD_* constants above)
  challengeUrl?: string;
  authorizeUrl?: string;
  verifyKeyUrl?: string;
  // Logging only
  publicKeyX?: string;
}

// ─── Private key loader ───────────────────────────────────────────────────────

export function loadProdPrivateKey(filePath: string): string {
  let pem: string;
  try {
    pem = readFileSync(filePath, "utf8");
  } catch (e) {
    throw new Error(
      `prod private key not found at "${filePath}": ` +
        `${e instanceof Error ? e.message : String(e)}`,
    );
  }
  if (!pem.includes("-----BEGIN")) {
    throw new Error(`prod private key at "${filePath}" does not look like a PEM file`);
  }
  return pem;
}

// ─── Sift request canonicalization ───────────────────────────────────────────
//
// Contract: sorted keys, no whitespace, ensure_ascii=FALSE.
// Used only for computing params_hash and signing the authorize preimage.
// Do NOT use for OxDeAI artifact hashes (use canonicalHash from helpers.ts).

function deepSortKeys(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return (value as unknown[]).map(deepSortKeys);
  const obj = value as Record<string, unknown>;
  const result: Record<string, unknown> = {};
  for (const k of Object.keys(obj).sort()) result[k] = deepSortKeys(obj[k]);
  return result;
}

function siftRequestCanonicalBytes(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(deepSortKeys(value)), "utf8");
}

function siftRequestCanonicalHash(value: unknown): string {
  return createHash("sha256").update(siftRequestCanonicalBytes(value)).digest("hex");
}

// ─── Challenge endpoint ───────────────────────────────────────────────────────
//
// Confirmed contract:
//   Request  POST { tenant_id, agent_id }
//   Response { tenant_id, agent_id, nonce, expires_at, proof_message_format,
//              signed_fields, signature_algorithm }
//   Nonce field name: exactly "nonce"

export async function fetchProdChallenge(
  config: ProdConfig,
): Promise<{ ok: true; nonce: string; rawShape?: Record<string, unknown> } | { ok: false; error: string }> {
  const url = config.challengeUrl ?? PROD_CHALLENGE_URL;

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Sift-Tenant": config.tenantId,
      },
      body: JSON.stringify({ tenant_id: config.tenantId, agent_id: config.agentId }),
    });
  } catch (e) {
    return { ok: false, error: `challenge: network error: ${e instanceof Error ? e.message : String(e)}` };
  }

  if (!response.ok) {
    let detail = "";
    try {
      const b = (await response.json()) as Record<string, unknown>;
      if (typeof b["message"] === "string") detail = `: ${b["message"]}`;
    } catch { /* ignore */ }
    return { ok: false, error: `challenge: HTTP ${response.status}${detail}` };
  }

  let raw: unknown;
  try { raw = await response.json() as unknown; }
  catch { return { ok: false, error: "challenge: response is not valid JSON" }; }

  if (typeof raw !== "object" || raw === null) {
    return { ok: false, error: "challenge: response is not a JSON object" };
  }
  const r = raw as Record<string, unknown>;
  if (typeof r["nonce"] !== "string" || r["nonce"].length === 0) {
    return { ok: false, error: "challenge: response missing field: nonce" };
  }
  return { ok: true, nonce: r["nonce"] as string, rawShape: r };
}

// ─── Authorize request ────────────────────────────────────────────────────────
//
// Confirmed body schema (Sift contract):
//   request_id, tenant_id, agent_id, agent_role, action, tool,
//   risk_tier, params, timestamp, nonce, signature
//
// Required header: X-Sift-Tenant: <tenant_id>
//
// Signing preimage (sift canonical JSON, ensure_ascii=false):
//   { request_id, tenant_id, agent_id, agent_role, action, tool,
//     risk_tier, nonce, timestamp, params_hash }
//   params_hash = sha256_hex(sift_canonical(params))
//   params itself is NOT in the preimage.

export interface ProdSigningPreimage {
  request_id:  string;
  tenant_id:   string;
  agent_id:    string;
  agent_role:  string;
  action:      string;
  tool:        string;
  risk_tier:   number;
  nonce:       string;
  timestamp:   number;
  params_hash: string;
}

export interface ProdAuthorizeRequest {
  request_id: string;
  tenant_id:  string;
  agent_id:   string;
  agent_role: string;
  action:     string;
  tool:       string;
  risk_tier:  number;
  params:     Record<string, unknown>;
  timestamp:  number;
  nonce:      string;
  signature:  string;
}

/**
 * Signs the preimage using the agent's Ed25519 private key.
 * Canonicalization: sorted keys, no whitespace, ensure_ascii=FALSE.
 * Returns base64url-no-padding signature.
 */
export function signAuthorizeRequest(
  preimage: ProdSigningPreimage,
  privateKeyPem: string,
): string {
  const bytes = siftRequestCanonicalBytes(preimage);
  const sig = nodeCryptoSign(null, bytes, privateKeyPem);
  return b64uEncode(sig);
}

/**
 * Builds the full signed authorize request body.
 * Generates a fresh UUID request_id and current unix timestamp.
 */
export function buildProdAuthorizeRequest(
  action: string,
  tool: string,
  riskTier: number,
  params: Record<string, unknown>,
  nonce: string,
  config: ProdConfig,
): ProdAuthorizeRequest {
  const request_id  = randomUUID();
  const timestamp   = Math.floor(Date.now() / 1000);
  const params_hash = siftRequestCanonicalHash(params);

  const preimage: ProdSigningPreimage = {
    request_id, tenant_id: config.tenantId, agent_id: config.agentId,
    agent_role: config.agentRole, action, tool, risk_tier: riskTier,
    nonce, timestamp, params_hash,
  };

  const signature = signAuthorizeRequest(preimage, config.privateKeyPem);

  return {
    request_id, tenant_id: config.tenantId, agent_id: config.agentId,
    agent_role: config.agentRole, action, tool, risk_tier: riskTier,
    params, timestamp, nonce, signature,
  };
}

/**
 * Same as buildProdAuthorizeRequest but also returns the intermediate values
 * needed to diagnose signing mismatches.  Used only when SIFT_PROD_DEBUG=1.
 * Never exposes the private key.
 */
export interface ProdAuthorizeRequestDebug {
  request:      ProdAuthorizeRequest;
  preimage:     ProdSigningPreimage;
  paramsHash:   string;
  canonicalJson: string;
  signature:    string;
}

export function buildProdAuthorizeRequestDebug(
  action: string,
  tool: string,
  riskTier: number,
  params: Record<string, unknown>,
  nonce: string,
  config: ProdConfig,
): ProdAuthorizeRequestDebug {
  const request_id  = randomUUID();
  const timestamp   = Math.floor(Date.now() / 1000);
  const paramsHash  = siftRequestCanonicalHash(params);

  const preimage: ProdSigningPreimage = {
    request_id, tenant_id: config.tenantId, agent_id: config.agentId,
    agent_role: config.agentRole, action, tool, risk_tier: riskTier,
    nonce, timestamp, params_hash: paramsHash,
  };

  const canonicalJson = JSON.stringify(deepSortKeys(preimage));
  const signature     = signAuthorizeRequest(preimage, config.privateKeyPem);

  const request: ProdAuthorizeRequest = {
    request_id, tenant_id: config.tenantId, agent_id: config.agentId,
    agent_role: config.agentRole, action, tool, risk_tier: riskTier,
    params, timestamp, nonce, signature,
  };

  return { request, preimage, paramsHash, canonicalJson, signature };
}

// ─── Network call to /api/v1/authorize ────────────────────────────────────────

export async function callProdAuthorize(
  request: ProdAuthorizeRequest,
  config: ProdConfig,
): Promise<{ ok: true; raw: unknown } | { ok: false; error: string }> {
  const url = config.authorizeUrl ?? PROD_AUTHORIZE_URL;

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Sift-Tenant": config.tenantId,
      },
      body: JSON.stringify(request),
    });
  } catch (e) {
    return { ok: false, error: `authorize: network error: ${e instanceof Error ? e.message : String(e)}` };
  }

  if (!response.ok) {
    let detail = "";
    try {
      const b = (await response.json()) as Record<string, unknown>;
      if (typeof b["message"] === "string") detail = `: ${b["message"]}`;
    } catch { /* ignore */ }
    return { ok: false, error: `authorize: HTTP ${response.status}${detail}` };
  }

  let raw: unknown;
  try { raw = await response.json() as unknown; }
  catch { return { ok: false, error: "authorize: response is not valid JSON" }; }

  return { ok: true, raw };
}

// ─── Receipt extraction ───────────────────────────────────────────────────────
//
// Accepts wrapped { "receipt": {...} } first, then top-level object.
// verifySiftReceipt() (called by run-prod.ts) does full shape + crypto validation.

export function extractRawReceipt(raw: unknown): unknown | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  if (typeof r["receipt"] === "object" && r["receipt"] !== null) return r["receipt"];
  return raw;
}

// ─── Sift-native receipt verification ─────────────────────────────────────────

export type SiftReceiptVerificationCode =
  | "MALFORMED_RECEIPT"
  | "MISSING_KEY_ID"
  | "KEY_NOT_FOUND"
  | "INVALID_PUBLIC_KEY"
  | "TAMPERED_RECEIPT"
  | "INVALID_SIGNATURE"
  | "INVALID_SIGNATURE_ALG"
  | "EXPIRED_RECEIPT"
  | "TENANT_MISMATCH"
  | "INVALID_POLICY_ID"
  | "INVALID_DECISION"
  | "DENY_DECISION"
  | "VERIFICATION_ERROR";

export type SiftReceiptVerificationResult =
  | { ok: true; receipt: SiftReceipt }
  | { ok: false; code: SiftReceiptVerificationCode; message: string };

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function failSiftReceipt(
  code: SiftReceiptVerificationCode,
  message: string,
): SiftReceiptVerificationResult {
  return { ok: false, code, message };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(deepSortKeys(value));
}

function publicKeyObjectFromRaw(raw: Buffer): ReturnType<typeof createPublicKey> {
  if (raw.length !== 32) {
    throw new TypeError(`Ed25519 public key must be 32 bytes, got ${raw.length}`);
  }
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

function requireString(
  obj: Record<string, unknown>,
  field: string,
): string | { error: SiftReceiptVerificationResult } {
  const value = obj[field];
  if (typeof value !== "string" || value.length === 0) {
    return { error: failSiftReceipt("MALFORMED_RECEIPT", `receipt missing field: ${field}`) };
  }
  return value;
}

function requireNumber(
  obj: Record<string, unknown>,
  field: string,
): number | { error: SiftReceiptVerificationResult } {
  const value = obj[field];
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    return { error: failSiftReceipt("MALFORMED_RECEIPT", `receipt field ${field} must be a safe integer`) };
  }
  return value;
}

function receiptString(
  obj: Record<string, unknown>,
  field: string,
  fallback = "",
): string {
  const value = obj[field];
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

function receiptNumber(
  obj: Record<string, unknown>,
  field: string,
  fallback = 0,
): number {
  const value = obj[field];
  return typeof value === "number" && Number.isSafeInteger(value) ? value : fallback;
}

function toOxDeAIReceipt(receipt: Record<string, unknown>): SiftReceipt {
  return {
    receipt_version: receiptString(receipt, "receipt_version", "1.0"),
    tenant_id: receiptString(receipt, "tenant_id"),
    agent_id: receiptString(receipt, "agent_id"),
    action: receiptString(receipt, "action"),
    tool: receiptString(receipt, "tool"),
    decision: receipt["decision"] === "ALLOW" ? "ALLOW" : "DENY",
    risk_tier: receiptNumber(receipt, "risk_tier"),
    timestamp: receiptString(receipt, "timestamp", new Date(receiptNumber(receipt, "issued_at") * 1000).toISOString()),
    nonce: receiptString(receipt, "nonce", receiptString(receipt, "request_id")),
    policy_matched: receiptString(receipt, "policy_hash"),
    receipt_hash: receiptString(receipt, "receipt_hash", createHash("sha256").update(receiptString(receipt, "canonical_payload")).digest("hex")),
    signature: receiptString(receipt, "signature"),
  };
}

function selectVerifyKey(
  verifyKeyResponse: unknown,
  keyId: string,
): { ok: true; publicKeyRaw: Buffer } | { ok: false; result: SiftReceiptVerificationResult } {
  const raw = asRecord(verifyKeyResponse);
  if (raw === null) {
    return { ok: false, result: failSiftReceipt("KEY_NOT_FOUND", "verify-key response is not a JSON object") };
  }

  const keys = asRecord(raw["keys"]);
  if (keys === null) {
    return { ok: false, result: failSiftReceipt("KEY_NOT_FOUND", "verify-key response missing field: keys") };
  }

  const encoded = keys[keyId];
  if (typeof encoded !== "string" || encoded.length === 0) {
    return { ok: false, result: failSiftReceipt("KEY_NOT_FOUND", `verify-key response missing key_id: ${keyId}`) };
  }

  const publicKeyRaw = b64uDecode(encoded);
  if (publicKeyRaw.length !== 32) {
    return {
      ok: false,
      result: failSiftReceipt("INVALID_PUBLIC_KEY", `verify-key public key for key_id "${keyId}" must decode to 32 bytes, got ${publicKeyRaw.length}`),
    };
  }

  return { ok: true, publicKeyRaw };
}

export function verifySiftReceipt(
  receipt: unknown,
  verifyKeyResponse: unknown,
  expectedTenant: string,
): SiftReceiptVerificationResult {
  try {
    const r = asRecord(receipt);
    if (r === null) {
      return failSiftReceipt("MALFORMED_RECEIPT", "receipt must be a JSON object");
    }

    const keyIdValue = requireString(r, "key_id");
    if (typeof keyIdValue !== "string") return keyIdValue.error;
    const keyId = keyIdValue;

    const canonicalPayloadValue = requireString(r, "canonical_payload");
    if (typeof canonicalPayloadValue !== "string") return canonicalPayloadValue.error;
    const canonicalPayload = canonicalPayloadValue;

    const signatureValue = requireString(r, "signature");
    if (typeof signatureValue !== "string") return signatureValue.error;
    const signature = signatureValue;

    const expiryValue = requireNumber(r, "expiry");
    if (typeof expiryValue !== "number") return expiryValue.error;
    const expiry = expiryValue;

    const tenantIdValue = requireString(r, "tenant_id");
    if (typeof tenantIdValue !== "string") return tenantIdValue.error;
    const tenantId = tenantIdValue;

    const decisionValue = requireString(r, "decision");
    if (typeof decisionValue !== "string") return decisionValue.error;
    const decision = decisionValue;

    const policyHashValue = requireString(r, "policy_hash");
    if (typeof policyHashValue !== "string") {
      return failSiftReceipt("INVALID_POLICY_ID", "receipt missing field: policy_hash");
    }

    const signatureAlg = r["signature_alg"];
    if (signatureAlg !== "ed25519") {
      return failSiftReceipt("INVALID_SIGNATURE_ALG", `signature_alg must be "ed25519", got: ${String(signatureAlg)}`);
    }

    const { signature: _sig, canonical_payload: _payload, ...base } = r;
    if (canonicalJson(base) !== canonicalPayload) {
      return failSiftReceipt("TAMPERED_RECEIPT", "canonical_payload does not match receipt body");
    }

    const key = selectVerifyKey(verifyKeyResponse, keyId);
    if (!key.ok) return key.result;

    const signatureBytes = b64uDecode(signature);
    const publicKey = publicKeyObjectFromRaw(key.publicKeyRaw);
    // S3-R3: a small-order verify-key authenticates nothing (a crafted signature
    // verifies against any payload). Reject it on the exact KeyObject passed to
    // verify, before verification. Fail closed.
    if (isSmallOrderEd25519Key(publicKey)) {
      return failSiftReceipt("INVALID_PUBLIC_KEY", `verify-key public key for key_id "${keyId}" is an Ed25519 small-order point and cannot be trusted`);
    }
    const signatureOk = nodeCryptoVerify(
      null,
      Buffer.from(canonicalPayload, "utf8"),
      publicKey,
      signatureBytes,
    );
    if (!signatureOk) {
      return failSiftReceipt("INVALID_SIGNATURE", "receipt signature verification failed");
    }

    if (Math.floor(Date.now() / 1000) > expiry) {
      return failSiftReceipt("EXPIRED_RECEIPT", "receipt has expired");
    }

    if (tenantId !== expectedTenant) {
      return failSiftReceipt("TENANT_MISMATCH", `receipt tenant_id "${tenantId}" does not match expected tenant`);
    }

    if (decision !== "ALLOW" && decision !== "DENY") {
      return failSiftReceipt("INVALID_DECISION", `receipt decision must be ALLOW or DENY, got: ${decision}`);
    }

    if (decision !== "ALLOW") {
      return failSiftReceipt("DENY_DECISION", "receipt decision is not ALLOW");
    }

    return { ok: true, receipt: toOxDeAIReceipt(r) };
  } catch (e) {
    return failSiftReceipt("VERIFICATION_ERROR", e instanceof Error ? e.message : String(e));
  }
}

export async function fetchProdVerifyKey(
  config: ProdConfig,
): Promise<{ ok: true; raw: unknown } | { ok: false; error: string }> {
  const url = config.verifyKeyUrl ?? PROD_VERIFY_KEY_URL;

  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      headers: { "X-Sift-Tenant": config.tenantId },
    });
  } catch (e) {
    return { ok: false, error: `verify-key: network error: ${e instanceof Error ? e.message : String(e)}` };
  }

  if (!response.ok) {
    return { ok: false, error: `verify-key: HTTP ${response.status}` };
  }

  let raw: unknown;
  try { raw = await response.json() as unknown; }
  catch { return { ok: false, error: "verify-key: response is not valid JSON" }; }

  return { ok: true, raw };
}
