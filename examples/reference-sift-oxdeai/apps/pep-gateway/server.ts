// SPDX-License-Identifier: Apache-2.0
/**
 * Policy Enforcement Point (PEP) Gateway.
 *
 * The PEP is the non-bypassable execution boundary. No request reaches the
 * upstream without passing all 10 verification steps below. Failures stop
 * forwarding; replay-store errors return 500, upstream failures 502.
 *
 * 10-step AuthorizationV1 verification (in order):
 *   1. Parse         — structural validation of request body
 *   2. Signature     — Ed25519 verification of the signing payload
 *   3. Issuer        — must be in the known-issuers set
 *   4. Audience      — must equal this PEP's configured audience
 *   5. Decision      — must be exactly "ALLOW"
 *   6. Expiry        — expires_at must be in the future
 *   7. Policy        — policy_id must be in the known-policies set
 *   8. Intent hash   — SHA-256(siftCanonical(intent)) must equal intent_hash
 *   9. State hash    — SHA-256(siftCanonical(normalized live state)) must equal state_hash
 *  10. Replay        — auth_id consumed (LAST; not transactional with effect)
 *
 * Only after all 10 checks pass does the PEP forward to upstream.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { verify as nodeVerify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { normalizeState } from "@oxdeai/sift";
import type { ReplayStore } from "../../packages/replay-store/index.js";
import {
  siftCanonicalJsonBytes,
  siftCanonicalJsonHash,
  b64uDecode,
} from "../../shared/canonical.js";
import type { AuthorizationV1Payload } from "../../shared/types.js";

// ─── Configuration ────────────────────────────────────────────────────────────

export interface PepConfig {
  port: number;
  /** Ed25519 public key used to verify AuthorizationV1 signatures. */
  adapterPublicKey: KeyObject;
  /** Set of accepted issuer claims. */
  knownIssuers: Set<string>;
  /** This PEP's audience — must match authorization.audience exactly. */
  audience: string;
  /** URL of the protected upstream (e.g. http://127.0.0.1:{port}/execute). */
  upstreamUrl: string;
  /** Internal token forwarded to the protected execution target via x-internal-executor-token. */
  internalToken: string;
  /** Example replay protection; the default harness store is in-memory only. */
  replayStore: ReplayStore;
  /** Deployer-owned accessor; request state is never authoritative. */
  getExecutionState: () => unknown | Promise<unknown>;
  /** Set of policy IDs this PEP accepts. */
  knownPolicies: Set<string>;
}

export interface PepHandle {
  url: string;
  close(): Promise<void>;
}

// ─── Internal types ───────────────────────────────────────────────────────────

type PepErrorCode =
  | "PARSE_ERROR"
  | "INVALID_SIGNATURE"
  | "UNKNOWN_ISSUER"
  | "AUDIENCE_MISMATCH"
  | "INVALID_DECISION"
  | "EXPIRED"
  | "UNKNOWN_POLICY"
  | "INTENT_HASH_MISMATCH"
  | "STATE_HASH_MISMATCH"
  | "REPLAY_DETECTED"
  | "REPLAY_STORE_ERROR";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function jsonResponse(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function deny(res: ServerResponse, code: PepErrorCode, message: string): void {
  jsonResponse(res, 403, { ok: false, code, message });
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk: Buffer) => { data += chunk.toString(); });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

/**
 * Reconstructs the signing payload from an AuthorizationV1.
 * Identical to AuthorizationV1 except signature.sig is absent.
 * siftCanonicalize sorts keys — this produces the exact same bytes
 * the adapter signed.
 */
function buildSigningPayload(auth: AuthorizationV1Payload): object {
  return {
    version: auth.version,
    auth_id: auth.auth_id,
    issuer: auth.issuer,
    audience: auth.audience,
    decision: auth.decision,
    intent_hash: auth.intent_hash,
    state_hash: auth.state_hash,
    policy_id: auth.policy_id,
    issued_at: auth.issued_at,
    expires_at: auth.expires_at,
    signature: {
      alg: auth.signature.alg,
      kid: auth.signature.kid,
      // sig intentionally absent from signing payload
    },
  };
}

/**
 * Validates the shape of an AuthorizationV1Payload received from the wire.
 * Returns the typed value or null if the shape is wrong.
 */
function parseAuthorization(raw: unknown): AuthorizationV1Payload | null {
  if (typeof raw !== "object" || raw === null) return null;
  const a = raw as Record<string, unknown>;

  if (a["version"] !== "AuthorizationV1") return null;
  if (!isNonEmptyString(a["auth_id"])) return null;
  if (!isNonEmptyString(a["issuer"])) return null;
  if (!isNonEmptyString(a["audience"])) return null;
  if (a["decision"] !== "ALLOW") return null;
  if (!isNonEmptyString(a["intent_hash"])) return null;
  if (!isNonEmptyString(a["state_hash"])) return null;
  if (!isNonEmptyString(a["policy_id"])) return null;
  if (typeof a["issued_at"] !== "number") return null;
  if (typeof a["expires_at"] !== "number") return null;

  const sig = a["signature"];
  if (typeof sig !== "object" || sig === null) return null;
  const s = sig as Record<string, unknown>;
  if (s["alg"] !== "ed25519") return null;
  if (!isNonEmptyString(s["kid"])) return null;
  if (!isNonEmptyString(s["sig"])) return null;

  return raw as AuthorizationV1Payload;
}

// ─── Server ───────────────────────────────────────────────────────────────────

export function startPepGateway(config: PepConfig): Promise<PepHandle> {
  if (typeof config.getExecutionState !== "function") {
    throw new TypeError("getExecutionState is required");
  }
  return new Promise((resolve, reject) => {
    const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      if (req.method !== "POST" || req.url !== "/execute") {
        return jsonResponse(res, 404, { ok: false, code: "NOT_FOUND", message: "Not found" });
      }

      // ── 1. Parse ─────────────────────────────────────────────────────────────
      let rawBody: string;
      try {
        rawBody = await readBody(req);
      } catch {
        return deny(res, "PARSE_ERROR", "Failed to read request body");
      }

      let parsed: { intent: unknown; state: unknown; authorization: unknown };
      try {
        parsed = JSON.parse(rawBody) as typeof parsed;
      } catch {
        return deny(res, "PARSE_ERROR", "Request body is not valid JSON");
      }

      if (
        typeof parsed !== "object" ||
        parsed === null ||
        !("intent" in parsed) ||
        !("state" in parsed) ||
        !("authorization" in parsed)
      ) {
        return deny(res, "PARSE_ERROR", "Request must have intent, state, and authorization fields");
      }

      const auth = parseAuthorization(parsed.authorization);
      if (auth === null) {
        return deny(res, "PARSE_ERROR", "authorization field is malformed or missing required fields");
      }

      // ── 2. Signature verification ─────────────────────────────────────────
      // Reconstructs the signing payload (auth minus signature.sig) and verifies
      // the Ed25519 signature. Fails before any semantic checks.
      let sigValid: boolean;
      try {
        const signingPayload = buildSigningPayload(auth);
        const preimage = siftCanonicalJsonBytes(signingPayload);
        const sigBytes = b64uDecode(auth.signature.sig);
        sigValid = nodeVerify(null, preimage, config.adapterPublicKey, sigBytes);
      } catch {
        return deny(res, "INVALID_SIGNATURE", "Signature verification encountered an error");
      }
      if (!sigValid) {
        return deny(res, "INVALID_SIGNATURE", "AuthorizationV1 signature is invalid");
      }

      // ── 3. Issuer ─────────────────────────────────────────────────────────
      if (!config.knownIssuers.has(auth.issuer)) {
        return deny(res, "UNKNOWN_ISSUER", `Issuer '${auth.issuer}' is not recognized`);
      }

      // ── 4. Audience ───────────────────────────────────────────────────────
      if (auth.audience !== config.audience) {
        return deny(
          res,
          "AUDIENCE_MISMATCH",
          `Authorization audience '${auth.audience}' does not match PEP audience '${config.audience}'`
        );
      }

      // ── 5. Decision ───────────────────────────────────────────────────────
      // parseAuthorization already enforces decision === "ALLOW", but this
      // guard remains explicit so the verification ordering is code-verifiable.
      if (auth.decision !== "ALLOW") {
        return deny(res, "INVALID_DECISION", "Authorization decision is not ALLOW");
      }

      // ── 6. Expiry ─────────────────────────────────────────────────────────
      const nowSec = Math.floor(Date.now() / 1000);
      if (auth.expires_at <= nowSec) {
        return deny(
          res,
          "EXPIRED",
          `Authorization expired at ${auth.expires_at}, current time is ${nowSec}`
        );
      }

      // ── 7. Policy ─────────────────────────────────────────────────────────
      if (!config.knownPolicies.has(auth.policy_id)) {
        return deny(res, "UNKNOWN_POLICY", `Policy '${auth.policy_id}' is not known to this PEP`);
      }

      // ── 8. Intent hash ────────────────────────────────────────────────────
      // Recomputes SHA-256(siftCanonical(intent)) and compares to intent_hash.
      // Any modification to the intent (tool, params) produces a different hash.
      let intentHash: string;
      try {
        intentHash = siftCanonicalJsonHash(parsed.intent);
      } catch {
        return deny(res, "INTENT_HASH_MISMATCH", "Failed to canonicalize intent");
      }
      if (intentHash !== auth.intent_hash) {
        return deny(
          res,
          "INTENT_HASH_MISMATCH",
          "intent_hash does not match the provided intent"
        );
      }

      // ── 9. State hash ─────────────────────────────────────────────────────
      let stateHash: string;
      try {
        const liveState = await config.getExecutionState();
        const normalized = normalizeState({ state: liveState });
        if (!normalized.ok) throw new Error(normalized.message);
        stateHash = siftCanonicalJsonHash(normalized.state);
      } catch {
        return deny(res, "STATE_HASH_MISMATCH", "Failed to obtain or normalize trusted execution state");
      }
      if (stateHash !== auth.state_hash) {
        return deny(
          res,
          "STATE_HASH_MISMATCH",
          "state_hash does not match trusted execution state"
        );
      }

      // ── 10. Replay protection (atomic, last) ──────────────────────────────
      // Replay check is LAST to prevent denial-of-service via replay of any
      // valid auth_id. Only a fully-valid authorization is consumed.
      // Store errors are fatal — fail-closed, never fall through to execution.
      let consumed: boolean;
      try {
        consumed = await config.replayStore.consumeAuthId(auth.auth_id, auth.expires_at);
      } catch (e) {
        return jsonResponse(res, 500, {
          ok: false,
          code: "REPLAY_STORE_ERROR",
          message: e instanceof Error ? e.message : String(e),
        });
      }
      if (!consumed) {
        return deny(
          res,
          "REPLAY_DETECTED",
          `auth_id '${auth.auth_id}' has already been consumed`
        );
      }

      // State read and this effect are separate: there is a race window.
      // Replay consumption is not rolled back if the upstream fails.
      // ── All checks passed — forward to upstream ───────────────────────────
      try {
        const upstreamRes = await fetch(config.upstreamUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-internal-executor-token": config.internalToken,
          },
          body: JSON.stringify({ intent: parsed.intent, auth_id: auth.auth_id }),
        });

        const upstreamBody = (await upstreamRes.json()) as unknown;
        return jsonResponse(res, upstreamRes.status, upstreamBody);
      } catch (e) {
        return jsonResponse(res, 502, {
          ok: false,
          code: "UPSTREAM_UNREACHABLE",
          message: e instanceof Error ? e.message : String(e),
        });
      }
    });

    server.on("error", reject);

    server.listen(config.port, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("Unexpected server address type"));
        return;
      }
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close(): Promise<void> {
          return new Promise((res, rej) =>
            server.close((e) => (e ? rej(e) : res()))
          );
        },
      });
    });
  });
}
