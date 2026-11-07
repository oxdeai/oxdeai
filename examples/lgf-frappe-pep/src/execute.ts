// SPDX-License-Identifier: Apache-2.0
import { randomUUID } from "node:crypto";
import { sha256HexFromJson, verifyAuthorization } from "@oxdeai/core";
import type { AuthorizationV1, KeySet } from "@oxdeai/core";
import type { ReplayStore } from "@oxdeai/guard";
import type { PepConfig } from "./config.js";
import type { ActionEnvelope, PepResponse, DecisionLog } from "./types.js";
import type { PlatformAdapter } from "./adapters/platform.js";
import { PROTECTED_ACTION, POLICY_ID } from "./policy.js";

function parseExecuteRequest(
  body: unknown,
): { envelope: ActionEnvelope; authorization: AuthorizationV1 } | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const b = body as Record<string, unknown>;
  const envelope = b["envelope"];
  const authorization = b["authorization"];
  if (typeof envelope !== "object" || envelope === null) return null;
  if (typeof authorization !== "object" || authorization === null) return null;

  const e = envelope as Record<string, unknown>;
  if (typeof e["source_bench"] !== "string") return null;
  if (typeof e["target_bench"] !== "string") return null;
  if (typeof e["agent_or_tool_context"] !== "string") return null;
  if (typeof e["user_identity"] !== "string") return null;
  if (typeof e["session_id"] !== "string") return null;
  const action = e["action"];
  if (typeof action !== "object" || action === null) return null;
  const a = action as Record<string, unknown>;
  if (a["type"] !== "EXECUTE") return null;
  if (typeof a["tool"] !== "string") return null;
  const params = a["params"];
  if (typeof params !== "object" || params === null) return null;
  const p = params as Record<string, unknown>;
  if (typeof p["subject"] !== "string") return null;
  if (typeof p["description"] !== "string") return null;
  if (typeof p["priority"] !== "string") return null;

  return {
    envelope: envelope as ActionEnvelope,
    authorization: authorization as AuthorizationV1,
  };
}

function denyResult(
  correlationId: string,
  reason: string,
  config: PepConfig,
  action: string,
  intentHash: string | null,
  authId: string | null,
  now: number,
): { status: number; body: PepResponse; log: DecisionLog } {
  return {
    status: 403,
    body: { ok: false, decision: "DENY", mode: config.mode, reason },
    log: {
      correlation_id: correlationId,
      action,
      expected_audience: config.expectedAudience,
      auth_id: authId,
      intent_hash: intentHash,
      policy_id: POLICY_ID,
      mode: config.mode,
      decision: "DENY",
      reason,
      executed: false,
      frappe_ticket_id: null,
      timestamp: new Date(now * 1000).toISOString(),
    },
  };
}

export function handleExecute(
  config: PepConfig,
  replayStore: ReplayStore,
  platformAdapter: PlatformAdapter,
) {
  const trustedKeySets: KeySet[] = [
    {
      issuer: config.issuer,
      version: "1",
      keys: [
        {
          kid: config.signingKid,
          alg: "Ed25519",
          public_key: config.signingPublicKeyPem,
          status: "active",
        },
      ],
    },
  ];

  return async (body: unknown): Promise<{ status: number; body: PepResponse; log: DecisionLog }> => {
    const correlationId = randomUUID();
    const now = Math.floor(Date.now() / 1000);

    // 1. Parse
    const parsed = parseExecuteRequest(body);
    if (!parsed) {
      return denyResult(correlationId, "INVALID_REQUEST", config, "unknown", null, null, now);
    }

    const { envelope, authorization } = parsed;

    // 2. Verify protected action name
    if (envelope.action.tool !== PROTECTED_ACTION) {
      return denyResult(
        correlationId, "UNSUPPORTED_ACTION", config,
        envelope.action.tool, null, authorization.auth_id ?? null, now,
      );
    }

    // 3. Canonicalize + compute intent hash
    let intentHash: string;
    try {
      intentHash = sha256HexFromJson(envelope.action);
    } catch {
      return denyResult(
        correlationId, "CANONICALIZATION_FAILED", config,
        envelope.action.tool, null, authorization.auth_id ?? null, now,
      );
    }

    // 4. Verify AuthorizationV1 — two independent questions, both required:
    //      trustedKeySets                  -> which key is trusted for this claimed issuer?
    //      trustedAuthorizationAuthorities -> is that issuer authorized for this policy_id?
    //
    //    A valid signature answers only the first. Without the second, any
    //    issuer holding a trusted key could issue for any policy this PEP
    //    enforces. Both lists come from deployment configuration established
    //    before the request arrived; neither is read out of the artifact.
    const verification = verifyAuthorization(authorization, {
      now,
      mode: "strict",
      trustedKeySets,
      requireSignatureVerification: true,
      expectedAudience: config.expectedAudience,
      trustedAuthorizationAuthorities: config.trustedAuthorizationAuthorities,
    });

    if (verification.status !== "ok") {
      const reason = verification.violations.map((v) => v.code).join(",") || "AUTHORIZATION_INVALID";
      return denyResult(
        correlationId, reason, config,
        envelope.action.tool, intentHash, authorization.auth_id ?? null, now,
      );
    }

    // 5. Verify intent hash binding
    if (authorization.intent_hash !== intentHash) {
      return denyResult(
        correlationId, "INTENT_HASH_MISMATCH", config,
        envelope.action.tool, intentHash, authorization.auth_id, now,
      );
    }

    // 6. Replay protection (last verification step before execution)
    // RR-01: only the literal boolean `true` is a successful consume; any
    // non-boolean result is a store malfunction and must not authorize.
    let consumed: unknown;
    try {
      consumed = await replayStore.consumeAuthId(authorization.auth_id, { expiry: authorization.expiry });
    } catch {
      return denyResult(
        correlationId, "REPLAY_STORE_UNAVAILABLE", config,
        envelope.action.tool, intentHash, authorization.auth_id, now,
      );
    }
    if (consumed !== true && consumed !== false) {
      return denyResult(
        correlationId, "REPLAY_STORE_UNAVAILABLE", config,
        envelope.action.tool, intentHash, authorization.auth_id, now,
      );
    }
    if (!consumed) {
      return denyResult(
        correlationId, "AUTH_REPLAY", config,
        envelope.action.tool, intentHash, authorization.auth_id, now,
      );
    }

    // 7. Mode check — observe mode stops here
    if (config.mode === "observe") {
      const log: DecisionLog = {
        correlation_id: correlationId,
        action: envelope.action.tool,
        expected_audience: config.expectedAudience,
        auth_id: authorization.auth_id,
        intent_hash: intentHash,
        policy_id: POLICY_ID,
        mode: "observe",
        decision: "ALLOW",
        reason: "OBSERVE_DRY_RUN",
        executed: false,
        frappe_ticket_id: null,
        timestamp: new Date(now * 1000).toISOString(),
      };
      return {
        status: 200,
        body: {
          ok: true,
          decision: "ALLOW",
          mode: "observe",
          auth_id: authorization.auth_id,
          intent_hash: intentHash,
          policy_id: POLICY_ID,
        },
        log,
      };
    }

    // 8. Enforce mode — call Frappe
    try {
      const result = await platformAdapter.execute(
        envelope.action.tool,
        envelope.action.params,
        {
          correlationId,
          mode: config.mode,
          authId: authorization.auth_id,
          expectedAudience: config.expectedAudience,
        },
      );

      const log: DecisionLog = {
        correlation_id: correlationId,
        action: envelope.action.tool,
        expected_audience: config.expectedAudience,
        auth_id: authorization.auth_id,
        intent_hash: intentHash,
        policy_id: POLICY_ID,
        mode: "enforce",
        decision: "ALLOW",
        reason: "AUTHORIZED",
        executed: true,
        frappe_ticket_id: result.resource_id,
        timestamp: new Date(now * 1000).toISOString(),
      };
      return {
        status: 200,
        body: {
          ok: true,
          decision: "ALLOW",
          mode: "enforce",
          auth_id: authorization.auth_id,
          intent_hash: intentHash,
          policy_id: POLICY_ID,
          frappe_ticket_id: result.resource_id,
        },
        log,
      };
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      const log: DecisionLog = {
        correlation_id: correlationId,
        action: envelope.action.tool,
        expected_audience: config.expectedAudience,
        auth_id: authorization.auth_id,
        intent_hash: intentHash,
        policy_id: POLICY_ID,
        mode: "enforce",
        decision: "DENY",
        reason: `FRAPPE_UPSTREAM_ERROR: ${detail.slice(0, 300)}`,
        executed: false,
        frappe_ticket_id: null,
        timestamp: new Date(now * 1000).toISOString(),
      };
      return {
        status: 502,
        body: { ok: false, decision: "DENY", mode: "enforce", reason: "FRAPPE_UPSTREAM_ERROR" },
        log,
      };
    }
  };
}
