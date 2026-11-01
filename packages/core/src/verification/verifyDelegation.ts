// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";
import type { AuthorizationV1 } from "../types/authorization.js";
import type { DelegationV1, DelegationScope } from "../types/delegation.js";
import type { KeySet } from "../types/keyset.js";
import type { VerificationResult, VerificationViolation } from "./types.js";
import {
  SIGNING_DOMAINS,
  findKeyInKeySets,
  keyIsActiveAt,
  verifyEd25519,
} from "../crypto/signatures.js";
import { canonicalJson } from "../crypto/hashes.js";
import { toPublicAuthorizationV1 } from "./verifyAuthorization.js";

// ── Options ───────────────────────────────────────────────────────────────────

/** @public */
export type VerifyDelegationOptions = {
  /** Current unix seconds. Injected for determinism; falls back to Date.now()/1000. */
  now?: number;
  /** KeySets used to resolve the delegation signing key. */
  trustedKeySets?: KeySet | readonly KeySet[];
  /** Fail if trustedKeySets are absent (mirrors requireSignatureVerification). */
  requireSignatureVerification?: boolean;
  /** Expected delegatee. Verification fails if delegation.delegatee does not match. */
  expectedDelegatee?: string;
  /** Expected policy_id. Verification fails if delegation.policy_id does not match. */
  expectedPolicyId?: string;
  /**
   * Parent scope — the authority granted in the parent AuthorizationV1.
   * When provided, scope narrowing invariants are enforced.
   * When absent, scope narrowing is skipped (deployer responsibility).
   */
  parentScope?: DelegationScope;
  /** Set of delegation_ids already consumed. Used for replay protection. */
  consumedDelegationIds?: readonly string[];
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function nowSeconds(now: number | undefined): number {
  return now !== undefined ? now : Math.floor(Date.now() / 1000);
}

function hasText(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

function sortViolations(violations: VerificationViolation[]): VerificationViolation[] {
  return [...violations].sort((a, b) => {
    if (a.code < b.code) return -1;
    if (a.code > b.code) return 1;
    return 0;
  });
}

/**
 * Compute the canonical hash of a parent `AuthorizationV1` for use in
 * `DelegationV1.parent_auth_hash`.
 *
 * Only normative `AuthorizationV1` fields are included in the hash so
 * independent implementations can reproduce the same value without access
 * to engine-internal state (e.g. `engine_signature`, `state_snapshot_hash`).
 *
 * @public
 */
export function delegationParentHash(parent: AuthorizationV1): string {
  return createHash("sha256").update(canonicalJson(toPublicAuthorizationV1(parent)), "utf8").digest("hex");
}

/** @public */
export function delegationSigningPayload(d: DelegationV1): Omit<DelegationV1, "signature"> {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { signature: _sig, ...unsigned } = d;
  return unsigned;
}

// ── verifyDelegation ──────────────────────────────────────────────────────────

/**
 * Verify a DelegationV1 artifact in isolation.
 * Does not resolve or check the parent AuthorizationV1.
 * Use verifyDelegationChain for full chain verification.
 *
 * @public
 */
export function verifyDelegation(
  delegation: DelegationV1,
  opts?: VerifyDelegationOptions
): VerificationResult {
  const violations: VerificationViolation[] = [];
  const now = nowSeconds(opts?.now);
  const consumed = new Set(opts?.consumedDelegationIds ?? []);

  // ── Required fields ────────────────────────────────────────────────────────
  for (const [field, value] of [
    ["delegation_id", delegation.delegation_id],
    ["issuer",        delegation.issuer],
    ["audience",      delegation.audience],
    ["parent_auth_hash", delegation.parent_auth_hash],
    ["delegator",     delegation.delegator],
    ["delegatee",     delegation.delegatee],
    ["policy_id",     delegation.policy_id],
    ["alg",           delegation.alg],
    ["kid",           delegation.kid],
    ["signature",     delegation.signature],
  ] as const) {
    if (!hasText(value)) {
      violations.push({ code: "DELEGATION_MISSING_FIELD", message: `${field} is required` });
    }
  }
  if (!Number.isInteger(delegation.issued_at)) {
    violations.push({ code: "DELEGATION_MISSING_FIELD", message: "issued_at must be integer unix seconds" });
  }
  if (!Number.isInteger(delegation.expiry)) {
    violations.push({ code: "DELEGATION_MISSING_FIELD", message: "expiry must be integer unix seconds" });
  }

  // ── Algorithm ──────────────────────────────────────────────────────────────
  if (hasText(delegation.alg) && delegation.alg !== "Ed25519") {
    violations.push({ code: "DELEGATION_ALG_UNSUPPORTED", message: "only Ed25519 is supported for DelegationV1" });
  }

  // ── Expiry ─────────────────────────────────────────────────────────────────
  if (Number.isInteger(delegation.expiry) && now >= delegation.expiry) {
    violations.push({ code: "DELEGATION_EXPIRED", message: "delegation has expired" });
  }

  // ── Audience / delegatee ───────────────────────────────────────────────────
  if (opts?.expectedDelegatee !== undefined && delegation.delegatee !== opts.expectedDelegatee) {
    violations.push({ code: "DELEGATION_AUDIENCE_MISMATCH", message: "delegatee does not match expectedDelegatee" });
  }

  // ── Policy ─────────────────────────────────────────────────────────────────
  if (opts?.expectedPolicyId !== undefined && delegation.policy_id !== opts.expectedPolicyId) {
    violations.push({ code: "DELEGATION_POLICY_MISMATCH", message: "policy_id does not match expectedPolicyId" });
  }

  // ── Canonical identifier (S2) ────────────────────────────────────────────
  // See verifyAuthorization: the signing payload NFC-normalizes strings while
  // replay protection keys on the raw delegation_id, so a canonically-equivalent
  // non-NFC form would keep a valid signature but a distinct replay key. Require
  // one canonical (NFC) representation and reject anything else; do not silently
  // normalize an attacker-controlled identifier.
  if (hasText(delegation.delegation_id) && delegation.delegation_id !== delegation.delegation_id.normalize("NFC")) {
    violations.push({ code: "DELEGATION_ID_NONCANONICAL", message: "delegation_id must be Unicode NFC-normalized" });
  }

  // ── Replay ─────────────────────────────────────────────────────────────────
  if (hasText(delegation.delegation_id) && consumed.has(delegation.delegation_id)) {
    violations.push({ code: "DELEGATION_REPLAY", message: "delegation_id has already been consumed" });
  }

  // ── Scope narrowing (when parentScope provided) ────────────────────────────
  if (opts?.parentScope !== undefined) {
    const scopeViolations = checkScopeNarrowing(delegation.scope, opts.parentScope);
    violations.push(...scopeViolations);
  }

  // ── Signature verification ─────────────────────────────────────────────────
  const trustedRaw = opts?.trustedKeySets;
  const trusted = trustedRaw
    ? (Array.isArray(trustedRaw) ? trustedRaw : [trustedRaw])
    : [];
  const requireSig = opts?.requireSignatureVerification ?? false;

  if (hasText(delegation.alg) && delegation.alg === "Ed25519" && hasText(delegation.kid) && hasText(delegation.signature)) {
    if (trusted.length === 0) {
      if (requireSig) {
        violations.push({ code: "DELEGATION_TRUST_MISSING", message: "trustedKeySets required for Ed25519 verification" });
      }
    } else {
      const key = findKeyInKeySets(trusted, delegation.issuer, delegation.kid, "Ed25519");
      if (!key) {
        violations.push({ code: "DELEGATION_KID_UNKNOWN", message: "kid not found for issuer/alg" });
      } else if (!keyIsActiveAt(key, now)) {
        violations.push({ code: "DELEGATION_KEY_INACTIVE", message: "key is not active at verification time" });
      } else {
        const payload = delegationSigningPayload(delegation);
        if (!verifyEd25519(SIGNING_DOMAINS.DELEGATION_V1, payload, delegation.signature, key.public_key)) {
          violations.push({ code: "DELEGATION_SIGNATURE_INVALID", message: "signature verification failed" });
        }
      }
    }
  }

  if (violations.length > 0) {
    return {
      ok: false,
      status: "invalid",
      violations: sortViolations(violations),
      policyId: hasText(delegation.policy_id) ? delegation.policy_id : undefined,
    };
  }

  return {
    ok: true,
    status: "ok",
    violations: [],
    policyId: delegation.policy_id,
  };
}

// ── verifyDelegationChain ─────────────────────────────────────────────────────

/**
 * Verify a DelegationV1 artifact against its parent AuthorizationV1.
 *
 * Enforces:
 * - signature verification (when trustedKeySets provided)
 * - parent hash binding
 * - single-hop constraint (parent must be AuthorizationV1, not DelegationV1)
 * - parent expiry
 * - delegator matches parent.audience
 * - policy_id matches parent.policy_id
 * - delegation expiry <= parent expiry
 * - scope narrowing against parent scope (when parentScope provided in opts)
 * - all verifyDelegation checks
 *
 * @public
 */
export function verifyDelegationChain(
  delegation: DelegationV1,
  parent: AuthorizationV1,
  opts?: VerifyDelegationOptions
): VerificationResult {
  const violations: VerificationViolation[] = [];
  const now = nowSeconds(opts?.now);

  // ── Single-hop: parent must be AuthorizationV1, not DelegationV1 ───────────
  if ("delegation_id" in (parent as object)) {
    violations.push({ code: "DELEGATION_MULTIHOP_DENIED", message: "parent must be AuthorizationV1 — multi-hop delegation is not permitted" });
    return { ok: false, status: "invalid", violations };
  }

  // ── Parent hash binding ────────────────────────────────────────────────────
  if (hasText(delegation.parent_auth_hash)) {
    const computedHash = delegationParentHash(parent);
    if (computedHash !== delegation.parent_auth_hash) {
      violations.push({ code: "DELEGATION_PARENT_HASH_MISMATCH", message: "parent_auth_hash does not match computed hash of parent authorization" });
    }
  }

  // ── Parent expiry ──────────────────────────────────────────────────────────
  if (Number.isInteger(parent.expiry) && now >= parent.expiry) {
    violations.push({ code: "DELEGATION_PARENT_EXPIRED", message: "parent authorization has expired" });
  }

  // ── Delegator binding ──────────────────────────────────────────────────────
  if (hasText(delegation.delegator) && hasText(parent.audience) && delegation.delegator !== parent.audience) {
    violations.push({ code: "DELEGATION_DELEGATOR_MISMATCH", message: "delegator does not match parent.audience" });
  }

  // ── Policy binding ─────────────────────────────────────────────────────────
  if (hasText(delegation.policy_id) && hasText(parent.policy_id) && delegation.policy_id !== parent.policy_id) {
    violations.push({ code: "DELEGATION_POLICY_ID_MISMATCH", message: "policy_id does not match parent.policy_id" });
  }

  // ── Expiry <= parent expiry ────────────────────────────────────────────────
  if (Number.isInteger(delegation.expiry) && Number.isInteger(parent.expiry) && delegation.expiry > parent.expiry) {
    violations.push({ code: "DELEGATION_EXPIRY_EXCEEDS_PARENT", message: "delegation expiry exceeds parent authorization expiry" });
  }

  // Return early on chain-level failures before running inner verification
  if (violations.length > 0) {
    return {
      ok: false,
      status: "invalid",
      violations: sortViolations(violations),
      policyId: hasText(delegation.policy_id) ? delegation.policy_id : undefined,
    };
  }

  // ── Delegate to verifyDelegation for remaining checks ─────────────────────
  return verifyDelegation(delegation, opts);
}

// ── Effective scope resolution ─────────────────────────────────────────────────

/**
 * Resolve the effective child delegation scope against a parent scope.
 *
 * For each field:
 *   - an explicitly supplied child value is kept as-is (the child may narrow
 *     further than the parent, but never widen — that is enforced separately
 *     by the internal `checkScopeNarrowing` narrowing check);
 *   - an omitted child value inherits the parent's value when the parent
 *     constrains that field — omission MUST NOT be read as "unconstrained"
 *     when the parent has already placed a limit on it (issue #284: a child
 *     that simply leaves a field out of its scope was previously able to
 *     obtain broader effective authority than its parent on that field);
 *   - a field left unconstrained by both the child and the parent remains
 *     unconstrained — there is nothing to inherit.
 *
 * This applies uniformly to every `DelegationScope` field (`tools`,
 * `max_amount`, `max_actions`, `max_depth`). `max_actions` is included on the
 * same basis as the others: it is an ordinary optional `DelegationScope`
 * field with no structural distinction from the rest, and the invariant that
 * a `DelegationV1` MUST NOT expand authority relative to its parent does not
 * carve out an exception for it.
 *
 * Resolution happens only at verification time. It never mutates its inputs
 * and its result is never written back into a signed `DelegationV1` artifact
 * — `createDelegation()` continues to sign exactly the raw scope the caller
 * supplied. This keeps existing signed bytes, and every existing signature,
 * unchanged.
 *
 * @public
 */
export function resolveEffectiveChildScope(
  child: DelegationScope,
  parent: DelegationScope
): DelegationScope {
  const effective: DelegationScope = {};

  effective.tools = child.tools !== undefined ? child.tools : parent.tools;
  effective.max_amount = child.max_amount !== undefined ? child.max_amount : parent.max_amount;
  effective.max_actions = child.max_actions !== undefined ? child.max_actions : parent.max_actions;
  effective.max_depth = child.max_depth !== undefined ? child.max_depth : parent.max_depth;

  if (effective.tools === undefined) delete effective.tools;
  if (effective.max_amount === undefined) delete effective.max_amount;
  if (effective.max_actions === undefined) delete effective.max_actions;
  if (effective.max_depth === undefined) delete effective.max_depth;

  return effective;
}

// ── Scope narrowing ───────────────────────────────────────────────────────────

function checkScopeNarrowing(
  child: DelegationScope,
  parent: DelegationScope
): VerificationViolation[] {
  const violations: VerificationViolation[] = [];
  const effective = resolveEffectiveChildScope(child, parent);

  // tools: effective child must be a subset of parent
  if (effective.tools !== undefined && parent.tools !== undefined) {
    const notAllowed = effective.tools.filter((t) => !parent.tools!.includes(t));
    if (notAllowed.length > 0) {
      violations.push({
        code: "DELEGATION_SCOPE_VIOLATION",
        message: `scope.tools contains tools not in parent: ${notAllowed.join(", ")}`,
      });
    }
  }

  // max_amount: effective child must be <= parent
  if (effective.max_amount !== undefined && parent.max_amount !== undefined) {
    if (effective.max_amount > parent.max_amount) {
      violations.push({
        code: "DELEGATION_SCOPE_VIOLATION",
        message: `scope.max_amount ${effective.max_amount} exceeds parent max_amount ${parent.max_amount}`,
      });
    }
  }

  // max_actions: effective child must be <= parent
  if (effective.max_actions !== undefined && parent.max_actions !== undefined) {
    if (effective.max_actions > parent.max_actions) {
      violations.push({
        code: "DELEGATION_SCOPE_VIOLATION",
        message: `scope.max_actions ${effective.max_actions} exceeds parent max_actions ${parent.max_actions}`,
      });
    }
  }

  // max_depth: effective child must be <= parent
  if (effective.max_depth !== undefined && parent.max_depth !== undefined) {
    if (effective.max_depth > parent.max_depth) {
      violations.push({
        code: "DELEGATION_SCOPE_VIOLATION",
        message: `scope.max_depth ${effective.max_depth} exceeds parent max_depth ${parent.max_depth}`,
      });
    }
  }

  return violations;
}
