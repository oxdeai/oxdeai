// SPDX-License-Identifier: Apache-2.0
/** @public */
export type VerificationStatus = "ok" | "invalid" | "inconclusive";

/**
 * How the verifier was *configured* — its posture, independent of the outcome.
 *
 * This deliberately describes configuration only, not whether cryptography
 * actually ran. It maps from the `mode` request option (`"strict" |
 * "best-effort"`, where `"best-effort"` reports as `"permissive"`):
 *
 * - `"strict"`     — strict verification was requested (a trusted key set is
 *                    mandatory and full cryptographic verification is enforced).
 * - `"permissive"` — best-effort verification was requested.
 *
 * Whether a signature was actually checked is a separate, orthogonal fact:
 * inspect {@link VerificationResult.signatureVerified} and
 * {@link VerificationResult.verificationCoverage}. A permissive verification
 * that skipped signature verification (e.g. no trust anchor was available)
 * reports `verificationMode: "permissive"`, `signatureVerified: false`,
 * `verificationCoverage: "none"` — the absence of cryptography is conveyed by
 * those fields, not by the mode.
 *
 * @public
 */
export type VerificationMode = "strict" | "permissive";

/**
 * Which authorization surface a cryptographic check was run against.
 *
 * This reports the surface that was cryptographically *evaluated*, independent
 * of whether authentication succeeded — a forged signature that was checked
 * against the full payload still reports `"authorization-v1-full"` (with
 * `signatureVerified: false`). Whether the check passed is the separate,
 * orthogonal fact on {@link VerificationResult.signatureVerified}.
 *
 * - `"authorization-v1-full"` — a cryptographic check ran against the full
 *                               normative AuthorizationV1 signing payload
 *                               (verified or rejected).
 * - `"engine-hmac-subset"`    — only the engine-HMAC field subset was
 *                               evaluated (see `PolicyEngine.verifyAuthorization`);
 *                               this is NOT full authorization verification.
 * - `"none"`                  — no cryptographic verifier ran at all (e.g.
 *                               missing trust material, unknown/inactive kid,
 *                               or absent HMAC secret).
 *
 * @public
 */
export type VerificationCoverage =
  | "authorization-v1-full"
  | "engine-hmac-subset"
  | "none";

/** @public */
export type VerificationViolationCode =
  | "MALFORMED_EVENT"
  | "POLICY_ID_MISSING"
  | "POLICY_ID_MISMATCH"
  | "MIXED_POLICY_ID"
  | "NON_MONOTONIC_TIMESTAMP"
  | "HASH_CHAIN_INVALID"
  | "NO_STATE_ANCHOR"
  | "SNAPSHOT_CORRUPT"
  | "ENVELOPE_MALFORMED"
  | "AUTH_DECISION_INVALID"
  | "AUTH_EXPIRED"
  | "AUTH_ISSUED_AT_IMPLAUSIBLE"
  | "AUTH_MISSING_FIELD"
  | "AUTH_ISSUER_MISMATCH"
  | "AUTH_AUDIENCE_MISMATCH"
  | "AUTH_POLICY_ID_MISMATCH"
  | "AUTH_ISSUER_POLICY_NOT_AUTHORIZED"
  | "AUTH_REPLAY"
  | "AUTH_ID_NONCANONICAL"
  | "AUTH_ALG_UNSUPPORTED"
  | "AUTH_KID_UNKNOWN"
  | "AUTH_SIGNATURE_INVALID"
  | "AUTH_TRUST_MISSING"
  | "AUTH_KEY_INACTIVE"
  | "ENVELOPE_SIGNATURE_MISSING"
  | "ENVELOPE_SIGNATURE_INVALID"
  | "ENVELOPE_ALG_UNSUPPORTED"
  | "ENVELOPE_KID_UNKNOWN"
  | "ENVELOPE_TRUST_MISSING"
  | "ENVELOPE_KEY_INACTIVE"
  | "DELEGATION_MISSING_FIELD"
  | "DELEGATION_ALG_UNSUPPORTED"
  | "DELEGATION_SIGNATURE_INVALID"
  | "DELEGATION_KID_UNKNOWN"
  | "DELEGATION_TRUST_MISSING"
  | "DELEGATION_KEY_INACTIVE"
  | "DELEGATION_EXPIRED"
  | "DELEGATION_PARENT_HASH_MISMATCH"
  | "DELEGATION_PARENT_EXPIRED"
  | "DELEGATION_DELEGATOR_MISMATCH"
  | "DELEGATION_SIGNER_NOT_AUTHORIZED"
  | "DELEGATION_POLICY_ID_MISMATCH"
  | "DELEGATION_EXPIRY_EXCEEDS_PARENT"
  | "DELEGATION_AUDIENCE_MISMATCH"
  | "DELEGATION_POLICY_MISMATCH"
  | "DELEGATION_SCOPE_VIOLATION"
  | "DELEGATION_MULTIHOP_DENIED"
  | "DELEGATION_REPLAY"
  | "DELEGATION_ID_NONCANONICAL"
  | "DELEGATION_TEMPORAL_INVALID"
  | "DELEGATION_ISSUED_AT_IMPLAUSIBLE"
  | "TRUSTED_KEYSETS_REQUIRED"
  | "KRL_MALFORMED"
  | "KRL_UNSUPPORTED_ALG"
  | "KRL_UNKNOWN_SIGNING_KID"
  | "KRL_SIGNING_KEY_INACTIVE"
  | "KRL_SIG_INVALID"
  | "KRL_EXPIRED"
  | "KRL_VERSION_REGRESSION";

/** @public */
export type VerificationViolation = {
  code: VerificationViolationCode;
  message?: string;
  index?: number;
};

/** @public */
export type VerificationResult = {
  ok: boolean;
  status: VerificationStatus;
  violations: VerificationViolation[];

  policyId?: string;
  stateHash?: string;
  auditHeadHash?: string;

  /**
   * Whether a cryptographic signature verification actually ran AND succeeded.
   *
   * This is `true` only when a real cryptographic check executed and passed —
   * never for a result that was merely structurally or semantically validated.
   * It is orthogonal to `ok`: a validly-signed but expired authorization has
   * `signatureVerified: true` and `ok: false`.
   *
   * Optional on the shared result type so verifiers that do not perform a
   * signature check can omit it; verifiers that expose a signature surface
   * (e.g. {@link AuthorizationVerificationResult}) always populate it.
   */
  signatureVerified?: boolean;

  /** Configured verification posture. See {@link VerificationMode}. */
  verificationMode?: VerificationMode;

  /** Which authorization surface the signature check covered. See {@link VerificationCoverage}. */
  verificationCoverage?: VerificationCoverage;
};

/**
 * Result of {@link verifyAuthorization}.
 *
 * A specialization of {@link VerificationResult} in which the
 * verification-surface descriptors are ALWAYS populated, so a caller can never
 * mistake a structurally-checked authorization for a cryptographically verified
 * one. To decide whether to rely on an authorization, check `signatureVerified`
 * (and `verificationCoverage`), not merely `ok`.
 *
 * This verifier only ever emits `verificationCoverage` of
 * `"authorization-v1-full"` (a cryptographic check ran against the full
 * AuthorizationV1 payload, whether it passed or was rejected) or `"none"`. It
 * never emits `"engine-hmac-subset"` — that value is reserved for
 * the engine HMAC helper (`PolicyEngine.verifyAuthorization`). Consumers must
 * not assume every verifier can produce every coverage level.
 *
 * @public
 */
export type AuthorizationVerificationResult = VerificationResult & {
  signatureVerified: boolean;
  verificationMode: VerificationMode;
  verificationCoverage: VerificationCoverage;
};

/** @public */
export type VerifyAuditOptions = {
  expectedPolicyId?: string;
  mode?: "strict" | "best-effort";
  requireStateAnchors?: boolean;
};

/** @public */
export type VerifyEnvelopeOptions = {
  now?: number;
  expectedPolicyId?: string;
  mode?: "strict" | "best-effort";
  expectedIssuer?: string;
  trustedKeySets?: import("../types/keyset.js").KeySet | readonly import("../types/keyset.js").KeySet[];
  requireSignatureVerification?: boolean;
};
