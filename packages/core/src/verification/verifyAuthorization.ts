// SPDX-License-Identifier: Apache-2.0
import { verify as nodeVerify } from "node:crypto";
import type { AuthorizationV1 } from "../types/authorization.js";
import type { KeySet } from "../types/keyset.js";
import type {
  AuthorizationVerificationResult,
  VerificationCoverage,
  VerificationMode,
  VerificationViolation
} from "./types.js";
import { canonicalJson } from "../crypto/hashes.js";
import { isTrustedAuthorizationAuthority } from "./authorizationAuthority.js";
import type { AuthorizationAuthority } from "./authorizationAuthority.js";
import {
  SIGNING_DOMAINS,
  findKeyInKeySets,
  isSmallOrderEd25519Pem,
  keyIsActiveAt,
  signEd25519,
  verifyEd25519,
  verifyHmacDomain
} from "../crypto/signatures.js";

/**
 * Default maximum number of seconds `issued_at` may lead the trusted
 * verification time and still be considered plausible.
 *
 * Chosen to absorb ordinary issuer/verifier clock drift while rejecting
 * grossly implausible future-dated authorizations.
 *
 * The default currently matches the recommended intent-freshness clock skew,
 * but the two security controls are intentionally independent.
 *
 * @public
 */
export const DEFAULT_MAX_FUTURE_ISSUED_AT_SKEW_SECONDS = 300;

/** @public */
export type VerifyAuthorizationOptions = {
  now?: number;
  mode?: "strict" | "best-effort";
  expectedIssuer?: string;
  expectedAudience?: string;
  expectedPolicyId?: string;
  /**
   * Deployer-configured (issuer, policyId) pairs authorized to issue
   * authorizations for this boundary.
   *
   * When supplied, the artifact's `(issuer, policy_id)` pair must appear as a
   * complete pair or verification fails with
   * `AUTH_ISSUER_POLICY_NOT_AUTHORIZED`. This is distinct from
   * `expectedIssuer` / `expectedPolicyId`, which compare one scalar each and
   * cannot express that a given issuer is authorized for one policy but not
   * another.
   *
   * ⚠️ Omitting this option performs no authority check. That is acceptable for
   * a library verifier, whose caller may legitimately be verifying an artifact
   * it does not enforce. It is NOT acceptable at an enforcement boundary that
   * accepts externally supplied authorizations: such a boundary MUST require
   * the configuration itself and MUST NOT treat `undefined` as "accept any
   * issuer/policy". See `PepGatewayOptions.trustedAuthorizationAuthorities`.
   */
  trustedAuthorizationAuthorities?: readonly AuthorizationAuthority[];
  consumedAuthIds?: readonly string[];
  trustedKeySets?: KeySet | readonly KeySet[];
  requireSignatureVerification?: boolean;
  /**
   * Maximum number of seconds `issued_at` may lead the trusted verification
   * time (`opts.now`, never `intent.timestamp`) and still be accepted.
   *
   * Defaults to {@link DEFAULT_MAX_FUTURE_ISSUED_AT_SKEW_SECONDS}. An
   * `issued_at` beyond this bound is rejected with
   * `AUTH_ISSUED_AT_IMPLAUSIBLE`, regardless of `expiry`.
   */
  maxFutureIssuedAtSkewSeconds?: number;
  /**
   * Shared secret for verifying HMAC-SHA256 signed authorization artifacts.
   *
   * @deprecated HMAC-SHA256 is a legacy compatibility path and is NOT part of the
   * standard AuthorizationV1 wire format. It cannot be independently verified by
   * third-party verifiers without sharing the secret. Use `trustedKeySets` with
   * Ed25519-signed artifacts for all new integrations. `legacyHmacSecret` will be
   * removed in a future major release.
   */
  legacyHmacSecret?: string;
};

function sortViolations(violations: VerificationViolation[]): VerificationViolation[] {
  return [...violations].sort((a, b) => {
    if (a.code < b.code) return -1;
    if (a.code > b.code) return 1;
    return (a.index ?? 0) - (b.index ?? 0);
  });
}

function hasText(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function signatureParts(auth: AuthorizationV1): { alg?: string; kid?: string; sig?: string; nested: boolean } {
  const raw = auth.signature;
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    return {
      alg: raw.alg,
      kid: raw.kid,
      sig: raw.sig,
      nested: true
    };
  }
  return {
    alg: auth.alg,
    kid: auth.kid,
    sig: typeof raw === "string" ? raw : undefined,
    nested: false
  };
}

/** @internal - exported for regression tests; NOT part of the public API (not re-exported by the package entry point). */
export function canonicalSignatureBytes(encoded: string): Buffer | null {
  // S4: accept base64url (RFC 4648 §5, Encoding B) alongside standard base64
  // (Encoding A), but ONLY in the canonical encoding of an exactly-64-byte
  // signature. The alphabet is detected the same way as before ('-'/'_' => url),
  // and the supplied string must equal the re-encoding of the decoded bytes IN
  // THAT SAME ALPHABET. This preserves base64url interop without letting a
  // non-canonical variant (whitespace, mutated final char, wrong padding, or a
  // cross-alphabet form) verify. The standard Encoding-A rule is NOT applied to
  // an Encoding-B string.
  if (typeof encoded !== "string" || encoded.length === 0) return null;
  // Encoding A: canonical standard Base64 (padded) of exactly 64 bytes.
  const std = Buffer.from(encoded, "base64");
  if (std.length === 64 && std.toString("base64") === encoded) return std;
  // Encoding B: canonical base64url (RFC 4648 §5, unpadded) of exactly 64 bytes.
  const url = Buffer.from(encoded, "base64url");
  if (url.length === 64 && url.toString("base64url") === encoded) return url;
  // Anything else (non-canonical, wrong length, cross-alphabet, padded url,
  // whitespace, mutated final char) is rejected.
  return null;
}

function verifyEd25519Raw(payload: unknown, signatureBase64: string, publicKeyPem: string): boolean {
  try {
    const bytes = canonicalSignatureBytes(signatureBase64);
    if (!bytes) return false;
    // S3: reject small-order / unreadable public keys on the Encoding-B fallback
    // path too, before trusting the verify result. Fail closed.
    if (isSmallOrderEd25519Pem(publicKeyPem)) return false;
    return nodeVerify(
      null,
      Buffer.from(canonicalJson(payload), "utf8"),
      publicKeyPem,
      bytes
    );
  } catch {
    return false;
  }
}

function nowOrThrow(now: number | undefined): number {
  if (now !== undefined) return now;
  return Math.floor(Date.now() / 1000);
}

/**
 * `maxFutureIssuedAtSkewSeconds` is a trusted-caller configuration input,
 * not attacker-reachable data. A malformed value is a caller precondition
 * violation - it throws rather than silently falling back to the default
 * or being coerced, so a broken deployment cannot be mistaken for a
 * data-driven `ALLOW`/`DENY`.
 */
function resolveMaxFutureIssuedAtSkewSeconds(value: number | undefined): number {
  if (value === undefined) return DEFAULT_MAX_FUTURE_ISSUED_AT_SKEW_SECONDS;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(
      "verifyAuthorization: maxFutureIssuedAtSkewSeconds must be a finite, non-negative safe integer (seconds)"
    );
  }
  return value;
}

/**
 * Strip an authorization object down to only the normative `AuthorizationV1`
 * fields, excluding internal engine fields (`authorization_id`,
 * `policy_version`, `state_snapshot_hash`, `engine_signature`, `expires_at`).
 *
 * Use this before computing `delegationParentHash` or any public signing
 * payload so that independent implementations can reproduce the same hash
 * without access to internal engine state.
 *
 * @public
 */
export function toPublicAuthorizationV1(auth: AuthorizationV1): AuthorizationV1 {
  const out: AuthorizationV1 = {
    auth_id:      auth.auth_id,
    issuer:       auth.issuer,
    audience:     auth.audience,
    intent_hash:  auth.intent_hash,
    state_hash:   auth.state_hash,
    policy_id:    auth.policy_id,
    decision:     auth.decision,
    issued_at:    auth.issued_at,
    expiry:       auth.expiry,
    alg:          auth.alg,
    kid:          auth.kid,
    signature:    auth.signature,
  };
  if (auth.version    !== undefined) out.version    = auth.version;
  if (auth.nonce      !== undefined) out.nonce      = auth.nonce;
  if (auth.capability !== undefined) out.capability = auth.capability;
  return out;
}

/** @public */
export function authorizationSigningPayload(auth: AuthorizationV1): Omit<AuthorizationV1, "signature"> | Record<string, unknown> {
  const sig = signatureParts(auth);
  const hasFlatAlgKid = hasText(auth.alg) && hasText(auth.kid);

  if (sig.nested) {
    // Use only normative AuthorizationV1 fields so legacy engine-internal fields
    // (engine_signature, state_snapshot_hash, etc.) are never included in the
    // Encoding B signing payload — independent implementations must be able to
    // reproduce this payload without access to engine-internal state.
    //
    // canonicalJson throws on undefined values; only include fields that are
    // actually present. Sift wire format omits `expiry` and uses `expires_at`
    // instead — both are normalised here so either wire format verifies correctly.
    const pub = toPublicAuthorizationV1(auth);
    const payload: Record<string, unknown> = {};
    payload.auth_id     = pub.auth_id;
    payload.issuer      = pub.issuer;
    payload.audience    = pub.audience;
    payload.intent_hash = pub.intent_hash;
    payload.state_hash  = pub.state_hash;
    payload.policy_id   = pub.policy_id;
    payload.decision    = pub.decision;
    payload.issued_at   = pub.issued_at;
    if (pub.expiry      !== undefined) payload.expiry      = pub.expiry;
    if (pub.version     !== undefined) payload.version     = pub.version;
    if (pub.nonce       !== undefined) payload.nonce       = pub.nonce;
    if (pub.capability  !== undefined) payload.capability  = pub.capability;
    // Sift wire format uses expires_at instead of expiry; preserve it when present
    // so Sift-issued tokens remain verifiable without re-signing.
    const raw = auth as Record<string, unknown>;
    if (typeof raw["expires_at"] === "number") payload["expires_at"] = raw["expires_at"];
    if (hasFlatAlgKid) {
      // The locked corpus uses nested signature bytes with signed top-level
      // alg/kid. Preserve those public fields when filtering engine internals.
      payload.alg = pub.alg;
      payload.kid = pub.kid;
    } else {
      payload.signature = { alg: sig.alg, kid: sig.kid };
    }
    return payload;
  }

  const payload: Record<string, unknown> = {
    auth_id: auth.auth_id,
    issuer: auth.issuer,
    audience: auth.audience,
    intent_hash: auth.intent_hash,
    state_hash: auth.state_hash,
    policy_id: auth.policy_id,
    decision: auth.decision,
    issued_at: auth.issued_at,
    expiry: auth.expiry,
    alg: auth.alg,
    kid: auth.kid
  };
  if (auth.version !== undefined) payload.version = auth.version;
  if (auth.nonce !== undefined) payload.nonce = auth.nonce;
  if (auth.capability !== undefined) payload.capability = auth.capability;
  return payload;
}

/** @public */
export function signAuthorizationEd25519(
  auth: Omit<AuthorizationV1, "signature" | "alg"> & { alg?: "Ed25519" },
  privateKeyPem: string
): AuthorizationV1 {
  const unsigned: AuthorizationV1 = {
    ...auth,
    alg: "Ed25519",
    signature: ""
  };
  const signature = signEd25519(SIGNING_DOMAINS.AUTH_V1, authorizationSigningPayload(unsigned), privateKeyPem);
  return { ...unsigned, signature };
}

/** @public */
export function verifyAuthorization(
  auth: AuthorizationV1,
  opts?: VerifyAuthorizationOptions
): AuthorizationVerificationResult {
  const violations: VerificationViolation[] = [];
  const now = nowOrThrow(opts?.now);
  // Verification-surface descriptors (#172). These make it impossible to
  // mistake a merely-structural result for a cryptographically verified one,
  // and they are fully orthogonal:
  //   - `signatureVerified` reports the OUTCOME of authentication: it flips true
  //     ONLY when a cryptographic check actually runs AND succeeds;
  //   - `verificationCoverage` reports which surface a cryptographic check was
  //     run AGAINST, independent of that outcome. It becomes
  //     "authorization-v1-full" the moment the check is engaged — so a forged
  //     signature reports full coverage with `signatureVerified: false` — and
  //     stays "none" only when no cryptographic verifier ran at all (missing
  //     trust material, unknown/inactive kid, or absent HMAC secret).
  // `verificationMode` is derived purely from the requested posture (below),
  // independent of whether cryptography ran. A permissive result sets
  // `signatureVerified` only when a cryptographic check was available, executed,
  // and succeeded, so a caller that only inspects `ok` cannot be silently misled.
  let signatureVerified = false;
  let verificationCoverage: VerificationCoverage = "none";
  const maxFutureIssuedAtSkewSeconds = resolveMaxFutureIssuedAtSkewSeconds(opts?.maxFutureIssuedAtSkewSeconds);
  const consumed = new Set(opts?.consumedAuthIds ?? []);

  if (!hasText(auth.decision) || auth.decision !== "ALLOW") {
    violations.push({ code: "AUTH_DECISION_INVALID", message: "authorization decision must be ALLOW" });
  }
  if (!hasText(auth.intent_hash)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "intent_hash is required" });
  }
  if (!hasText(auth.state_hash)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "state_hash is required" });
  }
  if (!hasText(auth.policy_id)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "policy_id is required" });
  }
  if (!hasText(auth.issuer)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "issuer is required" });
  }
  if (!hasText(auth.audience)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "audience is required" });
  }
  if (!hasText(auth.auth_id)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "auth_id is required" });
  } else if (auth.auth_id !== auth.auth_id.normalize("NFC")) {
    // S2: identifiers participate in signature verification via canonicalJson,
    // which NFC-normalizes strings, but replay protection keys on the raw
    // identifier. A canonically-equivalent non-NFC auth_id keeps a valid
    // signature yet a distinct replay key, allowing a consumed id to be
    // replayed. Require a single canonical (NFC) representation at this trust
    // boundary and reject anything else - never silently normalize an
    // attacker-controlled identifier.
    violations.push({ code: "AUTH_ID_NONCANONICAL", message: "auth_id must be Unicode NFC-normalized" });
  }
  if (!Number.isInteger(auth.issued_at)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "issued_at must be integer unix seconds" });
  } else if (
    !Number.isSafeInteger(auth.issued_at) ||
    auth.issued_at > now + maxFutureIssuedAtSkewSeconds
  ) {
    // issued_at is compared only against the trusted verificationTime (`now`,
    // supplied by the caller as `opts.now`) - never against `intent.timestamp`,
    // which this function does not receive. An unsafe-magnitude issued_at
    // (e.g. beyond Number.MAX_SAFE_INTEGER) is inherently implausible and
    // rejected without arithmetic that could overflow.
    violations.push({
      code: "AUTH_ISSUED_AT_IMPLAUSIBLE",
      message: `issued_at must not be more than ${maxFutureIssuedAtSkewSeconds}s ahead of verification time`
    });
  }
  const sig = signatureParts(auth);

  if (!hasText(sig.alg)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "alg is required" });
  }
  if (!hasText(sig.kid)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "kid is required" });
  }
  if (!hasText(sig.sig)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "signature is required" });
  }

  // Accept 'expires_at' (Sift wire format) as a fallback when 'expiry' is absent.
  const effectiveExpiry = Number.isInteger(auth.expiry)
    ? auth.expiry
    : Number.isInteger((auth as Record<string, unknown>)["expires_at"] as number)
    ? (auth as Record<string, unknown>)["expires_at"] as number
    : undefined;
  if (!Number.isInteger(effectiveExpiry)) {
    violations.push({ code: "AUTH_MISSING_FIELD", message: "expiry must be integer unix seconds" });
  } else if (now >= (effectiveExpiry as number)) {
    violations.push({ code: "AUTH_EXPIRED", message: "authorization has expired" });
  }

  if (opts?.expectedIssuer !== undefined && auth.issuer !== opts.expectedIssuer) {
    violations.push({ code: "AUTH_ISSUER_MISMATCH", message: "issuer does not match expectedIssuer" });
  }
  if (opts?.expectedAudience !== undefined && auth.audience !== opts.expectedAudience) {
    violations.push({ code: "AUTH_AUDIENCE_MISMATCH", message: "audience does not match expectedAudience" });
  }
  if (opts?.expectedPolicyId !== undefined && auth.policy_id !== opts.expectedPolicyId) {
    violations.push({ code: "AUTH_POLICY_ID_MISMATCH", message: "policy_id does not match expectedPolicyId" });
  }
  // Independent issuer-policy authority. Deliberately a distinct code from the
  // scalar mismatches above: those mean "a supplied expectation did not match",
  // whereas this means "this authenticated issuer is not authorized for this
  // policy at all". Reusing AUTH_ISSUER_MISMATCH here would misreport an
  // authority rejection as a configuration mismatch.
  if (opts?.trustedAuthorizationAuthorities !== undefined) {
    if (!isTrustedAuthorizationAuthority(opts.trustedAuthorizationAuthorities, auth.issuer, auth.policy_id)) {
      violations.push({
        code: "AUTH_ISSUER_POLICY_NOT_AUTHORIZED",
        message: "issuer is not authorized for this policy_id",
      });
    }
  }
  if (hasText(auth.auth_id) && consumed.has(auth.auth_id)) {
    violations.push({ code: "AUTH_REPLAY", message: "auth_id has already been consumed" });
  }

  const payload = authorizationSigningPayload(auth);

  const trustedRaw = opts?.trustedKeySets;
  const trusted = trustedRaw
    ? (Array.isArray(trustedRaw) ? trustedRaw : [trustedRaw])
    : [];

  if (opts?.mode === "strict" && trusted.length === 0) {
    // Strict was requested but cannot run: report the requested posture
    // ("strict") while making clear no signature was verified.
    return {
      ok: false,
      status: "invalid",
      violations: [{ code: "TRUSTED_KEYSETS_REQUIRED", message: "strict mode requires trustedKeySets to be provided" }],
      signatureVerified: false,
      verificationMode: "strict",
      verificationCoverage: "none"
    };
  }

  // Strict mode implies signature verification is mandatory: a strict result
  // must never be able to pass without a cryptographic check having actually
  // run and succeeded (pinned by the strict + ok invariant test). Without this,
  // an HMAC authorization under `mode: "strict"` with a non-empty trusted key
  // set but no `legacyHmacSecret` would slip through with `ok: true` and
  // `signatureVerified: false`.
  const requireSig =
    opts?.mode === "strict" ||
    (opts?.requireSignatureVerification ?? false);
  const hasSigMaterial = hasText(sig.alg) && hasText(sig.kid) && hasText(sig.sig);

  if (hasSigMaterial) {
    const sigAlg = sig.alg as string;
    const sigKid = sig.kid as string;
    const sigValue = sig.sig as string;
    if (sigAlg === "Ed25519" || sigAlg === "ed25519") {
      if (trusted.length === 0) {
        if (requireSig) {
          violations.push({ code: "AUTH_TRUST_MISSING", message: "trustedKeySets required for Ed25519 verification" });
        }
      } else {
        const key = findKeyInKeySets(trusted, auth.issuer, sigKid, "Ed25519");
        if (!key) {
          violations.push({ code: "AUTH_KID_UNKNOWN", message: "kid not found for issuer/alg" });
        } else if (!keyIsActiveAt(key, now)) {
          violations.push({ code: "AUTH_KEY_INACTIVE", message: "key is not active at verification time" });
        } else {
          // A cryptographic check is actually performed here (pass or fail).
          // Coverage records the surface evaluated and is set the moment the
          // check is engaged, independent of the outcome; `signatureVerified`
          // flips true only if it succeeds.
          verificationCoverage = "authorization-v1-full";
          if (
            !verifyEd25519(SIGNING_DOMAINS.AUTH_V1, payload, sigValue, key.public_key) &&
            !verifyEd25519Raw(payload, sigValue, key.public_key)
          ) {
            violations.push({ code: "AUTH_SIGNATURE_INVALID", message: "signature verification failed" });
          } else {
            signatureVerified = true;
          }
        }
      }
    } else if (sigAlg === "HMAC-SHA256") {
      if (opts?.legacyHmacSecret) {
        // Legacy HMAC covers the full AuthorizationV1 signing payload (not the
        // narrower engine-HMAC subset). Coverage reflects the surface evaluated
        // and is set once the check is engaged, independent of the outcome.
        verificationCoverage = "authorization-v1-full";
        if (!verifyHmacDomain(SIGNING_DOMAINS.AUTH_V1, payload, sigValue, opts.legacyHmacSecret)) {
          violations.push({ code: "AUTH_SIGNATURE_INVALID", message: "legacy HMAC signature verification failed" });
        } else {
          signatureVerified = true;
        }
      } else if (requireSig) {
        violations.push({ code: "AUTH_TRUST_MISSING", message: "legacyHmacSecret required for HMAC verification" });
      }
    } else {
      violations.push({ code: "AUTH_ALG_UNSUPPORTED", message: "unsupported signature algorithm" });
    }
  }

  // Configured posture only (independent of whether cryptography ran):
  // "strict" when requested, otherwise "permissive" (the best-effort default).
  // Whether a signature was actually checked is reported separately via
  // `signatureVerified` / `verificationCoverage`.
  const verificationMode: VerificationMode = opts?.mode === "strict" ? "strict" : "permissive";

  if (violations.length > 0) {
    return {
      ok: false,
      status: "invalid",
      violations: sortViolations(violations),
      policyId: hasText(auth.policy_id) ? auth.policy_id : undefined,
      stateHash: hasText(auth.state_hash) ? auth.state_hash : undefined,
      signatureVerified,
      verificationMode,
      verificationCoverage
    };
  }

  return {
    ok: true,
    status: "ok",
    violations: [],
    policyId: auth.policy_id,
    stateHash: auth.state_hash,
    signatureVerified,
    verificationMode,
    verificationCoverage
  };
}
