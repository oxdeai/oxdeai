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
  /**
   * When `true`, an invalid result carries `primaryReasonCode`: the code of the
   * first failing step of the normative verification sequence
   * (verification-v1.md §5, §9.1). `violations` is unaffected: same content,
   * same order.
   *
   * Opt-in so that existing results stay byte-identical: the published
   * `verification-result.schema.json` before 2.1 rejects unknown properties.
   */
  reportPrimaryReasonCode?: boolean;
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

/**
 * The violation of the earliest verification-v1.md §5 step, in insertion order
 * among violations of that step. Step 0 (verifier configuration) never
 * determines (verification-v1.md §5 "Preconditions").
 */
function determiningViolation(
  violations: readonly VerificationViolation[],
  stepOf: ReadonlyMap<VerificationViolation, number>
): VerificationViolation | undefined {
  let best: VerificationViolation | undefined;
  let bestStep = Number.POSITIVE_INFINITY;
  for (const v of violations) {
    const step = stepOf.get(v);
    if (step === undefined || step === 0) continue;
    if (step < bestStep) {
      best = v;
      bestStep = step;
    }
  }
  return best;
}

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

/**
 * Normative AuthorizationV1 top-level fields that are covered by the signature
 * (authorization-v1.md §5 "Signed field set"). `expires_at` is signed in the
 * nested encodings; in the flat encoding it is accepted only as an alias that
 * MUST equal the signed `expiry` (checked in verifyAuthorization).
 */
const AUTHORIZATION_SIGNED_FIELDS: ReadonlySet<string> = new Set([
  "version", "auth_id", "issuer", "audience", "intent_hash", "state_hash", "policy_id",
  "decision", "issued_at", "expiry", "expires_at", "alg", "kid", "nonce", "capability", "signature"
]);

/**
 * PolicyEngine legacy fields NOT covered by the AuthorizationV1 signature.
 * `authorization_id` must equal the signed `auth_id`; `policy_version`,
 * `state_snapshot_hash` and `engine_signature` belong to the engine-HMAC
 * domain and are never consulted by AuthorizationV1 verification.
 */
const AUTHORIZATION_LEGACY_ENGINE_FIELDS: ReadonlySet<string> = new Set([
  "authorization_id", "policy_version", "state_snapshot_hash", "engine_signature"
]);

const NESTED_SIGNATURE_FIELDS: ReadonlySet<string> = new Set(["alg", "kid", "sig"]);

/** Own property with a defined value (JSON cannot carry `undefined`). */
function isPresent(obj: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key) && obj[key] !== undefined;
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

/**
 * @internal - exported for regression tests; NOT part of the public API (not
 * re-exported by the package entry point). Accepts either canonical alphabet and
 * is therefore NOT used by verifyAuthorization, which binds the alphabet to the
 * declared alg (see canonicalBase64UrlSignatureBytes / verifyEd25519).
 */
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

/**
 * Encoding B (Sift-compatible) signature decoder: canonical, unpadded base64url
 * (RFC 4648 §5) of exactly 64 bytes, and nothing else. A standard-base64 string
 * is NOT accepted here — the alphabet is bound to the declared encoding
 * (authorization-v1.md §5), never auto-detected.
 * @internal
 */
function canonicalBase64UrlSignatureBytes(encoded: string): Buffer | null {
  if (typeof encoded !== "string" || encoded.length === 0) return null;
  const url = Buffer.from(encoded, "base64url");
  if (url.length === 64 && url.toString("base64url") === encoded) return url;
  return null;
}

/**
 * Encoding B verification: non-prefixed canonical preimage, base64url signature.
 * Used ONLY for `alg === "ed25519"`.
 */
function verifyEd25519SiftCompatible(payload: unknown, signatureBase64Url: string, publicKeyPem: string): boolean {
  try {
    const bytes = canonicalBase64UrlSignatureBytes(signatureBase64Url);
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
  // Each violation is tagged with the verification-v1.md §5 step that produced
  // it (0 = verifier configuration, outside the determining-code rule). The
  // tag never affects `violations` (content or order); it only feeds the
  // opt-in `primaryReasonCode` (verification-v1.md §9.1).
  const stepOf = new Map<VerificationViolation, number>();
  const add = (step: number, v: VerificationViolation): void => {
    violations.push(v);
    stepOf.set(v, step);
  };
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
    add(4, { code: "AUTH_DECISION_INVALID", message: "authorization decision must be ALLOW" });
  }
  if (!hasText(auth.intent_hash)) {
    add(2, { code: "AUTH_MISSING_FIELD", message: "intent_hash is required" });
  }
  if (!hasText(auth.state_hash)) {
    add(2, { code: "AUTH_MISSING_FIELD", message: "state_hash is required" });
  }
  if (!hasText(auth.policy_id)) {
    add(2, { code: "AUTH_MISSING_FIELD", message: "policy_id is required" });
  }
  if (!hasText(auth.issuer)) {
    add(2, { code: "AUTH_MISSING_FIELD", message: "issuer is required" });
  }
  if (!hasText(auth.audience)) {
    add(2, { code: "AUTH_MISSING_FIELD", message: "audience is required" });
  }
  if (!hasText(auth.auth_id)) {
    add(2, { code: "AUTH_MISSING_FIELD", message: "auth_id is required" });
  } else if (auth.auth_id !== auth.auth_id.normalize("NFC")) {
    // S2: identifiers participate in signature verification via canonicalJson,
    // which NFC-normalizes strings, but replay protection keys on the raw
    // identifier. A canonically-equivalent non-NFC auth_id keeps a valid
    // signature yet a distinct replay key, allowing a consumed id to be
    // replayed. Require a single canonical (NFC) representation at this trust
    // boundary and reject anything else - never silently normalize an
    // attacker-controlled identifier.
    add(3, { code: "AUTH_ID_NONCANONICAL", message: "auth_id must be Unicode NFC-normalized" });
  }
  if (!Number.isInteger(auth.issued_at)) {
    add(2, { code: "AUTH_MISSING_FIELD", message: "issued_at must be integer unix seconds" });
  } else if (
    !Number.isSafeInteger(auth.issued_at) ||
    auth.issued_at > now + maxFutureIssuedAtSkewSeconds
  ) {
    // issued_at is compared only against the trusted verificationTime (`now`,
    // supplied by the caller as `opts.now`) - never against `intent.timestamp`,
    // which this function does not receive. An unsafe-magnitude issued_at
    // (e.g. beyond Number.MAX_SAFE_INTEGER) is inherently implausible and
    // rejected without arithmetic that could overflow.
    add(12, {
      code: "AUTH_ISSUED_AT_IMPLAUSIBLE",
      message: `issued_at must not be more than ${maxFutureIssuedAtSkewSeconds}s ahead of verification time`
    });
  }
  const sig = signatureParts(auth);

  // Ambiguity guard (authorization-v1.md §5, §13): when the signature is nested,
  // top-level alg/kid are either absent, or BOTH present and identical to
  // signature.alg / signature.kid. A partial or conflicting pair would let the
  // signed top-level alg differ from the alg that selects the wire encoding.
  if (sig.nested && (auth.alg !== undefined || auth.kid !== undefined)) {
    if (auth.alg !== sig.alg || auth.kid !== sig.kid) {
      add(5, {
        code: "AUTH_ALG_UNSUPPORTED",
        message: "ambiguous signature encoding: top-level alg/kid conflict with signature.alg/kid"
      });
    }
  }

  if (!hasText(sig.alg)) {
    add(2, { code: "AUTH_MISSING_FIELD", message: "alg is required" });
  }
  if (!hasText(sig.kid)) {
    add(2, { code: "AUTH_MISSING_FIELD", message: "kid is required" });
  }
  if (!hasText(sig.sig)) {
    add(2, { code: "AUTH_MISSING_FIELD", message: "signature is required" });
  }

  // R-04 (authorization-v1.md §5 "Signed field set"): the artifact is a CLOSED
  // set. Every top-level field must be covered by the signature, except the
  // enumerated PolicyEngine legacy fields, which are either bound to a signed
  // field by equality or are engine-HMAC fields that core never consults.
  // Unknown fields are rejected rather than silently tolerated or dropped.
  const rawAuth = auth as unknown as Record<string, unknown>;
  const unsignedFields = Object.keys(rawAuth).filter(
    (k) => !AUTHORIZATION_SIGNED_FIELDS.has(k) && !AUTHORIZATION_LEGACY_ENGINE_FIELDS.has(k)
  );
  if (unsignedFields.length > 0) {
    add(2, {
      code: "AUTH_SIGNATURE_INVALID",
      message: `field(s) not covered by the signature: ${unsignedFields.slice(0, 5).map((k) => JSON.stringify(k).slice(0, 64)).join(", ")}`
    });
  }
  if (sig.nested) {
    const unsignedSigFields = Object.keys(rawAuth.signature as Record<string, unknown>).filter(
      (k) => !NESTED_SIGNATURE_FIELDS.has(k)
    );
    if (unsignedSigFields.length > 0) {
      add(2, { code: "AUTH_SIGNATURE_INVALID", message: "signature object carries fields other than alg, kid, sig" });
    }
  }
  if (isPresent(rawAuth, "authorization_id") && rawAuth.authorization_id !== auth.auth_id) {
    add(2, { code: "AUTH_SIGNATURE_INVALID", message: "unsigned authorization_id must equal the signed auth_id" });
  }
  for (const k of ["policy_version", "state_snapshot_hash", "engine_signature"] as const) {
    if (isPresent(rawAuth, k) && typeof rawAuth[k] !== "string") {
      add(2, { code: "AUTH_SIGNATURE_INVALID", message: `legacy field ${k} must be a string` });
    }
  }

  // R-03 (authorization-v1.md §5 "Expiry field resolution"): validity MUST
  // derive only from a SIGNED expiry. A present expiry field is never skipped
  // over when malformed (no fallback), and the flat encoding — whose preimage
  // signs `expiry` but not `expires_at` — requires `expiry`.
  const expiryPresent = isPresent(rawAuth, "expiry");
  const expiresAtPresent = isPresent(rawAuth, "expires_at");
  const expiryOk = expiryPresent && Number.isSafeInteger(rawAuth.expiry);
  const expiresAtOk = expiresAtPresent && Number.isSafeInteger(rawAuth.expires_at);
  if (expiryPresent && !expiryOk) {
    add(5, { code: "AUTH_MISSING_FIELD", message: "expiry must be integer unix seconds" });
  }
  if (expiresAtPresent && !expiresAtOk) {
    add(5, { code: "AUTH_MISSING_FIELD", message: "expires_at must be integer unix seconds" });
  }
  if (!expiryPresent && !expiresAtPresent) {
    add(5, { code: "AUTH_MISSING_FIELD", message: "expiry must be integer unix seconds" });
  } else if (!sig.nested && !expiryPresent) {
    add(5, { code: "AUTH_MISSING_FIELD", message: "flat signature requires signed expiry (expires_at is not signed in this encoding)" });
  }
  if (expiryOk && expiresAtOk && rawAuth.expiry !== rawAuth.expires_at) {
    // Same classification as PolicyEngine.verifyAuthorization for a conflicting
    // expiry alias: data outside (or beside) the signature contradicts it.
    add(5, { code: "AUTH_SIGNATURE_INVALID", message: "expiry and expires_at conflict" });
  }
  // `expiry` takes precedence; `expires_at` is used only by the nested encoding
  // (where it is signed) and only when `expiry` is absent.
  const effectiveExpiry = expiryOk
    ? (rawAuth.expiry as number)
    : sig.nested && !expiryPresent && expiresAtOk
    ? (rawAuth.expires_at as number)
    : undefined;
  if (effectiveExpiry !== undefined && now >= effectiveExpiry) {
    add(11, { code: "AUTH_EXPIRED", message: "authorization has expired" });
  }

  if (opts?.expectedIssuer !== undefined && auth.issuer !== opts.expectedIssuer) {
    add(6, { code: "AUTH_ISSUER_MISMATCH", message: "issuer does not match expectedIssuer" });
  }
  if (opts?.expectedAudience !== undefined && auth.audience !== opts.expectedAudience) {
    add(13, { code: "AUTH_AUDIENCE_MISMATCH", message: "audience does not match expectedAudience" });
  }
  if (opts?.expectedPolicyId !== undefined && auth.policy_id !== opts.expectedPolicyId) {
    add(14, { code: "AUTH_POLICY_ID_MISMATCH", message: "policy_id does not match expectedPolicyId" });
  }
  // Independent issuer-policy authority. Deliberately a distinct code from the
  // scalar mismatches above: those mean "a supplied expectation did not match",
  // whereas this means "this authenticated issuer is not authorized for this
  // policy at all". Reusing AUTH_ISSUER_MISMATCH here would misreport an
  // authority rejection as a configuration mismatch.
  if (opts?.trustedAuthorizationAuthorities !== undefined) {
    if (!isTrustedAuthorizationAuthority(opts.trustedAuthorizationAuthorities, auth.issuer, auth.policy_id)) {
      add(7, {
        code: "AUTH_ISSUER_POLICY_NOT_AUTHORIZED",
        message: "issuer is not authorized for this policy_id",
      });
    }
  }
  if (hasText(auth.auth_id) && consumed.has(auth.auth_id)) {
    add(16, { code: "AUTH_REPLAY", message: "auth_id has already been consumed" });
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
    if (sigAlg === "ed25519" && !sig.nested) {
      // Encoding B is defined only with a nested { alg, kid, sig } object.
      add(5, { code: "AUTH_ALG_UNSUPPORTED", message: "unsupported signature algorithm" });
    } else if (sigAlg === "Ed25519" || sigAlg === "ed25519") {
      if (trusted.length === 0) {
        if (requireSig) {
          add(0, { code: "AUTH_TRUST_MISSING", message: "trustedKeySets required for Ed25519 verification" });
        }
      } else {
        const key = findKeyInKeySets(trusted, auth.issuer, sigKid, "Ed25519");
        if (!key) {
          add(8, { code: "AUTH_KID_UNKNOWN", message: "kid not found for issuer/alg" });
        } else if (!keyIsActiveAt(key, now)) {
          add(9, { code: "AUTH_KEY_INACTIVE", message: "key is not active at verification time" });
        } else {
          // A cryptographic check is actually performed here (pass or fail).
          // Coverage records the surface evaluated and is set the moment the
          // check is engaged, independent of the outcome; `signatureVerified`
          // flips true only if it succeeds.
          verificationCoverage = "authorization-v1-full";
          // The declared alg selects exactly ONE (preimage, alphabet) pair —
          // no cross-encoding fallback (authorization-v1.md §5):
          //   "Ed25519" → "OXDEAI_AUTH_V1\n" || canonicalJson, standard base64
          //   "ed25519" → canonicalJson (no prefix),           base64url
          const cryptoOk = sigAlg === "Ed25519"
            ? verifyEd25519(SIGNING_DOMAINS.AUTH_V1, payload, sigValue, key.public_key)
            : verifyEd25519SiftCompatible(payload, sigValue, key.public_key);
          if (!cryptoOk) {
            add(10, { code: "AUTH_SIGNATURE_INVALID", message: "signature verification failed" });
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
          add(10, { code: "AUTH_SIGNATURE_INVALID", message: "legacy HMAC signature verification failed" });
        } else {
          signatureVerified = true;
        }
      } else if (requireSig) {
        add(0, { code: "AUTH_TRUST_MISSING", message: "legacyHmacSecret required for HMAC verification" });
      }
    } else {
      add(5, { code: "AUTH_ALG_UNSUPPORTED", message: "unsupported signature algorithm" });
    }
  }

  // Configured posture only (independent of whether cryptography ran):
  // "strict" when requested, otherwise "permissive" (the best-effort default).
  // Whether a signature was actually checked is reported separately via
  // `signatureVerified` / `verificationCoverage`.
  const verificationMode: VerificationMode = opts?.mode === "strict" ? "strict" : "permissive";

  if (violations.length > 0) {
    const result: AuthorizationVerificationResult = {
      ok: false,
      status: "invalid",
      violations: sortViolations(violations),
      policyId: hasText(auth.policy_id) ? auth.policy_id : undefined,
      stateHash: hasText(auth.state_hash) ? auth.state_hash : undefined,
      signatureVerified,
      verificationMode,
      verificationCoverage
    };
    if (opts?.reportPrimaryReasonCode === true) {
      const primary = determiningViolation(violations, stepOf);
      if (primary) result.primaryReasonCode = primary.code;
    }
    return result;
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
