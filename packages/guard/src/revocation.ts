// SPDX-License-Identifier: Apache-2.0
/**
 * F4-R6-07 (Lot C, DECISION_REQUIRED reference implementation): opt-in
 * SignedKRLV1 revocation enforcement on the guard delegation path.
 *
 * `verifySignedKrl` is a pure verifier; before this module nothing on an
 * enforcement path consumed a verified KRL, so a key revoked by a valid KRL
 * still authorized execution. When `config.revocation` is configured, every
 * delegation call obtains revocation evidence from a trusted provider,
 * verifies it, and denies before replay consumption and execution when the
 * evidence is missing, invalid, rolled back, or revokes a key in use.
 *
 * Deployment-specific policy choices are marked [DECISION].
 * The Guard integration contract and limitations are documented in
 * packages/guard/README.md.
 */
import { sha256HexFromJson, signedKrlSigningPayload, verifySignedKrl } from "@oxdeai/core";
import type { KeySet, SignedKRLV1 } from "@oxdeai/core";
import { OxDeAIGuardConfigurationError } from "./errors.js";

/**
 * Which key issuers a KRL publisher is authoritative for. SignedKRLV1
 * `revoked_kids` carry no key-issuer binding, so the deployer states it.
 * [DECISION] A kid is revoked for key `(issuer, kid)` only by a KRL whose
 * scope lists `issuer`.
 *
 * @public
 */
export type GuardRevocationScope = {
  /** `SignedKRLV1.issuer` of the KRL publisher. */
  readonly krlIssuer: string;
  /** Key-set issuers (`AuthorizationV1.issuer`, `DelegationV1.issuer`) this publisher may revoke kids for. */
  readonly keyIssuers: readonly string[];
};

/** @public */
export type GuardKrlWatermark = {
  /** Highest accepted `krl_version` for the KRL issuer. */
  readonly krlVersion: number;
  /** sha256 of the canonical signing payload of the KRL accepted at that version. */
  readonly digest: string;
};

/**
 * Monotonic per-KRL-issuer high-watermark. Implementations MUST be fail-closed
 * (throw on infrastructure failure) and MUST implement `accept` as an atomic
 * compare-and-set that never lowers the stored version and rejects a second,
 * different digest at the same version. OxDeAI does not verify durability or
 * atomicity of a caller-supplied store.
 *
 * @public
 */
export interface GuardKrlWatermarkStore {
  /**
   * Atomically accept a verified KRL watermark.
   * Lower versions and same-version digest conflicts MUST be rejected.
   * Infrastructure failures MUST throw.
   */
  accept(
    krlIssuer: string,
    candidate: GuardKrlWatermark
  ): Promise<"ACCEPTED" | "REJECTED">;
}

/**
 * Opt-in revocation enforcement for the delegation path.
 *
 * @public
 */
export type GuardRevocationConfig = {
  /** KRL signing key sets. A distinct trust domain (signed-krl-v1 §2): must not share keys with `trustedKeySets`. */
  readonly trustedKrlKeySets: KeySet | readonly KeySet[];
  /** One entry per KRL publisher whose KRL MUST be present on every call. */
  readonly scopes: readonly GuardRevocationScope[];
  /**
   * Trusted deployer code returning the current raw SignedKRLV1 envelopes
   * (exactly one per configured `krlIssuer`). Its output is never trusted as
   * returned: each envelope is cloned once and verified before use.
   */
  readonly provider: () => readonly unknown[] | Promise<readonly unknown[]>;
  /** Required monotonic store. Use a shared durable implementation for distributed deployments. */
  readonly watermarkStore: GuardKrlWatermarkStore;
};

/**
 * Process-local watermark store. Rollback protection lasts for the lifetime
 * of the instance only.
 *
 * @public
 */
export function createInMemoryKrlWatermarkStore(): GuardKrlWatermarkStore {
  const marks = new Map<string, GuardKrlWatermark>();

  return {
    async accept(krlIssuer, candidate) {
      if (
        candidate === null ||
        typeof candidate !== "object" ||
        typeof krlIssuer !== "string" ||
        krlIssuer.length === 0 ||
        !Number.isSafeInteger(candidate.krlVersion) ||
        candidate.krlVersion < 0 ||
        !/^[a-f0-9]{64}$/.test(candidate.digest)
      ) {
        return "REJECTED";
      }

      // No await between comparison and mutation: atomic within one JS process.
      const current = marks.get(krlIssuer);

      if (current !== undefined) {
        if (candidate.krlVersion < current.krlVersion) return "REJECTED";

        if (candidate.krlVersion === current.krlVersion) {
          return candidate.digest === current.digest
            ? "ACCEPTED"
            : "REJECTED";
        }
      }

      marks.set(
        krlIssuer,
        Object.freeze({
          krlVersion: candidate.krlVersion,
          digest: candidate.digest,
        })
      );

      return "ACCEPTED";
    },
  };
}

type ResolvedRevocation = {
  readonly trustedKrlKeySets: readonly KeySet[];
  readonly scopes: readonly GuardRevocationScope[];
  readonly provider: GuardRevocationConfig["provider"];
  readonly watermarkStore: GuardKrlWatermarkStore;
};

const nonEmpty = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * Validate and freeze `config.revocation` at construction. `undefined` keeps
 * the existing behavior (static `KeySet.status` only). Anything else must be
 * well-formed; a malformed value never silently disables enforcement.
 */
export function resolveRevocationConfig(value: unknown, trustedKeySets: readonly KeySet[]): ResolvedRevocation | undefined {
  if (value === undefined) return undefined;
  const fail = (m: string): never => { throw new OxDeAIGuardConfigurationError(`config.revocation: ${m}`); };
  if (!isRecord(value)) return fail("must be an object when provided.");
  const rawSets = value.trustedKrlKeySets;
  const krlSets: KeySet[] = Array.isArray(rawSets) ? [...rawSets] : rawSets !== undefined ? [rawSets as KeySet] : [];
  if (krlSets.length === 0) fail("trustedKrlKeySets must be a non-empty KeySet or KeySet array.");
  for (const ks of krlSets) {
    if (!isRecord(ks) || !nonEmpty(ks.issuer) || !Array.isArray(ks.keys) || ks.keys.length === 0) fail("each trusted KRL key set needs an issuer and keys.");
  }
  // signed-krl-v1 §2: the KRL signing keys are a distinct trust domain.
  const artifactKeys = new Set(trustedKeySets.flatMap((ks) => (Array.isArray(ks?.keys) ? ks.keys : [])).map((k) => String(k?.public_key ?? "").trim()));
  for (const ks of krlSets) for (const k of ks.keys) {
    if (artifactKeys.has(String(k?.public_key ?? "").trim())) fail("a KRL signing key is also present in trustedKeySets; the KRL trust domain must be separate.");
  }
  const scopesRaw = value.scopes;
  if (!Array.isArray(scopesRaw) || scopesRaw.length === 0) fail("scopes must be a non-empty array.");
  const seen = new Set<string>();
  const scopes: GuardRevocationScope[] = [];
  for (const s of scopesRaw as unknown[]) {
    if (!isRecord(s) || !nonEmpty(s.krlIssuer) || !Array.isArray(s.keyIssuers) || s.keyIssuers.length === 0 || !s.keyIssuers.every(nonEmpty)) {
      fail("each scope must be { krlIssuer: string, keyIssuers: non-empty string[] }.");
    }
    const scope = s as { krlIssuer: string; keyIssuers: string[] };
    if (seen.has(scope.krlIssuer)) fail(`duplicate scope for krlIssuer "${scope.krlIssuer}".`);
    seen.add(scope.krlIssuer);
    scopes.push(Object.freeze({ krlIssuer: scope.krlIssuer, keyIssuers: Object.freeze([...scope.keyIssuers]) }));
  }
  if (typeof value.provider !== "function") fail("provider must be a function.");
  const store = value.watermarkStore;
  if (!isRecord(store) || typeof store.accept !== "function") {
    fail("watermarkStore is required and must implement accept().");
  }
  return Object.freeze({
    trustedKrlKeySets: Object.freeze(krlSets.map(ks =>
      Object.freeze({
        ...ks,
        keys: Object.freeze(ks.keys.map(k => Object.freeze({ ...k }))) as unknown as KeySet['keys'],
      })
    )),
    scopes: Object.freeze(scopes),
    provider: value.provider as GuardRevocationConfig["provider"],
    watermarkStore: Object.freeze({ accept: (store as GuardKrlWatermarkStore).accept.bind(store) }),
  });
}

/** Outcome kinds mapped to boundary codes by the guard. */
export type RevocationDenial =
  | { readonly kind: "UNAVAILABLE"; readonly message: string }
  | { readonly kind: "INVALID"; readonly message: string }
  | { readonly kind: "REVOKED"; readonly role: "parent" | "delegation"; readonly issuer: string; readonly kid: string };

export type CheckedKey = { readonly role: "parent" | "delegation"; readonly issuer: string; readonly kid: string };

/**
 * Obtain, verify and apply revocation evidence for `keys`. Returns `undefined`
 * when every key is covered by verified evidence and none is revoked;
 * otherwise the first denial. Never throws.
 */
export async function evaluateRevocation(cfg: ResolvedRevocation, now: number, keys: readonly CheckedKey[]): Promise<RevocationDenial | undefined> {
  let raw: unknown;
  try {
    raw = await cfg.provider();
  } catch (err) {
    return { kind: "UNAVAILABLE", message: `revocation provider failed: ${err instanceof Error ? err.message : String(err)}` };
  }
  if (!Array.isArray(raw)) {
    return { kind: "UNAVAILABLE", message: "revocation provider returned no KRL list" };
  }

  try {
    raw = structuredClone(raw);
  } catch {
    return { kind: "INVALID", message: "KRL provider returned a non-cloneable list" };
  }

  const scopeIssuers = new Set(cfg.scopes.map((s) => s.krlIssuer));
  const byIssuer = new Map<string, SignedKRLV1>();
  for (const item of raw as unknown[]) {
    let env: unknown;
    try {
      env = structuredClone(item); // one read of provider output; Proxy/function fails here
    } catch {
      return { kind: "INVALID", message: "KRL envelope is not cloneable plain data" };
    }
    const issuer = isRecord(env) && nonEmpty(env.issuer) ? env.issuer : undefined;
    // [DECISION] strict: unexpected issuer or duplicate issuer → deny.
    if (issuer === undefined || !scopeIssuers.has(issuer)) return { kind: "INVALID", message: "KRL from an unconfigured or missing issuer" };
    if (byIssuer.has(issuer)) return { kind: "INVALID", message: `more than one KRL for issuer "${issuer}"` };
    byIssuer.set(issuer, env as SignedKRLV1);
  }

  const applied: Array<{
    krlIssuer: string;
    keyIssuers: readonly string[];
    revoked: ReadonlySet<string>;
    watermark: GuardKrlWatermark;
  }> = [];

  // Phase 1: verify every KRL without modifying watermark state.
  for (const scope of cfg.scopes) {
    const env = byIssuer.get(scope.krlIssuer);
    // Missing evidence is not "nothing revoked".
    if (env === undefined) return { kind: "UNAVAILABLE", message: `no KRL for issuer "${scope.krlIssuer}"` };
    let result;
    try {
      result = verifySignedKrl(env, {
        now,
        trustedKeySets: cfg.trustedKrlKeySets,
      });
    } catch {
      return { kind: "INVALID", message: `KRL "${scope.krlIssuer}" verification failed` };
    }

    if (!result.ok) {
      return {
        kind: "INVALID",
        message: `KRL "${scope.krlIssuer}" rejected: ${result.violations.map((v) => v.code).join(", ")}`,
      };
    }

    let digest: string;
    try {
      digest = sha256HexFromJson(signedKrlSigningPayload(env));
    } catch {
      return { kind: "INVALID", message: `KRL "${scope.krlIssuer}" canonicalization failed` };
    }

    applied.push({
      krlIssuer: scope.krlIssuer,
      keyIssuers: scope.keyIssuers,
      revoked: new Set(env.revoked_kids),
      watermark: { krlVersion: env.krl_version, digest },
    });
  }

  for (const key of keys) {
    if (!applied.some(a => a.keyIssuers.includes(key.issuer))) {
      return { kind: "UNAVAILABLE", message: `no revocation authority configured for key issuer "${key.issuer}"` };
    }
  }

  // Phase 3: atomically accept each verified watermark.
  // A rejection blocks execution; multi-issuer acceptance is not
  // a distributed transaction.
  for (const entry of applied) {
    let accepted: unknown;
    try {
      accepted = await cfg.watermarkStore.accept(
        entry.krlIssuer,
        entry.watermark
      );
    } catch {
      return { kind: "UNAVAILABLE", message: "KRL watermark store unavailable" };
    }

    if (accepted === "REJECTED") {
      return {
        kind: "INVALID",
        message: `KRL "${entry.krlIssuer}" version regression or digest conflict`,
      };
    }

    if (accepted !== "ACCEPTED") {
      return {
        kind: "UNAVAILABLE",
        message: "KRL watermark store returned an indeterminate result",
      };
    }
  }

  // Phase 4: deny revoked signing keys after watermark validation.
  for (const key of keys) {
    const covering = applied.filter((a) => a.keyIssuers.includes(key.issuer));
    if (covering.some((a) => a.revoked.has(key.kid))) {
      return {
        kind: "REVOKED",
        role: key.role,
        issuer: key.issuer,
        kid: key.kid,
      };
    }
  }

  return undefined;
}
