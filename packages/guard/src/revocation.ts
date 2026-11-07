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
import { createHash, createPublicKey } from "node:crypto";
import { sha256HexFromJson, signedKrlSigningPayload, verifySignedKrl } from "@oxdeai/core";
import type { KeySet, SignedKRLV1 } from "@oxdeai/core";
import { OxDeAIGuardConfigurationError } from "./errors.js";
import { snapshotPlainData, DelegationSnapshotError } from "./delegationSnapshot.js";
import { settleCallback, type SettledCallback } from "./settleCallback.js";

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
  /** F4-LOT-C-R3 (A5.1): canonical identities of every trusted KRL signing key. */
  readonly krlKeyIdentities: readonly string[];
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
  // F4-LOT-C-R3 (A5.1): compared by canonical key identity, never by PEM text.
  const krlKeyIdentities: string[] = [];
  krlSets.forEach((ks, i) => ks.keys.forEach((k, j) => {
    try {
      krlKeyIdentities.push(ed25519PublicKeyIdentity(isRecord(k) ? k.public_key : undefined));
    } catch {
      fail(`trustedKrlKeySets[${i}].keys[${j}] is not a valid Ed25519 public key.`);
    }
  }));
  // Fail fast at construction; the same check is repeated on every protected
  // decision (validatedTrustSnapshot) because trustedKeySets is read live.
  validatedTrustSnapshot(trustedKeySets, krlKeyIdentities);
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
    krlKeyIdentities: Object.freeze(krlKeyIdentities),
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
 * F4-LOT-C-R1 (F1): the AuthorizationV1 signing kid, selected exactly as core
 * `verifyAuthorization` selects its verification key: an object-valued
 * `signature` uses `signature.kid`; a string `signature` uses top-level `kid`.
 * A top-level `kid` that differs from a nested `signature.kid` is ambiguous
 * (the nested kid is not always signed) and yields `undefined`: fail closed.
 * The guard then confirms this kid with core before checking revocation.
 */
export function resolveAuthorizationSigningKid(auth: unknown): string | undefined {
  if (!isRecord(auth)) return undefined;
  const sig = auth.signature;
  if (isRecord(sig)) {
    if (!nonEmpty(sig.kid)) return undefined;
    if (auth.kid !== undefined && auth.kid !== sig.kid) return undefined;
    return sig.kid;
  }
  if (typeof sig === "string") return nonEmpty(auth.kid) ? auth.kid : undefined;
  return undefined;
}

/**
 * Trust material restricted to the single key `(issuer, kid)`, mirroring core
 * key lookup (first key set with a matching issuer). Verifying against it
 * proves that this key, and no other, produced the signature.
 */
export function pinKeySet(keySets: readonly KeySet[], issuer: string, kid: string): KeySet[] {
  const ks = keySets.find((k) => k.issuer === issuer);
  return ks ? [{ ...ks, keys: ks.keys.filter((k) => k.kid === kid) }] : [];
}

/**
 * Mirrors core's private `normalizePem` (crypto/signatures.ts) exactly, so the
 * key identified here is the key core verifies with: a value containing
 * "BEGIN" is PEM text, anything else is decoded as base64-wrapped PEM.
 */
function normalizePemLikeCore(key: string): string {
  return key.includes("BEGIN") ? key : Buffer.from(key, "base64").toString("utf8");
}

const IDENTITY_CACHE_MAX = 1024;
const identityCache = new Map<string, string>();

/**
 * F4-LOT-C-R3 (A5): canonical cryptographic identity of an Ed25519 public key:
 * sha256 over its SPKI DER export. Equivalent encodings (line endings, base64
 * wrapping, base64-wrapped PEM) yield the same identity; different keys yield
 * different identities. Throws (without echoing key material) for anything
 * that is not an Ed25519 PUBLIC key. Not re-exported by the package entry.
 */
export function ed25519PublicKeyIdentity(publicKey: unknown): string {
  if (typeof publicKey !== "string" || publicKey.length === 0) throw new Error("public key must be a non-empty string");
  const cached = identityCache.get(publicKey);
  if (cached !== undefined) return cached;
  const pem = normalizePemLikeCore(publicKey);
  // A trust set holds public keys only. createPublicKey would silently derive a
  // public key from private material; refuse it instead.
  if (pem.includes("PRIVATE KEY")) throw new Error("private key material is not accepted as a trusted public key");
  let der: Buffer;
  try {
    const key = createPublicKey(pem);
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new Error("not Ed25519");
    der = key.export({ type: "spki", format: "der" });
  } catch {
    throw new Error("not a parseable Ed25519 public key");
  }
  const identity = createHash("sha256").update(der).digest("hex");
  if (identityCache.size >= IDENTITY_CACHE_MAX) identityCache.clear();
  identityCache.set(publicKey, identity);
  return identity;
}

/**
 * F4-LOT-C-R3 (A5.1/A5.2): copy the CURRENT trusted key sets into frozen plain
 * data and validate that copy. The caller must use the returned snapshot (and
 * only it) for the verification that immediately follows, with no `await`
 * between, so a later mutation of the caller-owned configuration can neither
 * bypass nor invalidate the checked state.
 *
 * Enforced when SignedKRLV1 revocation is enabled (revocation is by kid, so a
 * kid must denote exactly one key):
 *  - every key is a parseable Ed25519 public key (fail closed otherwise);
 *  - no key is also a trusted KRL signing key (signed-krl-v1 §2);
 *  - one public key has exactly one (issuer, kid) identity (no aliases, within
 *    or across issuers);
 *  - one (issuer, kid) has exactly one registration; an exact duplicate entry
 *    (same key and lifecycle fields) is tolerated, a conflicting one is not.
 *
 * Throws OxDeAIGuardConfigurationError. Messages name positions, issuers and
 * kids only, never key material.
 */
export function validatedTrustSnapshot(live: unknown, krlKeyIdentities: readonly string[]): readonly KeySet[] {
  const fail = (m: string): never => { throw new OxDeAIGuardConfigurationError(`trustedKeySets: ${m}`); };
  let snap: unknown;
  try {
    snap = snapshotPlainData(live, "trustedKeySets");
  } catch (err) {
    return fail(`not supported plain data (${err instanceof DelegationSnapshotError ? err.message : "snapshot failed"}).`);
  }
  if (!Array.isArray(snap)) return fail("must be a KeySet array.");
  const krl = new Set(krlKeyIdentities);
  const ownerOfKey = new Map<string, string>();
  const entryOfIdentity = new Map<string, string>();
  (snap as unknown[]).forEach((ks, i) => {
    if (!isRecord(ks) || !nonEmpty(ks.issuer) || !Array.isArray(ks.keys)) fail(`[${i}] must have a non-empty issuer and a keys array.`);
    const set = ks as { issuer: string; keys: unknown[] };
    set.keys.forEach((k, j) => {
      const at = `[${i}].keys[${j}]`;
      if (!isRecord(k) || !nonEmpty(k.kid)) fail(`${at} must have a non-empty kid.`);
      const key = k as Record<string, unknown> & { kid: string };
      const who = `(issuer ${JSON.stringify(set.issuer)}, kid ${JSON.stringify(key.kid)})`;
      if (key.alg !== "Ed25519") fail(`${at} ${who}: only Ed25519 keys are supported when SignedKRLV1 revocation is enabled.`);
      let id = "";
      try {
        id = ed25519PublicKeyIdentity(key.public_key);
      } catch {
        fail(`${at} ${who}: public_key is not a valid Ed25519 public key.`);
      }
      if (krl.has(id)) fail(`${at} ${who}: this key is also a trusted KRL signing key; the KRL trust domain must be separate (signed-krl-v1 §2).`);
      const identity = JSON.stringify([set.issuer, key.kid]);
      const owner = ownerOfKey.get(id);
      if (owner !== undefined && owner !== identity) {
        fail(`${at} ${who}: the same public key is already registered as (issuer, kid) ${owner}; a signing key must have exactly one identity.`);
      }
      ownerOfKey.set(id, identity);
      const entry = [id, String(key.status), String(key.not_before), String(key.not_after)].join("|");
      const prior = entryOfIdentity.get(identity);
      if (prior !== undefined && prior !== entry) fail(`${at} ${who}: conflicting registrations for the same (issuer, kid).`);
      entryOfIdentity.set(identity, entry);
    });
  });
  return snap as readonly KeySet[];
}

/**
 * IR-03: denials are null-prototype objects. `evaluateRevocation` is `async`,
 * and an ordinary object returned from it is settled through promise
 * resolution, which consults an inherited `then`; a polluting `then` could turn
 * a denial into `undefined` ("nothing revoked").
 */
function denial(d: RevocationDenial): RevocationDenial {
  return Object.freeze(Object.assign(Object.create(null) as object, d)) as RevocationDenial;
}

/**
 * Obtain, verify and apply revocation evidence for `keys`. Returns `undefined`
 * when every key is covered by verified evidence and none is revoked;
 * otherwise the first denial. Never throws.
 */
export async function evaluateRevocation(cfg: ResolvedRevocation, now: number, keys: readonly CheckedKey[]): Promise<RevocationDenial | undefined> {
  let raw: unknown;
  // IR-03: settle the provider's answer without letting a `then` inherited
  // from a built-in prototype substitute it (e.g. an older KRL for the current one).
  let settledRaw: SettledCallback<unknown>;
  try {
    settledRaw = await settleCallback(() => cfg.provider());
  } catch (err) {
    return denial({ kind: "UNAVAILABLE", message: `revocation provider failed: ${err instanceof Error ? err.message : String(err)}` });
  }
  if (settledRaw.tampered) {
    return denial({ kind: "UNAVAILABLE", message: "a built-in prototype defines `then` (prototype pollution); the revocation provider's answer cannot be trusted" });
  }
  raw = settledRaw.value;
  if (!Array.isArray(raw)) {
    return denial({ kind: "UNAVAILABLE", message: "revocation provider returned no KRL list" });
  }

  try {
    raw = structuredClone(raw);
  } catch {
    return denial({ kind: "INVALID", message: "KRL provider returned a non-cloneable list" });
  }

  const scopeIssuers = new Set(cfg.scopes.map((s) => s.krlIssuer));
  const byIssuer = new Map<string, SignedKRLV1>();
  for (const item of raw as unknown[]) {
    let env: unknown;
    try {
      env = structuredClone(item); // one read of provider output; Proxy/function fails here
    } catch {
      return denial({ kind: "INVALID", message: "KRL envelope is not cloneable plain data" });
    }
    const issuer = isRecord(env) && nonEmpty(env.issuer) ? env.issuer : undefined;
    // [DECISION] strict: unexpected issuer or duplicate issuer → deny.
    if (issuer === undefined || !scopeIssuers.has(issuer)) return denial({ kind: "INVALID", message: "KRL from an unconfigured or missing issuer" });
    if (byIssuer.has(issuer)) return denial({ kind: "INVALID", message: `more than one KRL for issuer "${issuer}"` });
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
    if (env === undefined) return denial({ kind: "UNAVAILABLE", message: `no KRL for issuer "${scope.krlIssuer}"` });
    let result;
    try {
      result = verifySignedKrl(env, {
        now,
        trustedKeySets: cfg.trustedKrlKeySets,
      });
    } catch {
      return denial({ kind: "INVALID", message: `KRL "${scope.krlIssuer}" verification failed` });
    }

    if (!result.ok) {
      return denial({
        kind: "INVALID",
        message: `KRL "${scope.krlIssuer}" rejected: ${result.violations.map((v) => v.code).join(", ")}`,
      });
    }

    let digest: string;
    try {
      digest = sha256HexFromJson(signedKrlSigningPayload(env));
    } catch {
      return denial({ kind: "INVALID", message: `KRL "${scope.krlIssuer}" canonicalization failed` });
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
      return denial({ kind: "UNAVAILABLE", message: `no revocation authority configured for key issuer "${key.issuer}"` });
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
      return denial({ kind: "UNAVAILABLE", message: "KRL watermark store unavailable" });
    }

    if (accepted === "REJECTED") {
      return denial({
        kind: "INVALID",
        message: `KRL "${entry.krlIssuer}" version regression or digest conflict`,
      });
    }

    if (accepted !== "ACCEPTED") {
      return denial({
        kind: "UNAVAILABLE",
        message: "KRL watermark store returned an indeterminate result",
      });
    }
  }

  // Phase 4: deny revoked signing keys after watermark validation.
  for (const key of keys) {
    const covering = applied.filter((a) => a.keyIssuers.includes(key.issuer));
    if (covering.some((a) => a.revoked.has(key.kid))) {
      return denial({
        kind: "REVOKED",
        role: key.role,
        issuer: key.issuer,
        kid: key.kid,
      });
    }
  }

  return undefined;
}
