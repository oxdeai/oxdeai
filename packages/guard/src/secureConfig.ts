// SPDX-License-Identifier: Apache-2.0
/**
 * secureConfig.ts — construction-time capture of `createSecureGuard`
 * configuration (F4-AUD-01, REV-R1, REV-R2, RV-01, RV-02). Internal; not
 * re-exported by the package entry point.
 *
 * `createSecureGuard` must read the deployer's configuration exactly once and
 * never again. The first remediation did that with `{ ...config }`, which
 * copies only OWN ENUMERABLE properties. `OxDeAIGuardConfig` is a structural
 * type: a class instance with getters, an object with inherited or
 * non-enumerable properties, or a Proxy satisfies it, and `OxDeAIGuard` reads
 * all of them through ordinary property access. The spread silently dropped
 * such properties, so a declared `{mode:"shared", store}` fell through to the
 * process-local default (REV-R1) and signer authority, F4-C revocation and
 * SignedKRLV1 revocation were silently not enforced (REV-R2).
 *
 * The capture therefore:
 *
 *  - reads an EXPLICIT list of every `OxDeAIGuardConfig` option (compile-time
 *    exhaustive) through ordinary `[[Get]]`, so own, inherited, non-enumerable,
 *    accessor and Proxy-provided values are all honoured, exactly as
 *    `OxDeAIGuard` honours them;
 *  - reads each value ONCE, including the security-relevant members of nested
 *    option objects and the replay store's methods, into frozen data, so an
 *    accessor that answers differently on a second read cannot make
 *    validation and enforcement see different values;
 *  - turns any exception thrown while reading into
 *    `OxDeAIGuardConfigurationError` at construction. A read failure is never
 *    treated as "not configured", which would fall back to weaker protection.
 *
 * Prototype-pollution hardening (RV-01):
 *
 *  - per-option handlers live in a `Map`; only a registered handler can run,
 *    and nothing reached through `Object.prototype` is ever invoked or allowed
 *    to transform a configured value;
 *  - before any read, the intrinsic prototypes the reads can reach are checked
 *    for a property with any name this module reads. If one exists, the
 *    environment is polluted and construction fails closed. It does not
 *    honour the polluted value (which could supply an option the deployer
 *    omitted) and it does not ignore it silently;
 *  - every captured object holds ALL of its members as own data properties
 *    (`undefined` when not configured), so no later read of captured data can
 *    fall through to a prototype polluted after construction.
 *
 * Identity, not state, is captured for providers and stores (replay store,
 * engine, KRL provider, watermark store, F4-C provider, hooks): the object or
 * function present at construction is the one used, and whatever state it
 * consults stays live. Validation is left to the existing resolvers and
 * `OxDeAIGuard`; this module only fixes WHAT they see.
 */
import { OxDeAIGuardConfigurationError } from "./errors.js";
import { isEphemeralReplayStore } from "./replayStore.js";
import type { OxDeAIGuardConfig } from "./types.js";
import type { ReplayStore } from "./replayStore.js";

// Intrinsics, captured at module load.
const OBJECT_PROTOTYPE: object = Object.prototype;
const ARRAY_PROTOTYPE: object = Array.prototype;
const FUNCTION_PROTOTYPE: object = Function.prototype;
const reflectGet = Reflect.get;
const reflectHas = Reflect.has;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const getOwnDescriptor = Reflect.getOwnPropertyDescriptor;
const defineProperty = Object.defineProperty;
const freeze = Object.freeze;
const isArray = Array.isArray;

/** Every `OxDeAIGuardConfig` option, read once at construction. */
const CONFIG_FIELDS = [
  "engine",
  "getState",
  "setState",
  "mapActionToIntent",
  "beforeExecute",
  "onDecision",
  "onBoundaryEvent",
  "expectedAudience",
  "trustedKeySets",
  "trustedDelegationAuthorities",
  "trustedDelegationSigners",
  "delegationRevocationProvider",
  "requireDelegationRevocation",
  "revocation",
  "replayStore",
  "replayProtection",
  "requireExplicitReplayProtection",
  "computeStateHash",
] as const;

// Compile-time exhaustiveness: adding an option to OxDeAIGuardConfig without
// listing it above fails the build, instead of silently not capturing it.
type UncapturedField = Exclude<keyof OxDeAIGuardConfig, (typeof CONFIG_FIELDS)[number]>;
const _exhaustive: [UncapturedField] extends [never] ? true : UncapturedField = true;
void _exhaustive;

// Members read from nested option objects. Each list is the single source for
// both the reads and the pollution check below.
const REPLAY_PROTECTION_MEMBERS = ["mode", "store"] as const;
const REPLAY_STORE_MEMBERS = ["consumeAuthId", "consumeDelegationId"] as const;
const SIGNER_MEMBERS = ["delegator", "issuer"] as const;
const AUTHORITY_MEMBERS = ["issuer", "policyId"] as const;
const PROVIDER_MEMBERS = ["check"] as const;
const REVOCATION_MEMBERS = ["trustedKrlKeySets", "scopes", "provider", "watermarkStore"] as const;
const SCOPE_MEMBERS = ["krlIssuer", "keyIssuers"] as const;
const WATERMARK_MEMBERS = ["accept"] as const;
const KEYSET_MEMBERS = ["issuer", "version", "keys"] as const;
const KEYSET_KEY_MEMBERS = ["kid", "alg", "public_key", "status", "not_before", "not_after"] as const;

/** Every named property this module reads with `[[Get]]` / `[[HasProperty]]`. */
const READ_NAMES: ReadonlySet<string> = new Set<string>([
  ...CONFIG_FIELDS, ...REPLAY_PROTECTION_MEMBERS, ...REPLAY_STORE_MEMBERS, ...SIGNER_MEMBERS,
  ...AUTHORITY_MEMBERS, ...PROVIDER_MEMBERS, ...REVOCATION_MEMBERS, ...SCOPE_MEMBERS,
  ...WATERMARK_MEMBERS, ...KEYSET_MEMBERS, ...KEYSET_KEY_MEMBERS,
]);
/**
 * Names read from values that may be arrays (an authority entry may be any
 * object), from functions (a legacy replay store may be a function object),
 * or from arrays themselves (`length` is an own property of every array and
 * is not checked).
 */
const ARRAY_READ_NAMES = AUTHORITY_MEMBERS;
const FUNCTION_READ_NAMES = REPLAY_STORE_MEMBERS;

/** Callable options, invoked by the shared body as `config.<name>(…)`. */
const CALLABLE_FIELDS: ReadonlySet<string> = new Set([
  "getState", "setState", "mapActionToIntent", "beforeExecute", "onDecision", "onBoundaryEvent", "computeStateHash",
]);

function fail(message: string): never {
  throw new OxDeAIGuardConfigurationError(message);
}

const isIndexKey = (k: PropertyKey): boolean => typeof k === "string" && /^(0|[1-9][0-9]*)$/.test(k);

/**
 * RV-01: refuse to capture in a polluted environment. Any property on
 * `Object.prototype` named like something this module reads, any array-index
 * property on `Object.prototype` / `Array.prototype` (array holes would
 * resolve to it), and the few names read from arrays or functions on
 * `Array.prototype` / `Function.prototype`. Descriptors are inspected, never
 * invoked, so a polluting getter does not run.
 *
 * IR-01: run before AND after the capture reads, and again by
 * createSecureGuard once resolution is complete.
 *
 * @internal
 */
export function assertIntrinsicsUnpolluted(): void {
  const polluted = (proto: object, protoName: string, name: PropertyKey): never =>
    fail(
      `${protoName} has a property named ${JSON.stringify(String(name))}, which a secure guard option or member would ` +
        "inherit (prototype pollution). Refusing to construct: an inherited value could supply or replace security configuration."
    );
  for (const name of READ_NAMES) if (getOwnDescriptor(OBJECT_PROTOTYPE, name) !== undefined) polluted(OBJECT_PROTOTYPE, "Object.prototype", name);
  for (const name of ARRAY_READ_NAMES) if (getOwnDescriptor(ARRAY_PROTOTYPE, name) !== undefined) polluted(ARRAY_PROTOTYPE, "Array.prototype", name);
  for (const name of FUNCTION_READ_NAMES) if (getOwnDescriptor(FUNCTION_PROTOTYPE, name) !== undefined) polluted(FUNCTION_PROTOTYPE, "Function.prototype", name);
  for (const [proto, protoName] of [[OBJECT_PROTOTYPE, "Object.prototype"], [ARRAY_PROTOTYPE, "Array.prototype"]] as const) {
    for (const k of reflectOwnKeys(proto)) if (isIndexKey(k)) polluted(proto, protoName, k);
  }
}

/** One `[[Get]]`; a throwing accessor or Proxy trap is a configuration error. */
function read(source: object, key: string | number, label: string): unknown {
  // Invariant: every named read is covered by the pollution check.
  if (typeof key === "string" && key !== "length" && !READ_NAMES.has(key)) {
    throw new Error(`secureConfig internal error: unchecked read of "${key}"`);
  }
  try {
    return reflectGet(source, key);
  } catch {
    return fail(`${label} could not be read.`);
  }
}

/** One `[[HasProperty]]` (own or inherited); a throwing Proxy trap is a configuration error. */
function has(source: object, key: string, label: string): boolean {
  try {
    return reflectHas(source, key);
  } catch {
    return fail(`${label} could not be read.`);
  }
}

/** A frozen object whose listed members are ALL own data properties (RV-01). */
function ownRecord(entries: ReadonlyArray<readonly [string, unknown]>): Readonly<Record<string, unknown>> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of entries) defineProperty(out, k, { value: v, enumerable: true, writable: false, configurable: false });
  return freeze(out);
}

const isObject = (v: unknown): v is object => v !== null && typeof v === "object";
const isRecord = (v: unknown): v is object => isObject(v) && !isArray(v);

/**
 * Index-based, single-pass copy of an array (including a Proxy of one): one
 * read of `length`, one read per index. `Array.prototype` iteration is not
 * used, so an overridden iterator cannot change what is copied. A non-array
 * is returned unchanged for the downstream resolver to accept or reject.
 */
function copyArray<T>(value: unknown, label: string, entry: (e: unknown, label: string) => T): unknown {
  if (!isArray(value)) return value;
  const length = read(value, "length", `${label}.length`);
  if (typeof length !== "number" || !Number.isSafeInteger(length) || length < 0) fail(`${label} could not be read.`);
  const out: T[] = [];
  for (let i = 0; i < (length as number); i++) out.push(entry(read(value, i, `${label}[${i}]`), `${label}[${i}]`));
  return freeze(out);
}

/**
 * Copy the listed members of an entry (one read each, all kept as own
 * properties). A value that is not a record (or, with `anyObject`, not an
 * object) is returned unchanged.
 */
function copyMembers(value: unknown, label: string, keys: readonly string[], anyObject = false): unknown {
  if (!isObject(value) || (!anyObject && isArray(value))) return value;
  return ownRecord(keys.map((k) => [k, read(value, k, `${label}.${k}`)] as const));
}

/** Wrap a callable so it runs with its original receiver, whatever later calls it. */
function withReceiver(fn: unknown, receiver: object): unknown {
  if (typeof fn !== "function") return fn;
  const f = fn as (...args: unknown[]) => unknown;
  return (...args: unknown[]) => reflectApply(f, receiver, args);
}

/** Captured replay stores whose underlying object is OxDeAI's built-in in-memory store. */
const EPHEMERAL_CAPTURES = new WeakSet<object>();

/**
 * RV-02: a deployer-supplied replay store, captured ONCE, before replay
 * resolution. `consumeAuthId` and `consumeDelegationId` are each read once
 * and bound to the store object; the resolver then validates this snapshot
 * (plain data, no accessors), so it never re-reads the deployer's getters,
 * and a throwing getter is a configuration error. The store's IDENTITY and
 * STATE are untouched: one store passed to several guards is one replay
 * domain. Both members are own properties (`undefined` when absent), so the
 * shared body's per-call reads never reach a prototype. A non-callable member
 * is kept as-is: the resolver rejects it in `shared` mode, and in legacy mode
 * it fails closed per call, as before. A non-object store is returned
 * unchanged for the resolver to accept or reject.
 */
function captureReplayStore(store: unknown, label: string): unknown {
  if (!isObject(store) && typeof store !== "function") return store;
  const s = store as object;
  const captured = ownRecord(REPLAY_STORE_MEMBERS.map((m) => [m, withReceiver(read(s, m, `${label}.${m}`), s)] as const));
  if (isEphemeralReplayStore(s as ReplayStore)) EPHEMERAL_CAPTURES.add(captured);
  return captured;
}

/**
 * The resolver refuses OxDeAI's built-in in-memory store in `shared` mode by
 * object identity. It now sees the captured snapshot instead, so the secure
 * guard applies that same rule to the snapshot after resolution.
 *
 * @internal
 */
export function isCapturedEphemeralReplayStore(store: unknown): boolean {
  return isObject(store) && EPHEMERAL_CAPTURES.has(store);
}

/**
 * `replayProtection`: `mode` read once, `store` presence tested once and its
 * value captured once (RV-02). Presence is preserved
 * (`{mode:'process-local', store: undefined}` is still "carries a store").
 */
function captureReplayProtection(value: unknown): unknown {
  if (!isRecord(value)) return value; // undefined, or rejected by resolveReplayProtection
  const label = "config.replayProtection";
  const mode = read(value, "mode", `${label}.mode`);
  if (!has(value, "store", `${label}.store`)) return ownRecord([["mode", mode]]);
  return ownRecord([["mode", mode], ["store", captureReplayStore(read(value, "store", `${label}.store`), `${label}.store`)]]);
}

/** `trustedDelegationSigners`: each `{ delegator, issuer }` member read once. */
function captureSigners(value: unknown): unknown {
  return copyArray(value, "config.trustedDelegationSigners", (e, l) => copyMembers(e, l, SIGNER_MEMBERS));
}

/**
 * `trustedDelegationAuthorities`: each `{ issuer, policyId }` member read once.
 * Read per request by the shared body and validated by core, which treats a
 * non-array as authorizing nothing, so a non-array is passed through. Every
 * object entry (arrays included) is replaced by a copy, so no caller-owned
 * object stays reachable from the captured list.
 */
function captureAuthorities(value: unknown): unknown {
  return copyArray(value, "config.trustedDelegationAuthorities", (e, l) => copyMembers(e, l, AUTHORITY_MEMBERS, true));
}

/** F4-C provider: `check` read once and bound to the original provider object. */
function captureDelegationRevocationProvider(value: unknown): unknown {
  if (!isRecord(value)) return value; // undefined, or rejected by resolveDelegationRevocation
  return ownRecord([["check", withReceiver(read(value, "check", "config.delegationRevocationProvider.check"), value)]]);
}

function captureKeySet(value: unknown, label: string): unknown {
  if (!isRecord(value)) return value;
  return ownRecord([
    ["issuer", read(value, "issuer", `${label}.issuer`)],
    ["version", read(value, "version", `${label}.version`)],
    ["keys", copyArray(read(value, "keys", `${label}.keys`), `${label}.keys`, (k, l) => copyMembers(k, l, KEYSET_KEY_MEMBERS))],
  ]);
}

/**
 * SignedKRLV1 `revocation`: KRL key sets, scopes, provider and watermark store
 * each read once. The KRL `provider` function identity is kept (it is invoked
 * as a method of the resolved configuration, as in `OxDeAIGuard`); the
 * watermark store's `accept` is read once and bound to the original store.
 */
function captureRevocation(value: unknown): unknown {
  if (!isRecord(value)) return value; // undefined, or rejected by resolveRevocationConfig
  const label = "config.revocation";
  const rawSets = read(value, "trustedKrlKeySets", `${label}.trustedKrlKeySets`);
  const trustedKrlKeySets = isArray(rawSets)
    ? copyArray(rawSets, `${label}.trustedKrlKeySets`, captureKeySet)
    : captureKeySet(rawSets, `${label}.trustedKrlKeySets`);
  const scopes = copyArray(read(value, "scopes", `${label}.scopes`), `${label}.scopes`, (s, l) => {
    if (!isRecord(s)) return s;
    return ownRecord([
      ["krlIssuer", read(s, "krlIssuer", `${l}.krlIssuer`)],
      ["keyIssuers", copyArray(read(s, "keyIssuers", `${l}.keyIssuers`), `${l}.keyIssuers`, (x) => x)],
    ]);
  });
  const provider = read(value, "provider", `${label}.provider`);
  const rawStore = read(value, "watermarkStore", `${label}.watermarkStore`);
  const watermarkStore = isRecord(rawStore)
    ? ownRecord([["accept", withReceiver(read(rawStore, "accept", `${label}.watermarkStore.accept`), rawStore)]])
    : rawStore;
  return ownRecord([
    ["trustedKrlKeySets", trustedKrlKeySets],
    ["scopes", scopes],
    ["provider", provider],
    ["watermarkStore", watermarkStore],
  ]);
}

/**
 * RV-01: the only code that may transform a captured option. A `Map`, so a
 * lookup can never reach `Object.prototype`.
 */
const NESTED_CAPTURE: ReadonlyMap<string, (value: unknown) => unknown> = new Map<string, (value: unknown) => unknown>([
  ["replayProtection", captureReplayProtection],
  ["replayStore", (v) => captureReplayStore(v, "config.replayStore")],
  ["trustedDelegationSigners", captureSigners],
  ["trustedDelegationAuthorities", captureAuthorities],
  ["delegationRevocationProvider", captureDelegationRevocationProvider],
  ["revocation", captureRevocation],
]);

/**
 * Read the deployer's configuration once into a frozen object holding all 18
 * options as own, enumerable data properties (`undefined` when not
 * configured). Downstream code may spread or re-read the result freely: it
 * has no accessors and no Proxy, and none of its option reads can reach a
 * prototype.
 *
 * Retained by identity, by design (documented dynamic configuration):
 * `trustedKeySets` (the array and its KeySet objects — in-place key rotation),
 * `engine`, the replay store, and the objects behind captured callables.
 *
 * @internal
 */
export function captureSecureGuardConfig(config: unknown): OxDeAIGuardConfig {
  // Same rejection and message as OxDeAIGuard's validateConfig.
  if (!isObject(config)) fail("config must be a plain object.");
  assertIntrinsicsUnpolluted();
  const entries: Array<readonly [string, unknown]> = [];
  for (const key of CONFIG_FIELDS) {
    let value = read(config, key, `config.${key}`);
    const nested = NESTED_CAPTURE.get(key);
    if (nested !== undefined) value = nested(value);
    else if (CALLABLE_FIELDS.has(key)) value = withReceiver(value, config);
    entries.push([key, value]);
  }
  // IR-01: a deployer getter or Proxy trap run by a read above may itself have
  // polluted an intrinsic prototype after the first check, so a later read
  // could have inherited the polluted value. Check again once every read is done.
  assertIntrinsicsUnpolluted();
  return ownRecord(entries) as unknown as OxDeAIGuardConfig;
}
