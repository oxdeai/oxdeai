// SPDX-License-Identifier: Apache-2.0
/**
 * F4-R8-01 (supersedes F4-R6-02): one immutable authorization-input snapshot
 * for the guard delegation path.
 *
 * `opts.delegation` is a caller-supplied, live, in-process object. Before this
 * snapshot existed the guard read its fields many times: once for signature
 * verification, again for scope enforcement, again for replay consumption. An
 * accessor (getter) or Proxy could return the signed value to the verifier and
 * a different value to the enforcement or consume read, so a validly signed
 * narrow delegation executed above its signed cap, and the same signed
 * delegation executed more than once.
 *
 * Contract:
 *   - The caller's object graph is walked exactly once, here, before any
 *     verification. Every later step (signature, chain, scope, action binding,
 *     replay consumption, hooks) reads ONLY the returned snapshot.
 *   - Supported input model (what wire-decoded or `createDelegation` /
 *     `signAuthorizationEd25519` output looks like): plain objects (prototype
 *     `Object.prototype` or `null`) and dense plain arrays, whose own
 *     properties are all enumerable string-keyed DATA properties, with leaves
 *     of type string, number, bigint, boolean, null or undefined.
 *   - Anything else is rejected deterministically with
 *     `DelegationSnapshotError`: Proxy objects (detected before any property
 *     access, so no trap runs), accessor properties (never invoked: the getter
 *     does not run at all), non-enumerable or symbol-keyed own properties,
 *     class instances and other exotic objects (Date, Map, Set, typed arrays,
 *     boxed primitives, functions), sparse arrays or arrays with extra
 *     properties, cycles, and nesting deeper than {@link MAX_DEPTH}.
 *   - Only reflective operations that cannot execute user code on a
 *     non-Proxy object are used (`Object.getPrototypeOf`,
 *     `Reflect.ownKeys`, `Object.getOwnPropertyDescriptor`), so taking the
 *     snapshot runs no caller code and cannot throw from caller code.
 *   - Values are copied as-is: bigint stays bigint, numbers are not coerced,
 *     key order is preserved. Canonicalization and signature semantics are
 *     therefore identical to reading the original plain object. Semantic
 *     validation of the values (types, ranges) is done afterwards by the
 *     existing checks, on the snapshot.
 *   - The snapshot is deep-frozen.
 *
 * A failed snapshot never reaches verification, replay consumption or
 * execution.
 */
import { types } from "node:util";

/** Maximum object/array nesting accepted in a delegation input. DelegationV1 needs 3. */
export const MAX_DEPTH = 8;

export class DelegationSnapshotError extends Error {
  constructor(readonly path: string, readonly reason: string) {
    super(`${path}: ${reason}`);
    this.name = "DelegationSnapshotError";
  }
}

function snapshotValue(value: unknown, path: string, depth: number, seen: Set<object>): unknown {
  switch (typeof value) {
    case "string":
    case "number":
    case "bigint":
    case "boolean":
    case "undefined":
      return value;
    case "object":
      break;
    default:
      throw new DelegationSnapshotError(path, `unsupported value type ${typeof value}`);
  }
  if (value === null) return null;
  // Must be checked before ANY other operation: every reflective operation on
  // a Proxy (getPrototypeOf, ownKeys, getOwnPropertyDescriptor) runs a trap.
  if (types.isProxy(value)) throw new DelegationSnapshotError(path, "Proxy objects are not supported");
  if (depth >= MAX_DEPTH) throw new DelegationSnapshotError(path, `nesting exceeds ${MAX_DEPTH}`);
  if (seen.has(value)) throw new DelegationSnapshotError(path, "cyclic structure");
  seen.add(value);
  try {
    const proto = Object.getPrototypeOf(value);
    const isArray = Array.isArray(value);
    if (isArray ? proto !== Array.prototype : proto !== Object.prototype && proto !== null) {
      throw new DelegationSnapshotError(path, "only plain objects and plain arrays are supported");
    }
    const keys = Reflect.ownKeys(value);
    let out: unknown[] | Record<string, unknown>;
    if (isArray) {
      const length = (value as unknown[]).length;
      // own keys of a dense plain array are exactly "0".."length-1" plus "length".
      if (keys.length !== length + 1) {
        throw new DelegationSnapshotError(path, "sparse arrays and arrays with extra properties are not supported");
      }
      const arr: unknown[] = [];
      for (let i = 0; i < length; i++) {
        arr.push(readDataProperty(value, String(i), `${path}[${i}]`, depth, seen));
      }
      out = arr;
    } else {
      const obj: Record<string, unknown> = proto === null ? Object.create(null) : {};
      for (const key of keys) {
        if (typeof key !== "string") throw new DelegationSnapshotError(path, "symbol-keyed properties are not supported");
        // Plain assignment of "__proto__" on {} would set the prototype
        // instead of creating an own property: define it explicitly.
        Object.defineProperty(obj, key, {
          value: readDataProperty(value, key, `${path}.${key}`, depth, seen),
          enumerable: true, writable: true, configurable: true,
        });
      }
      out = obj;
    }
    return Object.freeze(out);
  } finally {
    seen.delete(value);
  }
}

function readDataProperty(owner: object, key: string, path: string, depth: number, seen: Set<object>): unknown {
  const desc = Object.getOwnPropertyDescriptor(owner, key);
  if (desc === undefined) throw new DelegationSnapshotError(path, "missing own property");
  if (!("value" in desc)) throw new DelegationSnapshotError(path, "accessor properties are not supported");
  if (!desc.enumerable) throw new DelegationSnapshotError(path, "non-enumerable properties are not supported");
  return snapshotValue(desc.value, path, depth + 1, seen);
}

/**
 * Deep, deterministic, frozen plain-data copy of `value` under the contract
 * above. Throws `DelegationSnapshotError` for anything outside the supported
 * input model.
 */
export function snapshotPlainData<T>(value: T, path = "input"): T {
  return snapshotValue(value, path, 0, new Set()) as T;
}
