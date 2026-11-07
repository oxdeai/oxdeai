// SPDX-License-Identifier: Apache-2.0
/**
 * IR-03: obtaining a deployer callback's result without letting a `then`
 * inherited from a built-in prototype substitute it.
 *
 * Promise resolution looks up `then` on every object it settles with. When
 * `Object.prototype.then` (or `Array.prototype.then`) is a function, that
 * lookup turns every plain result object or array into a thenable, and the
 * polluting function decides what the promise settles with. A revocation
 * provider's `REVOKED` can become `ACTIVE`, a state store's denying state can
 * become a permissive one, and a current KRL can become an older one.
 *
 * {@link settleCallback} closes the part of this that the guard controls:
 *
 *  - A plain (non-thenable) result is used as is. It never passes through
 *    promise resolution, so no inherited `then` is ever consulted for it, and a
 *    synchronous callback is not exposed at all.
 *  - A genuine thenable (native or library promise) is awaited as before, so
 *    asynchronous callbacks keep working.
 *  - Before the call, right after it returns, and after its promise settles,
 *    the built-in prototypes must carry no `then`. Otherwise the result cannot
 *    be trusted and the caller fails closed. The check right after the call
 *    catches a `then` installed during the synchronous part of the callback,
 *    which for an `async` function includes the resolution of its `return`.
 *
 * Not closed, and not closable here: an asynchronous callback's promise is
 * resolved inside the callback's own promise machinery. A `then` installed and
 * removed again by code running in-process WHILE that promise is pending
 * (after an internal `await`) is consulted there, before the guard can see the
 * value. Doing that needs arbitrary in-process code execution timed to the
 * request, which is outside the guard's threat model; the same code could
 * equally replace the callback or `Promise.prototype.then`.
 *
 * @internal
 */

const OBJECT_PROTOTYPE: object = Object.prototype;
const ARRAY_PROTOTYPE: object = Array.prototype;
const getOwnDescriptor = Object.getOwnPropertyDescriptor;

/** True when a built-in prototype that plain results inherit from carries a `then`. */
export function builtinPrototypeHasThen(): boolean {
  return getOwnDescriptor(OBJECT_PROTOTYPE, "then") !== undefined || getOwnDescriptor(ARRAY_PROTOTYPE, "then") !== undefined;
}

/** The outcome of {@link settleCallback}. A thrown or rejected callback propagates as is. */
export type SettledCallback<T> = { readonly tampered: false; readonly value: T } | { readonly tampered: true };

/**
 * Results are null-prototype objects: this function is itself `async`, and an
 * ordinary object returned from it would be settled through the same
 * inherited-`then` lookup it exists to avoid (a polluting `then` could replace
 * TAMPERED by a forged clean result).
 */
function settled<T>(fields: SettledCallback<T>): SettledCallback<T> {
  return Object.freeze(Object.assign(Object.create(null) as object, fields)) as SettledCallback<T>;
}
const TAMPERED: SettledCallback<never> = settled({ tampered: true });

/**
 * Call `invoke` and settle its result as described above. Exceptions thrown by
 * `invoke` and rejections of its promise propagate unchanged, so callers keep
 * their existing "unavailable" handling.
 */
export async function settleCallback<T>(invoke: () => T | PromiseLike<T>): Promise<SettledCallback<T>> {
  if (builtinPrototypeHasThen()) return TAMPERED;
  const result = invoke();
  if (builtinPrototypeHasThen()) return TAMPERED;
  let value: unknown = result;
  // With no `then` on the built-in prototypes (checked just above), a callable
  // `then` can only come from the result's own prototype chain: a genuine
  // promise or promise-like object supplied by the deployer.
  if (
    result !== null &&
    (typeof result === "object" || typeof result === "function") &&
    typeof (result as { then?: unknown }).then === "function"
  ) {
    value = await result;
  }
  if (builtinPrototypeHasThen()) return TAMPERED;
  return settled({ tampered: false, value: value as T });
}
