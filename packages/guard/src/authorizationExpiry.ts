// SPDX-License-Identifier: Apache-2.0
/**
 * R-03: the SIGNED effective expiry of an AuthorizationV1 that core
 * `verifyAuthorization` has already accepted (authorization-v1.md §5 "Expiry
 * field resolution"): `expiry` when present, otherwise the nested encoding's
 * signed `expires_at`. Used for replay-store retention so retention always
 * follows the same signed value that decided validity.
 *
 * Returns `undefined` when no valid integer expiry exists; callers MUST NOT
 * substitute a default. Not re-exported from the package entry point.
 * @internal
 */
export function signedEffectiveExpiry(auth: unknown): number | undefined {
  if (typeof auth !== "object" || auth === null) return undefined;
  const a = auth as Record<string, unknown>;
  if (a.expiry !== undefined) return Number.isSafeInteger(a.expiry) ? (a.expiry as number) : undefined;
  return Number.isSafeInteger(a.expires_at) ? (a.expires_at as number) : undefined;
}
