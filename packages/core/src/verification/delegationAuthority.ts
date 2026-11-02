// SPDX-License-Identifier: Apache-2.0

/**
 * One deployer-authorized (delegator, issuer) pair for delegation signing.
 *
 * ⚠️ This is NOT key trust, and it is NOT the same question as
 * `trustedAuthorizationAuthorities` (which authorizes an issuer for a policy on
 * the AUTHORIZATION path). This answers a delegation-specific question:
 *
 * ```text
 * trustedKeySets                  -> "which signing keys are trusted for this claimed issuer?"
 * trustedDelegationAuthorities    -> "which issuer is authorized to sign delegations for which delegator?"
 * ```
 *
 * A valid delegation signature proves only that a trusted key belonging to the
 * claimed `issuer` signed the artifact (F4-1/F4-2). It does NOT prove that this
 * issuer is permitted to act as the `delegator` named in the delegation. Both
 * questions must be answered before a delegation is accepted: otherwise any key
 * trusted for any purpose can mint a delegation of another principal's
 * authority (reproduced: an unrelated trusted signer `mallory` minting a
 * delegation whose `delegator` is `svc-A`).
 *
 * The default rule, applied when no `trustedDelegationAuthorities` is
 * configured, is self-delegation: the signer must BE the delegator
 * (`issuer === delegator`). This matches the reference model where the party a
 * parent authorization is issued to (`parent.audience`) is the delegator and
 * signs its own delegations. Configuring an explicit authority list is only
 * needed for broker/central-issuer deployments where a distinct issuer signs
 * delegations on behalf of a delegator.
 *
 * The pair is the unit of authority and is deliberately not decomposable into
 * two independent allow-lists (same rationale as AuthorizationAuthority).
 *
 * @public
 */
export type DelegationAuthority = {
  /** Exact `delegator` value the delegation must carry. */
  readonly delegator: string;
  /** Exact `issuer` value authorized to sign delegations for that delegator. */
  readonly issuer: string;
};

/**
 * True only when `(delegator, issuer)` appears as a complete pair in
 * `authorities`. Exact string equality on both members, no wildcard/normalization.
 * Fail-closed: an empty list authorizes no pair, and absence of configuration is
 * a different condition handled by the caller (it falls back to the
 * `issuer === delegator` self-delegation rule).
 *
 * @public
 */
export function isTrustedDelegationAuthority(
  authorities: readonly DelegationAuthority[],
  delegator: string,
  issuer: string
): boolean {
  if (!Array.isArray(authorities)) return false;
  if (typeof delegator !== "string" || delegator.length === 0) return false;
  if (typeof issuer !== "string" || issuer.length === 0) return false;

  for (const authority of authorities) {
    if (
      authority !== null &&
      typeof authority === "object" &&
      authority.delegator === delegator &&
      authority.issuer === issuer
    ) {
      return true;
    }
  }
  return false;
}
