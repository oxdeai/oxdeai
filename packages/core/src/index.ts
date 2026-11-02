// SPDX-License-Identifier: Apache-2.0
export type * from "./types/intent.js";
export type * from "./types/state.js";
export type * from "./types/policy.js";
export type * from "./types/authorization.js";
export type * from "./types/keyset.js";
export type * from "./types/delegation.js";
export type * from "./types/signed-krl.js";
export type * from "./verification/types.js";
export { encodeCanonicalState, decodeCanonicalState } from "./snapshot/CanonicalCodec.js";
export { createCanonicalState, withModuleState } from "./snapshot/CanonicalState.js";
export { canonicalJson, sha256HexFromJson, intentHash, stateSnapshotHash, authPayloadString } from "./crypto/hashes.js";
export { engineSignHmac } from "./crypto/sign.js";
export { engineVerifyHmac } from "./crypto/verify.js";
export {
  SIGNING_DOMAINS,
  signatureInput,
  signEd25519,
  verifyEd25519,
  signHmacDomain,
  verifyHmacDomain,
  findKeyInKeySets,
  keyIsActiveAt
} from "./crypto/signatures.js";
export { encodeEnvelope, decodeEnvelope, signEnvelopeEd25519, envelopeSigningPayload } from "./verification/envelope.js";
export { verifySnapshot } from "./verification/verifySnapshot.js";
export { verifyAuditEvents } from "./verification/verifyAuditEvents.js";
export { verifyEnvelope } from "./verification/verifyEnvelope.js";
export { verifyAuthorization, signAuthorizationEd25519, authorizationSigningPayload, toPublicAuthorizationV1, DEFAULT_MAX_FUTURE_ISSUED_AT_SKEW_SECONDS } from "./verification/verifyAuthorization.js";
export { isTrustedAuthorizationAuthority } from "./verification/authorizationAuthority.js";
export type { AuthorizationAuthority } from "./verification/authorizationAuthority.js";
export { isTrustedDelegationAuthority } from "./verification/delegationAuthority.js";
export type { DelegationAuthority } from "./verification/delegationAuthority.js";
export { createVerifier } from "./verification/createVerifier.js";
export type { VerifierConfig, BoundVerifier } from "./verification/createVerifier.js";
export {
  verifyDelegation,
  verifyDelegationChain,
  delegationParentHash,
  delegationSigningPayload,
  resolveEffectiveChildScope,
} from "./verification/verifyDelegation.js";
export type { VerifyDelegationOptions } from "./verification/verifyDelegation.js";
export { createDelegation } from "./delegation/createDelegation.js";
export type { CreateDelegationParams } from "./delegation/createDelegation.js";
export { PolicyEngine } from "./policy/PolicyEngine.js";
export type { EngineOptions, EngineEvalOptions, EvaluateOutput, EvaluatePureOutput, SimulationResult, EngineAuthorizationVerificationResult } from "./policy/PolicyEngine.js";
export { RECOMMENDED_TRUSTED_TIME_PROFILE } from "./policy/trustedTimeProfile.js";
export { verifyTrustedTime } from "./policy/verifyTrustedTime.js";
export type { VerifyTrustedTimeInput } from "./policy/verifyTrustedTime.js";
export { HashChainedLog } from "./audit/HashChainedLog.js";
export {
  verifySignedKrl,
  signedKrlSigningPayload,
} from "./verification/verifySignedKrl.js";
