// SPDX-License-Identifier: Apache-2.0
/**
 * @oxdeai/guard — Universal Execution Guard for OxDeAI.
 *
 * This package is the single Policy Enforcement Point (PEP) layer for the
 * OxDeAI ecosystem. Runtime adapters (LangGraph, CrewAI, OpenAI, etc.) should
 * delegate all authorization decisions here rather than reimplementing PEP
 * logic themselves.
 */

export { OxDeAIGuard } from "./guard.js";
export { createSecureGuard } from "./secureGuard.js";
export type { SecureGuardOptions } from "./secureGuard.js";
export {
  createTrustedExecutionContext,
  isTrustedExecutionContext,
} from "./trustedContext.js";
export type { TrustedExecutionContext } from "./trustedContext.js";
export { reconcileWithTrustedContext } from "./provenance.js";
export type { ClaimProvenance, ProvenanceRecord, ReconciliationResult, ReconciliationOptions } from "./provenance.js";
export type {
  GuardBoundaryStage,
  GuardBoundaryFailure,
  GuardBoundaryAuditEvent,
  GuardBoundaryEventHook,
} from "./boundaryEvent.js";
export {
  INTERNAL_EXECUTOR_TOKEN_HEADER,
  createPepGatewayExecutor,
  createPepGatewayHttpServer,
  createHttpUpstreamExecutor,
  createProtectedUpstreamHttpServer,
  hasValidInternalExecutorToken,
  protectUpstreamExecution,
  defaultUpstreamSuccess,
} from "./gateway.js";
export { defaultNormalizeAction } from "./normalizeAction.js";
export { createInMemoryReplayStore } from "./replayStore.js";
export type { ReplayStore } from "./replayStore.js";
export { createRedisReplayStore } from "./replayStore.redis.js";
export type { RedisClient, RedisReplayStoreConfig } from "./replayStore.redis.js";
export {
  OxDeAIDenyError,
  OxDeAIAuthorizationError,
  OxDeAIAuthorityError,
  OxDeAIConflictError,
  OxDeAIDelegationError,
  OxDeAIGuardConfigurationError,
  OxDeAINormalizationError,
  OxDeAIProvenanceConflictError,
} from "./errors.js";
export type {
  ProposedAction,
  OxDeAIGuardConfig,
  GuardDecisionRecord,
  GuardDelegationInput,
  GuardCallOptions,
  StateVersion,
  VersionedState,
} from "./types.js";
export type {
  PepGatewayExecuteRequest,
  PepGatewayOptions,
  PepGatewayResponseBody,
  PepGatewayResult,
  ProtectedUpstreamOptions,
  UpstreamExecutor,
  UpstreamResponse,
  UpstreamSuccessContract,
} from "./gateway.js";
