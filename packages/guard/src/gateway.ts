// SPDX-License-Identifier: Apache-2.0
import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, request as httpRequest } from "node:http";
import type { IncomingHttpHeaders, IncomingMessage, Server, ServerResponse } from "node:http";
import { sha256HexFromJson, verifyAuthorization } from "@oxdeai/core";
import type { AuthorizationAuthority, AuthorizationV1, KeySet } from "@oxdeai/core";
import { resolveReplayProtection, strictFromConfig } from "./replayProtection.js";
import type { ReplayProtection } from "./replayProtection.js";
import type { ReplayStore } from "./replayStore.js";
import { snapshotPlainData } from "./delegationSnapshot.js";

export const INTERNAL_EXECUTOR_TOKEN_HEADER = "x-internal-executor-token";

export type PepGatewayExecuteRequest = {
  action: unknown;
  authorization: AuthorizationV1;
};

export type PepGatewayResponseBody = {
  ok: boolean;
  /**
   * The authorization verdict. `ALLOW` / `DENY` are the normal outcomes, decided
   * before (DENY) or at (ALLOW) the gate.
   *
   * H-1 (R3.1): `UNKNOWN` is emitted ONLY by the HTTP handler's execution-phase
   * backstop - an unexpected internal fault thrown after the parsing phase, when
   * the gateway never obtained a verdict and cannot determine whether dispatch
   * occurred. It is NOT a denial: attributing `DENY` there would retroactively
   * turn a possibly-granted, possibly-dispatched request into a refusal, the very
   * conflation H-1 removes. `UNKNOWN` always travels with `outcome:"INDETERMINATE"`
   * and `executed:null`. Consumers must treat it as "no decision was reached",
   * never as ALLOW or DENY. A normal authorization response is only ever ALLOW or
   * DENY; UNKNOWN never appears on the success or the pre-dispatch-denial path.
   */
  decision: "ALLOW" | "DENY" | "UNKNOWN";
  /**
   * H-1: the authoritative three-state execution outcome. Consumers MUST branch
   * on this, not on `executed`.
   *   NOT_DISPATCHED - the request never reached the upstream (denied before
   *                    dispatch); no side effect is possible.
   *   EXECUTED       - the upstream confirmed success; the effect happened.
   *   INDETERMINATE  - the upstream was dispatched but its outcome is unknown
   *                    (timeout, connection reset, or any non-success status,
   *                    4xx included); a side effect cannot be ruled out.
   */
  outcome: "NOT_DISPATCHED" | "EXECUTED" | "INDETERMINATE";
  /**
   * H-1: `true` only on a confirmed EXECUTED outcome, `false` only on a
   * confirmed NOT_DISPATCHED outcome, and `null` when INDETERMINATE. It is
   * never `false` for a request that may already have executed. Prefer `outcome`.
   */
  executed: boolean | null;
  reason?: string;
  auth_id?: string;
  intent_hash?: string;
  upstream_result?: unknown;
  upstream_status?: number;
  upstream_error?: unknown;
};

export type PepGatewayResult = {
  status: 200 | 403 | 500 | 502 | 504;
  body: PepGatewayResponseBody;
  upstreamCalled: boolean;
};

export type UpstreamResponse = { status: number; body?: unknown };

export type UpstreamExecutor = (
  action: unknown,
  headers: Record<string, string>
) => Promise<UpstreamResponse>;

/**
 * H-1 (R3): the contract that decides whether a dispatched upstream response is
 * a CONFIRMED success (-> EXECUTED). It answers exactly one question: did the
 * upstream, by its own transport/application contract, confirm that it accepted
 * and performed the request? It is NOT a claim that a business effect is
 * durably committed - the gateway cannot observe that; EXECUTED means
 * "upstream-confirmed success per this contract", the strongest signal
 * available at this boundary. Anything this predicate does not confirm
 * (a 3xx, a 4xx, a 5xx, a malformed or missing response) leaves the effect in
 * doubt and is INDETERMINATE, never a confirmed non-execution.
 *
 * The default is {@link defaultUpstreamSuccess}: an integer HTTP 2xx status.
 * A deployment whose upstream signals success differently can supply its own.
 */
export type UpstreamSuccessContract = (upstream: UpstreamResponse | null | undefined) => boolean;

export type PepGatewayOptions = {
  expectedAudience: string;
  trustedKeySets: KeySet | readonly KeySet[];
  internalExecutorToken: string;
  /**
   * Dispatches an authorized action to the protected upstream.
   *
   * - Captured once at construction. Reassigning `options.executeUpstream`
   *   later has no effect (INVREG-F05).
   * - Invoked with this options object as `this`, as before INVREG-F05, so a
   *   method that uses `this` keeps working (GW-COMP-01).
   * - `action` is a fresh, mutable plain-data copy of the verified request
   *   action, value-identical to what was hashed and bound to the
   *   authorization. The executor may modify it. The gateway never reads it
   *   back, and it shares no object with the caller's request or with the
   *   gateway's own verified snapshot.
   */
  executeUpstream: UpstreamExecutor;
  /**
   * Deployer-configured (issuer, policyId) pairs authorized to issue
   * authorizations accepted by this gateway. REQUIRED.
   *
   * The gateway is the highest-risk boundary in the system: the authorization
   * arrives inside an untrusted request. A valid signature under
   * {@link trustedKeySets} proves that a trusted key for the *claimed* issuer
   * signed the artifact — it does not prove that this issuer may issue for the
   * claimed `policy_id`. This list is the only thing that can prove the latter,
   * and it must exist before the request arrives.
   *
   * ```text
   * missing    -> createPepGatewayExecutor() throws at construction
   * []         -> valid configuration authorizing no pair; every request denied
   * ```
   *
   * There is no unconstrained mode. `undefined` is a configuration error, not
   * "accept any issuer/policy".
   *
   * Authority is a complete pair, matched exactly on both members. Do not
   * decompose it into separate issuer and policy allow-lists: given `A/P1` and
   * `B/P2`, that would also authorize `A/P2` and `B/P1`.
   *
   * ⚠️ Supersedes the removed `expectedIssuer` option. To constrain the gateway
   * to a single issuer, list only that issuer's pairs.
   *
   * INVREG-F05: the list is validated and copied at construction. Every entry
   * must be a plain `{ issuer, policyId }` object with non-empty string
   * members (no Proxy, no accessor properties), or construction throws. Later
   * changes to the caller's array or entry objects, or reassignment of this
   * property, are NOT observed. There is no runtime rotation API for
   * authorities: to change them, construct a new executor. (Contrast
   * `trustedKeySets`, which is retained by reference so keys can be rotated in
   * place; key trust is not policy authority.)
   */
  trustedAuthorizationAuthorities: readonly AuthorizationAuthority[];
  /**
   * @deprecated P2-1: prefer `replayProtection`. Setting both is rejected at
   * construction. A bare `replayStore` is still honored for back-compat.
   */
  replayStore?: ReplayStore;
  /**
   * P2-1: explicit replay-protection posture (see {@link ReplayProtection}).
   * Mutually exclusive with `replayStore`. When neither is set, a process-local
   * store is used with a one-time migration warning (transitional).
   */
  replayProtection?: ReplayProtection;
  /** P2-1 strict mode (opt-in): see OxDeAIGuardConfig.requireExplicitReplayProtection. */
  requireExplicitReplayProtection?: boolean;
  now?: () => number;
  timeoutMs?: number;
  /**
   * @deprecated Custom action hashing is deprecated and will be removed in the
   * next major release. Omit it to use the default whole-action hash.
   *
   * Coverage rule (always enforced, no opt-out): a request is accepted only if
   * this function returns exactly `sha256HexFromJson(action)` - the hash of the
   * whole action under canonicalization-v1. Any other result (a different
   * digest, a projection that omits fields, a non-string) is denied with
   * `ACTION_HASH_UNCOVERED` before authorization verification and before any
   * replay state is touched, so no field of the action can be forwarded to the
   * upstream without being covered by `authorization.intent_hash`.
   *
   * `undefined` and `null` mean "not configured" (default hash). Any other
   * non-function value is rejected at construction. The function is captured
   * once at construction. Supplying it emits a one-time `DeprecationWarning`
   * (code `OXDEAI_DEP_HASH_ACTION`); under `--throw-deprecation` that warning
   * is thrown at construction.
   */
  hashAction?: ((action: unknown) => string) | null;
  /**
   * Maximum request body size, in bytes, accepted by
   * {@link createPepGatewayHttpServer}. Default 1 MiB (1_048_576); allowed
   * range 1_024..67_108_864. A larger body is rejected with 403
   * `BODY_TOO_LARGE` (`NOT_DISPATCHED`) without being parsed. Validated by the
   * HTTP server at construction; ignored by {@link createPepGatewayExecutor},
   * which receives already-parsed input.
   */
  maxBodyBytes?: number;
  /**
   * H-1 (R3): the contract that decides a CONFIRMED upstream success
   * (-> EXECUTED). Defaults to {@link defaultUpstreamSuccess} (integer HTTP 2xx).
   * Overriding it changes only what counts as a confirmed execution; it never
   * relaxes the fail-safe rule that an unconfirmed dispatched outcome is
   * INDETERMINATE, not a confirmed non-execution.
   */
  isUpstreamSuccess?: UpstreamSuccessContract;
};

export type ProtectedUpstreamOptions<T = unknown> = {
  expectedToken: string;
  execute: (body: unknown) => T | Promise<T>;
};

function deny(status: PepGatewayResult["status"], reason: string, extra: Partial<PepGatewayResponseBody> = {}): PepGatewayResult {
  return {
    status,
    upstreamCalled: false,
    body: { ok: false, decision: "DENY", outcome: "NOT_DISPATCHED", executed: false, reason, ...extra },
  };
}

// H-1 (R3): the default upstream-success contract - an integer HTTP 2xx status.
// A 3xx is not a success (the upstream did not confirm the effect); anything
// >= 400 or a malformed/missing response is a dispatched-but-uncertain outcome.
// See {@link UpstreamSuccessContract}: EXECUTED means "upstream-confirmed
// success per the contract", never a proof of a durable business effect.
export const defaultUpstreamSuccess: UpstreamSuccessContract = (upstream) => {
  const status = upstream?.status;
  return typeof status === "number" && Number.isInteger(status) && status >= 200 && status <= 299;
};

function requireText(value: string | undefined, name: string): void {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} is required`);
  }
}

// ── Request-body bounds (M-2) ─────────────────────────────────────────────
/** Default {@link PepGatewayOptions.maxBodyBytes} for both HTTP servers: 1 MiB. */
const DEFAULT_MAX_BODY_BYTES = 1_048_576;
const MIN_MAX_BODY_BYTES = 1_024;
const MAX_MAX_BODY_BYTES = 67_108_864;
/** Lingering close after an early rejection: discard at most this many further request bytes... */
const LINGER_MAX_BYTES = 64 * 1024;
/** ...for at most this long, then destroy the socket. */
const LINGER_MAX_MS = 2_000;

/** Validate a configured body limit. Trusted configuration: malformed values throw at construction. */
function resolveMaxBodyBytes(value: unknown): number {
  if (value === undefined) return DEFAULT_MAX_BODY_BYTES;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < MIN_MAX_BODY_BYTES || value > MAX_MAX_BODY_BYTES) {
    throw new Error(`maxBodyBytes must be an integer between ${MIN_MAX_BODY_BYTES} and ${MAX_MAX_BODY_BYTES}`);
  }
  return value;
}

/** Marker for a request body that exceeded the configured limit. Never carries body data. */
class BodyTooLargeError extends Error {
  constructor() {
    super("BODY_TOO_LARGE");
    this.name = "BodyTooLargeError";
  }
}

/** True when the request declares a body (chunked, or a non-zero Content-Length). */
function requestDeclaresBody(req: IncomingMessage): boolean {
  if (req.headers["transfer-encoding"] !== undefined) return true;
  const declared = req.headers["content-length"];
  return declared !== undefined && Number(declared) > 0;
}

/**
 * Read and parse a JSON request body without ever buffering more than `limit`
 * bytes. A declared Content-Length above the limit is rejected before any body
 * byte is read; a chunked body is rejected as soon as the running total exceeds
 * the limit. On overflow the partial buffer is discarded: it is never decoded
 * or parsed, so an oversized body whose prefix happens to be valid JSON cannot
 * be accepted. A body within the limit is decoded and parsed exactly as before
 * (UTF-8, empty body -> {}, malformed JSON -> SyntaxError).
 */
async function readBoundedJson(req: IncomingMessage, limit: number): Promise<unknown> {
  const declared = req.headers["content-length"];
  if (declared !== undefined && Number(declared) > limit) throw new BodyTooLargeError();
  const raw = await new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const cleanup = () => {
      req.off("data", onData);
      req.off("end", onEnd);
      req.off("error", onError);
      req.off("close", onClose);
    };
    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      cleanup();
      fn();
    };
    const onData = (chunk: Buffer | string) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buf.length;
      if (total > limit) {
        req.pause();
        chunks.length = 0; // discard: never decoded, never parsed
        settle(() => reject(new BodyTooLargeError()));
        return;
      }
      chunks.push(buf);
    };
    const onEnd = () => settle(() => resolve(Buffer.concat(chunks, total)));
    const onError = (err: Error) => settle(() => reject(err));
    const onClose = () => settle(() => reject(new Error("request closed before the body was complete")));
    req.on("data", onData);
    req.on("end", onEnd);
    req.on("error", onError);
    req.on("close", onClose);
  });
  const text = raw.toString("utf8");
  return text.trim() ? JSON.parse(text) : {};
}

/**
 * Send a final rejection for a request whose body has not been (fully) read,
 * then close the connection gracefully with a bounded drain:
 *   1. the complete response is sent with `Connection: close`;
 *   2. after it is flushed the connection is half-closed (FIN), keeping the
 *      read side open - Node's default for `Connection: close` is to destroy
 *      the socket after the flush, and destroying a socket with unread input
 *      can make the kernel reset the connection before the client has read
 *      the response;
 *   3. further request bytes are read and discarded - at most
 *      LINGER_MAX_BYTES or LINGER_MAX_MS, whichever comes first - and the
 *      socket is then destroyed (immediately once both directions are done).
 * Nothing read during the drain is buffered, parsed or dispatched: the
 * rejection is final. Bodiless requests are answered normally.
 */
function rejectAndClose(req: IncomingMessage, res: ServerResponse, status: number, body: unknown): void {
  if (!requestDeclaresBody(req)) return sendJson(res, status, body);
  const socket = req.socket;
  const destroy = () => {
    if (!socket.destroyed) socket.destroy();
  };
  const timer = setTimeout(destroy, LINGER_MAX_MS);
  timer.unref();
  socket.once("close", () => clearTimeout(timer));
  // Replace "end then destroy" with "end only" for this socket; the drain bounds below destroy it.
  // If a future Node version does not use this hook, the server destroys after the flush instead:
  // still bounded and fail-closed, only without the drain.
  Object.defineProperty(socket, "destroySoon", {
    configurable: true,
    writable: true,
    value: () => {
      if (!socket.writableEnded) socket.end();
    },
  });
  let drained = 0;
  let inputEnded = false;
  let outputDone = false;
  const maybeDone = () => {
    if (inputEnded && outputDone) destroy();
  };
  req.removeAllListeners("data");
  req.on("data", (chunk: Buffer | string) => {
    drained += typeof chunk === "string" ? Buffer.byteLength(chunk) : chunk.length;
    if (drained > LINGER_MAX_BYTES) destroy();
  });
  req.once("end", () => {
    inputEnded = true;
    maybeDone();
  });
  req.once("error", destroy);
  res.once("finish", () => {
    outputDone = true;
    maybeDone();
  });
  req.resume();
  const data = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(data),
    connection: "close",
  });
  res.end(data);
}

// ── Custom action hash deprecation (M-1) ─────────────────────────────────
let hashActionDeprecationWarned = false;
/** Test-only: reset the one-time deprecation latch. Not exported from the package entry point. */
export function __resetHashActionDeprecationWarningForTests(): void {
  hashActionDeprecationWarned = false;
}
function warnHashActionDeprecatedOnce(): void {
  if (hashActionDeprecationWarned) return;
  hashActionDeprecationWarned = true;
  process.emitWarning(
    "PepGatewayOptions.hashAction is deprecated and will be removed in the next major release. " +
      "Requests are accepted only when it returns the whole-action hash (sha256HexFromJson(action)); omit it to use the default.",
    { type: "DeprecationWarning", code: "OXDEAI_DEP_HASH_ACTION" }
  );
}

function asKeySets(keySets: KeySet | readonly KeySet[]): readonly KeySet[] {
  return Array.isArray(keySets) ? (keySets as readonly KeySet[]) : [keySets as KeySet];
}

/**
 * INVREG-F05: capture issuer-policy authority at construction.
 *
 * The caller's list is snapshotted (plain data only: a Proxy or accessor is
 * rejected without being invoked), every entry is validated, and a frozen copy
 * of exactly the `{ issuer, policyId }` pairs is retained. The caller's array
 * and entry objects are never read again, so mutating them after construction
 * cannot add a trusted (issuer, policy_id) pair. A malformed entry fails
 * construction instead of silently never matching.
 */
function resolveTrustedAuthorizationAuthorities(value: unknown): readonly AuthorizationAuthority[] {
  // Array.isArray does not run Proxy traps.
  if (!Array.isArray(value)) {
    throw new Error(
      "trustedAuthorizationAuthorities is required: the gateway accepts authorizations from untrusted " +
        "request input and cannot infer which issuer is authorized for which policy_id. " +
        "An absent authority list is not an unconstrained mode."
    );
  }
  let snapshot: readonly unknown[];
  try {
    snapshot = snapshotPlainData(value as readonly unknown[], "trustedAuthorizationAuthorities");
  } catch (err) {
    throw new Error(
      `trustedAuthorizationAuthorities must be a plain array of plain { issuer, policyId } objects: ${
        err instanceof Error ? err.message : String(err)
      }`
    );
  }
  const copy: AuthorizationAuthority[] = [];
  for (const entry of snapshot) {
    const e = entry as { issuer?: unknown; policyId?: unknown } | null;
    if (
      e === null || typeof e !== "object" || Array.isArray(e) ||
      typeof e.issuer !== "string" || e.issuer.length === 0 ||
      typeof e.policyId !== "string" || e.policyId.length === 0
    ) {
      throw new Error(
        "trustedAuthorizationAuthorities entries must be { issuer: string, policyId: string } with non-empty values."
      );
    }
    copy.push(Object.freeze({ issuer: e.issuer, policyId: e.policyId }));
  }
  return Object.freeze(copy);
}

/**
 * GW-COMP-01: mutable deep copy of the gateway's verified request snapshot,
 * handed to `executeUpstream`.
 *
 * Input is ONLY the output of `snapshotPlainData`: deep-frozen plain objects
 * (prototype `Object.prototype` or `null`), dense plain arrays, own enumerable
 * string-keyed data properties, and primitive leaves, with no cycles, no
 * accessors and no Proxies. Plain property reads are therefore safe here and
 * run no caller code.
 *
 * The copy keeps key order, leaf values (including bigint and -0), null
 * prototypes and own `"__proto__"` keys (defined as data, never as a prototype
 * change). It is value-identical to the snapshot at the moment it is made, so
 * it canonicalizes to the same bytes and hash. It shares no object with the
 * snapshot or the caller's request.
 */
function mutableCopyOfSnapshot(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    const arr: unknown[] = [];
    for (let i = 0; i < value.length; i++) arr.push(mutableCopyOfSnapshot(value[i]));
    return arr;
  }
  const out: Record<string, unknown> = Object.getPrototypeOf(value) === null ? Object.create(null) : {};
  for (const key of Object.keys(value)) {
    Object.defineProperty(out, key, {
      value: mutableCopyOfSnapshot((value as Record<string, unknown>)[key]),
      enumerable: true, writable: true, configurable: true,
    });
  }
  return out;
}

function headerValue(headers: IncomingHttpHeaders | Record<string, string | string[] | undefined>, name: string): string | undefined {
  const raw = headers[name.toLowerCase()];
  if (Array.isArray(raw)) return raw.length === 1 ? raw[0] : undefined;
  return raw;
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) return promise;
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(Object.assign(new Error("UPSTREAM_TIMEOUT"), { code: "UPSTREAM_TIMEOUT" })), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      }
    );
  });
}

export function hasValidInternalExecutorToken(
  headers: IncomingHttpHeaders | Record<string, string | string[] | undefined>,
  expectedToken: string
): boolean {
  requireText(expectedToken, "expectedToken");
  const supplied = headerValue(headers, INTERNAL_EXECUTOR_TOKEN_HEADER);
  // Constant-time comparison of fixed-length digests: no early exit on the first
  // differing byte or on a length difference. An absent header is hashed as ""
  // so absence and presence take the same path.
  const suppliedDigest = createHash("sha256").update(typeof supplied === "string" ? supplied : "", "utf8").digest();
  const expectedDigest = createHash("sha256").update(expectedToken, "utf8").digest();
  return timingSafeEqual(suppliedDigest, expectedDigest) && typeof supplied === "string";
}

export async function protectUpstreamExecution<T = unknown>(
  body: unknown,
  headers: IncomingHttpHeaders | Record<string, string | string[] | undefined>,
  options: ProtectedUpstreamOptions<T>
): Promise<{ status: 200 | 403 | 500; body: unknown; executed: boolean }> {
  if (!hasValidInternalExecutorToken(headers, options.expectedToken)) {
    return {
      status: 403,
      executed: false,
      body: { ok: false, executed: false, error: "missing or invalid internal executor token" },
    };
  }

  try {
    const result = await options.execute(body);
    return { status: 200, executed: true, body: result };
  } catch (err) {
    return {
      status: 500,
      executed: false,
      body: { ok: false, executed: false, error: err instanceof Error ? err.message : String(err) },
    };
  }
}

export function createPepGatewayExecutor(options: PepGatewayOptions) {
  // INVREG-F05 (GATE-CFG-05): every option that decides the trust boundary is
  // read exactly once, here. The returned executor never reads `options`
  // again, so reassigning `expectedAudience`, `internalExecutorToken`,
  // `executeUpstream` or `trustedAuthorizationAuthorities` on the caller's
  // options object after construction has no effect.
  const expectedAudience = options.expectedAudience;
  const internalExecutorToken = options.internalExecutorToken;
  const executeUpstream = options.executeUpstream;
  // GW-COMP-01: receiver for executeUpstream, as at baseline. It is an object
  // reference only; no property of it is read after construction.
  const upstreamReceiver: unknown = options;
  requireText(expectedAudience, "expectedAudience");
  requireText(internalExecutorToken, "internalExecutorToken");
  // Retained by reference on purpose: in-place mutation of the key-set array
  // and its KeySet objects is the documented key-rotation mechanism.
  const trustedKeySets = asKeySets(options.trustedKeySets);
  if (trustedKeySets.length === 0) throw new Error("trustedKeySets are required");
  // Fail at construction, not at first request: a gateway that cannot decide
  // policy authority must never come up in a state where it can serve traffic.
  // An explicitly configured empty array is accepted here and denies every
  // request at the authority check — a deliberate configuration, and distinct
  // from having configured nothing at all.
  const trustedAuthorizationAuthorities = resolveTrustedAuthorizationAuthorities(options.trustedAuthorizationAuthorities);
  const replayStore = resolveReplayProtection(options, { strict: strictFromConfig(options.requireExplicitReplayProtection) }).store;
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  // Custom action hash (deprecated): captured once here. undefined/null keep the
  // historical `options.hashAction ?? sha256HexFromJson` meaning (default hash,
  // no coverage check, no warning); any other non-function is a configuration error.
  const customHashAction: unknown = options.hashAction;
  if (customHashAction !== undefined && customHashAction !== null && typeof customHashAction !== "function") {
    throw new Error("hashAction must be a function");
  }
  const coverageGuard = typeof customHashAction === "function" ? (customHashAction as (action: unknown) => unknown) : null;
  if (coverageGuard) warnHashActionDeprecatedOnce();
  const timeoutMs = options.timeoutMs ?? 30_000;
  const isUpstreamSuccess = options.isUpstreamSuccess ?? defaultUpstreamSuccess;

  return async function executeThroughPep(input: unknown): Promise<PepGatewayResult> {
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      return deny(403, "INVALID_REQUEST");
    }

    // ── INVREG-F01 / INVREG-F02: one immutable request snapshot ────────────
    // The caller's request object is live, in-process data. Before this
    // snapshot the gateway re-read `action` and `authorization` fields at
    // hashing, verification, replay consumption and dispatch; a getter, a
    // Proxy, or a plain mutation during the awaited replay consume could make
    // the verified action differ from the executed one, or the verified
    // auth_id differ from the consumed one (one signature, many executions).
    //
    // The request graph is walked exactly once, here, before any security
    // decision. Every later step - hashing, signature/authority verification,
    // intent binding, replay consumption, dispatch and the response body -
    // reads ONLY this deep-frozen plain-data copy. Proxies, accessors and
    // non-plain values (class instances, Date, Map, Buffer/typed arrays,
    // functions, symbol keys, sparse arrays, cycles) are rejected without
    // invoking caller code, before replay state is touched. Values are copied
    // verbatim (no coercion, key order preserved), so canonicalization and the
    // action hash are unchanged for supported input. No nesting limit is added
    // (maxDepth = Infinity); nesting stays stack-bounded as in canonicalJson.
    let requestBody: Partial<PepGatewayExecuteRequest>;
    try {
      requestBody = snapshotPlainData(input as Partial<PepGatewayExecuteRequest>, "request", Infinity);
    } catch (err) {
      return deny(403, `INVALID_REQUEST_INPUT:${err instanceof Error ? err.message : String(err)}`);
    }
    const action = requestBody.action;
    const authorization = requestBody.authorization;
    if (action === undefined || !authorization) {
      return deny(403, "INVALID_REQUEST");
    }

    // The bound hash is always the whole-action hash. A custom hashAction can
    // only add denials: it must reproduce that hash exactly, so every field of
    // the action is covered by authorization.intent_hash (canonicalization-v1).
    // All of this runs before verification and before replay state is touched.
    let intentHash: string;
    if (coverageGuard) {
      let customHash: unknown;
      try {
        customHash = coverageGuard(action);
      } catch (err) {
        return deny(403, `ACTION_CANONICALIZATION_FAILED:${err instanceof Error ? err.message : String(err)}`);
      }
      if (customHash !== null && typeof customHash === "object" && typeof (customHash as { then?: unknown }).then === "function") {
        // An async hashAction is never a match; absorb its eventual rejection so it cannot crash the process.
        Promise.resolve(customHash).catch(() => undefined);
      }
      try {
        intentHash = sha256HexFromJson(action);
      } catch (err) {
        return deny(403, `ACTION_CANONICALIZATION_FAILED:${err instanceof Error ? err.message : String(err)}`);
      }
      if (typeof customHash !== "string" || customHash !== intentHash) {
        return deny(403, "ACTION_HASH_UNCOVERED");
      }
    } else {
      try {
        intentHash = sha256HexFromJson(action);
      } catch (err) {
        return deny(403, `ACTION_CANONICALIZATION_FAILED:${err instanceof Error ? err.message : String(err)}`);
      }
    }

    const verification = verifyAuthorization(authorization, {
      now: now(),
      mode: "strict",
      trustedKeySets,
      requireSignatureVerification: true,
      expectedAudience,
      // `expectedPolicyId: authorization.policy_id` was removed here (#301): it
      // compared the artifact against itself and proved nothing. Policy
      // authority now comes from deployer configuration that existed before the
      // request, evaluated as a complete (issuer, policy_id) pair.
      trustedAuthorizationAuthorities,
    });

    if (verification.status !== "ok") {
      const reason = verification.violations.map((v) => v.code).join(",") || "AUTHORIZATION_INVALID";
      return deny(403, reason);
    }

    if (authorization.intent_hash !== intentHash) {
      return deny(403, "INTENT_HASH_MISMATCH");
    }

    // GW-COMP-01: the upstream executor gets its own mutable deep copy of the
    // verified snapshot, built here, after verification and BEFORE replay
    // consumption, so a failed copy cannot burn the authorization. At the
    // moment of dispatch the copy is value-identical to the hashed snapshot
    // (same keys in the same order, same leaves, same prototypes), so the
    // executed action equals the authorized action (INVREG-F01). The executor
    // may edit its copy, as it could edit its input at baseline. The gateway
    // never reads the copy back: hashing, replay and the response body use only
    // the frozen snapshot, and the caller's object is not reachable from it.
    let upstreamAction: unknown;
    try {
      upstreamAction = mutableCopyOfSnapshot(action);
    } catch (err) {
      return deny(403, `INVALID_REQUEST_INPUT:${err instanceof Error ? err.message : String(err)}`);
    }

    let consumed: unknown;
    try {
      // INVREG-F02: `authorization` is the frozen snapshot that was verified,
      // so the consumed auth_id is the verified auth_id.
      consumed = await replayStore.consumeAuthId(authorization.auth_id, { expiry: authorization.expiry });
    } catch (err) {
      return deny(403, `REPLAY_STORE_UNAVAILABLE:${err instanceof Error ? err.message : String(err)}`);
    }
    // RR-01: ReplayStore resolves to a boolean. Only `true` is a successful
    // consume; `false` is a replay. Any other value is an indeterminate store
    // answer (verification-v1 §4.3) and fails closed. JavaScript truthiness is
    // never used: "false", 1, {} or "OK" must not open the gate. Whether the
    // store recorded the id before answering is unknown to the gateway.
    if (typeof consumed !== "boolean") return deny(403, "REPLAY_STORE_UNAVAILABLE:INVALID_RESULT");
    if (consumed !== true) return deny(403, "AUTH_REPLAY");

    try {
      // INVREG-F01: dispatch a copy of the verified snapshot - value-identical
      // to the object that was hashed and bound to the authorization - never
      // the caller's object.
      // GW-COMP-01: invoke with the deployer's options object as `this`, as at
      // baseline (`options.executeUpstream(...)`), so method-style executors
      // keep working. Only the receiver is restored. The function was captured
      // at construction, so reassigning `options.executeUpstream` later still
      // has no effect, and the gateway reads no property of `options` here.
      const upstream = await withTimeout(
        Reflect.apply(executeUpstream, upstreamReceiver, [
          upstreamAction,
          { [INTERNAL_EXECUTOR_TOKEN_HEADER]: internalExecutorToken },
        ]) as ReturnType<UpstreamExecutor>,
        timeoutMs
      );

      if (!isUpstreamSuccess(upstream)) {
        // H-1 (R3): EXECUTED is reserved for an upstream-confirmed success per
        // the configured success contract (default: integer 2xx). Any other
        // dispatched outcome - a 3xx, a 4xx, a 5xx, or a malformed response -
        // leaves the side effect in doubt and is INDETERMINATE, not a confirmed
        // non-execution. A 3xx is NOT a success: the upstream did not confirm
        // the effect, so it must not be reported as EXECUTED.
        // The request reached the upstream, so a side effect cannot be ruled
        // out: the outcome is INDETERMINATE and
        // `executed` is null, never a confirmed non-execution. The authorization
        // was granted and the gate did open, so `decision` stays "ALLOW"; the
        // transport failure is reported through `outcome`/`reason`, not by
        // retroactively turning the authorization verdict into a DENY.
        return {
          status: 502,
          upstreamCalled: true,
          body: {
            ok: false,
            decision: "ALLOW",
            outcome: "INDETERMINATE",
            executed: null,
            reason: "UPSTREAM_ERROR",
            auth_id: authorization.auth_id,
            intent_hash: intentHash,
            upstream_status: upstream?.status,
            upstream_error: upstream?.body,
          },
        };
      }

      return {
        status: 200,
        upstreamCalled: true,
        body: {
          ok: true,
          decision: "ALLOW",
          outcome: "EXECUTED",
          executed: true,
          auth_id: authorization.auth_id,
          intent_hash: intentHash,
          upstream_result: upstream.body,
        },
      };
    } catch (err) {
      // H-1: dispatch began (executeUpstream was invoked) and then the outcome
      // became unknown (timeout or a thrown transport error). The upstream may
      // already have committed the effect, so the outcome is INDETERMINATE and
      // `executed` is null, never false. `decision` stays "ALLOW": the gate was
      // opened on a valid authorization; it is the transport, not the
      // authorization, that is in doubt.
      if ((err as { code?: string })?.code === "UPSTREAM_TIMEOUT" || (err as Error)?.message === "UPSTREAM_TIMEOUT") {
        return {
          status: 504,
          upstreamCalled: true,
          body: { ok: false, decision: "ALLOW", outcome: "INDETERMINATE", executed: null, reason: "UPSTREAM_TIMEOUT", auth_id: authorization.auth_id, intent_hash: intentHash },
        };
      }
      return {
        status: 502,
        upstreamCalled: true,
        body: {
          ok: false,
          decision: "ALLOW",
          outcome: "INDETERMINATE",
          executed: null,
          reason: "UPSTREAM_ERROR",
          auth_id: authorization.auth_id,
          intent_hash: intentHash,
          upstream_error: err instanceof Error ? err.message : String(err),
        },
      };
    }
  };
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(data),
  });
  res.end(data);
}

export function createPepGatewayHttpServer(options: PepGatewayOptions): Server {
  const executeThroughPep = createPepGatewayExecutor(options);
  const maxBodyBytes = resolveMaxBodyBytes(options.maxBodyBytes);
  return createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/healthz") {
      return sendJson(res, 200, { ok: true, route: "gateway", status: "healthy" });
    }
    if (req.method !== "POST" || req.url !== "/execute") {
      return rejectAndClose(req, res, 404, { ok: false, error: "not found" });
    }

    // H-1 (R3): the parsing phase and the execution phase are isolated into two
    // separate try blocks. NOT_DISPATCHED can only be produced by the parsing
    // phase, which runs strictly before the request reaches the executor. This
    // is structural, not an argument about internal invariants: a SyntaxError
    // (or any error) raised during or after dispatch is caught by the execution
    // block below and can never be classified as NOT_DISPATCHED.
    let body: unknown;
    try {
      // PARSING PHASE - provably pre-dispatch. readBoundedJson consumes at most
      // maxBodyBytes of the request body and JSON.parses it; nothing here
      // reaches the executor.
      body = await readBoundedJson(req, maxBodyBytes);
    } catch (err) {
      if (err instanceof BodyTooLargeError) {
        // Oversized body: rejected in the parsing phase, never parsed, never dispatched.
        return rejectAndClose(req, res, 403, {
          ok: false,
          decision: "DENY",
          outcome: "NOT_DISPATCHED",
          executed: false,
          reason: "BODY_TOO_LARGE",
        });
      }
      if (err instanceof SyntaxError) {
        return sendJson(res, 403, {
          ok: false,
          decision: "DENY",
          outcome: "NOT_DISPATCHED",
          executed: false,
          reason: "INVALID_JSON",
        });
      }
      // A non-SyntaxError read failure (socket error, aborted body) is still
      // pre-dispatch: the executor was never invoked.
      return sendJson(res, 400, {
        ok: false,
        decision: "DENY",
        outcome: "NOT_DISPATCHED",
        executed: false,
        reason: "REQUEST_READ_ERROR",
      });
    }

    try {
      // EXECUTION PHASE. executeThroughPep returns a result for every outcome it
      // can classify; a throw escaping it here is an unexpected internal fault
      // AFTER the parsing phase. We cannot prove no dispatch occurred, and -
      // critically - a SyntaxError raised here (e.g. parsing an upstream
      // response) must NOT be mistaken for a malformed request. It fails safe to
      // INDETERMINATE (executed:null), never NOT_DISPATCHED.
      const result = await executeThroughPep(body);
      return sendJson(res, result.status, result.body);
    } catch {
      // H-1 (R3.1): an unexpected internal fault after the parsing phase. The
      // gateway did not obtain an authorization verdict and cannot determine
      // whether dispatch occurred, so the decision is explicitly UNKNOWN - not
      // DENY (which would retroactively refuse a possibly-granted request) and
      // not ALLOW. The uncertainty is carried honestly: UNKNOWN / INDETERMINATE
      // / executed:null. This is the fail-safe representation of "no decision
      // was reached", never a confident ALLOW or DENY.
      return sendJson(res, 500, {
        ok: false,
        decision: "UNKNOWN",
        outcome: "INDETERMINATE",
        executed: null,
        reason: "GATEWAY_ERROR",
      });
    }
  });
}

export function createHttpUpstreamExecutor(options: {
  hostname?: string;
  port: number;
  path: string;
  method?: "POST";
}): UpstreamExecutor {
  return (action, headers) =>
    new Promise((resolve, reject) => {
      const body = JSON.stringify((action as { params?: unknown })?.params ?? action ?? {});
      const req = httpRequest(
        {
          hostname: options.hostname ?? "localhost",
          port: options.port,
          path: options.path,
          method: options.method ?? "POST",
          headers: {
            "content-type": "application/json",
            "content-length": Buffer.byteLength(body),
            ...headers,
          },
        },
        (resp) => {
          let data = "";
          resp.on("data", (chunk) => (data += chunk));
          resp.on("end", () => {
            try {
              resolve({ status: resp.statusCode ?? 502, body: data ? JSON.parse(data) : {} });
            } catch (err) {
              reject(err);
            }
          });
        }
      );
      req.on("error", reject);
      req.write(body);
      req.end();
    });
}

export function createProtectedUpstreamHttpServer<T = unknown>(options: ProtectedUpstreamOptions<T> & {
  path?: string;
  /**
   * Maximum request body size in bytes. Default 1 MiB (1_048_576); allowed
   * range 1_024..67_108_864. A larger body (with a valid token) is answered
   * 413 `BODY_TOO_LARGE` without being parsed; `execute` is not called.
   */
  maxBodyBytes?: number;
}): Server {
  const path = options.path ?? "/execute";
  // Fail at construction instead of answering 500 to every request.
  requireText(options.expectedToken, "expectedToken");
  const maxBodyBytes = resolveMaxBodyBytes(options.maxBodyBytes);
  return createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/healthz") {
      return sendJson(res, 200, { ok: true, route: "upstream", status: "healthy" });
    }
    if (req.method !== "POST" || req.url !== path) {
      return rejectAndClose(req, res, 404, { ok: false, error: "not found" });
    }

    try {
      // M-3: authenticate from the headers before reading any body byte.
      if (!hasValidInternalExecutorToken(req.headers, options.expectedToken)) {
        return rejectAndClose(req, res, 403, { ok: false, executed: false, error: "missing or invalid internal executor token" });
      }
      const body = await readBoundedJson(req, maxBodyBytes);
      const result = await protectUpstreamExecution(body, req.headers, options);
      return sendJson(res, result.status, result.body);
    } catch (err) {
      if (err instanceof BodyTooLargeError) {
        return rejectAndClose(req, res, 413, { ok: false, executed: false, error: "BODY_TOO_LARGE" });
      }
      return sendJson(res, 500, {
        ok: false,
        executed: false,
        error: err instanceof SyntaxError ? "invalid JSON" : "upstream error",
      });
    }
  });
}
