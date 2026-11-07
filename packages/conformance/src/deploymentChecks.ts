// SPDX-License-Identifier: Apache-2.0
//
// Deployment checks: probes a deployer runs against THEIR deployment to test
// deployment assumptions that protocol conformance cannot establish (transport
// limits, replay-store behavior and sharing, configured trust, delegation signer
// authority, revocation, configuration immutability, bypass resistance).
//
// This is NOT protocol conformance. Its report has `kind: "deployment"`, a
// separate result, and is never merged into `validate` / `evidenceScope`
// reports.
//
// Evidence rules:
//   - PASS only on positive, attributable evidence of the expected behavior.
//   - FAIL only on a verified violation (an observed protected side effect, an
//     execution the deployment reported, a body processed past the declared
//     limit, replay state that is demonstrably not shared, a contradicted claim).
//   - NOT_TESTED otherwise: no probe, no prerequisite control, transport errors,
//     timeouts, service failures, probe exceptions, unattributed responses,
//     unattested topology. NOT_TESTED is never counted as PASS.

export const DEPLOYMENT_CHECKS_VERSION = 1;

export type DeploymentOutcome = "PASS" | "FAIL" | "NOT_TESTED";

export type DeploymentCheckId =
  | "DEP-CONTROL"
  | "DEP-REQUEST-SIZE"
  | "DEP-REPLAY-RESULT"
  | "DEP-REPLAY-SHARED"
  | "DEP-REPLAY-ERROR"
  | "DEP-AUTHORITY"
  | "DEP-DELEGATION-SIGNER"
  | "DEP-REVOCATION"
  | "DEP-CONFIG-IMMUTABLE"
  | "DEP-BYPASS";

export const DEPLOYMENT_CHECK_IDS: readonly DeploymentCheckId[] = [
  "DEP-CONTROL",
  "DEP-REQUEST-SIZE",
  "DEP-REPLAY-RESULT",
  "DEP-REPLAY-SHARED",
  "DEP-REPLAY-ERROR",
  "DEP-AUTHORITY",
  "DEP-DELEGATION-SIGNER",
  "DEP-REVOCATION",
  "DEP-CONFIG-IMMUTABLE",
  "DEP-BYPASS",
];

// ── Probe observation types ──────────────────────────────────────────────────

/** What a single HTTP-level probe observed. */
export type ProbeResponse =
  | {
      kind: "response";
      status: number;
      /**
       * For DEP-REQUEST-SIZE only: identifier of the declared limit that
       * produced this rejection (for example "ingress:client_max_body_size"),
       * established by the probe (a proxy marker header, a dedicated status
       * page). Without it a 413 is not attributed and the check is NOT_TESTED.
       */
      attributedTo?: string;
    }
  | { kind: "transport_error"; code?: string }
  | { kind: "timeout" };

/** Result of one attempt that the deployment is expected to refuse. */
export type RefusalObservation = {
  /**
   * How the attempt ended, as classified by the probe:
   *   refused         - the enforcement point answered with a refusal (4xx or a thrown denial);
   *   executed        - the deployment reported execution;
   *   service_error   - 5xx or another service failure, not an enforcement decision;
   *   transport_error - connection refused/reset, DNS, TLS;
   *   timeout         - no answer in time.
   */
  outcome: "refused" | "executed" | "service_error" | "transport_error" | "timeout";
  /** Protected side effects observed by the deployer's own instrumentation for this attempt. */
  sideEffects: number;
  /** HTTP status, when there was one. */
  status?: number;
  /** Machine-readable refusal code (for example "AUTH_ISSUER_POLICY_NOT_AUTHORIZED"). */
  reason?: string;
};
export type RefusalProbe = () => Promise<RefusalObservation>;

/** One legitimate request through the boundary; `executed` counts protected effects. */
export type ControlProbe = () => Promise<{ executed: number }>;

/** Minimal replay-store shape: the `@oxdeai/guard` `ReplayStore` contract. */
export type ReplayStoreHandle = {
  consumeAuthId(id: string, expiresAt?: number): Promise<unknown>;
};

/**
 * Deployer-attested topology of the two replay handles. The checker cannot
 * verify it; it records it, checks it for internal consistency, and refuses to
 * report PASS without it.
 */
export type ReplayTopology = {
  /**
   * independent-processes: handles live in separate OS processes or hosts;
   * independent-connections: separate client connections from one process;
   * in-process: both handles share process memory (shows nothing about instances).
   */
  kind: "independent-processes" | "independent-connections" | "in-process";
  instanceIds: readonly [string, string];
  connectionIds: readonly [string, string];
  /** Where the topology evidence is recorded (a run log, a deployment manifest). */
  evidenceRef: string;
};

export type DeploymentProbes = {
  /**
   * Positive control: one legitimate request through the enforcement boundary
   * to the protected resource. Run before the refusal checks and again after
   * each refusal probe; a refusal is only credited when the deployment still
   * executes a legitimate request afterwards. Each run performs one real
   * protected effect.
   */
  control?: ControlProbe;
  requestSize?: {
    /** The deployment's declared maximum accepted body size, in bytes. */
    limitBytes: number;
    send(bytes: number): Promise<ProbeResponse>;
    /** Liveness of the service behind the limit, checked before and after the oversize probe. */
    health(): Promise<boolean>;
  };
  /**
   * Handles to the deployed replay store. Ids are generated from `idPrefix`
   * and consumed for real, so use a prefix reserved for checks.
   */
  replay?: {
    handles: readonly ReplayStoreHandle[];
    idPrefix: string;
    /** Required for DEP-REPLAY-SHARED to PASS. */
    topology?: ReplayTopology;
    /** Parallel consumers in the atomicity probe (default 8). */
    concurrency?: number;
    expiresAt?: number;
  };
  /** Valid request while the replay store is made to fail (throw, reject or answer a non-boolean). */
  replayError?: RefusalProbe;
  /** Validly signed authorization from an issuer/policy the deployment must not trust. */
  authority?: RefusalProbe;
  /**
   * Delegation signer authority (DIV-01): a DelegationV1 signed by a key that
   * is trusted for its `issuer`, whose `(delegator, issuer)` pair is NOT listed
   * in the deployment's signer-authority configuration
   * (`trustedDelegationAuthorities` in core, `trustedDelegationSigners` in the
   * guard). Requires `delegationControl`.
   */
  delegationSigner?: RefusalProbe;
  /** Positive control for the delegation path: an authorized delegation executes exactly once. */
  delegationControl?: ControlProbe;
  /** Request using a revoked key or delegation, where revocation is required. */
  revocation?: RefusalProbe;
  /** Request that only passes if configuration mutated after construction were honored. */
  configImmutability?: RefusalProbe;
  /** Direct call to the protected resource, skipping the enforcement boundary. */
  bypass?: RefusalProbe;
};

/** Report provenance. Identifiers only: never credentials, tokens or payloads. */
export type DeploymentRunContext = {
  /** Stable identifier of the deployment under test (for example "payments-pep/staging"). */
  deploymentId: string;
  /** Identifier of the probe set and its version (for example "depcheck@3"). */
  probeSetId: string;
  /** Optional per-check probe identifiers and evidence references (log ids, ticket ids). */
  probes?: Partial<Record<DeploymentCheckId, { probeId: string; evidenceRef?: string }>>;
  /** Clock override, for reproducible tests. */
  now?: () => Date;
};

export type DeploymentCheckResult = {
  id: DeploymentCheckId;
  outcome: DeploymentOutcome;
  detail: string;
  probeId?: string;
  evidenceRef?: string;
};

export type DeploymentReport = {
  version: typeof DEPLOYMENT_CHECKS_VERSION;
  kind: "deployment";
  result: "PASS" | "FAIL" | "INCOMPLETE";
  provenance: {
    deploymentId: string;
    probeSetId: string;
    executedAt: string;
    complete: boolean;
    replayTopology?: { kind: ReplayTopology["kind"]; evidenceRef: string };
  };
  checks: DeploymentCheckResult[];
  limitations: string[];
};

const LIMITATIONS = [
  "Deployment checks are not protocol conformance and do not change any conformance result.",
  "Each check observes only the probe the deployer supplied, at the time it ran.",
  "Side-effect counts, topology and size-limit attribution come from the deployer; the checker records them but cannot verify them.",
  "A PASS does not show that no other path, configuration or time window is affected.",
  "NOT_TESTED means no evidence; it is never counted as PASS.",
];

// ── Helpers ───────────────────────────────────────────────────────────────────

const IDENTIFIER = /^[A-Za-z0-9._:/@#+=-]{1,128}$/;
const REASON = /^[A-Za-z0-9_.:-]{1,64}$/;

/** Identifiers only. Anything else (spaces, newlines, long blobs) is not echoed. */
function ident(v: unknown): string | undefined {
  return typeof v === "string" && IDENTIFIER.test(v) ? v : undefined;
}
function safeReason(v: unknown): string {
  return typeof v === "string" && REASON.test(v) ? v : "[unreported]";
}
function describe(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "string") return REASON.test(v) ? `string "${v}"` : "string";
  if (typeof v === "boolean" || typeof v === "number" || typeof v === "bigint") return String(v);
  return typeof v;
}
const ok = (id: DeploymentCheckId, detail: string): DeploymentCheckResult => ({ id, outcome: "PASS", detail });
const fail = (id: DeploymentCheckId, detail: string): DeploymentCheckResult => ({ id, outcome: "FAIL", detail });
const notTested = (id: DeploymentCheckId, detail: string): DeploymentCheckResult => ({ id, outcome: "NOT_TESTED", detail });

async function guarded(id: DeploymentCheckId, fn: () => Promise<DeploymentCheckResult>): Promise<DeploymentCheckResult> {
  try {
    return await fn();
  } catch {
    // A probe that throws produced no evidence either way. The exception text is
    // not echoed: it may carry connection strings or payloads.
    return notTested(id, "probe raised an error; no evidence");
  }
}

async function controlExecutedOnce(control: ControlProbe | undefined): Promise<boolean> {
  if (!control) return false;
  try {
    const r = await control();
    return r?.executed === 1;
  } catch {
    return false;
  }
}

function validObservation(o: unknown): o is RefusalObservation {
  const x = o as RefusalObservation;
  return !!x && typeof x === "object"
    && ["refused", "executed", "service_error", "transport_error", "timeout"].includes(x.outcome)
    && Number.isInteger(x.sideEffects) && x.sideEffects >= 0
    && (x.status === undefined || (Number.isInteger(x.status) && x.status >= 100 && x.status <= 599));
}

// ── Checks ────────────────────────────────────────────────────────────────────

async function refusalCheck(
  id: DeploymentCheckId,
  probe: RefusalProbe | undefined,
  control: ControlProbe | undefined,
  controlName: string,
  preControlPassed: boolean,
): Promise<DeploymentCheckResult> {
  if (!probe) return notTested(id, "no probe supplied");
  if (!control || !preControlPassed) return notTested(id, `${controlName} missing or failed before the probe; a refusal would not be informative`);
  return guarded(id, async () => {
    const o = await probe();
    if (!validObservation(o)) return notTested(id, "probe returned a malformed observation");
    // Verified violations first: an observed effect fails whatever the deployment said.
    if (o.sideEffects > 0) return fail(id, `protected side effects observed: ${o.sideEffects}`);
    if (o.outcome === "executed") return fail(id, "the deployment reported execution of a request it must refuse");
    if (o.outcome === "transport_error" || o.outcome === "timeout") {
      return notTested(id, `${o.outcome.replace("_", " ")}; not an enforcement decision`);
    }
    if (o.outcome === "service_error" || (o.status !== undefined && o.status >= 500)) {
      return notTested(id, `service failure${o.status !== undefined ? ` (status ${o.status})` : ""}; not an enforcement decision`);
    }
    // Only an explicit enforcement refusal can receive PASS.
    // A successful HTTP response is not evidence of denial.
    if (
      o.outcome !== "refused" ||
      (o.status !== undefined && (o.status < 400 || o.status >= 500))
    ) {
      return notTested(id, "probe did not establish a valid enforcement refusal");
    }
    // A refusal is credited only if the deployment still serves legitimate traffic.
    if (!(await controlExecutedOnce(control))) {
      return notTested(id, `${controlName} did not execute exactly once after the probe; the refusal cannot be attributed to enforcement`);
    }
    return ok(id, `refused${o.status !== undefined ? ` (status ${o.status})` : ""}, reason ${safeReason(o.reason)}; no protected side effect; ${controlName} executed after the probe`);
  });
}

async function requestSizeCheck(p: DeploymentProbes["requestSize"]): Promise<DeploymentCheckResult> {
  const id: DeploymentCheckId = "DEP-REQUEST-SIZE";
  if (!p) return notTested(id, "no request-size probe supplied");
  if (!Number.isInteger(p.limitBytes) || p.limitBytes <= 0) return notTested(id, "limitBytes must be a positive integer");
  return guarded(id, async () => {
    if ((await p.health()) !== true) return notTested(id, "service not healthy before the probe");

    // Control: a body at the declared limit must reach the service and not be size-rejected.
    const atLimit = await p.send(p.limitBytes);
    if (atLimit.kind !== "response") return notTested(id, `at-limit control: ${atLimit.kind.replace("_", " ")}`);
    if (atLimit.status >= 500) return notTested(id, `at-limit control: service failure (status ${atLimit.status})`);
    if (atLimit.status === 413) return fail(id, `a body of exactly limitBytes (${p.limitBytes}) was size-rejected: the effective limit is lower than declared`);

    const over = await p.send(p.limitBytes + 1);
    const healthyAfter = (await p.health()) === true;
    if (!healthyAfter) return fail(id, "service unhealthy after the oversized request");

    if (over.kind !== "response") {
      return notTested(id, `oversized request: ${over.kind.replace("_", " ")}; not an attributable size-limit rejection`);
    }
    if (over.status === 413) {
      const by = ident(over.attributedTo);
      return by
        ? ok(id, `body of ${p.limitBytes + 1} bytes rejected with 413, attributed to ${by}; service healthy afterwards`)
        : notTested(id, "413 observed but not attributed to a declared limit");
    }
    if (over.status >= 500) return notTested(id, `oversized request: service failure (status ${over.status}); not an attributable size-limit rejection`);
    return fail(id, `body of ${p.limitBytes + 1} bytes was processed past the declared limit (status ${over.status})`);
  });
}

async function replayResultCheck(p: DeploymentProbes["replay"]): Promise<DeploymentCheckResult> {
  const id: DeploymentCheckId = "DEP-REPLAY-RESULT";
  if (!p || p.handles.length < 1) return notTested(id, "no replay-store handle supplied");
  return guarded(id, async () => {
    const key = `${p.idPrefix}result-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const first = await p.handles[0].consumeAuthId(key, p.expiresAt);
    const second = await p.handles[0].consumeAuthId(key, p.expiresAt);
    if (first !== true) return fail(id, `first consume must resolve the boolean true, got ${describe(first)}`);
    if (second !== false) return fail(id, `second consume must resolve the boolean false, got ${describe(second)}`);
    return ok(id, "first consume true, second consume false (strict booleans)");
  });
}

function topologyProblem(t: ReplayTopology | undefined, a: ReplayStoreHandle, b: ReplayStoreHandle): { contradiction?: string; missing?: string } {
  const sameObject = a === b || a.consumeAuthId === b.consumeAuthId;
  if (!t) return { missing: sameObject ? "both handles are the same object (in-process only)" : "no topology evidence supplied" };
  if (!["independent-processes", "independent-connections", "in-process"].includes(t.kind)) return { missing: "unknown topology kind" };
  const ids = [t.instanceIds?.[0], t.instanceIds?.[1], t.connectionIds?.[0], t.connectionIds?.[1]].map(ident);
  if (ids.some((x) => x === undefined) || !ident(t.evidenceRef)) return { missing: "topology evidence incomplete (instance ids, connection ids and evidenceRef are required identifiers)" };
  if (t.kind === "in-process") return { missing: "topology is in-process; this shows nothing about separate instances" };
  if (sameObject) return { contradiction: `topology claims ${t.kind}, but both handles are the same object` };
  if (ids[2] === ids[3]) return { contradiction: `topology claims ${t.kind}, but both handles report the same connection id` };
  if (t.kind === "independent-processes" && ids[0] === ids[1]) return { contradiction: "topology claims independent processes, but both handles report the same instance id" };
  return {};
}

async function replaySharedCheck(p: DeploymentProbes["replay"]): Promise<DeploymentCheckResult> {
  const id: DeploymentCheckId = "DEP-REPLAY-SHARED";
  if (!p || p.handles.length < 2) return notTested(id, "two handles to the same backend are required");
  const [a, b] = p.handles;
  const topo = topologyProblem(p.topology, a, b);
  if (topo.contradiction) return fail(id, topo.contradiction);
  return guarded(id, async () => {
    const key = `${p.idPrefix}shared-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const onA = await a.consumeAuthId(key, p.expiresAt);
    const onB = await b.consumeAuthId(key, p.expiresAt);
    // Demonstrably unshared state is a violation whatever the topology evidence says.
    if (onA === true && onB === true) return fail(id, "the same id was consumed successfully through both handles: replay state is not shared");
    if (onA !== true || onB !== false) {
      return fail(id, `consume through handle A then B must give true then false, got ${describe(onA)} then ${describe(onB)}`);
    }
    const n = Math.max(2, p.concurrency ?? 8);
    const race = `${p.idPrefix}race-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const answers = await Promise.all(Array.from({ length: n }, (_, i) => p.handles[i % p.handles.length].consumeAuthId(race, p.expiresAt)));
    const wins = answers.filter((x) => x === true).length;
    const losses = answers.filter((x) => x === false).length;
    if (wins !== 1 || losses !== n - 1) {
      return fail(id, `${n} concurrent consumes of one id must give exactly one true and ${n - 1} false, got ${wins} true, ${losses} false`);
    }
    if (topo.missing) return notTested(id, `state behaves as shared, but ${topo.missing}`);
    return ok(id, `shared across ${p.topology!.kind} (evidence ${p.topology!.evidenceRef}); ${n} concurrent consumes produced exactly one true`);
  });
}

// ── Runner ────────────────────────────────────────────────────────────────────

/**
 * Run the deployment checks against the probes a deployer supplies.
 * Probes run sequentially, in the order of DEPLOYMENT_CHECK_IDS.
 */
export async function runDeploymentChecks(probes: DeploymentProbes, context?: DeploymentRunContext): Promise<DeploymentReport> {
  const executedAt = (context?.now ?? (() => new Date()))().toISOString();
  const deploymentId = ident(context?.deploymentId);
  const probeSetId = ident(context?.probeSetId);
  const checks: DeploymentCheckResult[] = [];

  let controlPassed = false;
  if (!probes.control) {
    checks.push(notTested("DEP-CONTROL", "no positive control supplied"));
  } else {
    const control = await guarded("DEP-CONTROL", async () => {
      const r = await probes.control!();
      return r?.executed === 1
        ? ok("DEP-CONTROL", "legitimate request executed exactly once")
        : fail("DEP-CONTROL", `legitimate request must execute exactly once, executed: ${describe(r?.executed)}`);
    });
    controlPassed = control.outcome === "PASS";
    checks.push(control);
  }
  const delegationControlPassed = await controlExecutedOnce(probes.delegationControl);

  checks.push(await requestSizeCheck(probes.requestSize));
  checks.push(await replayResultCheck(probes.replay));
  checks.push(await replaySharedCheck(probes.replay));
  checks.push(await refusalCheck("DEP-REPLAY-ERROR", probes.replayError, probes.control, "positive control", controlPassed));
  checks.push(await refusalCheck("DEP-AUTHORITY", probes.authority, probes.control, "positive control", controlPassed));
  checks.push(await refusalCheck("DEP-DELEGATION-SIGNER", probes.delegationSigner, probes.delegationControl, "delegation positive control", delegationControlPassed));
  checks.push(await refusalCheck("DEP-REVOCATION", probes.revocation, probes.control, "positive control", controlPassed));
  checks.push(await refusalCheck("DEP-CONFIG-IMMUTABLE", probes.configImmutability, probes.control, "positive control", controlPassed));
  checks.push(await refusalCheck("DEP-BYPASS", probes.bypass, probes.control, "positive control", controlPassed));

  for (const c of checks) {
    const meta = context?.probes?.[c.id];
    const probeId = ident(meta?.probeId);
    const evidenceRef = ident(meta?.evidenceRef);
    if (probeId) c.probeId = probeId;
    if (evidenceRef) c.evidenceRef = evidenceRef;
  }

  const complete = deploymentId !== undefined && probeSetId !== undefined;
  const result = checks.some((c) => c.outcome === "FAIL")
    ? "FAIL"
    : complete && checks.every((c) => c.outcome === "PASS")
      ? "PASS"
      : "INCOMPLETE";
  const topo = probes.replay?.topology;
  const topoKind = topo && ["independent-processes", "independent-connections", "in-process"].includes(topo.kind) ? topo.kind : undefined;
  const topoRef = ident(topo?.evidenceRef);
  return {
    version: DEPLOYMENT_CHECKS_VERSION,
    kind: "deployment",
    result,
    provenance: {
      deploymentId: deploymentId ?? "UNSPECIFIED",
      probeSetId: probeSetId ?? "UNSPECIFIED",
      executedAt,
      complete,
      ...(topoKind && topoRef ? { replayTopology: { kind: topoKind, evidenceRef: topoRef } } : {}),
    },
    checks,
    limitations: [
      ...LIMITATIONS,
      ...(complete ? [] : ["Provenance is incomplete (deploymentId and probeSetId are required identifiers); the aggregate cannot be PASS."]),
    ],
  };
}
