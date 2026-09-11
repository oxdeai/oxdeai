
# Trusted-Time Authorization - Core Profile v1

This document defines the normative **trusted-time** rules for Execution-Time
Authorization (ETA). It is a strict extension of `eta-core-v1.md`: it constrains
which clock an evaluator may rely on when a decision depends on time.

It defines the specification only. Verifier wiring (`verifyTrustedTime`), engine
integration, and conformance vectors are out of scope for this document and are
introduced by separate, independently reviewed changes.

---

## 1. Purpose

An `Intent` may carry an agent-supplied timestamp. An attacker who controls the
agent controls that value. Any time-dependent authorization decision that trusts
it — issuance, expiry, replay retention, or velocity accounting — is
attacker-influenced.

Trusted-time authorization removes that influence by separating two clocks and
restricting the untrusted one to a single, bounded purpose.

---

## 2. Two-Clock Trust Model

An evaluation reasons over two distinct time sources:

- **`intent.timestamp`** — an agent-supplied value on the `Intent` (unix
  seconds). It is an **untrusted freshness claim**. It is attacker-controllable
  and MUST NOT drive issuance, expiry, replay retention, or velocity accounting.
- **`evaluation_time`** — the **trusted PEP clock** read at the moment of
  evaluation (unix seconds). It is the sole authority for `issued_at`, expiry
  derivation, replay-window retention/eviction, and velocity windows.

`intent.timestamp` is admissible for exactly one purpose: a bounded **freshness**
check against `evaluation_time` (§6). Every other time-dependent decision MUST
key off `evaluation_time` only.

### 2.1 PEP Time-Source Requirements

`evaluation_time` is read from the PEP's trusted clock under the following
requirements:

- **Captured once.** `evaluation_time` MUST be sampled exactly once per
  evaluation and reused for every trusted-time-dependent decision within that
  evaluation. An evaluation MUST NOT re-read the clock mid-flight — this is the
  purity requirement of §3 stated for the clock specifically.
- **Monotonic non-decreasing.** Within a PEP, successive `evaluation_time`
  samples MUST NOT decrease. A wall-clock or NTP step-back MUST NOT move
  `evaluation_time` backward; an implementation SHOULD derive it from a monotonic
  source or clamp to the last observed value. A backward step MUST NOT be able to
  re-open a replay or velocity window that trusted time had already closed.
- **Multi-PEP authority.** A deployment with more than one PEP MUST either read
  from a single authoritative time source, or bound inter-PEP disagreement by a
  configured `maxInterPepSkewSeconds` (§5).
- **Effective replay-retention window.** Nonce retention is
  `[seen_at, seen_at + replayWindowSeconds)`, computed against `evaluation_time`.
  Under a bounded-skew multi-PEP deployment it MUST widen to
  `[seen_at, seen_at + replayWindowSeconds + maxInterPepSkewSeconds)`, so a nonce
  first seen at a leading PEP is not evicted early at a lagging PEP. This is the
  single normative definition of the retention window; §7 applies it.

---

## 3. Evaluation Contract

Trusted-time evaluation reuses the existing result types; it introduces **no
parallel result format**. A policy module returns a `PolicyResult`
(`packages/core/src/types/policy.ts`):

```
// ALLOW
{ decision: "ALLOW", reasons: [], stateDelta?: Partial<State> }
// DENY
{ decision: "DENY", reasons: ReasonCode[] }
```

- `decision` ∈ { `ALLOW`, `DENY` }, unchanged from `eta-core-v1`.
- On **`ALLOW`**, `reasons` MUST be empty; any trusted-time bookkeeping (nonce
  retention, velocity counters) is carried in the optional `stateDelta`.
- On **`DENY`**, `reasons` MUST carry one or more `ReasonCode` values (§8). No
  separate `status` field is introduced — the reason codes are the denial's
  machine-readable status.
- **`issued_at` and `expiry` are not fields of `PolicyResult`.** They are fields
  of the **Authorization** artifact (`packages/core/src/types/authorization.ts`),
  minted on `ALLOW` per `authorization-v1`. This profile only constrains how
  those artifact fields are *derived* from `evaluation_time` (§4); it does not
  add them to the module result. A `DENY` mints no Authorization artifact, so no
  `issued_at` / `expiry` exists for a denied intent.
- Evaluation MUST be a pure function of its inputs and MUST NOT read an ambient
  clock inside the evaluation; `evaluation_time` is the only time input, sampled
  once per evaluation (§2.1).

**Logical input model.** A trusted-time evaluation is normatively a pure function
of the logical inputs `(intent, state, evaluation_time)`. This is an *input
model*, not a mandated public API signature: the existing module signature is
`evaluate(intent, state)`, and how `evaluation_time` is threaded to the module
(an added parameter, a decision context, or a PEP-level pre-gate) is an
implementation concern deferred to a later, independently reviewed change (§9).
This profile fixes *what* the evaluation depends on, not *how* a signature
exposes it.

---

## 4. Consistency Invariants

A conformant trusted-time evaluation MUST hold all four invariants:

1. **Skew is freshness-only.** Skew tolerance applies only to the
   `intent.timestamp` freshness claim (§6); it MUST NOT widen expiry or any
   other window.
2. **Trusted issuance.** `issued_at` MUST be minted from trusted time:
   `issued_at = evaluation_time`.
3. **Trusted, bounded expiry.** `expiry` MUST be derived from trusted time and a
   validated fixed TTL: `expiry = evaluation_time + effective_ttl`.
4. **Enforcement stays zero-tolerance.** Trusted-time *mints* the expiry;
   downstream expiry verification remains zero-tolerance (`now < expiry`),
   unchanged from `eta-core-v1`. This profile does not relax enforcement.

---

## 5. Configuration

| field | meaning | requirement |
|---|---|---|
| `maxClockSkewSeconds` | max `intent.timestamp − evaluation_time` tolerated as fresh (future side) | REQUIRED |
| `maxIntentAgeSeconds` | max `evaluation_time − intent.timestamp` tolerated as fresh (stale side) | REQUIRED |
| `replayWindowSeconds` | nonce retention window, keyed to `evaluation_time` | REQUIRED |
| `maxTtlSeconds` | specification name for the resolved fixed issuance TTL; implementation mapping: `authorization_ttl_seconds ?? 60` | REQUIRED after resolution; implementation default 60 |
| `maxInterPepSkewSeconds` | bound on inter-PEP clock disagreement (§2.1) | profile-defined; REQUIRED for multi-PEP |
| `state.velocity.config.max_actions`, `state.velocity.config.window_seconds` | actions per trusted-time window | profile-defined |

- **REQUIRED** fields MUST be present after configuration resolution for a
  conformant trusted-time evaluation. The fixed authorization TTL is resolved
  through the explicit 60-second default defined below; this does not make a
  second TTL authority.
- **profile-defined** fields MAY be set or omitted by a profile, which MUST
  document its default when omitted. `maxInterPepSkewSeconds` is REQUIRED only
  for a deployment that runs more than one PEP without a single authoritative
  clock (§2.1).

### 5.1 Fixed Authorization TTL

The current profile has exactly one authorization TTL authority. It does not
support a caller-requested TTL, a policy-selected shorter TTL, or a
`min(requested_ttl, max_ttl)` selection rule.

Normatively:

```text
effective_ttl = configured fixed authorization TTL
issued_at = evaluation_time
expiry = evaluation_time + effective_ttl
```

For `PolicyEngine`, the implementation mapping is:

```text
effective_ttl =
  authorization_ttl_seconds, when explicitly configured
  60, when authorization_ttl_seconds is undefined
```

Where older trusted-time documents or vectors use `maxTtlSeconds`, that term
names this same resolved fixed TTL. It is not an independent runtime control.
Because there is no requested or policy-selected shorter TTL, the fixed
configured maximum is also the effective TTL.

The 60-second default applies only when `authorization_ttl_seconds` is
`undefined`. `null`, strings, NaN, infinities, fractional values, zero,
negative values, and unsafe integers are invalid configuration and MUST NOT be
coerced, clamped, or replaced by the default.

`evaluation_time + effective_ttl` MUST be a non-negative safe integer.
Overflow or any value outside the protocol numeric domain MUST refuse the
evaluation before authorization construction, canonicalization, or signing.
The same single `evaluation_time` sample MUST be used by freshness evaluation,
policy evaluation, `issued_at`, and expiry derivation. Timestamps MUST NOT be
mutated after signing.

The resulting authorization validity interval remains `[issued_at, expiry)`:
verification at `expiry - 1` succeeds when all other checks pass, while
verification at `expiry` fails with `AUTH_EXPIRED`.

This derivation changes signed field values whenever `evaluation_time` differs
from `intent.timestamp`. Consequently, canonical authorization bytes,
authorization hashes and `auth_id`, signatures, ALLOW/AUTH_EMITTED audit
timestamps, and EXECUTE concurrency expiry entries also change. Field names,
wire encodings, canonicalization rules, signing domains, algorithms, and intent
binding are unchanged, so no AuthorizationV1 schema-version increment is
required. Previously stored authorizations remain verifiable under their
original signed timestamps; mixed-version issuers may mint different artifacts
for the same logical intent until rollout is complete.

### 5.2 Numeric Domain

All time and duration quantities MUST lie in a well-defined numeric domain;
values outside it MUST cause the evaluation to fail closed, never a silent
coercion:

- `evaluation_time` and `intent.timestamp` MUST be finite, non-negative integers
  within the safe-integer range (unix seconds).
- Every duration field — `maxClockSkewSeconds`, `maxIntentAgeSeconds`,
  `replayWindowSeconds`, `maxTtlSeconds`, `maxInterPepSkewSeconds`,
  `state.velocity.config.window_seconds` — MUST be a finite non-negative
  integer; `state.velocity.config.max_actions` MUST be a finite non-negative integer count.
  `maxTtlSeconds` / `effective_ttl` MUST additionally be `≥ 1` (a zero TTL
  would mint `expiry == issued_at`).
- A malformed `intent.timestamp` (NaN, Infinity, non-integer, negative, or
  unsafe magnitude) MUST `DENY` with `STATE_INVALID` at the freshness gate (§6),
  minting no authorization. Malformed configuration MUST cause the implementation
  to refuse to evaluate (config-invalid) rather than proceed on a coerced value.

---

## 6. Freshness Semantics (Future and Stale)

Let `Δ = intent.timestamp − evaluation_time`. The freshness gate is evaluated
**before** replay and velocity (§7 ordering), and is the only gate that reads
`intent.timestamp`.

**Precondition.** A malformed `intent.timestamp` (NaN, Infinity, non-integer,
negative, or unsafe magnitude) fails closed with `STATE_INVALID` per §5.2
*before* `Δ` is computed; the freshness comparisons below assume a well-formed
`intent.timestamp`.

- **Future-dated.** `Δ > maxClockSkewSeconds` → `DENY`, no authorization minted.
- **Stale.** `−Δ > maxIntentAgeSeconds` → `DENY`, no authorization minted.
- **Fresh.** Otherwise the gate passes and evaluation proceeds. Issuance still
  derives entirely from `evaluation_time` (§4).

Because freshness precedes replay and velocity, an intent that would *also* fail
one of those gates MUST still deny with the freshness reason when it is
future-dated or stale — the freshness decision is reached first.

---

## 7. Replay, Velocity, and Tool-Call Windows (Trusted-Clock)

Replay, velocity, and tool-call windows MUST key off `evaluation_time` only.

- **Replay.** A nonce's retention/eviction MUST be computed against
  `evaluation_time`, over the **effective retention window defined in §2.1**,
  which is the single normative definition of that window; this section does not
  restate the formula. A future-dated `intent.timestamp` MUST NOT evict a nonce
  still inside it. Reuse of a retained nonce → `DENY`.
- **Velocity.** The action window is
  `[window_start, window_start + state.velocity.config.window_seconds)` in `evaluation_time`.
  `window_start` and every reset decision MUST derive exclusively from
  `evaluation_time`; `intent.timestamp`, authorization timestamps, metadata,
  ambient clocks, and fallback clocks MUST NOT affect them. The exact rule is:

  ```text
  while evaluation_time - window_start < window_seconds:
    the current window remains active

  when evaluation_time - window_start >= window_seconds:
    begin a new window with window_start = evaluation_time and count = 1
  ```

  The subtraction form avoids overflowing the protocol safe-integer domain.
  At the exact boundary a new window begins. If `evaluation_time <
  window_start`, evaluation MUST fail closed with `STATE_INVALID`; it MUST NOT
  reset, grant quota, decrease `window_start`, or substitute another clock.
  Exceeding `max_actions` within an active trusted window →
  `VELOCITY_EXCEEDED`. A denied action does not consume quota or mutate
  velocity state.

  Velocity configuration and persisted counter leaves MUST be validated
  without coercion. `window_seconds` MUST be a positive safe integer;
  `max_actions`, `window_start`, and `count` MUST be non-negative safe integers.
  Missing or malformed required containers and non-finite, fractional,
  negative, or unsafe values MUST fail closed with `STATE_INVALID`.

  > **Operational consequence (non-normative).** Fixed-window semantics may
  > permit bursts approaching `2 × max_actions` across adjacent window
  > boundaries. A configured limit of `N` actions per `T` seconds therefore
  > does not imply a strict bound of `N` actions over every rolling interval of
  > length `T`. Deployments requiring that property should use a
  > rolling/sliding-window control instead.

- **Tool-call windows.** Retention and new call timestamps MUST derive only
  from `evaluation_time`. `intent.timestamp` is non-authoritative and MUST NOT
  start, advance, reset, expire, or otherwise influence tool-call quota. A
  persisted call remains active while
  `evaluation_time - call.ts < tool_limits.window_seconds`; it expires when
  the difference is greater than or equal to the window. Thus the exact
  boundary expires the old call. If `evaluation_time < call.ts`, evaluation
  MUST fail closed with `STATE_INVALID`. Exhausting a valid aggregate or
  per-tool cap returns `TOOL_CALL_LIMIT_EXCEEDED`. A denial emits no tool-limit
  state delta and consumes no quota.

  Tool-window configuration and persisted events MUST be validated without
  coercion. Window seconds MUST be a positive safe integer; limits and event
  timestamps MUST be non-negative safe integers. Malformed containers,
  events, limits, unsafe values, or persisted counts inconsistent with their
  configured caps fail closed with `STATE_INVALID`.

The honest path MUST remain admissible: a distinct, unused nonce inside the
retention window, and a velocity window that legitimately reset because
*trusted* time advanced, are both `ALLOW` (subject to the rest of the policy).

**Evaluation order (normative):** freshness (§6) → replay → velocity.

This order is normative **among the trusted-time-dependent gates only**. It does
not mandate a complete global module order: other `eta-core-v1` gates
(kill-switch, allowlists, budget, auth) MAY be evaluated before, between, or
after these, provided that the relative freshness → replay → velocity order among
the trusted-time gates is preserved.

### 7.1 Persisted window state and deployment migration

Persisted window state here means retained policy state; its use does not prove
restart persistence or a replay backend's durability. Deterministic evaluation
assumes identical trusted inputs and available authoritative state, not merely
the same past security events. Required state that is unavailable or indeterminate
MUST NOT be treated as empty history permitting protected execution.

The nonce-retention rules in §2.1/§7 remain mandatory for their declared domain.
They do not replace the authorization/delegation entitlement store contract in
[verification §4.3](../verification/verification-v1.md#43-replay-store-contract-and-deployment-boundary),
or establish replica visibility, topology, persistence configuration, HA/SLA or
recovery guarantees. Those require deployment evidence.

The state schema is unchanged. Before the trusted-clock migration, existing
`window_start` values may have been derived from attacker-controlled
`intent.timestamp`; trusted and legacy values cannot be distinguished
structurally. Deployments SHOULD flush legacy velocity counters during rollout.
If flushing is operationally impossible, they MUST conservatively prevent
quota grants until each legacy window has expired against trusted time; a
legacy start ahead of `evaluation_time` fails closed rather than self-healing
through a backward reset. No state-version bump or automatic timestamp
conversion is defined.

In-memory state is affected whenever it survives an engine upgrade. External
state providers, including Redis-backed or database-backed deployments that
persist the full policy state, require the same operational treatment.
Mixed-version PEP deployments can disagree because older evaluators use
`intent.timestamp`; they SHOULD NOT share mutable velocity state during a
rolling upgrade. Upgrade evaluators together or drain/flush counters at the
version boundary.

The same migration rule applies to `tool_limits.calls`. Legacy call timestamps
may have been sourced from `intent.timestamp` and cannot be distinguished from
trusted timestamps in the unchanged state schema. Deployments SHOULD flush
legacy tool-call counters during rollout. Otherwise they MUST wait at least the
longest configured tool window plus the maximum allowed positive legacy clock
skew before granting quota from retained legacy state. Evaluators using old and
new clock semantics MUST NOT share mutable tool-limit state during a rolling
upgrade; upgrade them together or drain/flush the counters at the boundary.

Distributed PEPs MUST supply non-decreasing, sufficiently synchronized trusted
evaluation clocks. Clock rollback relative to a stored `window_start` fails
closed. Clock skew between PEPs can change when a reset becomes eligible even
though caller timestamps cannot. Deterministic evaluation performs no ambient
clock read; the supplied `evaluation_time` is its sole security-relevant
velocity clock.

State-provider compare-and-set, transactional update, serialization, or
equivalent conflict rejection remains REQUIRED for concurrent quota updates.
Trusted time prevents caller-controlled window movement but does not solve
lost-update races or make concurrent quota consumption atomic.

---

## 8. Reason-Code Mapping

Codes are mapped against the existing `ReasonCode` set in
`packages/core/src/types/policy.ts`. Reuse is preferred where the semantics
match; additions are **proposed and subject to review**.

| condition | code | status |
|---|---|---|
| retained-nonce reuse (§7) | `REPLAY_NONCE` | **reuse** — existing code |
| velocity window exceeded (§7) | `VELOCITY_EXCEEDED` | **reuse** — existing code |
| minted authorization later expired (downstream enforcement, §4) | `AUTH_EXPIRED` | **reuse** — existing code |
| intent future-dated beyond skew (§6) | `INTENT_FRESHNESS_FUTURE` | **proposed addition** |
| intent staler than `maxIntentAgeSeconds` (§6) | `INTENT_STALE` | **proposed addition** |

Notes for review:

- The enum has **no intent-freshness code today**. `AUTH_EXPIRED` is the
  expiry of an already-issued authorization (a different lifecycle stage), and
  `STATE_INVALID` is malformed state (a different meaning), so neither fits the
  freshness gate. The freshness direction genuinely needs new code(s).
- Open naming question: two self-describing codes (`INTENT_FRESHNESS_FUTURE`,
  `INTENT_STALE`, as above) versus one parametrized `INTENT_FRESHNESS_*` code
  carrying the direction. This profile lists two so each violation is
  self-describing, but the enum is the maintainers' to decide.
- `REPLAY_DETECTED` also exists, if a future revision wants to distinguish
  nonce-reuse from broader replay detection.

No code is final until the enum change is reviewed and merged separately.

---

## 9. Out of Scope

The following are explicitly outside the trusted-issuance rule and MUST NOT be
inferred from this profile:

- verifier-side future-`issued_at` policy changes
- SDK verifier-time changes
- replay-store clock changes
- velocity-window changes beyond the trusted-clock rules in §7
- key distribution, delegation, and orchestration (already out of scope per
  `eta-core-v1`)

---

## 10. Conformance

An implementation is trusted-time-conformant if:

- no time-dependent decision relies on `intent.timestamp` except the bounded
  freshness gate (§6);
- `issued_at` and `expiry` are minted from `evaluation_time` under the §4
  invariants;
- replay, velocity, and tool-call windows key off `evaluation_time` only (§7);
- the evaluation order is freshness → replay → tool-call window → velocity (§7);
- denials mint no authorization and carry a reason code (§3, §8).

Conformance MUST be verifiable via test vectors (introduced separately).

---
