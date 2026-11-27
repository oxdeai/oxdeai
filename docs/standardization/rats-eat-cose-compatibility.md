# OxDeAI Compatibility Analysis with RATS / EAT / COSE

**Document type:** Standardization positioning artifact
**Status:** Decided - per-surface compatibility decisions recorded (§3). Wire-format freeze of `ExecutionReceiptV1` remains separately gated (§5).
**Scope:** Compatibility decisions only - no protocol changes, no code changes, no conformance vector changes. Recording a decision here does not itself alter any artifact, schema, or vector.
**Gating relationship:** This document reaching a decided state makes `ExecutionReceiptV1` *eligible* to be frozen. Eligibility is not a freeze: the freeze has its own trigger (§5).
**Related documents:** `docs/standardization/aarm-alignment.md`, `docs/spec/core/canonicalization-v1.md`, `docs/spec/artifacts/authorization-v1.md`
**Decision date:** 2026-11-04. §2 status lines were re-verified on this date against authoritative IETF/RFC-Editor sources (exit criterion 3 satisfied); a final re-check is still required at freeze time, since draft and RFC status can move.

---

## 1. Purpose and Scope

This document records an explicit decision, per surface, on what OxDeAI **reuses**, **profiles**, **embeds**, or **keeps distinct** relative to the relevant IETF RATS, EAT, and COSE constructs.

COSE is not part of the RATS architecture. It is an IETF object-security standard used by EAT for its CBOR encoding, and it is in scope here for that reason rather than as a RATS component.

**What this document is:**

- A per-surface reuse/profile/embed/map-to decision record (§3)
- An explicit statement of the rationale where OxDeAI diverges
- A statement of what would reopen each decision
- The eligibility gate on `ExecutionReceiptV1` freeze

**What this document is not:**

- A conformance claim against any RFC
- A commitment to adopt EAT as a wire format
- A freeze of `ExecutionReceiptV1` (that is separately triggered - §5)
- A roadmap

An undocumented divergence reads as an oversight. A documented divergence reads as a design decision. This document converts the former into the latter.

### 1.1 Decision discipline: reflection vs freeze

Two things were deliberately separated so that one does not hold the other hostage:

- **The decision record (this document).** It does **not** wait for a receipt consumer. Nine of the eleven §3 rows are fully consumer-independent and are decided here and now; rows 9 and 10 are a **linked conditional pair** (row 9 holds the primary container choice, resolved by the freeze trigger; row 10, the wire encoding, follows directly from row 9 and carries no independent choice). Leaving the decided rows open would keep real divergences in an oversight-shaped state while costing the IETF-draft and OWASP authorization-to-outcome positioning the cheap interoperability vocabulary they can use immediately.
- **The wire-format freeze of `ExecutionReceiptV1`.** That genuinely should wait - freezing a format with no consumer encodes guesses (YAGNI). But a freeze is not a reflection. This document reaches *decided* without freezing anything.

The one row that is genuinely consumer-sensitive (signature container, §3 row 9) is **not** left open: it is recorded as a conditional decision with an explicit trigger, which satisfies exit criterion 2. This converts "decide under pressure when a consumer appears" into "the trigger is already written."

Circularity note: a consumer in the CWT/EAT ecosystem is more likely to appear if a concept mapping and a conditional profile already exist to target. No artifact → no consumer → no artifact. Publishing this decided record (non-binding, reversible, zero impact on the Stable artifacts) is therefore itself the action most likely to produce the consumer the freeze waits on.

---

## 2. External Reference Status

Status lines (type, stream, intended status) are recorded before any technical content, because several adjacent documents in this space have no formal standing. **Re-verified against authoritative IETF/RFC-Editor sources on 2026-11-04 (rfc-editor.org and an official I-D mirror; datatracker itself was not directly reachable, equivalent authoritative pages were used). All seven lines confirmed, with two precisions folded in below (RFC 9053 is additionally updated by RFC 9864; the draft-huang body declares Standards Track while its datatracker intended-status field is unset). Re-verify once more at freeze time.**

| Document | Type | Stream | Status |
| --- | --- | --- | --- |
| RFC 9334 - RATS Architecture | RFC, Informational | IETF | Published, January 2023 |
| RFC 9711 - Entity Attestation Token (EAT) | RFC, Proposed Standard | IETF | Published, April 2025 |
| RFC 10013 - EAT Measured Component | RFC, Proposed Standard | IETF (was `draft-ietf-rats-eat-measured-component`, rats WG) | Published, July 2026 |
| RFC 9052 - COSE: Structures and Process | RFC, Internet Standard (STD 96) | IETF | Published, August 2022; updated by RFC 9338 |
| RFC 9053 - COSE: Initial Algorithms | RFC, Informational | IETF | Published, August 2022; updated by RFC 9864 (fully-specified algorithm identifiers) |
| `draft-messous-eat-ai-01` | Internet-Draft, individual, Informational | None | Expired 2026-08-27; no formal standing |
| `draft-huang-rats-agentic-eat-cap-attest-00` | Internet-Draft, individual | None | Expired (published June 2025); datatracker intended-status unset though the draft body declares Standards Track; no formal standing |

Note on RFC 9334: IETF-stream and IESG-approved but **Informational**, not Standards Track. It supplies vocabulary and an architectural model, not normative wire requirements. Treat it accordingly.

Note on RFC 9052: carries STD 96 and is the strongest-status document in this table. It is also **updated by RFC 9338**, which must be read alongside it before the container decision (§3 row 9) is acted on in code.

Note on `draft-messous` expiry: recorded from the draft's own stated expiry date of 27 August 2026. Datatracker UI state may lag; re-verify at freeze time.

Neither agentic draft is a compliance target. Both are recorded here as prior art only. `draft-huang` references EAT as RFC 9248, whereas the published EAT specification is RFC 9711. This reinforces that the draft should be treated as non-authoritative prior art only.

Subject matter note: both agentic drafts attest **the agent** - model integrity, training provenance, declared capabilities. Neither specifies an execution receipt. The overlap with `ExecutionReceiptV1` is adjacent, not equivalent.

---

## 3. Comparison Matrix - decided

Each row is resolved with one of four outcomes:

- **REUSE** - adopt the external construct as-is
- **PROFILE** - adopt the construct, constrain it in an OxDeAI profile
- **EMBED** - carry the external construct inside an OxDeAI artifact
- **MAP TO** - keep the OxDeAI construct distinct, publish a concept mapping

| # | Question | OxDeAI | RATS / EAT / COSE | Outcome |
| --- | --- | --- | --- | --- |
| 1 | What is attested? | authorization decision / execution evidence | entity or component state | **MAP TO** |
| 2 | Who issues evidence? | authorization issuer / execution boundary | attester | **MAP TO** |
| 3 | Who establishes authority? | injected `trustedKeySets`, fail-closed if absent | verifier appraisal policy (RFC 9334) | **MAP TO** |
| 4 | Role vocabulary | issuer, PEP, relying party (informal) | Attester, Verifier, Relying Party, Endorser, Reference Value Provider | **MAP TO** (conditional functional mapping, documentation layer; no strict role identity) |
| 5 | Digest semantics | fixed SHA-256, bare lowercase hex | algorithm-explicit `[alg, val]` (RFC 10013 §4.2) | **MAP TO** (keep fixed; see §4.1) |
| 6 | Unknown profile | fail closed | fail closed for profiled fields (RFC 10013 §4.5) | **MAP TO** (concept alignment; no RFC 10013 conformance claim) |
| 7 | Independent verification | explicit objective; conformance vectors + Go/Python harnesses | core architectural assumption | **MAP TO** |
| 8 | Semantic effect of the artifact | authorization that may permit a future execution | Evidence / Attestation Results inform a relying party's own decision (RFC 9334 §4.2, §8.4) | **MAP TO** (receipt is *analogous* to Attestation Results in the Passport Model; architectural analogy, not a normative equivalence) |
| 9 | Signature container | domain-separated Ed25519 over a canonical OxDeAI payload | `COSE_Sign1` / `COSE_Sign` (RFC 9052 §4) | **PROFILE - conditional** (receipt only). *Decided now:* the conditional container choice (COSE_Sign1 if a CWT/EAT consumer imposes it, else JOSE). *Deferred to before freeze:* the exact JOSE or COSE profile parameters (signed bytes, serialization, crypto params, key ids, verification rules) |
| 10 | Wire encoding | canonical JSON, byte-exact | CBOR/CWT with COSE, or JSON/JWT with JOSE (RFC 9711) | **PROFILE** receipt only; **keep canonical JSON** for Authorization/Delegation |
| 11 | Execution authorization | core concern | not the primary abstraction | **MAP TO** (OxDeAI differentiator) |

### Per-row rationale and revision trigger

**Row 1 - What is attested? → MAP TO.** EAT attests the entity/agent; OxDeAI attests a *decision* and, for the receipt, an *execution outcome*. Distinct subjects. Publish a concept mapping; do not reshape OxDeAI claims into an EAT claims-set. *Revisit if* a future EAT profile defines an execution-outcome claim that an OxDeAI consumer must emit.

**Row 2 - Who issues evidence? → MAP TO.** For the receipt, the OxDeAI issuer or execution boundary is functionally analogous to a RATS Attester as a source of claims, without establishing RATS role equivalence (consistent with row 4); the nouns stay distinct with a published mapping. *Revisit if* row 9 resolves to COSE and a shared issuer identity model becomes necessary for interop.

**Row 3 - Who establishes authority? → MAP TO, no change.** Not a gap, but the correspondence must not be overstated: `trustedKeySets` supplies **configured cryptographic trust anchors** (it establishes authenticity of keys), **not** a RATS Appraisal Policy for Evidence. RATS places the appraisal policy with the Verifier and keeps it out of the evidence format; OxDeAI likewise keeps trust configuration injected and strict mode fails closed on its absence. The analogy is "trust is configured at the verifier, not carried in the artifact," not "trustedKeySets is an appraisal policy." *Revisit if* OxDeAI ever specifies trust-anchor distribution (it currently, correctly, does not).

**Row 4 - Role vocabulary → MAP TO (conditional functional mapping, documentation layer).** A cheap interoperability bridge, but the RATS roles are not strictly identical to OxDeAI's components, so this is a mapping, not a role identity. The correspondences hold only functionally and conditionally: an OxDeAI issuer maps to an Attester *for a receipt* (not for an authorization, which is downstream of appraisal); a PEP is functionally comparable to a Relying Party **only in its execution-control role**, because a PEP controls execution and does not appraise attestation evidence under an appraisal policy the way a RATS Verifier does; OxDeAI signature verification maps to the **cryptographic authenticity-checking function within** a RATS Verifier, **not to the complete Verifier role** (which also evaluates claims under an Appraisal Policy for Evidence, RFC 9334); `trustedKeySets` supplies configured cryptographic trust anchors, not a RATS appraisal policy, and maps to an Endorser or Reference Value Provider *only when* it actually supplies endorsement or reference values, which it need not. The mapping is documentation only, introduces no RFC conformance claim, and does **not** establish RATS role equivalence. *Revisit if* a mapped role is asserted as an identity anywhere, or if a component's RATS counterpart changes.

**Row 5 - Digest semantics → MAP TO, keep fixed.** This is the hash-agility question (§4.1), explicitly separable from the container decision (RFC 9052 §1 deliberately omits a digest structure, so adopting COSE does not force agility). Fixed SHA-256 is a stronger deterministic interoperability boundary; the `[alg, val]` form is recorded as *a candidate* migration vector (§4.1), not adopted now and not pre-approved for all future digests. *Revisit if* SHA-256 requires migration, at which point `[alg, val]` is one documented option to evaluate, not an automatic default.

**Row 6 - Unknown profile → MAP TO (concept alignment, no conformance claim).** OxDeAI's fail-closed treatment of unsupported protocol profiles is *conceptually aligned* with RFC 10013 §4.5, but the RFC's mandatory rejection rule is **specifically scoped** to measured components that carry profile-dependent authorities or profile-specific flags when the consumer does not know the applicable profile; it is **not** a general RFC requirement to reject every unknown claim. OxDeAI's behaviour (fail closed on unsupported profiles) is broader than, and not derived from, that scoped rule. This is deliberately MAP TO, not REUSE: OxDeAI does not formally reuse RFC 10013's profile mechanism, so `REUSE` would wrongly imply RFC 10013 conformance. The alignment is documentation only. *Revisit* never expected; a reversal would weaken fail-closed and is out of scope.

**Row 7 - Independent verification → MAP TO, no action.** Shared architectural assumption. Document that OxDeAI's conformance vectors plus the Go/Python harnesses are the concrete instance of the independence RATS assumes. *Revisit if* a cross-language divergence is ever found (the conformance suite exists to catch exactly this).

**Row 8 - Semantic effect → MAP TO (receipt ≈ Attestation Results, Passport Model).** This row prevents a category error. RFC 9334 §4.2 defines Evidence as claims produced for appraisal and Attestation Results as the Verifier's output; the authorization decision sits downstream of both (§3, §8.4). `AuthorizationV1` is therefore **not** EAT Evidence with renamed fields. But RFC 9334 §5.1 (Passport Model) - an Attester holding an Attestation Result and presenting it to multiple Relying Parties, each applying its own policy - is structurally close to a transferable receipt. The mapping is therefore: **`ExecutionReceiptV1` is *analogous* to Attestation Results in the Passport Model**, not Evidence. This is an architectural analogy, explicitly not a normative equivalence: a RATS Attestation Result is the output of a Verifier appraising evidence under a policy, whereas a receipt attests that an action occurred at a given boundary; absent a comparable appraisal step, the two objects are not semantically equivalent, and the receipt must not be labelled or consumed as a RATS Attestation Result. The analogy is used for positioning and vocabulary only. Further, a receipt must not overclaim: a signed response from the PEP is **not by itself** proof that the intended effect occurred. A valid authorization proves only that an action was permitted; a signed execution response proves only what its issuer can actually observe at its boundary. The receipt's claim must be scoped to that observable boundary, per the evidence layering in §4.3, and must not be read as confirmation of a downstream business effect it cannot witness. §5.1 also states standardization matters more for Attestation Results than for Evidence, which is why RATS vocabulary is worth taking seriously on this row even though the equivalence is only analogical. *Revisit if* the receipt's semantics move from "proof an execution occurred under a verified authorization" toward entity attestation (they should not), or if a genuine appraisal step is added (which would strengthen the analogy toward equivalence).

**Row 9 - Signature container → PROFILE, conditional (receipt only).** The load-bearing decision. RFC 9052 §10 explicitly expects a per-application profile, so `PROFILE` is a first-class outcome, not a compromise. COSE_Sign1's `Sig_structure` (§4.4) already begins with a context string (`"Signature1"`), giving structural domain separation analogous to OxDeAI's. COSE defines the signature *input structure* and imposes encoding restrictions on its **cryptographic structures** (`Sig_structure`, `Enc_structure`, `MAC_structure`, RFC 9052 §9); these requirements do **not**, by themselves, guarantee a canonical representation of the application payload. An OxDeAI COSE profile would therefore **separately** require deterministic encoding of the receipt payload (RFC 8949 §4.2.1) and define exact verification behaviour; the container alone does not supply payload determinism. **Conditional form, with a reasoned default toward JOSE.** The branch is: profile **COSE_Sign1 (CBOR)** only if a real consumer in the CWT/EAT ecosystem imposes it at freeze time; otherwise profile a **JOSE/JWS** container. JOSE is not a fallback here, it is the better engineering default for this specific protocol, for a falsifiable reason: OxDeAI's whole value proposition is deterministic, byte-exact artifacts reproduced identically across three runtimes (TypeScript, Go, Python). The point is tooling and discipline reuse, stated precisely: JWS signs an exact octet sequence and does **not** by itself impose OxDeAI's JSON canonicalization, so a JOSE receipt still has to pin its canonical serialization explicitly; what it saves is that this pinning reuses the canonical-JSON machinery the three runtimes already share and already keep byte-exact. A COSE/CBOR receipt, symmetrically, gets a determined signature structure (`Sig_structure`) from the container, but that does **not** make arbitrary CBOR content canonical either: it introduces a *second* deterministic-encoding regime (CBOR Core Deterministic Encoding, RFC 8949 §4.2.1) that every one of the three implementations must now also get byte-exact, taxing the cross-language byte-exactness that is the project's core differentiator. So the container choice does not decide determinism; the profile does (see the profile requirement below). The COSE branch should therefore require a genuinely compelling consumer (a CWT/EAT attestation pipeline that must ingest the receipt), not merely the presence of any consumer; a consumer indifferent to encoding resolves to JOSE. The two *Stable* artifacts (`AuthorizationV1`, `DelegationV1`) are **not** restructured into COSE under either branch - that would be a breaking change for zero security gain. **Trigger that resolves the branch:** first identified receipt consumer that imposes a wire-format requirement; absent one by freeze time, JOSE-profiled is the decided default, not an open question. Read RFC 9338 (which updates RFC 9052, countersignatures) before implementing the COSE branch.

**Decided now vs deferred to before freeze (this row is a positioning decision, not yet an executable cryptographic profile).** *Decided:* the conditional container choice above (COSE_Sign1 if a CWT/EAT consumer imposes it, else JOSE), that the Stable artifacts are untouched, and that the container does not by itself establish determinism. *Deferred, and MUST be fixed in the `ExecutionReceiptV1` profile before freeze, whichever container is chosen:* the exact signed bytes (the precise octet sequence over which the signature is computed), the serialization and its canonical form, the cryptographic parameters (algorithm, curve), the key identifiers (`kid` scheme and binding), and the verification rules (order of checks, failure modes, fail-closed behavior). Until those are fixed, this row is a decided positioning statement, not a frozen profile, and `ExecutionReceiptV1` stays `Planned`.

COSE and JOSE are **not interchangeable** at the artifact level: they differ in encoding (CBOR vs JSON/base64url), in signature structure, and in how protected headers, algorithms and key identifiers are represented. Switching between them, or interoperating across them, requires an explicit translation profile plus its own verification rules (which fields map to which, how the signed bytes are reconstructed on each side, how a verifier decides a cross-container receipt is valid). This document picks one container per the row 9 branch; it does **not** assume a receipt can be freely re-encoded between the two, and any dual-container support would be a separate, specified profile, not an implicit property.

**Row 10 - Wire encoding → PROFILE receipt only; keep canonical JSON for Auth/Delegation.** Follows from row 9. Dual encoding is intentional: the receipt lives in the attestation ecosystem (CBOR/CWT/COSE or JOSE), while the authorization artifacts stay in deterministic canonical JSON. If the COSE branch is taken, the receipt profile MUST pin CBOR Core Deterministic Encoding (RFC 8949 §4.2.1) to preserve byte-exactness. *Revisit with* row 9.

**Row 11 - Execution authorization → MAP TO (differentiator).** RATS deliberately stops at Attestation Results and leaves the authorization decision to the Relying Party. OxDeAI's core concern is exactly that downstream decision. State it as the differentiator, not as a gap to close. *Revisit* never expected.

---

## 4. Design Notes To Open Separately

These do not block the matrix and are not resolved by it.

### 4.1 Hash agility

> Is algorithm agility worth introducing into protocol artifacts, or does a fixed algorithm provide a stronger deterministic interoperability boundary until a versioned migration is explicitly required?

Decision recorded for the matrix's purposes (row 5): **keep fixed SHA-256**, converting implicit SHA-256 into an explicit normative choice; record `[alg, val]` (RFC 10013 §4.2) as *one possible* migration vector only. It is a design option to be evaluated if and when migration is actually required, **not** a form implicitly pre-approved for all future digests: adopting it later would itself be a deliberate, reviewed decision (which fields, which algorithms, downgrade protection), not an automatic consequence of this note. This question is **independent of the COSE rows** (RFC 9052 §1 omits a digest structure deliberately; a COSE container does not force agility on the hash fields). Open the full design note to document both directions; it does not gate the receipt.

### 4.2 Provenance model (issue #197)

`packages/guard/src/provenance.ts` carries two axes: how the premise was obtained (`declared | derived | read | attested`; only `declared`/`derived` implemented) and how the proposer's claim related to it (`ClaimProvenance = "absent" | "matched" | "conflict" | "unverified"`).

RFC 10013 §4.3.2 is useful prior art for separating an authority associated with a claim from the signer of the enclosing evidence; §4.5 requires the *profile*, not the format, to define what each authority entry means. Design implication for #197: when `attested` is implemented, it should carry an authority identifier distinct from the transport signer and name the profile under which that authority's statement is interpreted, reported as a structured object by the verifier rather than an enum member judged by it - otherwise the `signed != authoritative` invariant collapses. The decision belongs to #197, not to this document.

### 4.3 Execution evidence layering (scope of `ExecutionReceiptV1`)

The most important architectural constraint on the future receipt: a valid authorization does not prove an action was executed, and a signed execution response does not, on its own, prove the intended effect actually occurred. A receipt must state only what its issuer can verify, and at which layer. Four distinct evidence categories must be kept separate (they are categories, **not** a strict linear hierarchy: effect confirmation can arrive from an independent source without the consumer holding full proof of the initial dispatch, and the categories can be present in different combinations):

- **Authorization evidence** - the action was permitted (this is `AuthorizationV1` / `DelegationV1`, which exist today and are upstream of any receipt).
- **Boundary execution evidence** - what the PEP observed at its own boundary. Crucially, a PEP cannot always prove the protected system *received* the action; a successful local network write proves transmission, not remote processing. So this category admits finer observation states rather than a single "executed": `dispatch_attempted` (the PEP attempted the call), `request_transmitted` (transmission attested within transport limits), and `upstream_acknowledged` (an acknowledgement was observed). These refine the observation; they need not become separate top-level categories.
- **Outcome evidence** - the protected system returned an observable result. This requires the PEP to have observed that result, and distinguishes success from timeout, network error, or an async operation still pending.
- **Effect confirmation** - the business effect was confirmed by an authoritative source, *when such confirmation is available*. A PEP usually cannot witness this and must not assert it.

This layering matters precisely for the hard cases: network errors, timeouts, asynchronous operations, and partially-realized effects. A conformant `ExecutionReceiptV1` MUST label which category (and, within boundary execution, which observation state) it attests, MUST scope each claim to what is actually observable and verifiable at that boundary, and MUST NOT let a weaker observation (for example, `dispatch_attempted`) read as a stronger one (for example, `effect_confirmed`). The design goal is that a receipt never asserts more than its issuer can actually verify. The exact fields are deferred to the receipt profile (row 9), but this scoping is a decided architectural constraint now.

---

## 5. Exit Criteria and Freeze Trigger

**Decided state (met by this document):**

1. Every row in §3 carries `REUSE`, `PROFILE`, `EMBED`, or `MAP TO` with a written rationale. ✓
2. Each divergence states what would reopen the decision. ✓ (row 9 is recorded as a conditional decision with an explicit trigger, not left open)
3. §2 status lines re-verified at the decision date. **DONE (2026-11-04)** - all seven confirmed against authoritative IETF/RFC-Editor sources (see §2); two precisions folded in (RFC 9053 updated by RFC 9864; draft-huang datatracker intended-status unset vs Standards Track in the draft body). A final re-check is still required at freeze time, since draft/RFC status can move.

All three criteria are met: the matrix decisions stand and the status lines are verified. Criterion 3 is re-checked once more at freeze time as a matter of hygiene, not because it is currently outstanding.

**Definition - "real consumer" (used in the freeze trigger below):** any Relying Party that ingests and verifies an `ExecutionReceiptV1`, imposing a wire-format requirement OxDeAI does not itself control - not necessarily a paying customer. A first-party reference verifier does not count (it imposes no external constraint and is circular). What resolves the row 9 branch is the format requirement the consumer brings: a CWT/EAT attestation pipeline forces the COSE branch; a consumer indifferent to encoding points to the JOSE default.

**Freeze trigger (separate from the decided state above):** `ExecutionReceiptV1` may be frozen only when **all four** hold:

- (a) a real consumer (as defined above) exists - which resolves the row 9 branch (COSE vs JOSE); and
- (b) the row 9 deferred profile parameters are fixed (signed bytes, serialization, crypto params, key ids, verification rules); and
- (c) §2 status lines are re-verified at freeze time, and RFC 9338 is read alongside RFC 9052 if the COSE branch is taken; and
- (d) interoperability with the identified external consumer and byte-exact cross-implementation conformance have been demonstrated and recorded.

Criterion (d) makes explicit that the presence of a consumer is necessary but not sufficient: a consumer selects the container and justifies the freeze, but it does **not** by itself prove interoperability. Interoperability must be *demonstrated* against that consumer (the consumer verifies a real `ExecutionReceiptV1` produced by an OxDeAI implementation, and a cross-implementation test confirms byte-exact agreement), not inferred from the consumer merely existing or declaring support.

Until (a), (b), (c) and (d) hold, `ExecutionReceiptV1` remains `Planned`. The standalone verifier over `AuthorizationV1` and `DelegationV1` does **not** wait on this document or on the freeze.
