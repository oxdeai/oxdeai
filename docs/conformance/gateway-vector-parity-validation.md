# #315 gateway/vector parity — profile-specific maintainer review

## Final disposition

**`getStateHash` is removed.** `packages/guard/src/gateway.ts`, its enforcement
tests and its README are restored to HEAD. There is no added live-state gateway
behavior. The confirmed Core signing-payload repair remains, as do the applicable
signature, issuer-policy authority, intent and zero-upstream regressions.

The previous report's diagnosis of "missing gateway state verification" was
incorrect for this A/B gateway surface. The conditional PEP paragraph did not
justify adding that capability to `createPepGatewayExecutor`. This report
supersedes that interpretation and its claim that all nine PEP cases pass
through the reusable gateway.

**S_freeze remains DEFERRED.** The signing defect is repaired, and seven PEP
cases have passing gateway assertions. Two snapshot-dependent corpus cases
still need a maintainer-approved profile/surface assignment; they are not
claimed as gateway conformance passes. The unrelated optional Python adapter
failure (#306) also remains. No normative specifications, authoritative vectors,
signatures, expected outcomes, or spec-claim evidence levels are changed.
Structural PASS is not semantic proof or whole-protocol conformance.

The initial 1-pass / 2-fail consumer baseline was reproduced before edits at
`a1dc9f6`; the maintainer independently reproduced it on clean main at `e33468c`,
before #314. #290/#314 do not own or fix those pre-existing failures. Their
implemented acceptance criteria retain their prior disposition.

## Normative basis (reviewed before changes)

- [State provider requirements §1.4](../spec/state-provider-requirements.md#14-profile-specific-applicability),
  lines 42–52: Profile C uses `OxDeAIGuard` and `computeStateHash`; A/B do not
  perform gateway live-state re-verification and have no `getState()` call.
  Signature integrity protects `state_hash`. State-dependent enforcement
  equivalent to C changes the deployment's applicability; it is not universal.
- [External provider profile §2.1.3](../spec/interoperability/external-provider-profile.md#213-state-binding-at-profile-a),
  lines 119–124: Profile A does not re-verify against live state.
- [External provider profile §2.2.4](../spec/interoperability/external-provider-profile.md#224-state-binding-at-profile-b),
  lines 175–179: Profile B likewise enforces signature integrity only.
- [External provider profile §2.3 and §2.3.2](../spec/interoperability/external-provider-profile.md#23-profile-c---full-semantic-state-verification),
  lines 255–280: Profile C explicitly requires `OxDeAIGuard`, **not
  `createPepGatewayExecutor`**, with `getState`, `setState`, provider-compatible
  `computeStateHash`, and atomic CAS before execution. The removed callback did
  not provide that surface or establish Profile C conformance.
- [PEP gateway §6.4–6.6](../spec/enforcement/pep-gateway-v1.md#64-verification-requirements),
  lines 119–134: signature, audience, expiry, issuer trust, intent, replay,
  upstream isolation and response semantics apply at this gateway surface.
- [PEP gateway §13](../spec/enforcement/pep-gateway-v1.md#13-state-binding),
  lines 306–311: state consistency checks are conditional on state binding being
  required. It does not override the profile-specific scope above.

## Per-vector profile/surface classification

The authoritative [PEP corpus](../spec/test-vectors/pep-vectors-v1.json) contains
**no explicit profile tags**. Neither the corpus nor #314's authority metadata
assigns these vectors to Profile C or configures a state-binding deployment of
`createPepGatewayExecutor`. Descriptions and `state_snapshot_ref` establish
fixture snapshot context, not a live-state provider, CAS, or profile assignment.

Accordingly, the classifications below describe each case's exercised surface,
not a newly asserted authoritative A/B/C label. A/B-common means the assertion
is applicable to their shared gateway enforcement surface; it does not claim
complete Profile A or B conformance. The corpus's nested signatures with flat
metadata and raw preimages also must not be taken as proof of every profile's
encoding requirements.

| PEP vector | Surface/profile disposition | What this consumer establishes |
| --- | --- | --- |
| `pep-allow-upstream-success` | A/B-common gateway success; fixture also supplies matching snapshot context | Valid signature, fixed authority, intent, replay and successful forwarding; no claim that the snapshot was read or matched. |
| `pep-auth-invalid-signature` | A/B-common signature rejection | 403 and zero upstream calls. |
| `pep-auth-intent-mismatch` | A/B-common intent binding | Valid signature with incompatible action is rejected before upstream. |
| `pep-upstream-error` | A/B-common upstream error handling; matching fixture snapshot is incidental to this assertion | 502 after one upstream call, never executed=true. |
| `pep-upstream-timeout` | A/B-common upstream timeout handling; matching fixture snapshot is incidental to this assertion | 504 after one upstream call, never executed=true. |
| `pep-sb-state-mismatch` | Conditional snapshot-binding expectation; **not an A/B live-state obligation**; C/deployment assignment unestablished | DEFERRED for this gateway consumer. The artifact is validly signed despite disagreeing with the separate fixture snapshot. A/B signature integrity does not require that comparison. |
| `pep-sb-missing-state-snapshot` | Conditional snapshot-binding expectation; **not an A/B live-state obligation**; C/deployment assignment unestablished | DEFERRED for this gateway consumer. Its valid authorization does not require an external snapshot at an A/B gateway. |
| `pep-auth-forged-valid-hashes` | A/B-common signature rejection; matching fixture hashes do not authenticate the artifact | 403 and zero upstream calls, regardless of snapshot context. |
| `pep-sb-missing-auth-state-hash` | A/B-common required artifact field rejection; distinct from missing external state | 403 and zero upstream calls; `state_hash` remains a required signed artifact field (§2.1.2). |

`pep-sb-state-mismatch` and `pep-sb-missing-state-snapshot` remain unchanged in the
authoritative corpus. They are explicitly listed in `PEP_GATEWAY_SCOPE`,
reported as DEFERRED in test diagnostics and named in authority metadata. A
coverage assertion requires an exact disposition for every corpus ID, so new
or renamed cases cannot silently disappear. This is an explicit supported
surface correction; it is not a declaration that those two vector expectations
are wrong, nor a passing result for them.

The unchanged `scripts/verify-pep-vectors.mjs` consumes all nine cases as a
standalone fixture evaluator, including static snapshot comparisons. Its success
is not evidence that this reusable gateway performs live-state verification.
Actual Profile C obligations belong to `OxDeAIGuard` and its existing Profile C
corpus/tests. Moving these two cases there without proving their profile and
provider/CAS assumptions would also overstate the evidence; no such migration
is made in this patch.

The authorization corpus helper separately combines strict Core verification
with `proposed_action` and static `state_snapshot` fixture-context checks. Its
renamed test and metadata now say so explicitly. That composite fixture result
is not presented as Core-only semantics or gateway live-state re-verification.

## Confirmed signing-payload defect (repair preserved)

> **Superseded (2026-11, encoding separation).** The corpus construction
> described below signed **without** the `OXDEAI_AUTH_V1\n` domain prefix while
> declaring `alg: "Ed25519"`; it verified only because Core fell back to the
> non-prefixed preimage for every alg. That fallback is removed: `"Ed25519"`
> now verifies only the domain-prefixed preimage with standard base64, and
> `"ed25519"` only the non-prefixed preimage with base64url
> (`authorization-v1.md` §5). The corpus was re-signed accordingly by
> `scripts/generate-authorization-v1-vectors.mjs`; `auth-key-1` and `sb-key-1`
> were rotated to seed-derived test keys (original private keys were not
> available), `portable-key-1` is unchanged. The SPKI bodies and preimage
> fingerprints below are historical. The top-level `alg`/`kid` payload repair
> itself remains in force.

`auth-allow-valid` uses `auth-key-1`, whose committed Ed25519 SPKI body is
`MCowBQYDK2VwAyEASyQL4zdR435kMZBiqIKq87JvPivVmhOsAnGWZV4HJDY=`.
The consumer imports that public key unchanged into a fixed `issuer-1` KeySet.
The corpus construction, also used by `scripts/verify-authorization-vectors.mjs`,
signs UTF-8 canonical JSON of the artifact with the entire nested `signature`
object removed, retaining top-level `alg` and `kid`, without a domain prefix.
The signature is standard base64. Independent Node Ed25519 verification of
these bytes succeeds with the committed key; verification of Core's old payload
fails with the same key and signature.

Core's nested branch in `authorizationSigningPayload` filters public fields but
omitted top-level `alg` and `kid`. It detects their presence to omit the nested
signature metadata, then also omits those two public fields. Both the existing
domain-prefixed check and raw check therefore receive the wrong payload.
The repair preserves those two fields in that existing branch, while retaining
filtering of engine-internal fields. It adds no signature-verification fallback.

For `auth-allow-valid`, the repaired canonical preimage restores
`"alg":"Ed25519",` at the start and `"kid":"auth-key-1",` between `issuer` and
`policy_id`. For `sb-auth-allow-valid`, the latter field is `"kid":"sb-key-1",`.
No fixture bytes change. SHA-256 fingerprints of the verification preimages:

| Vector | Old Core preimage | Committed signed preimage (now used by Core) |
| --- | --- | --- |
| `auth-allow-valid` | `f134632328b455bcf75820e6273d0ed4848b54b4a21ba7208111717f14c45c52` | `26965ffdbfe40a55cc349a2427694a6ef15de9088bc6fe8273bec07b664ae429` |
| `sb-auth-allow-valid` | `4afd63553c32a5614ce5d403278d0b4f1c14f77ef65f38a93181bb5c4585ce10` | `18ea3166b8c9c9991ed92ea11802d5d082e60984282f440ad2cd5588557c69bc` |

`pep-allow-upstream-success` references **`sb-auth-allow-valid`**, not
`auth-allow-valid`. Its public key is `sb-key-1`, SPKI body
`MCowBQYDK2VwAyEAEpLwEc8AC3nZVxl/gO8ibomzrH3FVO9dzugk/ku9ack=`.
The gateway hashes the request action, invokes strict Core verification, then
returns `deny(403, "AUTH_SIGNATURE_INVALID")` from the non-ok verification
branch. Independent verification returns only that violation with the fixed
clock, audience, keyset and authority configuration. Thus the two initial
failures share the payload defect. The request never reaches the intent
comparison, replay store, or upstream executor. Its configured issuer-policy
pair and audience are correct; they are not the source of this 403.

Git history identifies `15ceea7` (public-artifact filtering) as the change that
removed these fields: its parent copied all defined non-signature properties
in this branch. This predates #301's issuer-policy authority change. The repair
restores only public signing metadata, not the old copying of engine internals.

## Applicable regression coverage

- Independent Ed25519 checks over the two committed successful signatures;
  exact Core preimage equality with the corpus signing construction; the old
  preimage lacking alg/kid fails verification.
- Mutated signed alg, kid, audience, policy and state hash reject with
  `AUTH_SIGNATURE_INVALID` and `signatureVerified: false`.
- A valid nested signature with cross-pair issuer-policy configuration yields
  exactly `AUTH_ISSUER_POLICY_NOT_AUTHORIZED`, with no upstream call. #301's
  trusted complete pairs, mandatory authority configuration and exact matching
  are untouched; authority is never derived from artifact claims.
- All seven applicable PEP cases retain their authoritative expected outcomes
  and actual upstream-call assertions. Invalid signatures, forged-valid-hashes,
  intent mismatch and missing artifact state hash reject without forwarding.
- A separate A/B surface regression uses the two valid signed artifacts as
  inputs, without treating their conditional PEP vectors as passes: intact
  artifacts can execute without external snapshots, while tampering the signed
  state hash yields 403 and zero upstream calls. This preserves the distinction
  between signature integrity and live-state matching.
- Existing default gateway enforcement/authority tests continue to cover replay,
  audience, missing authority and other fail-closed cases. The five tests for
  the removed state-reader API are removed with that API.

## Final changed files (relative to HEAD)

| File | Reason |
| --- | --- |
| `packages/core/src/verification/verifyAuthorization.ts` | Preserve signed top-level alg/kid in the existing nested-signature branch. |
| `packages/guard/src/test/gateway.vectors.test.ts` | Preserve applicable regressions, correct fixture-context interpretation, explicitly classify all nine PEP IDs, test seven gateway cases and the A/B signature-only state boundary. |
| `packages/guard/package.json` | Run the supported, explicitly scoped consumer in default guard tests. |
| `docs/conformance/corpus-authority.json` | Record exact subset/deferred scope and distinguish standalone snapshot evaluation from live-state gateway evidence. |
| `docs/conformance/corpus-authority.md` | Match that consumer metadata. |
| `docs/conformance/corpus-authority-validation.md` | Preserve historical #290 results and link the separate follow-up disposition. |
| `docs/conformance/gateway-vector-parity-validation.md` | This corrected profile review and validation record. |

`packages/guard/src/gateway.ts`, `packages/guard/src/test/gateway.enforcement.test.ts`
and `packages/guard/README.md` now have no diff. No live-state option remains.

## Targeted validation after profile review

Final results are recorded below after execution. Two deferred PEP dispositions
are coverage limitations, not passing tests or evidence of full-corpus parity.

| Command | Final result |
| --- | --- |
| `node --import tsx --test packages/guard/src/test/gateway.vectors.test.ts` | 6 tests PASS, 0 FAIL; 7 PEP cases checked, 2 explicitly DEFERRED in diagnostics |
| `pnpm --filter @oxdeai/guard test` | 267 PASS, 0 FAIL |
| `pnpm typecheck` | PASS; protocol builds and workspace typechecks exit 0 |
| `pnpm verify:corpus-authority` | Structural PASS, 24 logical corpora and exact Profile-C projection |
| `pnpm test:corpus-authority` | 27 PASS, 0 FAIL |
| `pnpm verify:spec-claims` | Structural PASS, 30 records (27 normative claims and 3 contextual locks) |
| `pnpm test:spec-claims` | 43 PASS, 0 FAIL |
| `pnpm test:vectors:auth` | 12 fixture cases PASS |
| `pnpm test:vectors:pep` | 9 standalone fixture cases PASS; not 9 reusable-gateway passes |
| `git diff --check` | PASS |
| Diff check against HEAD for gateway implementation, enforcement tests, README, normative specs, vector trees and spec-claims registry | No changes |

Logs for this review are `/tmp/gateway-profile-review-*.log`. The six passing
consumer tests include a seven-case gateway subset test; the two deferred
cases are not represented as passing subtests. No test-runner skips or TODOs
are used to imply that full-corpus parity has been achieved.

Earlier in this uncommitted patch, Core (383 tests), Sift (196 tests), packaged
conformance (262 assertions and 17 tests) passed. They were not rerun for this
profile review; the Core repair is unchanged. The optional package Python
adapter was independently reproduced failing at import with `KeyError:
'intent_id'` at line 29 (#306), and remains untouched. No new Go, Rust or root
Python-vector execution is claimed. Full workspace `pnpm test` was not run.

The consumer reclassification and unresolved assignment of two snapshot cases
need maintainer review; S_freeze is not cleared by the green scoped test run.
No commits or pushes were made.
