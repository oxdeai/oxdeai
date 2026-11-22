# AuthorizationV1 vector traceability (SA-002 pre-promotion check)

Non-normative. Machine-readable form: `authorization-vector-traceability.json`.

Rule for promotion to normative status (`docs/spec/conformance/test-vectors-v1.md`
§3.1): the specification defines the behavior and vectors verify it. Every
expected value of a candidate vector MUST trace to a normative clause, and its
inputs MUST be consumable without the reference implementation.

Result at `72b7f2a`, for the five candidate corpora (40 vectors):

| Corpus | Vectors | Expectations traceable | Promotable as is | Blocker |
|---|---|---|---|---|
| `authorization-verification` | 10 | 10 | 0 | T-UNSIGNED |
| `clock-semantics-verification` | 5 | 5 | 0 | T-UNSIGNED |
| `authorization-signature-verification` | 12 | 12 | 0 | T-NOT-MATERIALIZED |
| `key-lifecycle-verification` | 10 | 10 | 0 | T-NOT-MATERIALIZED |
| `intent-hash` | 3 | 3 | 0 | T-PROJECTION-UNSPECIFIED |

Each expected code now traces to a registered code and step
(`authorization-v1.md` §10.1, `verification-v1.md` §5). None of the 40 vectors
can be promoted as it stands:

- **T-UNSIGNED (15):** unsigned artifacts verified without trust configuration.
  Their verdict depends on a non-strict mode that no normative text defines.
- **T-NOT-MATERIALIZED (22):** the vector names a mode, and the artifact is
  built at run time by `packages/conformance/src/validate.ts`.
- **T-PROJECTION-UNSPECIFIED (3):** the expected hash uses the PolicyEngine
  `INTENT_BINDING_FIELDS` projection. That projection is named in
  `external-provider-profile.md:119`, but its fields are not listed in any
  normative document. These vectors test issuer behavior, not verifier
  behavior.

Promotion therefore requires materializing signed, strict-mode artifacts
(T-UNSIGNED, T-NOT-MATERIALIZED) and either listing the projection fields
normatively or reclassifying `intent-hash` as an issuer corpus. The two
corpora already materialized and normative, `authorization-wire-encoding-v1.json`
and `authorization-precedence-v1.json`, meet the rule.
