# Contributing to OxDeAI

**Status:** Working contribution guide for OxDeAI v1

**Last updated:** 2026-09-04

Thank you for considering contributing to OxDeAI.

OxDeAI is an open-source protocol for execution-time authorization of AI agents. The project values deterministic behavior, fail-closed enforcement, cross-language verifiability, conservative claims, and minimal changes that strengthen the protocol boundary.

OxDeAI is:

- an execution authorization boundary
- a protocol and reference implementation for deterministic pre-execution authorization
- a conformance-driven project

OxDeAI is not:

- an agent framework
- an AI runtime
- a policy-authoring product
- a model-alignment system
- a sandboxing system

Core invariant:

```text
No valid authorization → no execution path
````

---

## 1. Setup

From the repository root:

```bash
pnpm install
pnpm build
pnpm test
```

Recommended full validation before opening a pull request:

```bash
pnpm typecheck
pnpm test
pnpm -C packages/conformance validate
pnpm test:vectors:all
pnpm security:gate
pnpm run security:policy-boundary
```

Adapter validation, when relevant:

```bash
pnpm validate:adapters
```

Workspace-wide validation, when relevant:

```bash
pnpm -r build
pnpm -r test
```

---

## 2. Core Principles

Contributions must preserve OxDeAI’s core principles:

* deterministic evaluation only
* no hidden side effects in policy evaluation
* fail-closed by default
* no valid authorization means no execution path
* execution authority must be explicit and verifiable
* external metadata must not modify authority unless processed through the documented authorization path
* protocol behavior must be reproducible across implementations
* claims must be tied to tests, specs, vectors, or audit evidence

---

## 3. Developer Certificate of Origin

OxDeAI requires all commits to be signed off under the Developer Certificate of Origin.

Use:

```bash
git commit -s
```

Each commit must include a line like:

```text
Signed-off-by: Your Name <your.email@example.com>
```

### Why DCO instead of CLA

OxDeAI uses DCO rather than a Contributor License Agreement because:

* it is lightweight
* it preserves contributor copyright
* it avoids contributor copyright assignment
* it is widely used in major open-source projects
* it fits Apache-2.0 open-source protocol development

By contributing, you certify that you have the right to submit the contribution under the project license.

DCO enforcement may be automated through CI. If automation is not present yet, DCO sign-off is still required by project policy.

---

## 4. Before You Start

Open a GitHub issue before starting substantial work.

This includes:

* protocol specification changes
* conformance vector additions or changes
* new cross-language harnesses
* new integration adapters
* changes to `AuthorizationV1`
* changes to `DelegationV1`
* changes to `SignedKRLV1`
* changes to `canonicalization-v1`
* changes to PEP enforcement behavior
* significant refactors
* security-sensitive changes

Small fixes can go directly to a pull request:

* typo fixes
* small documentation corrections
* obvious test fixes
* small bug fixes with narrow scope

---

## 5. Contribution Types

### 5.1 Protocol specification changes

Protocol semantic changes are high scrutiny.

Examples:

* changing verification ordering
* changing signature preimages
* changing canonicalization rules
* changing artifact fields
* changing fail-closed behavior
* changing replay semantics
* changing state binding behavior

Protocol changes must include:

* issue discussion
* discovery or design notes
* spec update
* tests or vectors where applicable
* audit update where applicable
* validation output

Do not silently redefine protocol behavior in implementation code.

---

### 5.2 Conformance vector contributions

Conformance vectors are one of OxDeAI’s most important assets.

Good vector contributions:

* test one behavior clearly
* are deterministic
* are minimal
* are portable across implementations
* include expected result and reason code where applicable
* strengthen external implementer readiness
* do not mix unrelated behaviors in one vector

Changing expected outcomes in existing vectors is treated as a protocol semantic change unless the existing vector is demonstrably wrong.

---

### 5.3 Cross-language harness contributions

Cross-language harnesses strengthen OxDeAI’s standardization posture.

A new harness should:

* independently implement canonicalization
* independently verify hashes and signatures
* consume the official conformance vectors
* avoid runtime dependency on the TypeScript reference implementation
* produce clear pass/fail output
* fail closed on ambiguity
* use native cryptographic libraries where possible

Existing Go and Python harnesses are the current template for independent verification.

---

### 5.4 External integration adapters

External integration adapters are welcome when they strengthen OxDeAI’s protocol surface rather than creating provider-specific shortcuts.

A good adapter contribution should:

* preserve the invariant: no valid authorization → no execution path
* document trust boundaries clearly
* avoid coupling OxDeAI protocol semantics to one provider’s internal model
* keep non-authoritative metadata outside the authority path
* include tests, examples, or vectors where applicable
* surface protocol-level improvements that benefit future integrators

The `@oxdeai/sift` adapter is the current template: an external integration that exposed wire-format, key lifecycle, and revocation alignment issues, which were resolved at the protocol/specification layer rather than hidden as provider-specific shims.

Integration feedback is valuable when it produces general protocol improvements. It should not force OxDeAI semantics to follow one integrator’s private model or product timeline.

---

### 5.5 Documentation contributions

Documentation contributions are welcome.

Good documentation contributions:

* clarify behavior
* reduce ambiguity
* improve cross-references
* preserve conservative wording
* distinguish implemented, specified, documented, and residual behavior
* avoid marketing language

If documentation changes a claim about coverage, maturity, or risk, check whether the audit also needs updating.

---

### 5.6 Bug reports and bug fixes

Good bug reports include:

* affected version or commit
* affected package or spec
* reproduction steps
* expected behavior
* actual behavior
* security impact, if any

Bug fixes should include tests where behavior changes.

Security-sensitive bugs should be reported privately. See `SECURITY.md`.

---

## 6. Pull Request Process

### 6.1 PR expectations

A good pull request:

* is focused
* includes rationale
* references affected artifacts, such as `AuthorizationV1`, `DelegationV1`, `SignedKRLV1`, `canonicalization-v1`, or PEP behavior
* includes tests when behavior changes
* updates documentation when semantics or claims change
* preserves reproducibility
* includes validation output

### 6.2 PR body should include

Pull requests should use the repository pull request template at:

```text
.github/pull_request_template.md
```

Do not remove required sections from the template when they apply.

For non-trivial PRs, the PR body should clearly describe:

```text
Summary:

What changed:

Why:

Boundary:

Validation:
```

For protocol, bug-fix, or security-sensitive PRs, also include:

```text
Security impact:

Invariants preserved:

Regression proof:

Residual risks:

Audit/spec updates:
```

Regression proof should reproduce the failure mode where practical and show that the relevant test or CI signal fails when the protection is deliberately broken.

Required CI checks must not be weakened, bypassed, or made advisory in order to merge a contribution.

### 6.3 Validation before PR

Run:

```bash
pnpm typecheck
pnpm test
pnpm -C packages/conformance validate
pnpm test:vectors:all
pnpm security:gate
pnpm run security:policy-boundary
```

When adapters are affected:

```bash
pnpm validate:adapters
```

When workspace packages are affected:

```bash
pnpm -r build
pnpm -r test
```

For docs-only PRs, still run at minimum:

```bash
git diff --check
git diff -- packages/core/API_FINGERPRINT
```

and preferably the full validation suite.

---

## 7. What May Not Be Merged

The following changes will not be accepted:

* changes that create an execution path without valid authorization
* fail-open behavior
* advisory-only enforcement
* bypass paths around the PEP
* weakening signature verification
* weakening replay protection
* weakening canonicalization determinism
* making residual risks less visible
* overclaiming standardization readiness
* adopting external patent-encumbered system names as OxDeAI component names
* coupling OxDeAI protocol semantics to a single external provider
* large refactors without clear protocol or maintainability benefit
* feature additions without a defined boundary rationale

When a contribution is not accepted, the reason should be explained.

---

## 8. Audit and Documentation Discipline

OxDeAI maintains its current security scope and residual risks at:

```text
docs/audits/2.0-residual-scope.md
```

`docs/audits/protocol-audit-post-interoperability.md` is a historical snapshot
(2026-06-04); do not update its conclusions.

If a contribution changes maturity, coverage, risk, or conformance posture, update the residual scope.

When a P-item or residual changes state, check all affected sections, not only the primary follow-up entry.

Audit updates should remain conservative:

* do not mark residuals closed unless they are actually closed
* do not claim full standardization readiness prematurely
* distinguish protocol guarantees from deployment responsibilities
* preserve named residuals where risk remains

---

## 9. Security

Security issues must be reported privately.

Do not open public GitHub issues for vulnerabilities.

Security reports:

```text
security@oxdeai.dev
```

General contact:

```text
contact@oxdeai.dev
```

See `SECURITY.md` for the disclosure process.

OxDeAI has not yet undergone independent security review. Do not describe the project as independently audited or production-certified.

---

## 10. Coding Standards

### TypeScript

* keep types explicit
* avoid `any` unless narrowly justified
* preserve public API stability
* add tests for behavior changes
* avoid unnecessary runtime dependencies
* keep packages maintainable and minimal

### Go and Python harnesses

* prefer standard library where possible
* keep harnesses independent from TypeScript runtime code
* produce deterministic output
* fail non-zero on mismatch
* keep verification logic readable for external review

### Markdown and specs

* use clear headings
* use RFC 2119 language carefully
* avoid vague claims
* cross-reference specs and vectors
* keep examples mechanically checkable where possible

---

## 11. Recognition

Contributors are credited through:

* git history
* pull request history
* issue discussion
* release notes where applicable

A separate `CONTRIBUTORS.md` may be added if the contributor base grows.

---

## 12. Questions

For contribution questions, open a GitHub issue or contact:

```text
contact@oxdeai.dev
```

For security matters, use:

```text
security@oxdeai.dev
```

---

## 13. Summary

OxDeAI contributions should make the protocol more precise, more verifiable, or easier to evaluate.

The project prefers:

* small, focused changes
* clear boundaries
* deterministic behavior
* fail-closed semantics
* cross-language evidence
* honest documentation

The invariant remains:

```text
No valid authorization → no execution path
```
