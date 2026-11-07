# Security Policy

**Status:** Working security disclosure policy for OxDeAI v1  
**Last updated:** 2026-11-07

This document explains how to report security issues in OxDeAI, what versions are supported, and how vulnerability disclosure is handled.

OxDeAI is an open-source execution-time authorization protocol. Security reports should be handled privately and responsibly.

---

## 1. Security Review Status

OxDeAI has not yet undergone independent security review.

The current security scope, residual risks and deployment assumptions are documented in:

```text
docs/audits/2.0-residual-scope.md
docs/security/threat-model.md
```

`docs/audits/protocol-audit-post-interoperability.md` is a historical snapshot dated
2026-06-04. It is preserved for the record and does not describe the current state.

Known residuals include, but are not limited to:

* **RT-TRUST-1:** state provider integrity, specified with residual deployment responsibility
* **RT-TRUST-2:** KRL transport / migration-tracked revocation integrity posture
* **RT-TRUST-3:** replay store bootstrapping and deployment residuals

Production adopters should review the residual scope before relying on OxDeAI in high-assurance environments.

---

## 2. Supported Versions

OxDeAI is currently pre-1.0 / early v1 protocol work.

Security fixes are handled on the active default branch and published through the normal release process.

| Version / Branch              | Supported   |
| ----------------------------- | ----------- |
| `main`                        | Yes         |
| Latest published npm packages | Best effort |
| Older branches or tags        | Best effort |
| Forks                         | No          |

If a vulnerability affects a released package, the fix will be documented in the release notes.

---

## 3. Reporting a Vulnerability

Do not report security vulnerabilities as public GitHub issues.

Report suspected vulnerabilities privately by email:

```text
security@oxdeai.dev
```

For non-security contact:

```text
contact@oxdeai.dev
```

A good report should include:

* affected component
* affected version or commit
* vulnerability description
* reproduction steps, if available
* expected impact
* whether the issue is already public
* any proposed fix or mitigation

Do not include secrets, private keys, production credentials, or sensitive third-party data in the report.

---

## 4. Response Timeline

OxDeAI is currently solo-maintained, so response times are best effort.

Target response timeline:

| Step                                              | Target                              |
| ------------------------------------------------- | ----------------------------------- |
| Initial acknowledgement                           | within 7 days                       |
| Initial triage                                    | within 14 days                      |
| Remediation plan for confirmed significant issues | within 30 days                      |
| Public disclosure                                 | coordinated, usually within 90 days |

Severe issues affecting active adopters may be handled faster.

Low-impact or speculative issues may take longer.

---

## 5. Disclosure Process

The default process is coordinated disclosure.

1. Reporter emails `security@oxdeai.dev`.
2. Maintainer acknowledges the report.
3. Maintainer triages severity and affected components.
4. If valid, a private fix plan is prepared.
5. Fix is developed and validated.
6. Release or patch is published.
7. Public advisory or disclosure is issued when appropriate.

Public disclosure may be accelerated if:

* exploitation is active
* the issue is already public
* users need immediate mitigation guidance

Reporter credit will be given unless anonymity is requested.

---

## 6. Bug Bounty

OxDeAI does not currently operate a bug bounty program.

Security researchers are welcome to report issues, but no monetary reward is promised unless a separate written agreement exists.

---

## 7. Security Scope

Security reports are in scope if they affect OxDeAI’s authorization boundary, verification semantics, conformance guarantees, or security-relevant implementation behavior.

Examples of in-scope issues:

* bypassing `AuthorizationV1` verification
* execution without valid authorization
* fail-open behavior
* replay protection failure
* signature verification flaws
* canonicalization inconsistencies
* key lifecycle / revocation failures
* `SignedKRLV1` verification failures
* delegation scope widening
* PEP bypass paths
* state binding failures
* audit-chain integrity failures
* cross-language vector inconsistency
* security-sensitive documentation errors that could cause unsafe deployment

Examples of out-of-scope issues:

* generic website styling issues
* speculative reports without an actionable attack path
* vulnerabilities only present in unsupported forks
* social engineering
* denial-of-service reports requiring unrealistic resource assumptions
* reports based only on lack of independent security review
* reports about risks already documented as residuals, unless a new exploit path is shown

---

## 8. Residual Risks

Some risks are known and documented. Reporting them again is useful only if the report adds a new exploit path, evidence, or mitigation.

Current known residuals include:

### RT-TRUST-1 - State provider integrity

OxDeAI verifies state binding at the PEP, but state-source compliance remains a deployment responsibility.

The relevant specification is:

```text
docs/spec/state-provider-requirements.md
```

A non-compliant or compromised state provider remains a residual risk.

### RT-TRUST-2 - KRL revocation integrity posture

KRL integrity has been hardened through signed KRL verification paths, persistent high-watermark handling, and last-known-good cache behavior for configured deployments.

Residual risk remains for deployments using weaker migration modes or incomplete configuration.

### RT-TRUST-3 - Replay store bootstrapping

Replay protection depends on correct deployment of the replay store.

In-memory stores are suitable for development and single-process contexts, but production deployments should use durable replay infrastructure appropriate to their scaling model.

---

## 9. Safe Harbor

Security research conducted in good faith is welcome.

To remain within safe harbor:

* act only against systems you own or are explicitly authorized to test
* avoid privacy violations
* avoid data destruction
* avoid service disruption
* do not attempt extortion
* report findings promptly
* give the project a reasonable opportunity to fix confirmed issues before public disclosure

This safe harbor does not authorize testing against third-party deployments of OxDeAI without their permission.

---

## 10. Handling Public Issues

If a security issue is accidentally opened publicly:

* the issue may be closed or minimized
* the reporter may be asked to continue by email
* public details may be limited until a fix or advisory is ready

Do not post exploit details, private keys, credentials, or active attack instructions in public issues.

---

## 11. Security Advisory Format

When a public advisory is needed, it should include:

* affected component
* affected versions or commits
* severity assessment
* impact
* fixed version or commit
* mitigation steps
* credit, if applicable
* links to relevant audit/spec updates

Advisories should avoid unnecessary exploit detail before users have had reasonable time to upgrade.

---

## 12. Security Contact

Security reports:

```text
security@oxdeai.dev
```

General contact:

```text
contact@oxdeai.dev
```

GitHub issues are appropriate for non-sensitive bugs, documentation improvements, feature requests, and public design discussion.

Security vulnerabilities should be reported privately.
