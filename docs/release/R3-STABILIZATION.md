# R3 stabilization candidate

R3 remains NO-GO. Version allocation is not publication or security acceptance.

The candidate uses Guard 2.0.5, conformance 2.0.4 and all five framework adapters 2.0.1. Core/SDK remain 2.0.3 and CLI remains 0.3.3. Adapters require Guard ^2.0.5, excluding 2.0.4 through normal semver resolution. Semver alone does not authenticate artifact bytes: retain the signed source revision, frozen manifests and tarball integrity checks.

Each framework identifier (id, call_id or step_id) is captured once. Top-level getters and Proxies execute during translation; no blanket rejection or sandbox is claimed. The protected executor must consume the verified action. Legacy zero-argument closures remain outside that guarantee.

**Residual integration risk (F-06, predates R3, unchanged).** The adapters pass the captured framework identifier through as `context.intent_id` without checking its type. If a framework supplies an identifier that is not a non-empty string (for example `id: 42` or `id: ""`), the executor's verified action still carries that value as `context.intent_id`. The guard's normalizer (`packages/guard/src/normalizeAction.ts`) instead evaluates and authorizes a generated `intent_id`. `context.intent_id` is framework-supplied metadata and is never evidence of authorization; bind and audit only against the verified authorization's `intent_id`. When the framework identifier is not a non-empty string, the two identifiers may differ. Identifier normalization and adapter execution behaviour are deliberately unchanged in R3.

**Integration level.** The five adapters are shape adapters: they translate a framework-shaped tool call into a Guard `ProposedAction` and depend on no framework package. They register no framework hook. Only calls that the integrator routes through the returned guard function are authorized; a framework that executes tools directly bypasses them. See the integration-level notes in each adapter README.

## Release scope and mode

R3 is released in **full mode**: run `precheck` **without** `--selection`.

When the released Guard carries the adapter security floor (Guard ≥ 2.0.5, as here), a selection must name all ten POLICY packages at their POLICY versions. The rule is `assertCompleteReleaseSelection` in `scripts/release-2.0/orchestrator.mjs`. It is enforced at three points:

1. **PRECHECK** (`precheck()` and the CLI): a partial selection fails and no receipt is written.
2. **Receipt validation** (`validatePrecheckReceipt`): a persisted receipt that carries a partial selection is invalid. PACK therefore refuses it before packing or writing any manifest, state or tarball, and VERIFY_LOCAL refuses it when re-reading the receipt, leaving the release state unchanged.
3. **Publication planning** (`publicationPackages`): no publication plan, publication, registry or install verification, promotion or finalization step can be derived from a manifest that carries a partial selection. Validating its release state also fails. `loadAndValidateManifest` itself still only checks manifest integrity, so historical manifests keep loading as before; every phase that acts on a loaded manifest applies the rule.

Points 2 and 3 exist because the receipt digest is a consistency check, not authentication: a receipt edited to add a selection, with its digest recomputed, must not pass merely because PRECHECK was bypassed (finding F-R4-1). Tests: `scripts/release-2.0/release-completeness.test.mjs` (rule, forged receipt, PACK, VERIFY_LOCAL, manifest, direct `publicationPackages`), `selection.test.mjs`, `release-finalization.test.mjs` and `release-scope.test.mjs`.

| Mode | PRECHECK on this checkout | Evaluated, packed, verified | Planned for publication |
|---|---|---|---|
| Full (no `--selection`) | passes | 10 | 10, in POLICY publish order, adapters included |
| `--selection=f2-cli1` | **refused** (names the five omitted adapters) | — | — |
| Forged `f2-cli1` receipt (digest recomputed) | not run | **refused** by PACK; VERIFY_LOCAL refuses a receipt forged after PACK | **refused** |

Why it is refused: `f2-cli1` names core, guard, sdk, conformance and cli and none of the five adapters, so Guard 2.0.5 would ship without the 2.0.1 adapters.

Backward compatibility:
- For a policy whose Guard is below the floor (pre-R3), the rule does not apply.
- Full-mode receipts and manifests (no `selection`) are unaffected by all three checks.
- Historical manifests behave exactly as before: the R2 full-mode (`r2-final-8e71ff03823a`) and 2.0.0 (`release-2.0.0`) manifests still load and plan, and the R2 selection manifest (`r2-selected-8e71ff03823a`) still fails, at the same exact-profile check as before (see the next point), before the completeness rule is reached.
- Existing limitation, not introduced here (F-07): `F2_CLI1_SELECTION` was updated in place to the R3 versions, so R2-era selection manifests (Guard 2.0.4) fail validation. Consequently the only selection that can reach receipt validation or publication planning on this checkout is the R3 `f2-cli1` partial selection, which the rule refuses; selection mode is not usable for R3.
- `f2-cli1` is the fixed R2 remediation profile; it remains in the code only for that profile.

Two different counts apply and must not be confused:

| Package | R3 baseline afabb9b (same versions as R2 final 8e71ff0) | R3 candidate | Change vs baseline | npm `latest` on 2026-11-16 | Candidate already on npm? |
|---|---|---|---|---|---|
| @oxdeai/core | 2.0.3 | 2.0.3 | unchanged, no source change | 2.0.2 | no |
| @oxdeai/sdk | 2.0.3 | 2.0.3 | unchanged, no source change | 2.0.2 | no |
| @oxdeai/cli | 0.3.3 | 0.3.3 | unchanged, no source change | 0.3.2 | no |
| @oxdeai/guard | 2.0.4 | 2.0.5 | version bump | 2.0.3 | no |
| @oxdeai/conformance | 2.0.3 | 2.0.4 | version bump | 2.0.2 | no |
| @oxdeai/autogen, crewai, langgraph, openai-agents, openclaw | 2.0.0 | 2.0.1 | version bump + identifier fix | 2.0.0 | no |

- **Seven new versions** relative to the R3 baseline afabb9b, whose versions are those of the R2 final candidate 8e71ff0: Guard, conformance and the five adapters.
- **Ten packages** evaluated, packed, verified and, in full mode, published. The R2 candidate versions of core, SDK, CLI, Guard (2.0.4) and conformance (2.0.3) were never published, so every one of the ten candidate versions is new to the registry. Recheck the registry immediately before any publication.

The published adapters 2.0.0 declare `@oxdeai/guard ^2.0.0`. Once Guard 2.0.5 is published, existing 2.0.0 installs can resolve it, but they keep the 2.0.0 adapter code without the single-read identifier fix. Consumers must upgrade to the 2.0.1 adapters.

## Guard security floor gate

`scripts/verify-packed-artifacts.mjs` now enforces the floor in both the standalone packed-artifact gate and VERIFY_LOCAL (`verifyPackedTarballs`):

- The manifest is read from **each packed tarball**, not from source.
- All five adapter tarballs must declare `dependencies["@oxdeai/guard"]` exactly `^2.0.5`. Guard must not appear in `optionalDependencies`, `peerDependencies` or bundled dependencies. Any other package that declares Guard is held to the same rule.
- The check runs before the conformance baseline and before any npm/pnpm consumer install. The pnpm consumer's local `overrides` therefore cannot mask a bad range.
- At module load, the floor list must equal the POLICY adapter set, and the Guard version being released must satisfy the floor.
- Negative tests: `scripts/release-2.0/guard-floor.test.mjs` (run by `pnpm test:release`). They include tarball-level cases for every per-manifest rule (optional, peer and bundled Guard; weaker Guard on a non-adapter) and module-load cases. The module-load cases import a copy of the gate module with a below-floor Guard or an exempted adapter and expect the import to fail.

The exact-match rule rejects stricter ranges too. Raising the floor is a reviewed change to `GUARD_SECURITY_FLOOR`.

## Dependency audit remediation

Development/build audit upgrades are limited to Puppeteer within major 25, patched Zod 4, fast-uri 4.2.3 and minimatch 11.0.8. The private OpenAI demo uses the already-locked SDK 6.36.0, whose Zod 4 peer is patched, replacing SDK 4 and its vulnerable Zod 3 peer. No advisory exceptions or global policy changes are introduced. Audit and compatibility gates must pass before committing.

**minimatch override crosses a major version.** The root override `minimatch: 11.0.8` applies to every dependent. Its only dependent is `@microsoft/api-extractor@7.58.7` (build/API-report tooling, not shipped), which declares an exact `minimatch: 10.2.3`; API Extractor 7.60.1 still declares 10.2.3. The override therefore runs API Extractor on a minimatch major it does not declare, to clear GHSA-g3hv-75wg-m249 (patched only in >=11.0.1). Evidence: the real `api:check` API extraction passes with minimatch 11.0.8. If an API Extractor upgrade adds another minimatch dependent, or `api:check` fails, re-evaluate: scope the override to `@microsoft/api-extractor>minimatch` or adopt an upstream fix. It must not be treated as a general minimatch 11 compatibility claim.

The previous `form-data: 4.0.6` override was removed. After the SDK-4 chain was removed, `form-data` no longer appears in the dependency graph, so the override matched nothing. If `form-data` reappears transitively, the advisory gate evaluates it like any other dependency.

## Release procedure

Run the documented PRECHECK (full mode), reproducible-pack, PACK and VERIFY_LOCAL commands from the resulting clean signed commit. Dirty-tree packaging is not valid release evidence. New package versions and conformance provenance necessarily change tarball bytes; Core and SDK runtime sources and protocol semantics are unchanged.
