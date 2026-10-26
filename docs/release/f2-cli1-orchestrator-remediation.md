# F2/CLI-1 orchestrator remediation (maintainers)

The F2/CLI-1 contract separates ten evaluated packages from five selected
operations. Start a **new** PRECHECK with `selection: F2_CLI1_SELECTION` in the
library, or `precheck --selection=f2-cli1 --release-dir <fresh-directory>` in the
local CLI. This change does not produce official release evidence. Do not reuse
an earlier PRECHECK or attach selection to an existing packed candidate.

The ordered selection is core 2.0.2, guard 2.0.3, sdk 2.0.2, conformance 2.0.2,
and cli 0.3.2. Extra entries, duplicates, other versions and other orders fail.
POLICY still governs discovery, access/visibility observations, package metadata,
packing and local consumer verification for all ten public packages. PACK retains
all ten original archives. Excluded adapter state stays pending and cannot carry
publication or verification evidence.

The PRECHECK receipt includes selection in its receiptDigest. PACK reobserves
source cleanliness/revision, policy and exact package.json bytes and copies
selection into the manifest. manifestIntegrity binds selection, source revision,
PRECHECK and all archive SRI values. State history binds the PRECHECK digest.
The publication plan preserves ten packagesEvaluated but contains five operations.
Each authorization binds the manifest digest and one exact operation. Editing a
selection, archive, receipt or operation invalidates these bindings. Digests are
consistency checks, not signatures; trusted calling code still owns consent,
credentials and custody of release evidence. Builds retain the existing process
provenance limitations; this is not independent reproducible-build proof.

For a selected manifest, `publishPlannedOperation` now requires an explicit
`authorization` receipt even with an injected fixture transport.
`publishAuthorizedOperation` forwards the validated receipt. Each invocation
allows at most one publication and independently observes registry integrity
after the attempt, including after a successful transport response. Matching
already-published bytes reconcile without publication; different bytes hard-stop.
Predecessors must have matching published integrity before the next operation.
Resume reads all original archives, reconciles only selected versions, rejects
unknown registry observations and never packs or publishes. Subsequent registry,
external-install verification and promotion **planning** cover the selected set.
No CLI publication command or new live capability is introduced.

Compatibility: manifest, state, receipt and authorization version numbers remain
1. Selection is an additive field. Existing manifests/receipts without selection
retain their all-package contract and injected-transport behavior. They are **not
F2/CLI-1 release candidates** and must not be used for this remediation. The new
profile must be chosen explicitly at the new PRECHECK; it cannot be inferred from
version numbers. Unknown CLI selection spellings fail closed.

Dependency checks read observed package.json bytes at PRECHECK and before/after
PACK. The five current packages have no runtime, peer or optional dependencies
outside the selected batch; their workspace:* core references become the exact
core version when packed. Dependency order must agree with POLICY. This narrow
profile accepts exact internal versions and workspace:* references. Any external
dependency or unsupported range blocks preparation: external registry dependency
resolution is deliberately not implemented because none is needed for this lot.
A future dependency change requires an explicit compatible-resolution contract
and tests before this profile can proceed.

Validation uses fixture archives and injected transports, plus existing release
tests and local preflight checks. A clean-source real PACK/consumer verification
and live registry checks remain separate release preparation work. No existing
PRECHECK is reused; no official PACK, publication or dist-tag change is performed
by this remediation.

## Remediation validation (2026-10-20)

Initial directory, branch, revision and clean status were verified before edits:
`oxdeai-f2-cli1-orchestrator`, `fix/f2-cli1-release-orchestrator`,
`65f799f1ffe655a80617a7bb4630953057be1a0c`.

- Targeted orchestrator, planning, publication, authorization, npm transport and
  readiness tests passed. `node scripts/release-2.0/selection.test.mjs`: 26 passed.
- `node --test --test-concurrency=1 scripts/release-2.0/*.test.mjs`:
  599 tests, 598 passed, zero failures, one skipped. All ten build-output checks
  passed. Real clean-source PRECHECK/PACK/VERIFY_LOCAL was skipped because the
  remediation was uncommitted; that test verified rejection of dirty PACK.
- Sandbox subprocess restrictions initially caused EPERM. With authorized local
  subprocess execution, receipt tests passed; build tests exposed missing local
  dependencies. `pnpm install --offline --frozen-lockfile --ignore-scripts`
  restored the locked dependencies without network or lockfile changes. The
  complete suite above then passed.
- `git diff --check` passed. Before committing, all five local preflights passed
  every check except the expected dirty-tree gate. They must be rerun after the
  local review commit. No registry availability/rights freshness claim is made.

No existing tests or release gates were removed. No package versions changed.
No official PACK, old-PRECHECK reuse, registry publication, dist-tag operation,
push or advisory disclosure was performed. Changes are confined to this worktree.
