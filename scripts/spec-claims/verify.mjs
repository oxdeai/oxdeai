import { evidenceScope, repositoryMetadata, digest } from "../../packages/conformance/src/evidenceScope.mjs";
import { readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { resolve, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
export const REGISTRY = 'docs/verification/spec-claims/claims.json';
const classifications = ['portable', 'implementation-specific', 'deployment-assumption', 'documentation-only'];
const levels = ['TRACEABLE', 'TESTED', 'INTEGRATION_TESTED', 'ADVERSARIAL_TESTED', 'CONFORMANCE_TESTED'];
const kinds = ['unit', 'vector', 'integration', 'adversarial', 'cross-runtime'];
const categories = ['ARTIFACT', 'VERIFY', 'ENFORCEMENT', 'TRUST', 'DELEGATION', 'TIME', 'REPLAY', 'STATE', 'AUDIT'];
const isObject = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const nonempty = x => typeof x === 'string' && x.trim().length > 0;

// Deliberately recognizes direct, statically named node:test declarations only.
// Comments, string mentions, dynamic names, .skip/.todo and options are not evidence.
const testCache = new Map();
const declarationCache = new Map();
export function testNames(source, path) {
  const key = `${path}\0${source}`;
  if (testCache.has(key)) return [...testCache.get(key)];
  const names = [];
  const tree = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true);
  const visit = node => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'test' &&
        node.arguments.length === 2 && ts.isStringLiteralLike(node.arguments[0]) &&
        (ts.isArrowFunction(node.arguments[1]) || ts.isFunctionExpression(node.arguments[1]))) names.push(node.arguments[0].text);
    ts.forEachChild(node, visit);
  };
  visit(tree);
  testCache.set(key, names);
  return [...names];
}

export function verify(registry, root = ROOT) {
  const issues = [], rows = [];
  const error = (id, code, detail) => issues.push({ id, code, detail });
  function record(x, keys, at) {
    if (!isObject(x)) { error(at, 'MALFORMED', 'expected object'); return false; }
    for (const k of keys) if (!(k in x)) error(at, 'MALFORMED', `missing ${k}`);
    for (const k of Object.keys(x)) if (!keys.includes(k)) error(at, 'MALFORMED', `unknown field ${k}`);
    return keys.every(k => k in x);
  }
  function string(x, at) { if (!nonempty(x)) error(at, 'MALFORMED', 'expected non-empty string'); }
  function enumeration(x, values, at) { if (!values.includes(x)) error(at, 'MALFORMED', `expected one of ${values.join(', ')}`); }
  function array(x, at) { if (!Array.isArray(x)) { error(at, 'MALFORMED', 'expected array'); return []; } return x; }
  function boolean(x, at) { if (typeof x !== 'boolean') error(at, 'MALFORMED', 'expected boolean'); }
  function file(path, at, code) {
    if (!nonempty(path) || path.includes('\\') || path.startsWith('/') || path.split('/').some(p => p === '..' || p === '.')) {
      error(at, code, `invalid repository-relative path: ${String(path)}`); return null;
    }
    try {
      const abs = realpathSync(resolve(root, path));
      if (relative(realpathSync(root), abs).startsWith('..') || !statSync(abs).isFile()) throw Error('outside root or not a file');
      return readFileSync(abs, 'utf8');
    } catch { error(at, code, `missing/unreadable file: ${path}`); return null; }
  }
  if (!record(registry, ['version', 'claims'], 'registry')) return { issues, rows };
  if (registry.version !== 2) error('registry', 'MALFORMED', 'version must be 2 (explicit migration required)');
  if (Array.isArray(registry.claims) && registry.claims.length === 0) error('registry', 'MALFORMED', 'claim inventory must not be empty');
  const ids = new Set();
  for (const [i, c] of array(registry.claims, 'claims').entries()) {
    const at = nonempty(c?.id) ? c.id : `claims[${i}]`;
    const before = issues.length;
    if (!record(c, ['id', 'title', 'source', 'strength', 'category', 'implementation', 'evidence', 'requiredLevels', 'securityCritical', 'negativeRequired', 'classification', 'portableRequired', 'recordType', 'normativeState', 'evidenceState', 'scopeDisposition', 'appliesWhen', 'dependsOn', 'inferenceGuard', 'maintainerDecisionRequired', 'notes'], at)) continue;
    for (const k of ['id', 'title', 'notes']) string(c[k], `${at}.${k}`);
    if (!/^[A-Z][A-Z0-9-]*-[0-9]+$/.test(c.id)) error(at, 'MALFORMED', 'invalid stable claim ID');
    if (ids.has(c.id)) error(at, 'DUPLICATE_ID', c.id);
    ids.add(c.id);
    enumeration(c.strength, ['MUST', 'MUST NOT', 'REQUIRED', 'SHOULD', 'normative-statement', 'not-applicable'], `${at}.strength`);
    enumeration(c.category, categories, `${at}.category`);
    enumeration(c.classification, classifications, `${at}.classification`);
    enumeration(c.recordType, ['requirement', 'corpus-lock'], `${at}.recordType`);
    enumeration(c.normativeState, ['specified', 'ambiguous', 'unresolved', 'non-normative'], `${at}.normativeState`);
    enumeration(c.evidenceState, ['mapped', 'gap', 'unassessed'], `${at}.evidenceState`);
    enumeration(c.scopeDisposition, ['in-scope', 'deferred', 'deployment', 'conditional', 'out-of-scope'], `${at}.scopeDisposition`);
    for (const k of ['securityCritical', 'negativeRequired', 'portableRequired', 'maintainerDecisionRequired']) boolean(c[k], `${at}.${k}`);
    for (const k of ['implementation', 'evidence', 'requiredLevels', 'dependsOn', 'inferenceGuard', 'appliesWhen']) array(c[k], `${at}.${k}`);
    if (issues.length > before) continue;
    // Review metadata is not an execution policy. Only explicit evidence obligations gate CI.
    if (c.recordType === 'corpus-lock' && (c.strength !== 'not-applicable' || c.source?.role !== 'context' || c.requiredLevels.length || c.negativeRequired || c.portableRequired)) error(at, 'LOCK_PROMOTION', 'corpus locks require contextual sourcing, not-applicable strength and no executable evidence obligations');
    if (c.recordType === 'requirement' && (c.strength === 'not-applicable' || c.source?.role !== 'normative')) error(at, 'MALFORMED', 'requirements retain normative source and strength');
    const dependencies = new Set();
    for (const d of c.dependsOn) {
      if (!record(d, ['id', 'relation', 'reason'], `${at}.dependsOn`)) continue;
      string(d.id, `${at}.dependsOn.id`); string(d.reason, `${at}.dependsOn.reason`);
      enumeration(d.relation, ['interpretation', 'trust-premise', 'conditional-mitigation'], `${at}.dependsOn.relation`);
      if (d.id === c.id || dependencies.has(d.id)) error(at, 'INVALID_DEPENDENCY', 'self or duplicate dependency');
      dependencies.add(d.id);
    }
    for (const g of c.inferenceGuard) {
      if (!record(g, ['from', 'to', 'reason'], `${at}.inferenceGuard`)) continue;
      for (const k of ['from', 'to', 'reason']) string(g[k], `${at}.inferenceGuard.${k}`);
    }
    const settings = new Set();
    for (const condition of c.appliesWhen) {
      if (!record(condition, ['setting', 'equals'], `${at}.appliesWhen`)) continue;
      string(condition.setting, `${at}.appliesWhen.setting`); string(condition.equals, `${at}.appliesWhen.equals`);
      if (settings.has(condition.setting)) error(at, 'MALFORMED', 'duplicate applicability setting');
      settings.add(condition.setting);
    }
    if ((c.scopeDisposition === 'conditional') !== (c.appliesWhen.length > 0)) error(at, 'MALFORMED', 'conditional scope requires non-empty appliesWhen; other scopes require []');
    if (c.negativeRequired && !c.securityCritical) error(at, 'MALFORMED', 'negativeRequired requires securityCritical');
    if (record(c.source, ['path', 'section', 'quote', 'role'], `${at}.source`)) {
      enumeration(c.source.role, ['normative', 'context'], `${at}.source.role`);
      string(c.source.section, `${at}.source.section`); string(c.source.quote, `${at}.source.quote`);
      const prose = file(c.source.path, at, 'MISSING_SOURCE');
      if (typeof c.source.path !== 'string' || !c.source.path.endsWith('.md') || (c.source.role === 'normative' && !c.source.path.startsWith('docs/spec/'))) error(at, 'MISSING_SOURCE', 'source must be Markdown; normative source must be docs/spec/**/*.md');
      if (prose !== null) {
        const lines = prose.split(/\r?\n/), start = lines.indexOf(c.source.section);
        const depth = String(c.source.section).match(/^#+/)?.[0].length;
        let end = start + 1;
        while (end < lines.length && !(depth && new RegExp(`^#{1,${depth}} `).test(lines[end]))) end++;
        if (start < 0 || !depth || !lines.slice(start, end).join('\n').includes(c.source.quote)) error(at, 'STALE_SOURCE', 'section/quote no longer matches; review normative drift');
      }
    }
    let impl = 0;
    for (const ref of array(c.implementation, `${at}.implementation`)) {
      if (!record(ref, ['path', 'symbol'], `${at}.implementation`)) continue;
      string(ref.symbol, `${at}.symbol`);
      const source = file(ref.path, at, 'STALE_IMPLEMENTATION');
      if (source !== null) {
        const key = `${ref.path}\0${source}`;
        if (!declarationCache.has(key)) {
          const tree = ts.createSourceFile(ref.path, source, ts.ScriptTarget.Latest, true);
          const declarations = new Set();
          const visit = node => {
            if ((ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node) || ts.isMethodDeclaration(node) || ts.isVariableDeclaration(node)) && node.name) declarations.add(node.name.getText(tree));
            ts.forEachChild(node, visit);
          };
          visit(tree);
          declarationCache.set(key, declarations);
        }
        const found = declarationCache.get(key).has(ref.symbol);
        if (!found) error(at, 'STALE_IMPLEMENTATION', `${ref.path}: declaration ${ref.symbol} missing`); else impl++;
      }
    }
    const evidence = [];
    for (const [j, ref] of array(c.evidence, `${at}.evidence`).entries()) {
      const eBefore = issues.length;
      if (!record(ref, ['path', 'selector', 'kind', 'negative', 'portable', 'runner', 'supports'], `${at}.evidence[${j}]`)) continue;
      enumeration(ref.kind, kinds, `${at}.evidence.kind`);
      boolean(ref.negative, `${at}.evidence.negative`); boolean(ref.portable, `${at}.evidence.portable`);
      string(ref.supports, `${at}.evidence.supports`);
      const source = file(ref.path, at, 'STALE_EVIDENCE');
      if (record(ref.selector, ['type', 'id'], `${at}.selector`)) {
        enumeration(ref.selector.type, ['test', 'vector'], `${at}.selector.type`); string(ref.selector.id, `${at}.selector.id`);
        if (source !== null) {
          try {
            const data = ref.selector.type === 'vector' ? JSON.parse(source) : null;
            const names = ref.selector.type === 'test' ? testNames(source, ref.path) : (Array.isArray(data) ? data : data.vectors).map(v => v.id);
            if (names.filter(n => n === ref.selector.id).length !== 1) error(at, 'STALE_EVIDENCE', `${ref.path}: ${ref.selector.id} must identify exactly one active test/vector`);
          } catch { error(at, 'STALE_EVIDENCE', `${ref.path}: cannot resolve selector`); }
        }
      }
      if (record(ref.runner, ['path', 'contains', 'command', 'runtime'], `${at}.runner`)) {
        for (const k of ['contains', 'command', 'runtime']) string(ref.runner[k], `${at}.runner.${k}`);
        const runner = file(ref.runner.path, at, 'STALE_EVIDENCE');
        if (ref.selector?.type === 'test' && typeof ref.path === 'string' && !String(ref.runner.contains).includes(ref.path.split('/').at(-1).replace(/\.ts$/, '.js')) && !String(ref.runner.contains).includes('dist/test/*.test.js')) error(at, 'STALE_EVIDENCE', 'test runner binding must name compiled test or core test glob');
        if (runner !== null && !runner.includes(ref.runner.contains)) error(at, 'STALE_EVIDENCE', `${ref.runner.path}: runner binding missing: ${ref.runner.contains}`);
      }
      if (ref.portable && (c.classification !== 'portable' || ref.selector?.type !== 'vector')) error(at, 'PORTABLE_INCONSISTENT', 'portable evidence requires a portable claim and vector selector');
      if (ref.kind === 'vector' && ref.selector?.type !== 'vector') error(at, 'MALFORMED', 'vector kind requires vector selector');
      if (ref.kind === 'adversarial' && !ref.negative) error(at, 'MALFORMED', 'adversarial evidence must be negative');
      if (ref.kind === 'cross-runtime' && (!ref.portable || !['Go', 'Python', 'Rust'].includes(ref.runner?.runtime))) error(at, 'PORTABLE_INCONSISTENT', 'cross-runtime evidence requires portable vector and independent runtime');
      if (issues.length === eBefore) evidence.push(ref);
    }
    const supported = [];
    if (impl) supported.push('TRACEABLE');
    if (impl && evidence.length) supported.push('TESTED');
    if (impl && evidence.some(e => e.kind === 'integration')) supported.push('INTEGRATION_TESTED');
    if (impl && evidence.some(e => e.negative)) supported.push('ADVERSARIAL_TESTED');
    if (impl && evidence.some(e => e.portable)) supported.push('CONFORMANCE_TESTED');
    for (const level of array(c.requiredLevels, `${at}.requiredLevels`)) {
      enumeration(level, levels, `${at}.requiredLevels`);
      if (!supported.includes(level)) error(at, 'MISSING_REQUIRED_EVIDENCE', level);
    }
    if (c.evidenceState === 'mapped' && (!impl || (c.recordType === 'requirement' && !c.requiredLevels.includes('TRACEABLE')))) error(at, 'MISSING_IMPLEMENTATION', 'mapped claim needs implementation and required TRACEABLE');
    if (c.negativeRequired && !evidence.some(e => e.negative)) error(at, 'MISSING_NEGATIVE', 'required negative evidence absent');
    if (c.portableRequired && (c.classification !== 'portable' || !evidence.some(e => e.portable))) error(at, 'PORTABLE_INCONSISTENT', 'required portable evidence absent or classification invalid');
    rows.push({ id: c.id, recordType: c.recordType, normativeState: c.normativeState, evidenceState: c.evidenceState, scopeDisposition: c.scopeDisposition, appliesWhen: c.appliesWhen, dependsOn: c.dependsOn, inferenceGuard: c.inferenceGuard, maintainerDecisionRequired: c.maintainerDecisionRequired, classification: c.classification, impl, evidence, levels: supported, valid: issues.length === before, securityCritical: c.securityCritical, negativeRequired: c.negativeRequired, portableRequired: c.portableRequired, requiredLevels: Array.isArray(c.requiredLevels) ? c.requiredLevels : [], notes: c.notes });
  }
  // Resolve after all records: forward references are permitted. No proof, obligation,
  // applicability or failure is inherited from a dependency, including cyclic context.
  for (const row of rows) for (const dependency of row.dependsOn) {
    if (isObject(dependency) && nonempty(dependency.id) && !ids.has(dependency.id)) {
      error(row.id, 'INVALID_DEPENDENCY', `unknown target ${dependency.id}`);
      row.valid = false;
    }
  }
  return { issues, rows };
}

export function report(result) {
  const { issues, rows } = result;
  const claims = rows.filter(r => r.recordType === 'requirement');
  const count = fn => claims.filter(fn).length;
  const lines = ['OxDeAI Spec-to-Code Claim Verification', '', `Registered records: ${rows.length}`, `Normative claim records (curated, not exhaustive): ${claims.length}`, `Contextual corpus locks (not executable requirements): ${rows.length - claims.length}`, 'Traceability (requirements only; references validated; evidence NOT executed by this command):',
    ` implementation mapped: ${count(r => r.impl > 0)}/${claims.length}`,
    ` executable evidence mapped: ${count(r => r.evidence.length > 0)}/${claims.length}`,
    ` integration evidence: ${count(r => r.requiredLevels.includes('INTEGRATION_TESTED') && r.levels.includes('INTEGRATION_TESTED'))}/${count(r => r.requiredLevels.includes('INTEGRATION_TESTED'))} required`,
    ` negative evidence: ${count(r => r.negativeRequired && r.evidence.some(e => e.negative))}/${count(r => r.negativeRequired)} required`,
    ` security-critical with negative evidence: ${count(r => r.securityCritical && r.evidence.some(e => e.negative))}/${count(r => r.securityCritical)}`,
    ` portable conformance evidence: ${count(r => r.classification === 'portable' && r.evidence.some(e => e.portable))}/${count(r => r.classification === 'portable')} applicable`,
    '', 'Independent dimensions and evidence capabilities (curated scope, not proof or current execution results):'];
  for (const r of rows) {
    lines.push(` ${r.id} [${r.recordType}; normative=${r.normativeState}; evidence=${r.evidenceState}; scope=${r.scopeDisposition}; ${r.classification}] ${r.levels.join(', ') || 'NO EXECUTABLE MAPPING'}`);
    if (r.appliesWhen.length) lines.push(`  Applies when (all conditions; NOT evaluated): ${r.appliesWhen.map(c => `${c?.setting}=${c?.equals}`).join(', ')}`);
    for (const d of r.dependsOn) lines.push(`  Depends on ${d?.id} (${d?.relation}; context only): ${d?.reason}`);
    for (const g of r.inferenceGuard) lines.push(`  DO NOT INFER ${g?.from} -> ${g?.to}: ${g?.reason}`);
  }
  lines.push('', 'Issues:', ` unmapped claims: ${count(r => !r.impl)}`, ` ambiguous claims: ${count(r => r.normativeState === 'ambiguous')}`, ` maintainer decisions pending (advisory): ${rows.filter(r => r.maintainerDecisionRequired).length}`, ` stale implementation refs: ${issues.filter(i => i.code === 'STALE_IMPLEMENTATION').length}`, ` stale evidence refs: ${issues.filter(i => i.code === 'STALE_EVIDENCE').length}`, ` missing required evidence: ${issues.filter(i => ['MISSING_REQUIRED_EVIDENCE', 'MISSING_NEGATIVE', 'PORTABLE_INCONSISTENT'].includes(i.code)).length}`);
  for (const r of rows.filter(r => r.maintainerDecisionRequired || r.normativeState !== 'specified' || r.evidenceState !== 'mapped' || r.scopeDisposition !== 'in-scope' || (r.securityCritical && !r.evidence.some(e => e.negative)))) lines.push(` REVIEW ${r.id}: ${r.notes}`);
  for (const i of issues) lines.push(` ERROR ${i.id} ${i.code}: ${i.detail}`);
  lines.push('', 'Mapped ≠ demonstrated. Tested ≠ portable conformance tested. Signature validity ≠ trusted premises.', 'Structural PASS is not semantic proof or whole-protocol conformance. Dependencies and pending decisions do not close locks.', 'See docs/verification/spec-claims/README.md for corpus boundaries and maintainer findings.', `RESULT: ${issues.length ? 'FAIL' : 'PASS'} (structural verification only)`);
  return lines.join('\n');
}

export function advisory(registry, root = ROOT) {
  const candidates = [], unmappedTests = [];
  const walk = dir => readdirSync(resolve(root, dir), { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : 1).flatMap(e => e.isDirectory() ? walk(`${dir}/${e.name}`) : [`${dir}/${e.name}`]);
  for (const path of walk('docs/spec').filter(p => p.endsWith('.md'))) {
    const quotes = (registry.claims ?? []).filter(c => c.recordType === 'requirement' && c.source?.role === 'normative' && c.source.path === path).map(c => c.source.quote);
    readFileSync(resolve(root, path), 'utf8').split(/\r?\n/).forEach((line, i) => {
      if (/\b(MUST|REQUIRED|SHOULD)\b/.test(line) && !quotes.some(q => q.includes(line) || line.includes(q))) candidates.push(`${path}:${i + 1}: ${line.trim()}`);
    });
  }
  const mapped = new Set((registry.claims ?? []).flatMap(c => c.evidence ?? []).map(e => `${e.path}#${e.selector?.id}`));
  for (const dir of ['packages/core/src/test', 'packages/guard/src/test', 'packages/conformance/src']) {
    for (const path of walk(dir).filter(p => p.endsWith('.test.ts'))) {
      for (const name of testNames(readFileSync(resolve(root, path), 'utf8'), path)) if (!mapped.has(`${path}#${name}`)) unmappedTests.push(`${path}#${name}`);
    }
  }
  return `ADVISORY ONLY — candidates may overlap registered claims; no CI authority\nPotential unregistered normative lines (${candidates.length}):\n${candidates.join('\n')}\nTests without a registry mapping (${unmappedTests.length}; not necessarily without a requirement):\n${unmappedTests.join('\n')}`;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    let registryPath = resolve(ROOT, REGISTRY);
    const index = args.indexOf('--registry');
    if (index !== -1) {
      if (!args[index + 1] || args[index + 1].startsWith('--')) throw Error('--registry requires a JSON path');
      registryPath = resolve(args[index + 1]);
      args.splice(index, 2);
    }
    if (args.some(a => !['--advisory', '--json'].includes(a))) throw Error('usage: node scripts/spec-claims/verify.mjs [--json] [--advisory] [--registry path]');
    const registry = JSON.parse(readFileSync(registryPath, 'utf8'));
    const result = verify(registry);
    const metadata = repositoryMetadata(ROOT);
    metadata.registry = registry;
    metadata.source.artifacts[REGISTRY] = digest(readFileSync(registryPath));
    result.evidenceScope = evidenceScope({ kind: "structural-only", metadata, consumer: "scripts/spec-claims/verify.mjs", runtime: "JavaScript" });
    console.log(args.includes('--json') ? JSON.stringify(result, null, 2) : report(result));
    if (!args.includes("--json")) console.log(JSON.stringify({ evidenceScope: result.evidenceScope }));
    if (args.includes('--advisory')) console.log(advisory(registry));
    process.exitCode = result.issues.length ? 1 : 0;
  } catch (e) { console.error(`RESULT: FAIL — ${e.message}`); process.exitCode = 1; }
}
