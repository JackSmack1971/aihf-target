import test from 'node:test';
import assert from 'node:assert/strict';
import { ROOT, readText, readJson, walk, codexFiles } from '../helpers.mjs';
import fs from 'node:fs';
import path from 'node:path';
import { parseToml, TomlError } from '../../src/contracts/toml-subset.mjs';
import {
  AGENT_ROLES, ALLOWED_CODEX_FILES, APPROVABLE_SERVERS, BOUNDARY_CLAUSE, FEATURE_PINS, REQUIREMENTS_FEATURE_PINS,
  checkProjectCodex, checkFundOpsRequirements, checkProfile,
} from '../../src/contracts/codex-config-checker.mjs';
import { checkMcpSurface } from '../../src/contracts/mcp-surface-checker.mjs';

const REQ = () => readText('config', 'codex', 'requirements.fund-ops.toml');
const OPS = () => readText('config', 'codex', 'fund-ops.config.toml');
const DEV = () => readText('config', 'codex', 'fund-dev.config.toml');
const OK = { ok: true, violations: [] };

// ---- strict TOML subset parser ----
test('toml subset: parses the supported constructs exactly', () => {
  const doc = parseToml([
    '# comment', 'a = 1', 'b = "x\\ty"', "c = 'C:\\raw'", 'd = [1, 2,', '  3,]', 'e = { f = true, g = "h" }', '',
    '[t]', 'u = -7', '[t.v]', '":read-only" = true', 'm = """', 'l1', 'l2"""', 'k.j = 1', '',
  ].join('\n'));
  assert.deepEqual(doc, { a: 1, b: 'x\ty', c: 'C:\\raw', d: [1, 2, 3], e: { f: true, g: 'h' }, t: { u: -7, v: { ':read-only': true, m: 'l1\nl2', k: { j: 1 } } } });
  assert.deepEqual(parseToml('x = 1\r\ny = """a\r\nb"""\r\n'), { x: 1, y: 'a\nb' }, 'CRLF is normalized');
  assert.throws(() => parseToml('\uFEFFx = 1\n'), TomlError, 'a byte-order mark is rejected (fail closed: consumers differ)');
});

test('toml subset: unsupported or ambiguous syntax throws (fail closed)', () => {
  const bad = ['a = 1\na = 2', '[a]\n[a]', 'x = 1.5', 'x = 2026-01-01', 'x = 0x10', '[[a]]', 'a = {b = 1}\na.c = 2', 'a.b = 1\n[a]', 'x = "abc', 'x = ', 'x = [1,', "x = 'a\nb'",
    'x = "a\nb"', '= 1', 'x = 1 y = 2', 'x = {a = 1,}', 'x = "\\q"', 'x = "\\ud800"', 'a = 1\n[a.b]', 'x = tru', 'x = 99999999999999999999', 'x = "a\u0001b"'];
  for (const s of bad) assert.throws(() => parseToml(s), TomlError, JSON.stringify(s));
  for (const k of ['__proto__', 'constructor', 'prototype']) assert.throws(() => parseToml(`${k} = 1`), TomlError, k);
  assert.throws(() => parseToml('[__proto__]\nx = 1'), TomlError);
  assert.throws(() => parseToml(null), TomlError);
});

// ---- project .codex surface ----
test('project .codex: exact reviewed file set, exact [agents] config, nine canonical roles', () => {
  const files = codexFiles(ROOT);
  assert.deepEqual(Object.keys(files).sort(), [...ALLOWED_CODEX_FILES].sort());
  assert.deepEqual(AGENT_ROLES, ['data', 'macro', 'structure', 'quant', 'catalyst', 'pm', 'risk', 'execution', 'auditor']);
  assert.deepEqual(parseToml(files['.codex/config.toml']), { agents: { enabled: true, max_concurrent_threads_per_session: 4 } });
  assert.deepEqual(checkProjectCodex(files), OK);
});

test('project .codex agents: required custom-agent fields only; nothing the parent session should own', () => {
  for (const role of AGENT_ROLES) {
    const doc = parseToml(readText('.codex', 'agents', `${role}.toml`));
    assert.deepEqual(Object.keys(doc).sort(), ['description', 'developer_instructions', 'name'], role);
    assert.equal(doc.name, role);
    assert.ok(doc.description.length > 10 && doc.description.length <= 300, role);
    assert.ok(doc.developer_instructions.includes(BOUNDARY_CLAUSE), `${role} carries the pinned boundary clause`);
  }
});

test('project .codex agents: authority rows equal the blueprint section 8 matrix (independent re-statement)', () => {
  // Blueprint section 8, restricted to the nine spawned roles. y = Y/R, n = N.
  const matrix = {
    coinvest_read: { data: 'y', macro: 'y', structure: 'y', quant: 'y', catalyst: 'y', pm: 'y', risk: 'y', execution: 'n', auditor: 'y' },
    openrouter: { data: 'n', macro: 'y', structure: 'y', quant: 'y', catalyst: 'y', pm: 'y', risk: 'y', execution: 'y', auditor: 'y' },
    scratch: { data: 'y', macro: 'y', structure: 'y', quant: 'y', catalyst: 'y', pm: 'y', risk: 'y', execution: 'y', auditor: 'n' },
    submit_intent: { pm: 'y' },
    risk_verdict: { risk: 'y' },
    exec_recommendation: { execution: 'y' },
  };
  for (const role of AGENT_ROLES) {
    const text = parseToml(readText('.codex', 'agents', `${role}.toml`)).developer_instructions;
    const line = text.split('\n').filter((l) => l.startsWith('Authority:'));
    assert.equal(line.length, 1, role);
    const kv = Object.fromEntries(line[0].slice('Authority:'.length).trim().split(/\s+/).map((p) => p.split('=')));
    for (const [row, who] of Object.entries(matrix)) assert.equal(kv[row] === 'yes', who[role] === 'y', `${role}.${row}`);
    for (const never of ['coinvest_writes', 'sign', 'key_access', 'policy_change', 'transfer']) assert.equal(kv[never], 'no', `${role}.${never}`);
    assert.equal(kv.market_data, 'read');
    assert.equal(kv.fund_state, 'read');
  }
  const submitters = AGENT_ROLES.filter((r) => /submit_intent=yes/.test(readText('.codex', 'agents', `${r}.toml`)));
  assert.deepEqual(submitters, ['pm']);
});

test('project .codex agents: no agent file carries sandbox, MCP, model, permission or approval settings', () => {
  for (const f of ALLOWED_CODEX_FILES.filter((x) => x.includes('/agents/'))) {
    const text = readText(...f.split('/'));
    for (const key of ['sandbox_mode', 'mcp_servers', 'model', 'permissions', 'approval_policy', 'default_permissions', 'features', 'hooks', 'skills', 'web_search']) {
      assert.ok(!Object.hasOwn(parseToml(text), key), `${f} must not set ${key}`);
      assert.ok(!new RegExp(`^\\[?${key}\\b`, 'm').test(text), `${f} must not declare ${key}`);
    }
  }
});

// ---- profiles and managed requirements ----
test('managed requirements: generated shape is accepted and pins exactly the reviewed policy', () => {
  assert.deepEqual(checkFundOpsRequirements(REQ()), OK);
  const d = parseToml(REQ());
  assert.equal(d.default_permissions, ':read-only');
  assert.deepEqual(d.allowed_permission_profiles, { ':read-only': true });
  assert.ok(!Object.keys(d.allowed_permission_profiles).includes(':danger-full-access'), 'full access omitted = denied');
  assert.deepEqual(d.allowed_sandbox_modes, ['read-only']);
  assert.deepEqual(d.allowed_approval_policies, ['on-request']);
  assert.deepEqual(d.allowed_approvals_reviewers, ['user']);
  assert.deepEqual(d.allowed_web_search_modes, ['cached']);
  assert.equal(d.allow_managed_hooks_only, true);
  assert.equal(d.allow_browser_and_computer_use, false);
  assert.deepEqual(d.features, REQUIREMENTS_FEATURE_PINS);
  assert.equal(d.features.memories, false, 'OD-7: Memories pinned off in the managed requirements');
  for (const v of Object.values(d.features)) assert.equal(v, false);
  assert.deepEqual(d.windows, { allowed_sandbox_implementations: ['elevated'] });
});

test('managed requirements: MCP allowlist is present and EMPTY (every MCP server disabled until a reviewed identity is added)', () => {
  const d = parseToml(REQ());
  assert.deepEqual(d.mcp_servers, {});
  assert.ok(/^\[mcp_servers\]\s*$/m.test(REQ()), 'explicit empty table header');
  assert.deepEqual(APPROVABLE_SERVERS, ['fund-state-mcp', 'intent-gateway-mcp']);
});

test('user profiles: shipped fund-ops and fund-dev profiles are accepted and register no MCP server', () => {
  assert.deepEqual(checkProfile('fund-ops', OPS(), REQ()), OK);
  assert.deepEqual(checkProfile('fund-dev', DEV()), OK);
  const ops = parseToml(OPS());
  assert.equal(ops.default_permissions, ':read-only');
  assert.equal(ops.approval_policy, 'on-request');
  assert.equal(ops.approvals_reviewer, 'user');
  assert.equal(ops.web_search, 'cached');
  assert.equal(ops.sandbox_mode, undefined, 'sandbox_mode would switch Codex to the legacy sandbox path');
  assert.deepEqual(ops.features, FEATURE_PINS);
  assert.equal(ops.mcp_servers, undefined);
  const dev = parseToml(DEV());
  assert.equal(dev.default_permissions, ':workspace');
  assert.equal(dev.mcp_servers, undefined);
  for (const [name, text] of [['fund-ops', OPS()], ['fund-dev', DEV()]]) {
    assert.ok(!/^\[profiles\./m.test(text) && !/^profile\s*=/m.test(text), `${name}: legacy profile tables/selectors are unsupported since Codex 0.134`);
  }
});

test('profiles and requirements live outside the project .codex directory and the repo has no other Codex config', () => {
  for (const f of ['fund-ops.config.toml', 'fund-dev.config.toml', 'requirements.fund-ops.toml']) {
    assert.ok(fs.existsSync(path.join(ROOT, 'config', 'codex', f)), f);
    assert.ok(!fs.existsSync(path.join(ROOT, '.codex', f)), `${f} must not be a project .codex file`);
  }
  const stray = walk().map((p) => path.relative(ROOT, p).split(path.sep).join('/'))
    .filter((p) => /(^|\/)(requirements|managed_config)[^/]*\.toml$|(^|\/)config\.toml$|\.config\.toml$/.test(p));
  assert.deepEqual(stray.sort(), ['.codex/config.toml', 'config/codex/fund-dev.config.toml', 'config/codex/fund-ops.config.toml', 'config/codex/requirements.fund-ops.toml'].sort());
});

// ---- Co-Invest, MCP surface, secrets, Phase-0 invariants ----
test('no direct production registration of an unrestricted Co-Invest endpoint anywhere in Codex configuration', () => {
  const texts = [...Object.values(codexFiles(ROOT)), REQ(), OPS(), DEV()];
  for (const t of texts) {
    assert.ok(!/liquid\.trade/i.test(t), 'no Liquid upstream host');
    assert.ok(!/coinvest[-_ ]?(computer|main|restricted)/i.test(t), 'no Computer/Main/Restricted endpoint');
    assert.ok(!/^\s*url\s*=/m.test(t), 'no HTTP MCP registration at all in P1-S1');
    assert.ok(!/^\[mcp_servers\.[^\]]+\]/m.test(t), 'no MCP server registered in P1-S1');
  }
});

test('tool allowlists never default open: the MCP surface contract is untouched and no server is registered', () => {
  assert.deepEqual(checkMcpSurface(readJson('contracts', 'mcp-surface.json')), OK);
  for (const s of readJson('contracts', 'mcp-surface.json').servers) {
    if (['fin-data-mcp', 'massive-mcp', 'hyperliquid-info-mcp', 'openrouter-committee-mcp'].includes(s.id)) assert.deepEqual(s.enabled_tools, [], `${s.id} stays at zero tools`);
  }
});

test('AGENTS.md carries the reviewed-surface rule and keeps the other repository prohibitions', () => {
  const t = readText('AGENTS.md');
  assert.ok(!/does not exist yet/i.test(t), 'obsolete Phase 0 sentence removed');
  assert.ok(/\.codex\/config\.toml/.test(t) && /\.codex\/agents\/<role>\.toml/.test(t));
  assert.ok(/Never create `AGENTS\.override\.md`/.test(t), 'override file stays prohibited');
  assert.ok(/Do not add `\.claude\/` configuration/.test(t), 'target .claude stays prohibited');
  assert.ok(/never set approval, sandbox, permission, MCP, feature, hook or profile keys/i.test(t));
  assert.ok(fs.statSync(path.join(ROOT, 'AGENTS.md')).size < 32768);
});

test('registry still lists the .codex denial as enforced with an unchanged id and contract', () => {
  const e = readJson('contracts', 'forbidden-capabilities.json').capabilities.find((c) => c.id === 'EARLY_CODEX_CONFIG');
  assert.equal(e.denial_test, 'DENY-REPO-EARLY-CODEX-CONFIG');
  assert.equal(e.enforcement, 'enforced');
  assert.equal(e.enforced_in_phase, 0);
  assert.equal(e.contract, 'AGENTS.md');
});
