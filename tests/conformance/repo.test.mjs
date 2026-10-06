import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { ROOT, abs, readText, readJson, walk, denyTest, repoViolations, tempDir, writeFiles } from '../helpers.mjs';

const rel = (p) => path.relative(ROOT, p);
const files = () => walk().map(rel);

test('AGENTS.md exists, is non-empty, and names its contract files', () => {
  const t = readText('AGENTS.md');
  assert.ok(t.trim().length > 0);
  for (const s of ['contracts/forbidden-capabilities.json', 'AGENTS.override.md', 'node --test', 'contracts/trust-zones.json']) {
    assert.ok(t.includes(s), `AGENTS.md must mention ${s}`);
  }
});

const fixture = (extra) => writeFiles(tempDir(), { 'AGENTS.md': 'ok\n', ...extra });
const codes = (d) => repoViolations(d).map((x) => x.split(':')[0]);

denyTest('DENY-REPO-AGENTS-TRUNCATION', () => {
  const size = fs.statSync(abs('AGENTS.md')).size;
  assert.ok(size > 0 && size < 32768, `AGENTS.md is ${size} bytes`);
  assert.deepEqual(codes(fixture({})), [], 'positive control');
  assert.ok(codes(fixture({ 'AGENTS.md': 'x'.repeat(32768) })).includes('AGENTS_SIZE'));
  assert.ok(codes(fixture({ 'AGENTS.md': '' })).includes('AGENTS_EMPTY'));
  assert.ok(codes(writeFiles(tempDir(), {})).includes('AGENTS_MISSING'));
});

denyTest('DENY-REPO-AGENTS-OVERRIDE', () => {
  assert.deepEqual(files().filter((f) => path.basename(f).toLowerCase() === 'agents.override.md'), []);
  assert.ok(codes(fixture({ 'AGENTS.override.md': 'x' })).includes('AGENTS_OVERRIDE'));
  assert.ok(codes(fixture({ 'sub/dir/agents.override.md': 'x' })).includes('AGENTS_OVERRIDE'));
});

test('no nested AGENTS.md exists until registered by a reviewed decision', () => {
  assert.deepEqual(files().filter((f) => path.basename(f).toLowerCase() === 'agents.md' && f !== 'AGENTS.md'), []);
  assert.ok(codes(fixture({ 'pkg/AGENTS.md': 'x' })).includes('NESTED_AGENTS'));
  assert.deepEqual(repoViolations(ROOT), [], 'real repository has no violations');
});

denyTest('DENY-REPO-EARLY-CODEX-CONFIG', () => {
  assert.deepEqual(files().filter((f) => f.split(path.sep).includes('.codex')), []);
  assert.ok(codes(fixture({ '.codex/config.toml': 'x' })).includes('CODEX_DIR'));
});

denyTest('DENY-REPO-CLAUDE-CONFIG', () => {
  assert.deepEqual(files().filter((f) => f.split(path.sep).includes('.claude') || /^claude\.md$/i.test(path.basename(f))), []);
  assert.ok(codes(fixture({ '.claude/settings.json': '{}' })).includes('CLAUDE_CONFIG'));
  assert.ok(codes(fixture({ 'CLAUDE.md': 'x' })).includes('CLAUDE_CONFIG'));
});

denyTest('DENY-REPO-SECRET-FILES', () => {
  const bad = files().filter((f) => /\.(key|pem|p12|pfx)$/i.test(f) || /^\.env/.test(path.basename(f)) || f.split(path.sep)[0] === 'secrets' || f.split(path.sep)[0] === '.runtime');
  assert.deepEqual(bad, []);
  for (const f of ['wallet.key', 'a/b.pem', '.env', '.env.local', 'secrets/x', '.runtime/state']) assert.ok(codes(fixture({ [f]: 'x' })).includes('SECRET_FILE'), f);
  const ignore = readText('.gitignore').split('\n').map((l) => l.trim());
  for (const p of ['.runtime/', '*.key', '*.pem', '.env*', 'secrets/']) assert.ok(ignore.includes(p), `.gitignore missing ${p}`);
});

test('no secret-looking material in tracked text files', () => {
  const re = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\b0x[0-9a-fA-F]{64}\b/;
  for (const f of files()) {
    const p = abs(f);
    if (!fs.statSync(p).isFile()) continue;
    assert.ok(!re.test(fs.readFileSync(p, 'utf8')), `secret-like content in ${f}`);
  }
});

test('package.json is zero-dependency Node>=22 ESM with node --test', () => {
  const p = readJson('package.json');
  assert.equal(p.type, 'module');
  assert.equal(p.private, true);
  assert.equal(p.engines.node, '>=22');
  assert.equal(p.scripts.test, 'node --test');
  for (const k of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) assert.equal(p[k], undefined, k);
});

test('required Phase 0 artifacts exist', () => {
  for (const f of ['README.md', 'docs/architecture.md', 'docs/threat-model.md', 'contracts/trust-zones.json', 'contracts/threat-model.json',
    'contracts/runtime-state-machine.json', 'contracts/trade-intent-state-machine.json', 'contracts/forbidden-capabilities.json',
    'schemas/trade-intent.schema.json', 'schemas/execution-permit.schema.json', 'schemas/risk-policy.schema.json', 'schemas/signer-policy.schema.json',
    'config/risk-policy.template.json', 'config/signer-policy.json', 'src/contracts/schema-validator.mjs', 'src/contracts/state-machine.mjs']) {
    assert.ok(fs.existsSync(abs(f)), `${f} missing`);
  }
});
