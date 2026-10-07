import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { validate } from '../src/contracts/schema-validator.mjs';
import { ALLOWED_CODEX_FILES } from '../src/contracts/codex-config-checker.mjs';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const abs = (...p) => path.join(ROOT, ...p);
export const readText = (...p) => fs.readFileSync(abs(...p), 'utf8');
export const readJson = (...p) => JSON.parse(readText(...p));
export const schema = (name) => readJson('schemas', `${name}.schema.json`);
export const clone = (o) => structuredClone(o);
export const isValid = (schemaName, data) => validate(schema(schemaName), data).valid;

/** Denial test: the id is the literal first argument so the registry meta-test can find it. */
export function denyTest(id, fn) {
  return test(`${id}: denial path`, fn);
}

export function walk(dir = ROOT, skip = new Set(['.git', 'node_modules'])) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (skip.has(e.name)) continue;
    const p = path.join(dir, e.name);
    out.push(p);
    if (e.isDirectory()) out.push(...walk(p, skip));
  }
  return out;
}

export const GENERIC_ENTRYPOINT_PATTERNS = [
  /sign(raw|any|arbitrary|generic|payload|typed)/i,
  /raw_?action/i,
  /private_?key/i,
  /secret_?key/i,
  /mnemonic|seed_?phrase/i,
  /eth_sign|personal_sign/i,
  /\bfetch\s*\(|\bWebSocket\b|\bXMLHttpRequest\b/,
];

/** Returns names of forbidden identifiers/patterns found in text. */
export function scanText(text, identifiers) {
  const lower = text.toLowerCase();
  const hits = identifiers.filter((id) => lower.includes(id.toLowerCase()));
  for (const re of GENERIC_ENTRYPOINT_PATTERNS) if (re.test(text)) hits.push(String(re));
  return hits;
}

export function srcFiles() {
  return walk(abs('src')).filter((p) => fs.statSync(p).isFile());
}

// ---- positive fixtures (synthetic; the numerics are FIXTURE values for tests only) ----
const H = `sha256:${'a'.repeat(64)}`;
export const validIntent = () => ({
  trade_intent_id: 'TI-20261006-000017', research_question_id: 'RQ-1', thesis_id: 'THESIS-1',
  strategy_id: 'STRAT-MOMENTUM-001', strategy_version: H, account_id: 'AIHF-CANARY-01', instrument: 'BTC',
  side: 'long', effect: 'increase', thesis: 'test thesis', evidence_refs: ['ev-1'],
  evidence_cutoff_at: '2026-10-06T12:00:00Z',
  entry: { kind: 'limit_range', min_price: '100000', max_price: '101000' },
  invalidation: { kind: 'price', price: '98000' },
  risk: { risk_budget_bps_nav: 25, max_loss_usd: '10.00', requested_notional_usd: '100.00', requested_leverage: '1' },
  execution_constraints: { allowed_order_types: ['limit_gtc'], max_slippage_bps: 8, expires_at: '2026-10-06T13:00:00Z' },
  exit_conditions: [], created_at: '2026-10-06T12:00:00Z',
});
export const validPermit = () => ({
  permit_id: 'EP-20261006-000017-01', trade_intent_id: 'TI-20261006-000017', strategy_id: 'STRAT-MOMENTUM-001',
  strategy_version: H, account: 'AIHF-CANARY-01', instrument: 'BTC', side: 'buy', effect: 'increase',
  max_total_size: '0.0010', max_notional_usd: '125.00', price_constraint: { kind: 'limit_cap', max_price: '125000' },
  max_slippage_bps: 8, allowed_order_types: ['limit_gtc', 'limit_ioc'], reduce_only: false,
  issued_at: '2026-10-06T12:00:00Z', expires_at: '2026-10-06T12:01:00Z', policy_hash: H, activation_hash: H,
  single_use_nonce: 'nonce-0123456789abcdef', authorization: 'mac-placeholder-for-test',
});
export const NUMERIC_LIMITS = Object.keys(readJson('config', 'risk-policy.template.json')).filter((k) => !k.startsWith('allow_'));
export const validRiskPolicy = () => ({
  ...Object.fromEntries(NUMERIC_LIMITS.map((k) => [k, 1])),
  allow_market_entry_orders: false, allow_protective_emergency_orders: true, allow_withdrawals: false,
  allow_transfers: false, allow_unlisted_assets: false, allow_third_party_capital: false,
});

// ---- scanner extensions ----
// Per-file import allowlist for src/. Files not listed get NO imports (fail closed). Relative './' imports are allowed.
export const SRC_IMPORT_ALLOWLIST = {
  'schema-validator.mjs': [],
  'permit-consistency.mjs': [],
  'state-machine.mjs': ['node:fs'],
  'signer-policy-consistency.mjs': ['node:fs'],
  'trust-zone-checker.mjs': ['node:fs', 'node:path'],
  'safe-state-mapping.mjs': [],
  'mcp-surface-checker.mjs': [],
  'toml-subset.mjs': [],
  'codex-config-checker.mjs': [],
  'ops-layout-checker.mjs': [],
};

/** Flags dynamic import(), require(, eval-like constructs and any import specifier outside `allowed`. */
export function scanImports(text, allowed = []) {
  const hits = [];
  if (/\bimport\s*\(/.test(text)) hits.push('dynamic import()');
  if (/\brequire\s*\(/.test(text)) hits.push('require(');
  if (/\bcreateRequire\b|\bprocess\.binding\b|\beval\s*\(|\bFunction\s*\(/.test(text)) hits.push('code-loading construct');
  // Loader-evasion forms: builtin-module getter, computed global/process access, module.constructor, aliased require/import.
  if (/\bgetBuiltinModule\b|\bprocess\s*\.\s*(?:mainModule|dlopen)\b/.test(text)) hits.push('builtin module getter');
  if (/\b(?:globalThis|global|self|window|process)\s*(?:\?\.)?\s*\[/.test(text)) hits.push('computed global access');
  if (/\bmodule\s*(?:\?\.)?\s*(?:\.\s*constructor\b|\.\s*require\b|\[)/.test(text) || /\.\s*constructor\s*\.\s*constructor\b/.test(text)) hits.push('module/constructor escape');
  if (/\bReflect\s*(?:\?\.)?\s*\.\s*(?:get|apply|construct|has|ownKeys|getOwnPropertyDescriptor)\b|\bReflect\s*\[/.test(text)) hits.push('reflective access');
  if (/getPrototypeOf\s*\([^;]*\)\s*\.\s*constructor\b|__proto__/.test(text)) hits.push('module/constructor escape');
  if (/\b(?:fs|fsp|nodeFs|promises)\s*(?:\?\.)?\s*\[/.test(text)) hits.push('computed fs access');
  if (/\brequire\b(?!\s*\()/.test(text)) hits.push('aliased require');
  if (/(?:=|,|\(|:|\[|\?|\|\||&&)\s*import\b(?!\s*[.(])/.test(text)) hits.push('aliased import');
  const re = /\b(?:import|export)\s+(?:[\w*{}\s,$]*?\s*from\s*)?['"]([^'"]+)['"]/g;
  for (const m of text.matchAll(re)) {
    const spec = m[1];
    if (/^\.\//.test(spec)) continue;
    if (!allowed.includes(spec)) hits.push(`import ${spec}`);
  }
  return hits;
}

/** Scans a file on disk with identifiers, generic patterns and the per-file import allowlist. */
export function scanFile(file, identifiers, allowedImports = []) {
  const text = fs.readFileSync(file, 'utf8');
  return [...scanText(text, identifiers), ...scanImports(text, allowedImports)];
}

export function tempDir(prefix = 'aihf-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}
export function writeFiles(dir, files) {
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  return dir;
}
/**
 * Create a non-regular entry at linkPath for "unreadable code file" fixtures.
 * Uses a file symlink; where the OS refuses (Windows without Developer Mode:
 * EPERM/EACCES) it falls back to a directory junction, which needs no
 * privilege and is equally non-regular to collectTree. Never skips.
 */
export function makeNonRegularEntry(linkPath) {
  try {
    fs.symlinkSync('/etc/hostname', linkPath);
  } catch (err) {
    if (err.code !== 'EPERM' && err.code !== 'EACCES') throw err;
    fs.symlinkSync(fs.mkdtempSync(path.join(os.tmpdir(), 'aihf-junction-')), linkPath, 'junction');
  }
  const st = fs.lstatSync(linkPath);
  if (st.isFile()) throw new Error(`fixture is a regular file: ${linkPath}`);
}

const CODEX_DIRS = new Set(['.codex', '.codex/agents']);

/** Map of repo-relative POSIX path -> text for every regular file under a top-level .codex/ directory of `dir`. */
export function codexFiles(dir) {
  const out = {};
  const root = path.join(dir, '.codex');
  if (!fs.existsSync(root)) return out;
  for (const p of walk(root)) {
    if (fs.lstatSync(p).isFile()) out[path.relative(dir, p).split(path.sep).join('/')] = fs.readFileSync(p, 'utf8');
  }
  return out;
}

/** Repository-level violations for a directory tree (used on the real repo and on temp fixtures). */
export function repoViolations(dir) {
  const v = [];
  const rel = (p) => path.relative(dir, p);
  const agents = path.join(dir, 'AGENTS.md');
  if (!fs.existsSync(agents)) v.push('AGENTS_MISSING');
  else {
    const size = fs.statSync(agents).size;
    if (size === 0) v.push('AGENTS_EMPTY');
    if (size >= 32768) v.push('AGENTS_SIZE');
  }
  for (const p of walk(dir)) {
    const r = rel(p);
    const parts = r.split(path.sep);
    const base = path.basename(r);
    if (base.toLowerCase() === 'agents.override.md') v.push(`AGENTS_OVERRIDE:${r}`);
    if (base.toLowerCase() === 'agents.md' && r !== 'AGENTS.md') v.push(`NESTED_AGENTS:${r}`);
    // Phase 1: only the reviewed .codex surface may exist; any other .codex path is denied (content is checked by checkProjectCodex).
    if (parts.includes('.codex') && !CODEX_DIRS.has(r.split(path.sep).join('/')) && !ALLOWED_CODEX_FILES.includes(r.split(path.sep).join('/'))) v.push(`CODEX_DIR:${r}`);
    if (parts.includes('.claude') || /^claude\.md$/i.test(base)) v.push(`CLAUDE_CONFIG:${r}`);
    if (/\.(key|pem|p12|pfx)$/i.test(base) || /^\.env/.test(base) || parts[0] === 'secrets' || parts[0] === '.runtime') v.push(`SECRET_FILE:${r}`);
  }
  return v;
}

// ---- comment-insensitive test-name matching ----
export function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
export function countDenyTests(sources, id) {
  const re = new RegExp(`(?:denyTest|test|it)\\(\\s*['"\`]${esc(id)}(?:['"\`]|:)`, 'g');
  return sources.reduce((n, s) => n + (stripComments(s).match(re) || []).length, 0);
}
