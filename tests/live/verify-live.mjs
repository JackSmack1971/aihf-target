#!/usr/bin/env node
// Live runtime verification of the Phase 1 Codex configuration layer against the INSTALLED Codex (target: codex-cli 0.160.1).
// Operator/CI tooling, not product code (it spawns Codex and writes scratch files, so it lives under tests/). It is not run by `node --test`.
//
// Usage: node tests/live/verify-live.mjs --mode isolated|managed [--codex <codex.exe>] [--out <report.json>]
//                                        [--emit-test-requirements <file>]
//   CODEX_EXE may replace --codex.
//
// Safety: every session runs with a scratch CODEX_HOME and a dummy MCP fixture; no model call is made (app-server JSON-RPC only);
// it never reads or writes the operator's real Codex home. It never installs anything. `managed` mode only OBSERVES the
// system requirements file the operator installed deliberately (%ProgramData%\OpenAI\Codex\requirements.toml or /etc/codex/requirements.toml).
//
// Classification: results are STATICALLY VERIFIED (unit tests) vs LIVE. LIVE ENFORCEMENT VERIFIED is claimed only by a `managed` run in which
// the requirements are installed AND every MAN-* check passes (run once with the production template and once with --emit-test-requirements output).
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TARGET = path.resolve(HERE, '..', '..');
const FIXTURE = path.join(HERE, 'fixture-mcp.mjs');
const NODE = process.execPath;

const argv = process.argv.slice(2);
const opt = (name, dflt = null) => { const i = argv.indexOf(`--${name}`); return i >= 0 ? argv[i + 1] : dflt; };
const MODE = opt('mode', 'isolated');
const CODEX = opt('codex', process.env.CODEX_EXE ?? null);
const OUT = opt('out');
const EMIT = opt('emit-test-requirements');

const read = (...p) => fs.readFileSync(path.join(TARGET, ...p), 'utf8');
const sha256 = (s) => crypto.createHash('sha256').update(s.replace(/\r\n/g, '\n')).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const lit = (s) => `'${s}'`; // TOML literal string: no escapes, safe for Windows paths

// ---------------------------------------------------------------- test-only requirements variant
function testRequirements() {
  const base = read('config', 'codex', 'requirements.fund-ops.toml');
  return `${base}
# ---- TEST VARIANT ONLY (tests/live/verify-live.mjs --emit-test-requirements): never install this on a production runtime ----
[mcp_servers.fx_ok.identity]
command = { executable = ${lit(NODE)}, args = [ { match = "exact", value = ${lit(FIXTURE)} } ] }
[mcp_servers.fx_drift.identity]
command = { executable = ${lit(NODE)}, args = [ { match = "exact", value = ${lit(FIXTURE)} }, { match = "exact", value = "--approved-arg" } ] }
`;
}
if (EMIT) {
  fs.writeFileSync(EMIT, testRequirements());
  console.log(`wrote test requirements variant: ${EMIT}\nsha256=${sha256(testRequirements())}`);
  process.exit(0);
}
if (!['isolated', 'managed'].includes(MODE)) { console.error('--mode must be isolated or managed'); process.exit(64); }
if (!CODEX || !fs.existsSync(CODEX)) { console.error('Codex executable not found: pass --codex <path> or set CODEX_EXE (the native codex binary, not the npm shim)'); process.exit(64); }

// ---------------------------------------------------------------- scratch + JSON-RPC client over `codex app-server`
const scratchDirs = [];
function scratch() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aihf-live-'));
  scratchDirs.push(root);
  const home = path.join(root, 'codex-home');
  fs.mkdirSync(home);
  return { root, home };
}
async function cleanup() {
  for (const d of scratchDirs) {
    for (let i = 0; i < 6; i++) {
      try { fs.rmSync(d, { recursive: true, force: true }); break; } catch { await sleep(700); }
    }
    if (fs.existsSync(d)) console.error(`note: scratch directory left behind (locked): ${d}`);
  }
}

async function session(home, { strict = true } = {}) {
  const child = spawn(CODEX, ['app-server', ...(strict ? ['--strict-config'] : [])], { env: { ...scrubbedEnv(), CODEX_HOME: home }, stdio: ['pipe', 'pipe', 'pipe'] });
  let id = 0;
  let buf = '';
  let stderr = '';
  const pending = new Map();
  const notes = [];
  child.stdout.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      try {
        const m = JSON.parse(line);
        if (m.id !== undefined && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } else if (m.method) notes.push(m);
      } catch { /* ignore non-JSON */ }
    }
  });
  child.stderr.on('data', (d) => { stderr += d; });
  const exited = new Promise((r) => child.on('exit', (c) => r(c)));
  const rpc = (method, params) => new Promise((resolve) => {
    const i = ++id;
    pending.set(i, resolve);
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: i, method, params })}\n`);
    setTimeout(() => { if (pending.delete(i)) resolve({ timeout: method }); }, 30000);
  });
  const init = await Promise.race([rpc('initialize', { clientInfo: { name: 'aihf-live', version: '0' } }), exited.then((c) => ({ exited: c }))]);
  if (init.result) child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'initialized' })}\n`);
  return { rpc, notes, init, stderr: () => stderr, exited, stop: async () => { child.kill(); await Promise.race([exited, sleep(3000)]); } };
}

// The child gets no API credentials: only local app-server JSON-RPC is used.
const scrubbedEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !/(^|_)(API_KEY|TOKEN|SECRET|PASSWORD)$|^(OPENAI|CODEX|ANTHROPIC)_.*(KEY|TOKEN)/i.test(k)));
const RESULTS = [];
const record = (id, status, summary, evidence = {}) => { RESULTS.push({ id, status, summary, evidence }); console.log(`${status.padEnd(11)} ${id.padEnd(34)} ${summary}`); };
const toolNames = (s) => Object.keys(s?.tools ?? {}).sort();
const within = (t) => !!t.result && t.result.sandbox?.type === 'readOnly' && t.result.approvalPolicy === 'on-request' && t.result.approvalsReviewer === 'user'
  && (t.result.activePermissionProfile == null || t.result.activePermissionProfile.id === ':read-only');

function mcpConfig() {
  return `
[mcp_servers.fx_ok]
command = ${lit(NODE)}
args = [${lit(FIXTURE)}]
enabled_tools = ["dummy_read_a", "dummy_read_b"]

[mcp_servers.fx_rogue]
command = ${lit(NODE)}
args = [${lit(FIXTURE)}, "--rogue"]

[mcp_servers.fx_drift]
command = ${lit(NODE)}
args = [${lit(FIXTURE)}, "--unapproved-arg"]
enabled_tools = ["dummy_read_a"]

[mcp_servers.fx_open]
command = ${lit(NODE)}
args = [${lit(FIXTURE)}, "--no-allowlist"]
`;
}
async function mcpTools(extraConfig = '') {
  const { home } = scratch();
  fs.writeFileSync(path.join(home, 'config.toml'), mcpConfig() + extraConfig);
  const s = await session(home);
  const st = await s.rpc('mcpServerStatus/list', {});
  await s.stop();
  return Object.fromEntries((st.result?.data ?? []).map((e) => [e.name, toolNames(e)]));
}

const OVERRIDES = [
  ['sandbox=danger-full-access', { sandbox: 'danger-full-access' }],
  ['sandbox=workspace-write', { sandbox: 'workspace-write' }],
  ['approval=never', { approvalPolicy: 'never' }],
  ['danger + never', { sandbox: 'danger-full-access', approvalPolicy: 'never' }],
  ['reviewer=auto_review', { approvalsReviewer: 'auto_review' }],
  ['config default_permissions=:danger-full-access', { config: { default_permissions: ':danger-full-access' } }],
  ['config default_permissions=:workspace', { config: { default_permissions: ':workspace' } }],
  ['config sandbox_mode=danger-full-access', { config: { sandbox_mode: 'danger-full-access' } }],
];

// ---------------------------------------------------------------- isolated checks (no managed requirements needed)
async function isolated() {
  const { root, home } = scratch();
  const ws = path.join(root, 'ws');
  fs.mkdirSync(path.join(ws, '.codex', 'agents'), { recursive: true });
  for (const f of ['config.toml']) fs.copyFileSync(path.join(TARGET, '.codex', f), path.join(ws, '.codex', f));
  for (const f of fs.readdirSync(path.join(TARGET, '.codex', 'agents'))) fs.copyFileSync(path.join(TARGET, '.codex', 'agents', f), path.join(ws, '.codex', 'agents', f));
  // Codex keys project trust by the lower-cased native path.
  fs.writeFileSync(path.join(home, 'config.toml'), `[projects.${lit(path.resolve(ws).toLowerCase())}]\ntrust_level = "trusted"\n`);
  let s = await session(home);
  const cfg = await s.rpc('config/read', { cwd: ws, includeLayers: true });
  const proj = (cfg.result?.layers ?? []).find((l) => l.name?.type === 'project');
  const a = cfg.result?.config?.agents;
  record('ISO-1 project-layer-loads', proj && !proj.disabledReason && a?.enabled === true && a?.max_concurrent_threads_per_session === 4 ? 'PASS' : 'FAIL',
    'trusted project: effective [agents] equals the reviewed project config', { agents: a, layerConfig: proj?.config, disabledReason: proj?.disabledReason });
  await s.rpc('thread/start', { cwd: ws });
  await sleep(500);
  const warn = s.notes.filter((n) => n.method === 'configWarning').map((n) => n.params?.summary);
  const agentWarn = warn.filter((w) => /agent/i.test(w ?? ''));
  await s.stop();
  fs.writeFileSync(path.join(ws, '.codex', 'agents', 'broken.toml'), 'name = "broken"\n');
  s = await session(home);
  await s.rpc('thread/start', { cwd: ws });
  await sleep(500);
  const warn2 = s.notes.filter((n) => n.method === 'configWarning').map((n) => n.params?.summary);
  await s.stop();
  const ctlOk = warn2.some((w) => /broken\.toml/.test(w ?? ''));
  record('ISO-2 agent-files-load', agentWarn.length === 0 && ctlOk ? 'PASS' : 'FAIL',
    'nine reviewed agent files raise no loader warning; a malformed control file is reported (control is discriminating)', { warningsForReviewedFiles: agentWarn, controlWarnings: warn2 });

  // untrusted project: the project layer must be ignored
  const u = scratch();
  fs.writeFileSync(path.join(u.home, 'config.toml'), '');
  s = await session(u.home);
  const ucfg = await s.rpc('config/read', { cwd: ws, includeLayers: true });
  await s.stop();
  const uproj = (ucfg.result?.layers ?? []).find((l) => l.name?.type === 'project');
  record('ISO-3 untrusted-project-ignored', (uproj ? !!uproj.disabledReason : true) && ucfg.result?.config?.agents == null ? 'PASS' : 'FAIL',
    'untrusted project: project .codex layer is disabled and contributes nothing', { disabledReason: uproj?.disabledReason, agents: ucfg.result?.config?.agents });

  // profile content parses strictly and yields the intended effective values (applied as a user layer; app-server cannot select --profile)
  for (const [name, expect] of [['fund-ops', { default_permissions: ':read-only', approval_policy: 'on-request', approvals_reviewer: 'user', web_search: 'cached' }],
    ['fund-dev', { default_permissions: ':workspace', approval_policy: 'on-request', approvals_reviewer: 'user', web_search: 'cached' }]]) {
    const p = scratch();
    fs.writeFileSync(path.join(p.home, 'config.toml'), read('config', 'codex', `${name}.config.toml`));
    s = await session(p.home);
    const pc = await s.rpc('config/read', { includeLayers: false });
    await s.stop();
    const c = pc.result?.config ?? {};
    const okVals = Object.entries(expect).every(([k, v]) => c[k] === v);
    const okFeat = name === 'fund-dev' || ['apps', 'plugins', 'remote_plugin', 'browser_use', 'browser_use_external', 'browser_use_full_cdp_access', 'computer_use', 'in_app_browser'].every((k) => c.features?.[k] === false);
    record(`ISO-4 profile-${name}-strict`, pc.result && okVals && okFeat ? 'PASS' : 'FAIL', 'profile content accepted by --strict-config with the intended effective values', { effective: Object.fromEntries(Object.keys(expect).map((k) => [k, c[k]])) });
  }
  const bad = scratch();
  fs.writeFileSync(path.join(bad.home, 'config.toml'), 'bogus_unknown_key = 1\n');
  s = await session(bad.home);
  const badExit = await Promise.race([s.exited, sleep(8000).then(() => 'running')]);
  await s.stop();
  record('ISO-4c strict-control', badExit !== 'running' && badExit !== 0 && /unknown configuration field/.test(s.stderr()) ? 'CONTROL' : 'FAIL',
    'an unknown key is rejected by --strict-config (so ISO-4 acceptance is discriminating)', { exit: badExit });

  // tool exposure
  const tools = await mcpTools();
  record('ISO-5 enabled_tools-subset', JSON.stringify(tools.fx_ok) === JSON.stringify(['dummy_read_a', 'dummy_read_b']) ? 'PASS' : 'FAIL',
    'enabled_tools exposes only the allowlisted dummy subset; the non-allowlisted dummy tool is unavailable', { fx_ok: tools.fx_ok, fx_drift: tools.fx_drift });
  record('ISO-5b open-by-default-control', JSON.stringify(tools.fx_open) === JSON.stringify(['dummy_read_a', 'dummy_read_b', 'dummy_write_c']) ? 'CONTROL' : 'FAIL',
    'a server WITHOUT enabled_tools exposes every tool (fail-open default: why the checker forbids it)', { fx_open: tools.fx_open });

  // baseline: without managed requirements ordinary overrides SUCCEED (negative control for the managed checks)
  const b = scratch();
  fs.writeFileSync(path.join(b.home, 'config.toml'), '');
  s = await session(b.home);
  const def = await s.rpc('thread/start', { cwd: b.root });
  const dangerous = [];
  for (const [label, p] of OVERRIDES) {
    const t = await s.rpc('thread/start', { cwd: b.root, ...p });
    if (!within(t)) dangerous.push(label);
  }
  await s.stop();
  record('ISO-6 baseline-overrides-succeed', within(def) && dangerous.length >= 4 ? 'CONTROL' : 'FAIL',
    'WITHOUT managed requirements the ordinary overrides escape read-only/on-request (negative control; managed checks must show the opposite)', { escapedOverrides: dangerous });
}

// ---------------------------------------------------------------- managed checks (operator must have installed requirements)
const SYSTEM_REQ = process.platform === 'win32' ? path.join(process.env.ProgramData ?? 'C:\\ProgramData', 'OpenAI', 'Codex', 'requirements.toml') : '/etc/codex/requirements.toml';
async function managed() {
  const installed = fs.existsSync(SYSTEM_REQ) ? fs.readFileSync(SYSTEM_REQ, 'utf8') : null;
  const prod = sha256(read('config', 'codex', 'requirements.fund-ops.toml'));
  const variant = sha256(testRequirements());
  const have = installed === null ? null : sha256(installed);
  const which = have === null ? 'none' : have === prod ? 'production-template' : have === variant ? 'test-variant' : 'unknown';
  record('MAN-0 requirements-installed', have !== null && which !== 'unknown' ? 'PASS' : 'FAIL',
    `system requirements file ${have === null ? 'NOT installed' : `installed (${which})`} at ${SYSTEM_REQ}`, { sha256: have, production: prod, testVariant: variant });
  const { home } = scratch();
  fs.writeFileSync(path.join(home, 'config.toml'), mcpConfig());
  const s = await session(home);
  const req = await s.rpc('configRequirements/read', {});
  record('MAN-0b runtime-sees-requirements', req.result?.requirements ? 'PASS' : 'FAIL', 'the running Codex reports non-null managed requirements', { requirements: req.result?.requirements ?? null });
  const r = req.result?.requirements ?? {};
  const js = JSON.stringify;
  const feat = js(r.featureRequirements ?? {});
  const featOk = ['apps', 'plugins', 'remote_plugin', 'browser_use', 'browser_use_external', 'browser_use_full_cdp_access', 'computer_use', 'in_app_browser'].every((k) => new RegExp(`"${k}":false`).test(feat));
  const webOk = Array.isArray(r.allowedWebSearchModes) && r.allowedWebSearchModes.includes('cached') && r.allowedWebSearchModes.every((m) => ['cached', 'disabled'].includes(m));
  const winOk = process.platform !== 'win32' || js(r.allowedWindowsSandboxImplementations) === js(['elevated']);
  const fieldChecks = {
    permissionProfiles: js(r.allowedPermissionProfiles) === js({ ':read-only': true }), defaultPermissions: r.defaultPermissions === ':read-only',
    sandboxModes: js(r.allowedSandboxModes) === js(['read-only']), approvalPolicies: js(r.allowedApprovalPolicies) === js(['on-request']), webSearch: webOk,
    managedHooksOnly: r.allowManagedHooksOnly === true, browserComputer: r.allowBrowserAndComputerUse === false, features: featOk, windowsSandbox: winOk,
  };
  record('MAN-0c runtime-requirement-fields', Object.values(fieldChecks).every(Boolean) ? 'PASS' : 'FAIL',
    'runtime-reported requirements equal the reviewed policy on every field Codex exposes (approvals reviewer and mcp_servers are not exposed: covered behaviorally by MAN-1/MAN-2)',
    { fieldChecks, reported: r });
  const bad = [];
  const results = {};
  for (const [label, p] of [['default', {}], ...OVERRIDES]) {
    const t = await s.rpc('thread/start', { cwd: home, ...p });
    results[label] = t.error ? `error: ${JSON.stringify(t.error).slice(0, 120)}` : { sandbox: t.result?.sandbox?.type, approval: t.result?.approvalPolicy, reviewer: t.result?.approvalsReviewer, profile: t.result?.activePermissionProfile?.id ?? null };
    if (!t.error && !within(t)) bad.push(label);
  }
  record('MAN-1 overrides-cannot-escape', bad.length === 0 ? 'PASS' : 'FAIL',
    'every ordinary session/CLI-style override leaves the session inside read-only / on-request / user-reviewed (denied or clamped)', { escaped: bad, results });
  const st = await s.rpc('mcpServerStatus/list', {});
  await s.stop();
  const t = Object.fromEntries((st.result?.data ?? []).map((e) => [e.name, toolNames(e)]));
  const stOk = Array.isArray(st.result?.data); // a failed status call must not read as 'no tools exposed'
  record('MAN-2 unlisted-server-disabled', stOk && (t.fx_rogue ?? []).length === 0 && (t.fx_open ?? []).length === 0 ? 'PASS' : 'FAIL',
    'servers not in the managed identity allowlist expose no tools', { fx_rogue: t.fx_rogue ?? null, fx_open: t.fx_open ?? null });
  if (which === 'test-variant') {
    record('MAN-3 identity-drift-disabled', (t.fx_drift ?? []).length === 0 ? 'PASS' : 'FAIL', 'allowlisted NAME with a non-matching command/args identity is disabled', { fx_drift: t.fx_drift ?? null });
    record('MAN-4 allowed-identity-accepted', JSON.stringify(t.fx_ok) === JSON.stringify(['dummy_read_a', 'dummy_read_b']) ? 'PASS' : 'FAIL',
      'an allowlisted identity is accepted and enabled_tools still exposes only the intended dummy subset', { fx_ok: t.fx_ok ?? null });
  } else {
    record('MAN-3 identity-drift-disabled', 'UNVERIFIED', 'needs the test variant installed (emit with --emit-test-requirements)');
    record('MAN-4 allowed-identity-accepted', stOk && which === 'production-template' && (t.fx_ok ?? []).length === 0 ? 'PASS' : 'UNVERIFIED',
      which === 'production-template' ? 'production template ships an EMPTY allowlist: even the dummy "ok" server is disabled (all MCP off)' : 'needs the test variant installed');
  }
}

// ---------------------------------------------------------------- run
(async () => {
  console.log(`# verify-live mode=${MODE} codex=${CODEX}`);
  const ver = await new Promise((resolve) => { const c = spawn(CODEX, ['--version']); let o = ''; c.stdout.on('data', (d) => { o += d; }); c.on('exit', () => resolve(o.trim())); });
  console.log(`# ${ver}`);
  try { await (MODE === 'isolated' ? isolated() : managed()); } catch (e) { record('HARNESS', 'FAIL', `harness error: ${e.message}`); }
  await cleanup();
  const failed = RESULTS.filter((r) => r.status === 'FAIL');
  const unverified = RESULTS.filter((r) => r.status === 'UNVERIFIED');
  const classification = MODE === 'managed' && failed.length === 0 && unverified.length === 0 ? 'LIVE ENFORCEMENT VERIFIED (this requirements variant)'
    : MODE === 'managed' ? 'LIVE ENFORCEMENT NOT VERIFIED' : 'RUNTIME ACCEPTANCE/NEGATIVE CONTROLS ONLY (no managed enforcement exercised)';
  console.log(`# classification: ${classification}; pass=${RESULTS.filter((r) => r.status === 'PASS').length} control=${RESULTS.filter((r) => r.status === 'CONTROL').length} fail=${failed.length} unverified=${unverified.length}`);
  if (OUT) fs.writeFileSync(OUT, `${JSON.stringify({ mode: MODE, codex: ver, at: new Date().toISOString(), classification, results: RESULTS }, null, 2)}\n`);
  process.exit(failed.length ? 2 : 0);
})();
