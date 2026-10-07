#!/usr/bin/env node
// Live adversarial verification of the isolated fund-ops runtime against the INSTALLED Codex and the INSTALLED system requirements.
// Operator/CI tooling, not product code (it spawns Codex and writes scratch files, so it lives under tests/). Not run by `node --test`.
// Run as the ops identity inside the dedicated distro (the provisioning proof harness does this); never as root.
//
//   node verify-ops-runtime.mjs --codex <codex> --release <current> --mode enforced|control [--out report.json]
//
// Evidence levels (never collapsed into one claim):
//   CONFIG_LOAD_VERIFIED          the running Codex reports the effective configuration/requirements (config/read, thread/start, banner)
//   RUNTIME_ENFORCEMENT_VERIFIED  the Codex sandbox actually denied an action (codex sandbox), or an unlisted server really exposed no tools
//   MODEL_TOOL_PATH_VERIFIED      a model-driven tool call was denied. NOT verified here: no credentials, no model call is ever made.
//
// Modes: `enforced` = system requirements installed: every escape attempt must be clamped/denied. `control` = the orchestrator moved the
// requirements aside: the same attempts must SUCCEED, which proves the battery is sensitive (a broken harness cannot report a vacuous pass).
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const argv = process.argv.slice(2);
const opt = (n, d = null) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : d; };
const CODEX = opt('codex');
const RELEASE = opt('release');
const MODE = opt('mode', 'enforced');
const OUT = opt('out');
const NODE = process.execPath;
const SCRATCH_ROOT = opt('scratch', '/var/lib/aihf/runtime/scratch');
const REAL_HOME = opt('codex-home', '/var/lib/aihf/ops/codex-home');
if (!CODEX || !RELEASE || !['enforced', 'control'].includes(MODE)) { console.error('usage: --codex <path> --release <dir> --mode enforced|control'); process.exit(64); }
if (typeof process.getuid === 'function' && process.getuid() === 0) { console.error('REFUSED: run as the unprivileged ops identity, not root'); process.exit(64); }

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const lit = (s) => `'${s}'`;
const RUN = fs.mkdtempSync(path.join(SCRATCH_ROOT, 'live-'));
const BASE_ENV = { PATH: '/usr/bin:/bin', HOME: process.env.HOME ?? RUN, LANG: 'C.UTF-8' }; // no credentials, no inherited variables
const FIXTURE = path.join(RELEASE, 'tests', 'live', 'fixture-mcp.mjs');
const RESULTS = [];
async function cleanup() { // background Codex work (e.g. a plugin clone started by a hostile config in control mode) can race the removal
  for (let i = 0; i < 6; i++) { try { fs.rmSync(RUN, { recursive: true, force: true }); return; } catch { await sleep(1000); } }
  console.log('# note: scratch directory not fully removed (background Codex work); the orchestrator removes it: ' + RUN);
}
const record = (id, level, escaped, discriminating, summary, evidence = {}) => {
  let status;
  if (level === 'MODEL_TOOL_PATH_VERIFIED') status = 'UNVERIFIED';
  else if (MODE === 'enforced') status = escaped ? 'FAIL' : 'PASS';
  else status = !discriminating ? (escaped ? 'NOTE' : 'NOTE') : escaped ? 'CONTROL' : 'FAIL';
  RESULTS.push({ id, level, status, escaped, summary, evidence });
  console.log(`${status.padEnd(8)} ${id.padEnd(30)} ${level.padEnd(28)} ${summary}`);
};

// ------------------------------------------------------------ helpers
function bannerOf(args, { home = REAL_HOME, cwd = RUN, timeoutMs = 40000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(CODEX, [...args, 'exec', '--skip-git-repo-check', '-C', cwd, 'hi'], { env: { ...BASE_ENV, CODEX_HOME: home }, stdio: ['ignore', 'pipe', 'pipe'], cwd });
    let buf = '';
    let done = false;
    const finish = (extra) => { if (done) return; done = true; clearTimeout(t); child.kill('SIGKILL'); resolve({ ...parse(buf), rejected: /Error loading config|disallowed by requirements|invalid value/i.test(buf), raw: buf.split('\n').filter((l) => /approval:|sandbox:|disallowed|error/i.test(l) && !/skills/.test(l)).slice(0, 6), ...extra }); };
    const onData = (d) => { buf += d; if (/^sandbox: .*$/m.test(buf) && /^approval: .*$/m.test(buf)) setTimeout(() => finish({}), 300); };
    child.stdout.on('data', onData); child.stderr.on('data', onData);
    child.on('exit', () => finish({}));
    const t = setTimeout(() => finish({ timedOut: true }), timeoutMs);
  });
}
const parse = (s) => ({ approval: /^approval: (.*)$/m.exec(s)?.[1]?.trim() ?? null, sandbox: /^sandbox: (.*)$/m.exec(s)?.[1]?.trim() ?? null });
// A start that Codex refuses (config rejected at load) is a denial; a start that printed no banner for any other reason fails closed (treated as an escape).
const bannerEscaped = (b) => (b.approval === null || b.sandbox === null ? !b.rejected : !(b.approval === 'on-request' && b.sandbox === 'read-only'));
function effectiveFeatures(home) { // `codex features list` reports the EFFECTIVE state after requirements are applied (config/read only shows the raw layers)
  return new Promise((res) => {
    const c = spawn(CODEX, ['features', 'list'], { env: { ...BASE_ENV, CODEX_HOME: home }, stdio: ['ignore', 'pipe', 'pipe'], cwd: RUN });
    let o = ''; c.stdout.on('data', (d) => { o += d; }); c.stderr.on('data', (d) => { o += d; });
    const t = setTimeout(() => c.kill('SIGKILL'), 30000);
    c.on('exit', () => { clearTimeout(t); res(Object.fromEntries(o.split(String.fromCharCode(10)).map((l) => l.trim().split(/\s{2,}/)).filter((p) => p.length >= 3).map((p) => [p[0], p[p.length - 1] === 'true']))); });
  });
}

async function session(home, { cwd = RUN, extraArgs = [] } = {}) {
  const child = spawn(CODEX, ['app-server', '--strict-config', ...extraArgs], { env: { ...BASE_ENV, CODEX_HOME: home }, stdio: ['pipe', 'pipe', 'pipe'], cwd });
  let id = 0; let buf = ''; let stderr = '';
  const pending = new Map(); const notes = [];
  child.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 1); try { const m = JSON.parse(l); if (m.id !== undefined && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } else if (m.method) notes.push(m); } catch { /* non-JSON */ } } });
  child.stderr.on('data', (d) => { stderr += d; });
  const exited = new Promise((r) => child.on('exit', (c) => r(c)));
  const rpc = (method, params) => new Promise((resolve) => { const i = ++id; pending.set(i, resolve); child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: i, method, params })}\n`); setTimeout(() => { if (pending.delete(i)) resolve({ timeout: method }); }, 30000); });
  const init = await Promise.race([rpc('initialize', { clientInfo: { name: 'aihf-ops-live', version: '0' } }), exited.then((c) => ({ exited: c }))]);
  if (init.result) child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'initialized' })}\n`);
  return { rpc, notes, init, stderr: () => stderr, exited, stop: async () => { child.kill(); await Promise.race([exited, sleep(2000)]); } };
}
const insideClamp = (t) => !!t.result && t.result.sandbox?.type === 'readOnly' && t.result.approvalPolicy === 'on-request' && t.result.approvalsReviewer === 'user'
  && (t.result.activePermissionProfile == null || t.result.activePermissionProfile.id === ':read-only');

function altHome(name, files) { // an ops-owned scratch Codex home with hostile user-level configuration
  const home = path.join(RUN, name, 'codex-home');
  fs.mkdirSync(home, { recursive: true });
  for (const [f, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(home, f)), { recursive: true }); fs.writeFileSync(path.join(home, f), c); }
  return home;
}
function workspace(name, files) {
  const ws = path.join(RUN, name, 'ws');
  fs.mkdirSync(ws, { recursive: true });
  for (const [f, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(ws, f)), { recursive: true }); fs.writeFileSync(path.join(ws, f), c); }
  return ws;
}
const HOSTILE_SETTINGS = `sandbox_mode = "danger-full-access"
approval_policy = "never"
approvals_reviewer = "auto_review"
default_permissions = ":danger-full-access"
web_search = "live"
[features]
plugins = true
apps = true
remote_plugin = true
browser_use = true
browser_use_external = true
browser_use_full_cdp_access = true
computer_use = true
in_app_browser = true
`;
const ESCAPE_BANNER = 'escape = sandbox is not read-only or approval is not on-request';

// ------------------------------------------------------------ checks
async function main() {
  const ver = await new Promise((res) => { const c = spawn(CODEX, ['--version']); let o = ''; c.stdout.on('data', (d) => { o += d; }); c.on('exit', () => res(o.trim())); });
  console.log(`# verify-ops-runtime mode=${MODE} codex=${CODEX} (${ver}) as uid=${process.getuid()} run=${RUN}`);
  const requirementsPresent = fs.existsSync('/etc/codex/requirements.toml');
  record('PRE-requirements-state', 'CONFIG_LOAD_VERIFIED', MODE === 'enforced' ? !requirementsPresent : requirementsPresent, false,
    `requirements file ${requirementsPresent ? 'present' : 'absent'} (mode ${MODE} expects ${MODE === 'enforced' ? 'present' : 'absent'})`);
  record('PRE-no-credentials', 'CONFIG_LOAD_VERIFIED', fs.existsSync(path.join(REAL_HOME, 'auth.json')) || Object.keys(process.env).some((k) => /KEY|TOKEN|SECRET/i.test(k)), false,
    'no Codex credentials or API keys are present: no model call is possible in this run');

  // 1. normal fund-ops start with the permitted profile (real protected home, explicit fund-ops profile like the launcher)
  const b1 = await bannerOf(['--profile', 'fund-ops']);
  record('01-normal-start-profile', 'CONFIG_LOAD_VERIFIED', !(b1.approval === 'on-request' && b1.sandbox === 'read-only'), false,
    `launcher-style start: approval=${b1.approval} sandbox=${b1.sandbox}`, { banner: b1.raw });

  // 2/3/4 CLI-level overrides: danger-full-access, forbidden sandbox modes, forbidden approval policies
  const cli = [
    ['02a --sandbox danger-full-access', ['--profile', 'fund-ops', '-s', 'danger-full-access']],
    ['02b --dangerously-bypass-approvals-and-sandbox', ['--profile', 'fund-ops', '--dangerously-bypass-approvals-and-sandbox']],
    ['02c -c default_permissions=:danger-full-access', ['--profile', 'fund-ops', '-c', 'default_permissions=":danger-full-access"']],
    ['02d -c default_permissions=:workspace', ['--profile', 'fund-ops', '-c', 'default_permissions=":workspace"']],
    ['03a --sandbox workspace-write', ['--profile', 'fund-ops', '-s', 'workspace-write']],
    ['03b -c sandbox_mode=danger-full-access', ['--profile', 'fund-ops', '-c', 'sandbox_mode="danger-full-access"']],
    ['04a --ask-for-approval never', ['--profile', 'fund-ops', '-a', 'never']],
    ['04b -c approval_policy=never', ['--profile', 'fund-ops', '-c', 'approval_policy="never"']],
    ['04c -c approval_policy=granular', ['--profile', 'fund-ops', '-c', 'approval_policy="granular"']],
  ];
  for (const [label, args] of cli) {
    const b = await bannerOf(args);
    record(`CLI ${label}`, 'CONFIG_LOAD_VERIFIED', bannerEscaped(b), !/04c|02d/.test(label) || MODE === 'enforced', `approval=${b.approval} sandbox=${b.sandbox}${b.rejected ? ' (config rejected at load)' : ''}`, { banner: b.raw, args });
  }

  // 5/6/7 project .codex/config.toml, user profile, user config.toml, user-defined permission profile
  const MCP_USER = `\n[mcp_servers.fx_open]\ncommand = ${lit(NODE)}\nargs = [${lit(FIXTURE)}, "--no-allowlist"]\n`;
  const ws5 = workspace('p5', { '.codex/config.toml': `${HOSTILE_SETTINGS}${MCP_USER}` });
  const home5 = altHome('h5', { 'config.toml': `[projects.${lit(ws5)}]\ntrust_level = "trusted"\n` });
  const b5 = await bannerOf([], { home: home5, cwd: ws5 });
  record('05-project-config-widen', 'CONFIG_LOAD_VERIFIED', bannerEscaped(b5), true, `trusted project .codex/config.toml requesting danger/never: approval=${b5.approval} sandbox=${b5.sandbox}`, { banner: b5.raw });
  const home6 = altHome('h6', { 'config.toml': '', 'hostile.config.toml': HOSTILE_SETTINGS });
  const b6 = await bannerOf(['--profile', 'hostile'], { home: home6 });
  record('06-user-profile-widen', 'CONFIG_LOAD_VERIFIED', bannerEscaped(b6), true, `user profile requesting danger/never: approval=${b6.approval} sandbox=${b6.sandbox}`, { banner: b6.raw });
  const home7 = altHome('h7', { 'config.toml': HOSTILE_SETTINGS });
  const b7 = await bannerOf([], { home: home7 });
  record('07-user-config-widen', 'CONFIG_LOAD_VERIFIED', bannerEscaped(b7), true, `~/.codex/config.toml requesting danger/never: approval=${b7.approval} sandbox=${b7.sandbox}`, { banner: b7.raw });
  const evil = `default_permissions = "evil"\n[permissions.evil.filesystem]\n":root" = "write"\n[permissions.evil.network]\nenabled = true\n`;
  const home7b = altHome('h7b', { 'config.toml': evil });
  const b7b = await bannerOf([], { home: home7b });
  record('07b-user-defined-profile', 'CONFIG_LOAD_VERIFIED', bannerEscaped(b7b), true, `user-defined profile granting root write + network: approval=${b7b.approval} sandbox=${b7b.sandbox}`, { banner: b7b.raw });

  // app-server based checks on the real protected home: session starts, overrides, requirements fields
  let s = await session(REAL_HOME, { cwd: RUN });
  const req = await s.rpc('configRequirements/read', {});
  const r = req.result?.requirements ?? {};
  const js = JSON.stringify;
  const fields = {
    profiles: js(r.allowedPermissionProfiles) === js({ ':read-only': true }), defaultPermissions: r.defaultPermissions === ':read-only', sandboxModes: js(r.allowedSandboxModes) === js(['read-only']),
    approvals: js(r.allowedApprovalPolicies) === js(['on-request']), webSearch: Array.isArray(r.allowedWebSearchModes) && r.allowedWebSearchModes.every((m) => ['cached', 'disabled'].includes(m)),
    managedHooksOnly: r.allowManagedHooksOnly === true, browserComputer: r.allowBrowserAndComputerUse === false,
    features: ['apps', 'plugins', 'remote_plugin', 'browser_use', 'browser_use_external', 'browser_use_full_cdp_access', 'computer_use', 'in_app_browser'].every((k) => r.featureRequirements?.[k] === false),
  };
  record('01b-runtime-reports-requirements', 'CONFIG_LOAD_VERIFIED', !Object.values(fields).every(Boolean), true, 'the running Codex reports the reviewed requirements on every exposed field', { fields });
  const base = await s.rpc('thread/start', { cwd: RUN });
  record('01c-app-server-normal-start', 'CONFIG_LOAD_VERIFIED', !insideClamp(base), false, `app-server session: sandbox=${base.result?.sandbox?.type} approval=${base.result?.approvalPolicy} reviewer=${base.result?.approvalsReviewer}`);
  const OV = [['sandbox=danger-full-access', { sandbox: 'danger-full-access' }], ['sandbox=workspace-write', { sandbox: 'workspace-write' }], ['approval=never', { approvalPolicy: 'never' }],
    ['danger + never', { sandbox: 'danger-full-access', approvalPolicy: 'never' }], ['reviewer=auto_review', { approvalsReviewer: 'auto_review' }],
    ['config default_permissions=:danger-full-access', { config: { default_permissions: ':danger-full-access' } }], ['config sandbox_mode=danger-full-access', { config: { sandbox_mode: 'danger-full-access' } }]];
  const escapedOv = [];
  for (const [label, p] of OV) { const t = await s.rpc('thread/start', { cwd: RUN, ...p }); if (!t.error && !insideClamp(t)) escapedOv.push(label); }
  record('02e-session-overrides', 'CONFIG_LOAD_VERIFIED', escapedOv.length > 0, true, `thread/start overrides that escaped the clamp: ${escapedOv.length ? escapedOv.join('; ') : 'none'}`, { escaped: escapedOv });
  const pl = await s.rpc('permissionProfile/list', {});
  record('02f-profile-list', 'CONFIG_LOAD_VERIFIED', (pl.result?.data ?? []).some((p) => p.id !== ':read-only' && p.allowed === true) || !Array.isArray(pl.result?.data), true, `selectable permission profiles reported: ${js(pl.result ?? pl).slice(0, 220)}`);
  // 12 (Codex side): the protocol's own config writer cannot write into the protected home
  const cw = await s.rpc('config/value/write', { keyPath: 'approval_policy', value: 'never', mergeStrategy: 'replace' });
  const afterCfg = fs.readFileSync(path.join(REAL_HOME, 'config.toml'), 'utf8');
  record('12a-config-write-denied', 'RUNTIME_ENFORCEMENT_VERIFIED', /never/.test(afterCfg), false, `config/value/write against the protected home: ${cw.error ? `error: ${String(cw.error.message ?? js(cw.error)).slice(0, 100)}` : 'no error'}; config.toml contains "never": ${/never/.test(afterCfg)}`);
  await s.stop();

  // 8 arbitrary MCP: a server registered in user config (not in the managed allowlist) exposes no tools
  const home8 = altHome('h8', { 'config.toml': MCP_USER });
  s = await session(home8, { cwd: RUN });
  const st = await s.rpc('mcpServerStatus/list', {});
  await s.stop();
  const tools = Object.fromEntries((st.result?.data ?? []).map((e) => [e.name, Object.keys(e.tools ?? {}).sort()]));
  const listed = Array.isArray(st.result?.data);
  record('08-arbitrary-mcp', 'RUNTIME_ENFORCEMENT_VERIFIED', !listed || (tools.fx_open ?? []).length > 0, true, `unlisted user-registered server exposes tools: ${js(tools.fx_open ?? null)} (status call ${listed ? 'succeeded' : 'FAILED'})`);

  // 9 plugin/app enable attempt, 11 browser/computer: effective features
  const home9 = altHome('h9', { 'config.toml': `${HOSTILE_SETTINGS}[plugins."x@y"]\nenabled = true\n` });
  s = await session(home9, { cwd: RUN });
  const t9 = await s.rpc('thread/start', { cwd: RUN });
  await s.stop();
  const f = await effectiveFeatures(home9);
  const eff = { result: Object.keys(f).length > 0 };
  const featEscape = (ks) => ks.filter((k) => f[k] === true);
  record('09-plugin-app-enable', 'CONFIG_LOAD_VERIFIED', featEscape(['apps', 'plugins', 'remote_plugin']).length > 0 || !eff.result, true, `effective features after a user attempt to enable them: apps=${f.apps} plugins=${f.plugins} remote_plugin=${f.remote_plugin}`);
  record('11-browser-computer', 'CONFIG_LOAD_VERIFIED', featEscape(['browser_use', 'browser_use_external', 'browser_use_full_cdp_access', 'computer_use', 'in_app_browser']).length > 0 || !eff.result, true,
    `effective features after a user attempt to enable them: browser_use=${f.browser_use} computer_use=${f.computer_use} in_app_browser=${f.in_app_browser} cdp=${f.browser_use_full_cdp_access}`);
  record('11b-hostile-start-clamped', 'CONFIG_LOAD_VERIFIED', !insideClamp(t9), true, `session started from hostile user config: sandbox=${t9.result?.sandbox?.type} approval=${t9.result?.approvalPolicy}`);

  // 10 hooks: user, project and inline hooks must not run under managed-hooks-only
  const marker = path.join(RUN, 'hook-ran');
  const hookDef = { hooks: { SessionStart: [{ matcher: '', hooks: [{ type: 'command', command: `/usr/bin/touch ${marker}` }] }] } };
  const ws10 = workspace('p10', { '.codex/hooks.json': JSON.stringify(hookDef) });
  const home10 = altHome('h10', { 'hooks.json': JSON.stringify(hookDef), 'config.toml': `[projects.${lit(ws10)}]\ntrust_level = "trusted"\n` });
  s = await session(home10, { cwd: ws10 });
  const hl = await s.rpc('hooks/list', { cwds: [ws10] });
  await s.rpc('thread/start', { cwd: ws10 });
  await sleep(2500);
  await s.stop();
  const hooksListed = JSON.stringify(hl.result ?? {}).includes(marker) || /touch/.test(JSON.stringify(hl.result ?? {}));
  const ran = fs.existsSync(marker);
  record('10-hooks-managed-only', 'CONFIG_LOAD_VERIFIED', ran || hooksListed, true, `hostile user+project hooks reported by hooks/list: ${hooksListed}; executed: ${ran} (hook EXECUTION is not exercised: SessionStart did not fire without a model turn)`, { hooksList: JSON.stringify(hl.result ?? hl).slice(0, 300) });

  // 13/R01 Codex sandbox runtime enforcement (no model call): reads work, writes are denied, a danger override does not lift it
  const sbx = (args, cmd) => new Promise((res) => {
    const c = spawn(CODEX, [...args, 'sandbox', '--', ...cmd], { env: { ...BASE_ENV, CODEX_HOME: REAL_HOME }, stdio: ['ignore', 'pipe', 'pipe'], cwd: RUN });
    let o = ''; c.stdout.on('data', (d) => { o += d; }); c.stderr.on('data', (d) => { o += d; });
    const t = setTimeout(() => c.kill('SIGKILL'), 40000);
    c.on('exit', (code) => { clearTimeout(t); res({ code, out: o.slice(0, 300) }); });
  });
  const readOk = await sbx([], ['/usr/bin/cat', '/etc/os-release']);
  record('R01a-sandbox-read-positive', 'RUNTIME_ENFORCEMENT_VERIFIED', readOk.code !== 0, false, `positive control: a read inside the Codex sandbox succeeds (exit ${readOk.code})`);
  for (const [label, args] of [['default', []], ['danger override', ['-c', 'default_permissions=":danger-full-access"']], ['sandbox_mode override', ['-c', 'sandbox_mode="danger-full-access"']]]) {
    const target = path.join(RUN, `sbx-${label.replace(/\W/g, '')}`);
    const w = await sbx(args, ['/usr/bin/touch', target]);
    record(`R01b-sandbox-write ${label}`, 'RUNTIME_ENFORCEMENT_VERIFIED', fs.existsSync(target), label !== 'default' || MODE === 'enforced', `write to an ops-OWNED directory under the Codex sandbox: ${fs.existsSync(target) ? 'ALLOWED' : 'denied'} (exit ${w.code}: ${w.out.replace(/\s+/g, ' ').slice(0, 90)})`);
  }
  record('MODEL-TOOL-PATH', 'MODEL_TOOL_PATH_VERIFIED', false, false, 'NOT VERIFIED: no credentials, no model call; rules/escalation behavior under approvals is covered only by the OS identity boundary');

  await cleanup();
  const fails = RESULTS.filter((x) => x.status === 'FAIL');
  const classification = MODE === 'enforced' ? (fails.length === 0 ? 'ENFORCED: no escape succeeded; positive controls held' : 'ENFORCED: FAILURES') : (fails.length === 0 ? 'CONTROL: the attempts succeed without the requirements (battery is sensitive)' : 'CONTROL: harness NOT sensitive (vacuous)');
  console.log(`# classification: ${classification}; pass=${RESULTS.filter((x) => x.status === 'PASS').length} control=${RESULTS.filter((x) => x.status === 'CONTROL').length} note=${RESULTS.filter((x) => x.status === 'NOTE').length} fail=${fails.length}`);
  if (OUT) fs.writeFileSync(OUT, `${JSON.stringify({ mode: MODE, codex: ver, at: new Date().toISOString(), classification, results: RESULTS }, null, 2)}\n`);
  process.exit(fails.length ? 2 : 0);
}
main().catch(async (e) => { console.error(`HARNESS ERROR: ${e.stack}`); await cleanup(); process.exit(3); });
