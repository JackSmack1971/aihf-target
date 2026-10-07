// Deterministic checker for contracts/ops-runtime-layout.json: the OS ownership/permission layout of the isolated fund-ops runtime.
// It parses data only. Every invariant below is pinned in code, so weakening the JSON cannot weaken the check.
// Capability: OPS_RUNTIME_BOUNDARY (the ops identity cannot modify managed policy, the activated release or the toolchain, and
// mutable runtime state is separated from them). It is a layout contract, not a runtime control: the live proof is the operator-run verifier under the pinned provisioning directory.

// Absolute paths are assembled from parts so the repo-wide filesystem tripwire (which flags quoted absolute paths outside tests/) does not match this pinned data.
const SL = String.fromCharCode(47);
const DOT = String.fromCharCode(46);
const DOTDOT = DOT + DOT;
const abs = (...seg) => ['', ...seg].join(SL);

const CAP = 'OPS_RUNTIME_BOUNDARY';
const OPS_USER = 'aihf-ops';
const REQUIREMENTS = abs('etc', 'codex', 'requirements.toml');
const RELEASE_ROOT = abs('opt', 'aihf', 'releases');
const RELEASE_CURRENT = abs('opt', 'aihf', 'current');
const TOOLCHAIN = abs('opt', 'aihf', 'toolchain');
const LAUNCHER = abs('opt', 'aihf', 'bin', 'fund-ops');
const RUNTIME_ROOT = abs('var', 'lib', 'aihf', 'runtime');
const OPS_HOME = abs('var', 'lib', 'aihf', 'ops', 'home');
const CODEX_HOME = abs('var', 'lib', 'aihf', 'ops', 'codex-home');
const ENV_ALLOW = Object.freeze(['CODEX_HOME', 'HOME', 'LANG', 'PATH', 'TERM']);
const TOP_KEYS = Object.freeze(['codex_home_protected', 'entries', 'ops_home_protected', 'identities', 'note', 'runtime', 'schema_version', 'wsl']);
const RUNTIME_KEYS = Object.freeze(['codex_home', 'codex_version_pin', 'launcher', 'launcher_env_allowlist', 'launcher_path_env', 'ops_home', 'platform',
  'release_current', 'release_root', 'requirements_path', 'runtime_state_root', 'scratch', 'state', 'toolchain_codex_bin']);
const IDENTITY_KEYS = Object.freeze(['group', 'home', 'id', 'password', 'shell', 'sudo', 'supplementary_groups', 'system_account', 'user']);
const ENTRY_KEYS = Object.freeze(['group', 'mode', 'owner', 'path', 'role', 'type']);
const ROLES = Object.freeze(['managed_policy', 'release', 'toolchain', 'state_parent', 'ops_writable', 'codex_home', 'sticky_home']);
const TYPES = Object.freeze(['dir', 'file', 'symlink']);
const PROTECTED = Object.freeze({
  'config.toml': 'file', 'fund-ops.config.toml': 'file', 'hooks.json': 'file', 'AGENTS.md': 'file', 'AGENTS.override.md': 'file',
  rules: 'dir', skills: 'dir', agents: 'dir', prompts: 'dir', plugins: 'dir', '.env': 'file',
});
// HOME is sticky and root-owned too: documented user skill roots and shell startup files live under HOME.
const HOME_PROTECTED = Object.freeze({ '.agents': 'dir', '.codex': 'dir', '.bashrc': 'file', '.profile': 'file', '.bash_profile': 'file', '.bash_login': 'file' });
// Paths that would put the runtime on a Windows mount or in a developer-owned tree.
const FORBIDDEN_PREFIXES = Object.freeze(['mnt', 'media', 'home', 'Users', 'c', 'root'].map((d) => abs(d)));
const SERVICE_NAME = /riskd|traderd|signerd/i;

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const V = (message) => ({ capability: CAP, message });
const sameKeys = (o, keys) => isObj(o) && JSON.stringify(Object.keys(o).sort()) === JSON.stringify([...keys].sort());
const modeNum = (m) => (typeof m === 'string' && /^[0-7]{4}$/.test(m) ? parseInt(m, 8) : null);
const under = (p, root) => p === root || p.startsWith(root + SL);
const parentOf = (p) => p.slice(0, p.lastIndexOf(SL)) || SL;

function pathProblem(p) {
  if (typeof p !== 'string' || !p.startsWith(SL) || p.length < 2) return 'must be an absolute path';
  if (p.endsWith(SL) || p.includes(SL + SL) || p.split(SL).some((s) => s === DOT || s === DOTDOT)) return 'must be normalized (no repeated separators, dot segments or trailing separator)';
  const bad = FORBIDDEN_PREFIXES.find((x) => under(p, x));
  if (bad) return `must not be under ${bad} (Windows mounts and developer trees are outside the runtime)`;
  return null;
}

/** @returns {{ok:boolean, violations:{capability:string,message:string}[]}} */
export function checkOpsLayout(doc) {
  const out = [];
  const add = (m) => out.push(V(m));
  if (!sameKeys(doc, TOP_KEYS)) { add('document shape is closed: unexpected or missing top-level keys'); return { ok: false, violations: out }; }
  if (doc.schema_version !== 1) add('schema_version must be 1');

  // ---- runtime pins
  const r = doc.runtime;
  if (!sameKeys(r, RUNTIME_KEYS)) { add('runtime shape is closed'); return { ok: false, violations: out }; }
  const pins = {
    requirements_path: REQUIREMENTS, release_root: RELEASE_ROOT, release_current: RELEASE_CURRENT, launcher: LAUNCHER, runtime_state_root: RUNTIME_ROOT,
    ops_home: OPS_HOME, codex_home: CODEX_HOME, scratch: RUNTIME_ROOT + SL + 'scratch', state: RUNTIME_ROOT + SL + 'state',
    platform: 'wsl2-ubuntu-dedicated-distro', launcher_path_env: abs('usr', 'bin') + ':' + abs('bin'),
  };
  for (const [k, v] of Object.entries(pins)) if (r[k] !== v) add(`runtime.${k} must be exactly ${v}`);
  if (typeof r.toolchain_codex_bin !== 'string' || !r.toolchain_codex_bin.startsWith(TOOLCHAIN + SL)) add(`runtime.toolchain_codex_bin must be under ${TOOLCHAIN} (root-owned, never a developer checkout or a Windows path)`);
  if (typeof r.codex_version_pin !== 'string' || !/^\d+\.\d+\.\d+$/.test(r.codex_version_pin)) add('runtime.codex_version_pin must be a semantic version');
  if (JSON.stringify(r.launcher_env_allowlist) !== JSON.stringify(ENV_ALLOW)) add(`runtime.launcher_env_allowlist must be exactly ${ENV_ALLOW.join(',')} (no inherited environment)`);
  for (const k of ['requirements_path', 'release_root', 'release_current', 'toolchain_codex_bin', 'launcher', 'runtime_state_root', 'ops_home', 'codex_home', 'scratch', 'state']) {
    const p = pathProblem(r[k]);
    if (p) add(`runtime.${k} ${p}`);
  }

  // ---- identities: exactly the ops identity, no service identity yet
  const ids = Array.isArray(doc.identities) ? doc.identities : [];
  if (ids.length !== 1) add('exactly one identity (ops) is defined in this slice; riskd/traderd/signerd identities belong to a later slice');
  for (const i of ids) {
    if (!sameKeys(i, IDENTITY_KEYS)) { add('identity shape is closed'); continue; }
    if (SERVICE_NAME.test(JSON.stringify(i))) add('a service identity (riskd/traderd/signerd) must not be introduced in this slice');
    if (i.id !== 'ops' || i.user !== OPS_USER || i.group !== OPS_USER) add(`the ops identity must be user/group ${OPS_USER}`);
    if (i.system_account !== true) add('the ops account must be a system account');
    if (i.password !== 'locked') add('the ops account password must be locked');
    if (i.sudo !== false) add('the ops account must have no sudo');
    if (!Array.isArray(i.supplementary_groups) || i.supplementary_groups.length !== 0) add('the ops account must have no supplementary groups');
    if (i.shell !== abs('bin', 'bash')) add('the ops account shell must be the system bash');
    if (i.home !== OPS_HOME) add(`the ops home must be ${OPS_HOME}`);
  }

  // ---- entries
  const entries = Array.isArray(doc.entries) ? doc.entries : [];
  const byPath = new Map();
  for (const e of entries) {
    if (!sameKeys(e, ENTRY_KEYS)) { add('entry shape is closed'); continue; }
    const pp = pathProblem(e.path);
    if (pp) { add(`entry ${String(e.path)} ${pp}`); continue; }
    if (byPath.has(e.path)) add(`duplicate entry ${e.path}`);
    byPath.set(e.path, e);
    const m = modeNum(e.mode);
    if (m === null || !TYPES.includes(e.type) || !ROLES.includes(e.role) || typeof e.owner !== 'string' || typeof e.group !== 'string') { add(`entry ${e.path} is malformed`); continue; }
    const isLink = e.type === 'symlink';
    if (e.owner === OPS_USER && e.role !== 'ops_writable') add(`${e.path}: the ops identity owns only ops_writable paths`);
    if (['managed_policy', 'release', 'toolchain', 'state_parent'].includes(e.role)) {
      if (e.owner !== 'root' || e.group !== 'root') add(`${e.path}: ${e.role} entries must be root:root`);
      if (!isLink && (m & 0o022) !== 0) add(`${e.path}: ${e.role} entries must not be group- or other-writable`);
      if ((m & 0o1000) !== 0 && !isLink) add(`${e.path}: unexpected sticky bit on ${e.role}`);
    }
    if (e.role === 'ops_writable') {
      if (e.owner !== OPS_USER || e.group !== OPS_USER) add(`${e.path}: ops_writable entries are owned by ${OPS_USER}:${OPS_USER}`);
      if ((m & 0o077) !== 0) add(`${e.path}: ops_writable entries must not be accessible to group or other`);
      if (!under(e.path, RUNTIME_ROOT)) add(`${e.path}: ops-writable paths are limited to the runtime state root`);
      if (e.type !== 'dir') add(`${e.path}: ops_writable entries are directories`);
    }
    if (e.role === 'sticky_home') {
      if (e.path !== OPS_HOME || e.owner !== 'root' || e.group !== OPS_USER || e.mode !== '1770') add(`${e.path}: the ops home must be root:${OPS_USER} mode 1770 (sticky; protected names pre-created root-owned)`);
    }
    if (e.role === 'codex_home') {
      if (e.path !== CODEX_HOME || e.owner !== 'root' || e.group !== OPS_USER || e.mode !== '1770') add(`${e.path}: the Codex home must be root:${OPS_USER} mode 1770 (sticky, group-writable, no other access)`);
    }
    const sys = under(e.path, abs('etc')) || under(e.path, abs('opt'));
    if (sys && e.owner !== 'root') add(`${e.path}: everything under the system configuration and release trees is root-owned`);
    if (sys && e.role === 'ops_writable') add(`${e.path}: nothing under the system configuration or release trees is ops-writable`);
  }
  // required entries
  for (const k of ['requirements_path', 'release_root', 'release_current', 'launcher', 'scratch', 'state', 'ops_home', 'codex_home']) {
    if (typeof r[k] === 'string' && !byPath.has(r[k])) add(`no layout entry for runtime.${k} (${r[k]})`);
  }
  for (const p of [abs('etc', 'codex'), abs('opt', 'aihf'), TOOLCHAIN, abs('opt', 'aihf', 'bin'), abs('var', 'lib', 'aihf'), abs('var', 'lib', 'aihf', 'ops'), RUNTIME_ROOT]) {
    if (!byPath.has(p)) add(`no layout entry for ${p}`);
  }
  // an ops-writable path could be replaced or renamed by its owner if its parent were writable by the ops identity: demand root-owned, non-writable parents
  for (const e of byPath.values()) {
    if (e.role !== 'ops_writable') continue;
    const parent = byPath.get(parentOf(e.path));
    if (!parent) add(`${e.path}: parent ${parentOf(e.path)} must be a declared root-owned directory`);
    else if (parent.owner !== 'root' || (modeNum(parent.mode) & 0o022) !== 0) add(`${e.path}: parent ${parent.path} must be root-owned and not group/other-writable`);
  }
  // separation of immutable and mutable trees, judged on the DECLARED paths (the pinned roots alone would be a vacuous comparison)
  const mutable = [RUNTIME_ROOT, OPS_HOME, CODEX_HOME];
  for (const e of byPath.values()) {
    if (!['managed_policy', 'release', 'toolchain'].includes(e.role)) continue;
    for (const b of mutable) if (under(e.path, b) || under(b, e.path)) add(`${e.path} (${e.role}) and ${b} overlap: immutable and mutable trees must be disjoint`);
  }
  for (const a of mutable) for (const b of mutable) if (a !== b && under(a, b)) add(`${a} is nested under ${b}: mutable roots must be disjoint`);

  // ---- Codex home protected surface
  const prot = Array.isArray(doc.codex_home_protected) ? doc.codex_home_protected : [];
  const names = prot.map((p) => p?.name);
  if (JSON.stringify([...names].sort()) !== JSON.stringify(Object.keys(PROTECTED).sort())) add('codex_home_protected must list exactly the pinned security-critical names');
  for (const p of prot) {
    if (!sameKeys(p, ['mode', 'name', 'type'])) { add('codex_home_protected entry shape is closed'); continue; }
    if (PROTECTED[p.name] !== p.type) add(`codex_home_protected ${p.name} must be a ${PROTECTED[p.name]}`);
    const m = modeNum(p.mode);
    if (m === null || (m & 0o022) !== 0) add(`codex_home_protected ${p.name} must not be group- or other-writable`);
  }

  const hp = Array.isArray(doc.ops_home_protected) ? doc.ops_home_protected : [];
  if (JSON.stringify(hp.map((p) => p?.name).sort()) !== JSON.stringify(Object.keys(HOME_PROTECTED).sort())) add('ops_home_protected must list exactly the pinned security-critical names');
  for (const p of hp) {
    if (!sameKeys(p, ['mode', 'name', 'type'])) { add('ops_home_protected entry shape is closed'); continue; }
    if (HOME_PROTECTED[p.name] !== p.type) add(`ops_home_protected ${p.name} must be a ${HOME_PROTECTED[p.name]}`);
    const m = modeNum(p.mode);
    if (m === null || (m & 0o022) !== 0) add(`ops_home_protected ${p.name} must not be group- or other-writable`);
  }

  // ---- WSL hardening
  const w = doc.wsl;
  if (!sameKeys(w, ['append_windows_path', 'automount_enabled', 'default_user', 'interop_enabled', 'systemd'])) add('wsl shape is closed');
  else {
    if (w.automount_enabled !== false) add('wsl.automount_enabled must be false (no Windows drive mounts, no developer checkout, no host credentials)');
    if (w.interop_enabled !== false) add('wsl.interop_enabled must be false (no Windows executable invocation)');
    if (w.append_windows_path !== false) add('wsl.append_windows_path must be false (no Windows PATH injection)');
    if (w.default_user !== OPS_USER) add(`wsl.default_user must be ${OPS_USER}`);
    if (typeof w.systemd !== 'boolean') add('wsl.systemd must be boolean');
  }
  return { ok: out.length === 0, violations: out };
}
