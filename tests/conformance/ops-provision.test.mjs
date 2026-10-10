import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { ROOT, abs, readJson, readText, denyTest, clone, tempDir, writeFiles, makeNonRegularEntry, walk } from '../helpers.mjs';
import { checkOpsLayout } from '../../src/contracts/ops-layout-checker.mjs';
import { checkRepoTree, collectTree, parseRules, OPS_PROVISION_FILES, OPS_FUNDCTL_FILE } from '../../src/contracts/trust-zone-checker.mjs';

const LAYOUT = () => readJson('contracts', 'ops-runtime-layout.json');
const mut = (fn) => { const d = clone(LAYOUT()); fn(d); return d; };
const entry = (d, p) => d.entries.find((e) => e.path === p);
const rejects = (doc, re, label) => {
  const r = checkOpsLayout(doc);
  assert.equal(r.ok, false, `${label}: must be rejected`);
  if (re) assert.ok(r.violations.some((v) => re.test(v.message)), `${label}: expected ${re}, got ${r.violations.map((v) => v.message).join(' | ')}`);
};
const treeOf = (files) => checkRepoTree(collectTree(writeFiles(tempDir(), files)));
const caps = (r) => [...new Set(r.violations.map((v) => v.capability))];
const P = (...s) => ['', ...s].join('/'); // absolute paths assembled so fixtures read clearly
const PROV = 'ops/provision';
const lf = (s) => s.replace(/\r\n/g, '\n');
const sha = (s) => crypto.createHash('sha256').update(lf(s)).digest('hex');
const sh = (name) => readText('ops', 'provision', name);

// ------------------------------------------------------------------ layout contract
test('ops layout: shipped contract is accepted; ops plus three non-login, sudo-less service identities with private groups', () => {
  assert.deepEqual(checkOpsLayout(LAYOUT()), { ok: true, violations: [] });
  const d = LAYOUT();
  assert.deepEqual(d.identities.map((i) => i.id), ['ops', 'riskd', 'traderd', 'signerd']);
  for (const i of d.identities) { assert.equal(i.sudo, false); assert.deepEqual(i.supplementary_groups, []); assert.equal(i.password, 'locked'); assert.equal(i.user, i.group); }
  assert.deepEqual(d.identities.slice(1).map((i) => i.shell), ['/usr/sbin/nologin', '/usr/sbin/nologin', '/usr/sbin/nologin']);
  assert.equal(d.identities[0].user, 'aihf-ops');
  assert.equal(d.identities[0].sudo, false);
  assert.deepEqual(d.identities[0].supplementary_groups, []);
  for (const bad of [null, {}, [], { schema_version: 1 }]) assert.equal(checkOpsLayout(bad).ok, false);
});

denyTest('DENY-OPS-RUNTIME-BOUNDARY', () => {
  assert.deepEqual(checkOpsLayout(LAYOUT()), { ok: true, violations: [] }, 'positive control');
  // managed policy, release and toolchain must be root-owned and not writable by the ops identity
  for (const p of [P('etc', 'codex'), P('etc', 'codex', 'requirements.toml'), P('opt', 'aihf'), P('opt', 'aihf', 'releases'), P('opt', 'aihf', 'toolchain'), P('opt', 'aihf', 'bin', 'fund-ops')]) {
    rejects(mut((d) => { entry(d, p).owner = 'aihf-ops'; }), /ops identity owns|root:root|root-owned/, `${p} owned by ops`);
    rejects(mut((d) => { entry(d, p).group = 'aihf-ops'; }), /root:root/, `${p} group ops`);
    rejects(mut((d) => { entry(d, p).mode = '0775'; }), /writable/, `${p} group-writable`);
    rejects(mut((d) => { entry(d, p).mode = '0757'; }), /writable/, `${p} other-writable`);
    rejects(mut((d) => { entry(d, p).role = 'ops_writable'; }), null, `${p} reclassified ops-writable`);
  }
  // the release symlink and requirements path are pinned
  rejects(mut((d) => { d.runtime.requirements_path = P('etc', 'codex', 'other.toml'); }), /requirements_path must be exactly/, 'requirements path moved');
  rejects(mut((d) => { d.runtime.release_current = P('home', 'dev', 'checkout'); }), /release_current must be exactly/, 'release points at a developer path');
  rejects(mut((d) => { d.runtime.toolchain_codex_bin = P('mnt', 'c', 'Users', 'x', 'codex'); }), /toolchain_codex_bin/, 'Windows toolchain');
  rejects(mut((d) => { d.runtime.toolchain_codex_bin = P('var', 'lib', 'aihf', 'runtime', 'codex'); }), /toolchain_codex_bin must be under/, 'toolchain in mutable tree');
  // ops-writable set is bounded and parents are root-owned
  rejects(mut((d) => { d.entries.push({ path: P('opt', 'aihf', 'cache'), type: 'dir', owner: 'aihf-ops', group: 'aihf-ops', mode: '0700', role: 'ops_writable' }); }), /ops_writable paths are limited|nothing under/, 'ops-writable under /opt');
  rejects(mut((d) => { d.entries.push({ path: P('srv', 'data'), type: 'dir', owner: 'aihf-ops', group: 'aihf-ops', mode: '0700', role: 'ops_writable' }); }), /limited to/, 'arbitrary writable root');
  rejects(mut((d) => { entry(d, P('var', 'lib', 'aihf', 'runtime', 'scratch')).mode = '0770'; }), /accessible to group or other/, 'scratch group-accessible');
  rejects(mut((d) => { entry(d, P('var', 'lib', 'aihf', 'runtime')).owner = 'aihf-ops'; entry(d, P('var', 'lib', 'aihf', 'runtime')).group = 'aihf-ops'; }), /ops identity owns|parent/, 'runtime parent owned by ops (scratch could be renamed away)');
  rejects(mut((d) => { entry(d, P('var', 'lib', 'aihf', 'runtime')).mode = '0775'; }), /writable/, 'runtime parent group-writable');
  // HOME is sticky and root-owned too (the documented user skill root lives under HOME)
  for (const m of ['0700', '0770', '0777', '1777', '1775']) rejects(mut((d) => { entry(d, P('var', 'lib', 'aihf', 'ops', 'home')).mode = m; }), /1770/, `ops home mode ${m}`);
  rejects(mut((d) => { const e = entry(d, P('var', 'lib', 'aihf', 'ops', 'home')); e.owner = 'aihf-ops'; e.group = 'aihf-ops'; e.mode = '0700'; e.role = 'ops_writable'; }), /limited to the runtime state root/, 'ops home reverted to an ops-owned writable directory');
  rejects(mut((d) => { d.ops_home_protected = d.ops_home_protected.filter((x) => x.name !== '.agents'); }), /ops_home_protected must list exactly/, 'HOME/.agents no longer protected');
  rejects(mut((d) => { d.ops_home_protected.push({ name: 'extra', type: 'file', mode: '0644' }); }), /ops_home_protected must list exactly/, 'unreviewed HOME protected name');
  rejects(mut((d) => { d.ops_home_protected.find((x) => x.name === '.bashrc').mode = '0666'; }), /ops_home_protected \.bashrc must not be group/, 'HOME shell startup file writable');
  rejects(mut((d) => { d.ops_home_protected.find((x) => x.name === '.agents').type = 'file'; }), /must be a dir/, 'HOME/.agents becomes a file');
  rejects(mut((d) => { d.codex_home_protected = d.codex_home_protected.filter((x) => x.name !== '.env'); }), /exactly the pinned/, 'Codex home .env no longer protected');
  // Codex home: sticky root-owned group-writable only
  for (const m of ['0770', '0777', '1777', '1775', '0700']) rejects(mut((d) => { entry(d, P('var', 'lib', 'aihf', 'ops', 'codex-home')).mode = m; }), /1770/, `codex home mode ${m}`);
  rejects(mut((d) => { entry(d, P('var', 'lib', 'aihf', 'ops', 'codex-home')).owner = 'aihf-ops'; }), /1770|ops identity owns/, 'codex home owned by ops');
  // protected Codex-home surface is exact and never writable by group/other
  rejects(mut((d) => { d.codex_home_protected = d.codex_home_protected.filter((x) => x.name !== 'rules'); }), /exactly the pinned/, 'rules dir no longer protected');
  rejects(mut((d) => { d.codex_home_protected = d.codex_home_protected.filter((x) => x.name !== 'hooks.json'); }), /exactly the pinned/, 'hooks no longer protected');
  rejects(mut((d) => { d.codex_home_protected.push({ name: 'extra', type: 'file', mode: '0644' }); }), /exactly the pinned/, 'unreviewed extra protected name');
  rejects(mut((d) => { d.codex_home_protected.find((x) => x.name === 'config.toml').mode = '0664'; }), /writable/, 'config.toml group-writable');
  rejects(mut((d) => { d.codex_home_protected.find((x) => x.name === 'skills').type = 'file'; }), /must be a dir/, 'skills becomes a file');
  // separation of immutable and mutable trees
  rejects(mut((d) => { d.runtime.release_root = P('var', 'lib', 'aihf', 'runtime', 'releases'); entry(d, P('opt', 'aihf', 'releases')).path = P('var', 'lib', 'aihf', 'runtime', 'releases'); }), /must be exactly|overlap/, 'release inside mutable runtime');
  // Windows mounts and developer trees are outside the runtime
  for (const bad of [P('mnt', 'c', 'aihf'), P('home', 'dev', 'aihf'), P('Users', 'x'), P('root', 'aihf')]) rejects(mut((d) => { d.runtime.scratch = bad; }), /scratch/, `scratch ${bad}`);
  for (const bad of [P('var', 'lib', '..', 'x'), P('var', 'lib', '.', 'x'), 'relative/path', `${P('var', 'lib', 'aihf')}/`, P('var', '', 'x')]) rejects(mut((d) => { d.entries.push({ path: bad, type: 'dir', owner: 'root', group: 'root', mode: '0755', role: 'state_parent' }); }), /normalized|absolute/, `path ${bad}`);
  // each of these is caught ONLY by the check named in the label (mutation-check survivors turned into tests)
  rejects(mut((d) => { const e = entry(d, P('var', 'lib', 'aihf', 'runtime')); e.role = 'ops_writable'; e.owner = 'aihf-ops'; e.group = 'aihf-ops'; e.mode = '0700'; }), /must be root-owned and not group/, 'runtime parent made ops-owned by a role change (scratch could be renamed away)');
  rejects(mut((d) => { d.identities.push(clone(d.identities[0])); }), /identities must be exactly/, 'duplicate ops identity');
  rejects(mut((d) => { d.entries.push({ path: P('mnt', 'c', 'aihf'), type: 'dir', owner: 'root', group: 'root', mode: '0755', role: 'state_parent' }); }), /must not be under/, 'declared path on a Windows mount');
  rejects(mut((d) => { d.entries.push({ path: P('var', 'lib', 'aihf', 'runtime', 'releases'), type: 'dir', owner: 'root', group: 'root', mode: '0755', role: 'release' }); }), /overlap/, 'release declared inside the mutable runtime');
  rejects(mut((d) => { d.entries.push({ path: P('var', 'lib', 'aihf', 'ops', 'codex-home', 'policy'), type: 'dir', owner: 'root', group: 'root', mode: '0755', role: 'managed_policy' }); }), /overlap/, 'managed policy declared inside the Codex home');
  // no service identity, no second identity, no privilege on the ops account
  rejects(mut((d) => { d.identities.push({ ...d.identities[0], id: 'signerd', user: 'aihf-signerd', group: 'aihf-signerd' }); }), /identities must be exactly/, 'extra identity beyond ops, riskd, traderd, signerd');
  rejects(mut((d) => { d.identities[0].user = 'traderd'; }), /service identity|ops identity must be/, 'ops identity renamed to a service');
  rejects(mut((d) => { d.identities[0].sudo = true; }), /no sudo/, 'sudo');
  rejects(mut((d) => { d.identities[0].supplementary_groups = ['sudo']; }), /supplementary groups/, 'group sudo');
  rejects(mut((d) => { d.identities[0].password = 'set'; }), /locked/, 'password set');
  rejects(mut((d) => { d.identities[0].system_account = false; }), /system account/, 'normal account');
  rejects(mut((d) => { d.identities[0].home = P('home', 'aihf-ops'); }), /ops home/, 'home moved');
  // launcher environment
  rejects(mut((d) => { d.runtime.launcher_env_allowlist.push('WSLENV'); }), /launcher_env_allowlist/, 'WSLENV inherited');
  rejects(mut((d) => { d.runtime.launcher_env_allowlist = ['PATH']; }), /launcher_env_allowlist/, 'allowlist shrunk silently');
  rejects(mut((d) => { d.runtime.launcher_path_env = `${P('usr', 'bin')}:${P('mnt', 'c', 'Windows')}`; }), /launcher_path_env/, 'Windows PATH');
  // WSL interoperability must be off
  for (const k of ['automount_enabled', 'interop_enabled', 'append_windows_path']) rejects(mut((d) => { d.wsl[k] = true; }), new RegExp(k), `wsl ${k}`);
  rejects(mut((d) => { d.wsl.default_user = 'root'; }), /default_user/, 'default user root');
  // closed document shape
  rejects(mut((d) => { d.extra = 1; }), /shape is closed/, 'extra top-level key');
  rejects(mut((d) => { d.runtime.extra = 1; }), /shape is closed/, 'extra runtime key');
  rejects(mut((d) => { entry(d, P('etc', 'codex')).extra = 1; }), /shape is closed/, 'extra entry key');
  rejects(mut((d) => { d.entries = d.entries.filter((e) => e.path !== P('etc', 'codex', 'requirements.toml')); }), /no layout entry/, 'requirements entry dropped');
  rejects(mut((d) => { d.entries.push(clone(d.entries[0])); }), /duplicate entry/, 'duplicate entry');
  assert.deepEqual(checkOpsLayout(LAYOUT()), { ok: true, violations: [] }, 'positive control still holds');
});

// ------------------------------------------------------------------ shell constants mirror the layout contract
function shellVars(text) {
  const vars = {};
  for (const m of text.matchAll(/^(AIHF_[A-Z_]+)="([^"]*)"$/gm)) vars[m[1]] = m[2];
  const arr = (name) => [...(new RegExp(`^${name}=\\(\\n([\\s\\S]*?)\\n\\)`, 'm').exec(text)?.[1] ?? '').matchAll(/^\s*"([^"]+)"$/gm)].map((m) => m[1].split(' '));
  return { vars, dirs: arr('AIHF_DIRS'), services: arr('AIHF_SERVICES'), prot: arr('AIHF_CODEX_HOME_PROTECTED'), homeProt: arr('AIHF_OPS_HOME_PROTECTED') };
}
test('ops provision: fund-ops-layout.sh mirrors contracts/ops-runtime-layout.json exactly (no drift)', () => {
  const { vars, dirs, prot } = shellVars(sh('fund-ops-layout.sh'));
  const d = LAYOUT();
  const r = d.runtime;
  assert.equal(vars.AIHF_CODEX_PIN, r.codex_version_pin);
  assert.equal(vars.AIHF_OPS_USER, d.identities[0].user);
  assert.equal(vars.AIHF_OPS_GROUP, d.identities[0].group);
  assert.equal(vars.AIHF_OPS_HOME, r.ops_home);
  assert.equal(vars.AIHF_OPS_SHELL, d.identities[0].shell);
  assert.equal(vars.AIHF_REQUIREMENTS, r.requirements_path);
  assert.equal(vars.AIHF_RELEASE_ROOT, r.release_root);
  assert.equal(vars.AIHF_RELEASE_CURRENT, r.release_current);
  assert.equal(vars.AIHF_CODEX_BIN, r.toolchain_codex_bin);
  assert.equal(vars.AIHF_LAUNCHER, r.launcher);
  assert.equal(vars.AIHF_LAUNCHER_PATH_ENV, r.launcher_path_env);
  assert.equal(vars.AIHF_RUNTIME_ROOT, r.runtime_state_root);
  assert.equal(vars.AIHF_SCRATCH, r.scratch);
  assert.equal(vars.AIHF_STATE, r.state);
  assert.equal(vars.AIHF_CODEX_HOME, r.codex_home);
  const wantDirs = d.entries.filter((e) => e.type === 'dir' && e.role !== 'toolchain' || e.path === P('opt', 'aihf', 'toolchain') || e.path === P('opt', 'aihf', 'bin'))
    .filter((e) => e.path !== P('opt', 'aihf', 'toolchain', 'codex'))
    .filter((e) => e.type === 'dir'); // P1-S3B: service state, the signer secret directory and the operator-control parent are provisioned too
  assert.deepEqual(dirs.map((x) => x.join(' ')).sort(), wantDirs.map((e) => `${e.path} ${e.owner} ${e.group} ${e.mode}`).sort());
  assert.deepEqual(prot.map((x) => x.join(' ')).sort(), d.codex_home_protected.map((p) => `${p.name} ${p.type} ${p.mode}`).sort());
  const homeProt = shellVars(sh('fund-ops-layout.sh')).homeProt;
  assert.deepEqual(homeProt.map((x) => x.join(' ')).sort(), d.ops_home_protected.map((p) => `${p.name} ${p.type} ${p.mode}`).sort());
  // P1-S3B: service identities, signer sentinel and fundctl constants mirror the contract
  const svc = shellVars(sh('fund-ops-layout.sh')).services;
  assert.deepEqual(svc.map((x) => x.join(' ')), d.identities.slice(1).map((i) => `${i.user} ${i.home}`), 'service identity table');
  assert.equal(vars.AIHF_SERVICE_SHELL, '/usr/sbin/nologin');
  for (const i of d.identities.slice(1)) assert.equal(i.shell, vars.AIHF_SERVICE_SHELL);
  const fe = (p) => d.entries.find((e) => e.path === p);
  assert.equal(vars.AIHF_SIGNER_SENTINEL, P('var', 'lib', 'aihf', 'signerd', 'secrets', 'sentinel'));
  assert.equal(vars.AIHF_SIGNER_SECRET_DIR, P('var', 'lib', 'aihf', 'signerd', 'secrets'));
  assert.deepEqual([fe(vars.AIHF_SIGNER_SENTINEL).owner, fe(vars.AIHF_SIGNER_SENTINEL).group, fe(vars.AIHF_SIGNER_SENTINEL).mode], ['aihf-signerd', 'aihf-signerd', '0600']);
  assert.equal(vars.AIHF_FUNDCTL, d.fundctl.install_path);
  assert.equal(vars.AIHF_FUNDCTL_SOURCE, d.fundctl.source_path);
  assert.deepEqual([fe(vars.AIHF_FUNDCTL).owner, fe(vars.AIHF_FUNDCTL).group, fe(vars.AIHF_FUNDCTL).mode], ['root', 'root', '0700']);
  assert.ok(dirs.length === 17 && prot.length === 11 && homeProt.length === 6, 'parser sanity: tables were actually read');
  assert.match(sh('fund-ops-layout.sh'), /^AIHF_CODEX_SHA256="[0-9a-f]{64}"$/m, 'the Codex binary hash pin exists');
});

test('ops provision: WSL template matches the layout contract hardening flags', () => {
  const t = sh('wsl.conf.fund-ops').split('\n').filter((l) => !l.trim().startsWith('#'));
  const w = LAYOUT().wsl;
  assert.equal(t.filter((l) => /^enabled\s*=\s*false$/.test(l.trim())).length, 2, 'automount and interop disabled');
  assert.ok(t.some((l) => /^appendWindowsPath\s*=\s*false$/.test(l.trim())));
  assert.ok(t.some((l) => new RegExp(`^default\\s*=\\s*${w.default_user}$`).test(l.trim())));
  assert.equal(w.automount_enabled || w.interop_enabled || w.append_windows_path, false);
});

// ------------------------------------------------------------------ pinned canonical artifacts
test('ops provision: canonical-artifacts.sha256 pins exactly the reviewed artifacts and every pin matches', () => {
  const rows = sh('canonical-artifacts.sha256').trim().split('\n').map((l) => l.split(/\s+/));
  assert.deepEqual(rows.map((r) => r[1]).sort(), ['config/codex/fund-ops.config.toml', 'config/codex/requirements.fund-ops.toml', 'contracts/ops-runtime-layout.json', 'ops/fundctl/fundctl', 'ops/provision/wsl.conf.fund-ops']);
  for (const [want, rel] of rows) {
    assert.match(want, /^[0-9a-f]{64}$/);
    assert.equal(sha(fs.readFileSync(abs(rel), 'utf8')), want, `${rel} differs from its pin (update the pin in the same reviewed change)`);
  }
});

// ------------------------------------------------------------------ provisioning script properties (static)
function scriptProblems(name, text) {
  const out = [];
  const code = text.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n');
  if (name !== 'fund-ops-layout.sh' && !/^set -[a-z]*u/m.test(code)) out.push('no nounset');
  // the layout file is data: only comments, assignments, array rows and closing parentheses
  if (name === 'fund-ops-layout.sh' && code.split('\n').some((l) => l.trim() && !/^(AIHF_[A-Z0-9_]+=("[^"]*"|\()|"[^"]*"|\))$/.test(l.trim()))) out.push('layout file contains commands');
  if (/chmod\s+(-R\s+)?(0?7[0-7][2367]|0?[0-7]?[0-7][2367]7|a\+w|o\+w|go\+w|777|666)\b/.test(code)) out.push('widening chmod');
  if (/NOPASSWD|visudo|usermod\s+-a?G|gpasswd\s+-a|adduser\s+\S+\s+sudo|chpasswd|passwd\s+-d\b/.test(code)) out.push('privilege grant');
  // P1-S3B: service accounts are referenced only through the layout table (AIHF_SERVICES) or by pinned aihf- prefixed names and paths; a bare name is outside the contract
  if (/(^|[^\w/-])(riskd|traderd|signerd)\b/i.test(code)) out.push('service identity');
  if (/co[-_ ]?invest/i.test(code)) out.push('Co-Invest reference');
  // the validator and verifier legitimately contain the secret-SCANNING pattern (a grep for key headers); no other secret reference is allowed
  const noScan = code.split('\n').filter((l) => !(/^(fund-ops-validate|fund-ops-verify)\.sh$/.test(name) && /grep .*BEGIN \[A-Z \]\*PRIVATE KEY/.test(l))).join('\n');
  if (/(-----BEGIN|0x[0-9a-fA-F]{64}|private[_ ]?key|mnemonic|seed[_ ]?phrase|api[_ ]?wallet)/i.test(noScan)) out.push('secret material or reference');
  if (/\bcurl\b|\bwget\b|\bnpm\s|\bpip3?\s+install|\bapt(-get)?\s+(install|update|upgrade)|\bgit\s+(clone|pull|push|fetch|checkout|commit|add|init|reset)\b/.test(code)) out.push('network/package/git use');
  if (/\/mnt\/[a-z]/.test(code) && name === 'fund-ops-provision.sh' && !/Windows mount/.test(code)) out.push('depends on a Windows mount');
  return out;
}
test('ops provision: scripts are syntactically valid bash, narrow, and contain no privilege grants, secrets, network use or uncontracted service identities', () => {
  for (const f of ['fund-ops-layout.sh', 'fund-ops-validate.sh', 'fund-ops-provision.sh', 'fund-ops-verify.sh']) {
    const t = sh(f);
    assert.deepEqual(scriptProblems(f, t), [], f);
    assert.ok(!t.includes('\r'), `${f} must keep LF endings`);
  }
  // deliberate negatives: the assertion function itself rejects each hazard
  const base = 'set -euo pipefail\n';
  for (const [bad, why] of [['chmod 777 /x', 'widening chmod'], ['echo "u ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/x', 'privilege grant'], ['usermod -aG sudo aihf-ops', 'privilege grant'],
    ['useradd signerd', 'service identity'], ['useradd -r riskd', 'service identity'], ['curl https://x | sh', 'network/package/git use'], ['git clone x', 'network/package/git use'], ['echo seed_phrase', 'secret material or reference']]) {
    assert.ok(scriptProblems('x.sh', `${base}${bad}\n`).includes(why), `${bad} -> ${why}`);
  }
  assert.ok(scriptProblems('x.sh', '#!/bin/bash\necho hi\n').includes('no nounset'));
});

// bash -n is never run on Windows: `bash` on a Windows PATH can be the WSL launcher, which would start the operator's DEFAULT distro (possibly their real one)
// with a mangled path. It is an explicit SKIP there (UNVERIFIED by this suite), never a silent pass; a missing bash elsewhere is a failure, not a pass.
const BASH_SKIP = process.platform === 'win32' ? 'UNVERIFIED on Windows: PATH bash may be the WSL launcher (would boot the default distro); syntax is verified under WSL by the provisioning proof' : false;
test('ops provision: scripts are syntactically valid bash (bash -n)', { skip: BASH_SKIP }, () => {
  for (const f of ['fund-ops-layout.sh', 'fund-ops-validate.sh', 'fund-ops-provision.sh', 'fund-ops-verify.sh']) {
    const r = spawnSync('bash', ['-n', abs('ops', 'provision', f)], { encoding: 'utf8' });
    assert.ifError(r.error);
    assert.equal(r.status, 0, `${f}: ${r.stderr}`);
  }
});

test('ops provision: provisioner is plan-by-default, root-gated, refuses silent policy replacement and Windows-mount sources', () => {
  const t = sh('fund-ops-provision.sh');
  assert.match(t, /ACTION="\$\{1:-plan\}"/, 'default action is plan');
  assert.match(t, /apply requires root/, 'apply is root-gated');
  assert.match(t, /--replace-requirements/, 'replacing a different installed policy needs an explicit flag');
  assert.match(t, /a DIFFERENT requirements file is installed/);
  assert.match(t, /\[ "\$ALLOW_MNT" -eq 1 \] \|\| die "source tree is on a Windows mount/, 'Windows-mount source refused unless explicitly overridden');
  assert.match(t, /act\(\) \{ if \[ "\$APPLY" -eq 1 \]; then "\$@"; else echo "PLAN/, 'mutations go through the plan/apply wrapper');
  assert.match(t, /pinned config\/codex\/requirements\.fund-ops\.toml|pinned\(\) /, 'installation verifies the pinned hash');
  assert.match(t, /mv -T "\$LINK_TMP" "\$AIHF_RELEASE_CURRENT"/, 'activation is an atomic rename');
  assert.match(t, /releases are immutable/, 'release ids are immutable');
  assert.match(t, /supplementary groups/, 'refuses an ops account with extra groups');
  assert.match(t, /referenced in sudoers/, 'refuses an ops account referenced in sudoers');
  assert.match(t, /passwd -l/, 'locks the account password');
  assert.ok(!/\bsudo\b/.test(t.split('\n').filter((l) => !l.trim().startsWith('#') && !/sudoers|"[^"]*sudo/.test(l)).join('\n')), 'never calls sudo');
  // review round 1 (B1/B2 and should-fix items): staging happens in a root-only directory, never inside a group-writable home
  assert.match(t, /STAGE_ROOT="\/var\/lib\/aihf\/ops\/\.stage\.\$\$"/, 'protected files are staged in a root-only directory');
  assert.match(t, /tmp="\$STAGE_ROOT\/\$n"/, 'staged names live under the root-only directory');
  assert.ok(!/"\$p\.tmp\.\$\$"/.test(t), 'no predictable temp name is created inside a group-writable home');
  assert.match(t, /mv -T -- "\$tmp" "\$p"/, 'atomic rename replaces anything planted at the final name');
  // FU-0011 (supersedes the P1-S3C pgrep-by-name check): processes are matched by NUMERIC uid for the ops identity AND every service identity. An absent account
  // (getent exit 2) owns no processes, which still lets a truly fresh distro apply (the P1-S3C live finding); any other getent failure is refused, never read as "absent".
  assert.match(t, /\n  require_no_identity_processes\n/, 'refuses to provision while ops or service processes run');
  assert.match(t, /getent_exists passwd "\$u" \|\| continue/, 'the process check skips only an account that does not exist');
  assert.match(t, /case "\$rc" in 0\) return 0 ;; 2\) return 1 ;; \*\) die "getent/, 'getent exit 2 means absent; every other failure is refused');
  assert.ok(!/\bpgrep\b/.test(t.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n')), 'no name-keyed pgrep');
  assert.match(t, /= "\$AIHF_CODEX_SHA256" \] \|\| die/, 'the Codex binary is hash-pinned (and refused on mismatch) before it is executed as root');
  assert.match(t, /symbolic links or special files/, 'special files are refused in the release source');
  assert.match(t, /install_protected "\$AIHF_OPS_HOME"/, 'HOME protected surface is installed');
  assert.ok(!/\[ "\$APPLY" -eq 1 \] && \{/.test(t), 'no apply-mode work hides inside an && / || list that errexit cannot see');
  const v = sh('fund-ops-verify.sh');
  assert.match(v, /plant a user skill under HOME\/\.agents\/skills/, 'HOME skill root is attacked by the verifier');
  assert.match(v, /protwritable=\$\(printf/, 'protected names are excluded from the writable allowlist');
  assert.match(v, /as_ops test -x "\$PE" \|\| fail/, 'PE probe has a precheck');
  assert.match(v, /launch_assign/, 'the launcher environment is judged from the installed launcher');
  assert.ok(!/printenv WSLENV/.test(v), 'no vacuous environment check');
  assert.match(v, /as_ops\(\) \{ runuser -u "\$AIHF_OPS_USER" -- "\$\{OPS_ENV\[@\]\}" "\$@"; \}/, 'denial tests run as the real ops identity through a clean environment');
  assert.match(v, /control "allowed \(intended\)/, 'positive controls exist');
  assert.match(v, /writable set/, 'writable-set enumeration exists');
  assert.match(v, /--expect-hardened-wsl/, 'WSL hardening is checkable');
});

// ------------------------------------------------------------------ repository tripwire: the ops/provision exemption
denyTest('DENY-OPS-PROVISION-ISOLATION', () => {
  // pinned list
  assert.deepEqual([...OPS_PROVISION_FILES].sort(), ['README.md', 'canonical-artifacts.sha256', 'fund-ops-layout.sh', 'fund-ops-provision.sh', 'fund-ops-validate.sh', 'fund-ops-verify.sh', 'wsl.conf.fund-ops'].map((f) => `${PROV}/${f}`).sort());
  // the real tree is accepted, and the real provisioning directory contains only the pinned files
  assert.deepEqual(checkRepoTree(collectTree(ROOT)), { ok: true, violations: [] }, 'positive control');
  const onDisk = walk(abs('ops')).filter((p) => fs.statSync(p).isFile()).map((p) => path.relative(ROOT, p).split(path.sep).join('/'));
  assert.deepEqual(onDisk.sort(), [...OPS_PROVISION_FILES, OPS_FUNDCTL_FILE].sort(), 'ops/ holds the pinned provisioning files and exactly the one pinned fundctl');
  assert.ok(!fs.existsSync(abs('ops', 'provision', 'deploy')), 'no deploy path under ops');

  // privileged content that the exemption covers: path-scoped to exactly the pinned files
  const PRIV = `touch '${P('etc', 'codex', 'requirements.toml')}'\n`;
  for (const f of OPS_PROVISION_FILES.filter((x) => /\.sh$/.test(x))) assert.equal(treeOf({ [f]: PRIV }).ok, true, `pinned ${f} accepted`);
  // equivalent privileged scripts are rejected everywhere else, including every sibling path
  for (const f of ['ops/foo.sh', 'ops/runtime/provision.sh', 'scripts/provision.sh', 'src/provision.mjs', 'deploy/provision.sh', 'tools/fund-ops-provision.sh', 'ops/provision/extra.sh', 'ops/provision/sub/fund-ops-verify.sh',
    'OPS/provision/fund-ops-verify.sh', 'ops/Provision/fund-ops-verify.sh', 'ops-provision/fund-ops-verify.sh', 'lib/provision.sh']) {
    const r = treeOf({ [f]: f.endsWith('.mjs') ? `export const p = '${P('etc', 'codex')}';\n` : PRIV });
    assert.equal(r.ok, false, `${f} must be rejected`);
  }
  // unpinned entries beneath ops/ are rejected even when they are not code
  for (const f of ['ops/notes.md', 'ops/provision/notes.md', 'ops/runtime/x.json', 'ops/provision/fund-ops-provision.sh.bak', 'OPS/notes.md', 'Ops/runtime/x.json']) assert.ok(caps(treeOf({ [f]: 'x\n' })).includes('OPS_PROVISION_ISOLATION'), f);
  // the exemption does not cover any other capability, even inside a pinned file
  const other = [['git commit -m x', 'OPS_MODE_GIT_WRITES'], ['kubectl apply -f x', 'AUTONOMOUS_DEPLOYMENT'], ['echo seed_phrase', 'ZONE_CODEX_TRADERD_KEY'], ['import x from "node:child_process"', 'ZONE_SIGNING_ARBITRARY_SHELL'],
    ['fetch(u)', 'ZONE_SIGNING_GENERAL_NETWORK'], ['promoteStrategy()', 'SELF_PROMOTION'], ['approveAgent()', 'API_WALLET_MANAGEMENT'], ['coInvestLiveExecute()', 'COINVEST_LIVE_EXECUTION']];
  for (const [code, cap] of other) assert.ok(caps(treeOf({ [`${PROV}/fund-ops-verify.sh`]: `${code}\n` })).includes(cap), `${code} -> ${cap} still enforced inside a pinned file`);
  // the deploy* path prohibition still applies
  assert.ok(caps(treeOf({ [`${PROV}/deploy.sh`]: 'x\n' })).includes('AUTONOMOUS_DEPLOYMENT'), 'deploy path rule preserved');
  assert.ok(caps(treeOf({ 'deploy/provision.sh': 'x\n' })).includes('AUTONOMOUS_DEPLOYMENT'), 'deploy directory preserved');
  // a pinned file that is not a regular file is unscannable and rejected
  const dir = writeFiles(tempDir(), { 'ops/provision/README.md': 'x\n', 'ops/provision/fund-ops-layout.sh': 'AIHF_X="y"\n' });
  makeNonRegularEntry(path.join(dir, 'ops', 'provision', 'fund-ops-verify.sh'));
  assert.equal(checkRepoTree(collectTree(dir)).ok, false, 'symlinked pinned script rejected');
  // not importable or callable from runtime or model-facing code
  for (const [f, code] of [['src/x.mjs', "import './../ops/provision/fund-ops-verify.sh';"], ['src/y.mjs', "export const c = 'bash ops/provision/fund-ops-provision.sh apply';"], ['lib/z.sh', 'bash fund-ops-provision.sh apply'],
    ['scripts/r.sh', '. ./fund-ops-layout.sh'], ['src/w.mjs', "export const p = 'ops\\provision\\x';"], ['src/v.mjs', "export const p = 'ops\\\\provision\\\\x';"]]) {
    assert.ok(caps(treeOf({ [f]: `${code}\n` })).includes('OPS_PROVISION_ISOLATION'), `${f} references the provisioning artifacts`);
  }
  assert.ok(caps(treeOf({ 'package.json': '{"scripts":{"provision":"bash ops/provision/fund-ops-provision.sh apply"}}' })).includes('OPS_PROVISION_ISOLATION'), 'npm script invoking it');
  assert.equal(treeOf({ 'tests/x.test.mjs': "export const c = 'ops/provision/fund-ops-verify.sh';\n" }).ok, true, 'tests may reference it');
  // Codex fund-ops is never granted a way to run it: the managed requirements add no allow rules and keep the read-only profile
  const req = readText('config', 'codex', 'requirements.fund-ops.toml');
  assert.ok(!/^\s*\[rules\]/m.test(req) && !/\ballow\b\s*=/.test(req.replace(/^#.*$/gm, '').replace(/allowed_[a-z_]+|allow_[a-z_]+/g, '')), 'no allow-style rules in the managed requirements');
  assert.match(req, /^default_permissions = ":read-only"/m);
  assert.equal(LAYOUT().identities[0].sudo, false);
  // the rules data keeps covering the new capability: deleting its rules fails closed
  const raw = readJson('contracts', 'phase0-checker-rules.json');
  const noOps = clone(raw); noOps.tree_rules = noOps.tree_rules.filter((x) => x.capability !== 'OPS_PROVISION_ISOLATION');
  assert.throws(() => parseRules(noOps), /no tree rule covers OPS_PROVISION_ISOLATION/);
  assert.ok(raw.tree_rules.some((x) => x.capability === 'OPS_PROVISION_ISOLATION' && x.scope === 'code') && raw.tree_rules.some((x) => x.capability === 'OPS_PROVISION_ISOLATION' && x.scope === 'package_json'));
});

// FU-0007 (resolved in P1-S3B): ops/fundctl/fundctl is admitted as ONE exact pinned path; nothing nearby and nothing broader.
test('FU-0007: the ops/fundctl/fundctl exemption is exact (OPS_PROVISION_ISOLATION denial family)', () => {
  assert.equal(OPS_FUNDCTL_FILE, 'ops/fundctl/fundctl');
  const real = fs.readFileSync(abs('ops', 'fundctl', 'fundctl'), 'utf8');
  // this exact path is allowed
  assert.equal(treeOf({ [OPS_FUNDCTL_FILE]: real }).ok, true, 'the exact pinned fundctl path is accepted');
  assert.equal(treeOf({ [OPS_FUNDCTL_FILE]: '#!/bin/sh\necho NOT_IMPLEMENTED\nexit 1\n' }).ok, true, 'and with benign content');
  // nearby / unapproved executable paths stay rejected (same content, other path)
  for (const f of ['ops/fundctl/fundctl.sh', 'ops/fundctl/fundctl2', 'ops/fundctl/extra', 'ops/fundctl/sub/fundctl', 'ops/fundctl/README.md', 'ops/fundctl/.fundctl',
    'ops/fundctl.sh', 'ops/Fundctl/fundctl', 'OPS/fundctl/fundctl', 'Ops/fundctl/fundctl', 'ops/fundctl/FUNDCTL', 'ops/bin/fundctl', 'ops/other/fundctl', 'ops/provision/fundctl',
    'ops/fundctl-extra/fundctl']) {
    assert.equal(treeOf({ [f]: real }).ok, false, `${f} must be rejected`);
  }
  // outside ops/ the same privileged content is rejected wherever it lives
  const PRIV = `touch '${P('etc', 'codex', 'requirements.toml')}'\n`;
  for (const f of ['fundctl.sh', 'scripts/fundctl.sh', 'src/fundctl.sh', 'ops-fundctl/fundctl.sh', 'fundctl/fundctl.sh']) assert.equal(treeOf({ [f]: PRIV }).ok, false, `${f} with privileged content must be rejected`);
  // the exemption is not a general ops/ exemption
  for (const f of ['ops/runner.sh', 'ops/tools/run', 'ops/notes.md']) assert.ok(caps(treeOf({ [f]: 'x\n' })).includes('OPS_PROVISION_ISOLATION'), f);
  // the pinned file receives NO capability exemption: it is scanned as code by every rule
  const hostile = [['git commit -m x', 'OPS_MODE_GIT_WRITES'], ['kubectl apply -f x', 'AUTONOMOUS_DEPLOYMENT'], ['echo seed_phrase', 'ZONE_CODEX_TRADERD_KEY'],
    ['import x from "node:child_process"', 'ZONE_SIGNING_ARBITRARY_SHELL'], ['fetch(u)', 'ZONE_SIGNING_GENERAL_NETWORK'], ['bash ops/provision/fund-ops-provision.sh apply', 'OPS_PROVISION_ISOLATION'],
    [`touch '${P('etc', 'codex', 'requirements.toml')}'`, 'ZONE_SIGNING_FILESYSTEM_ESCAPE']];
  for (const [code, cap] of hostile) assert.ok(caps(treeOf({ [OPS_FUNDCTL_FILE]: `#!/bin/sh\n${code}\n` })).includes(cap), `${code} -> ${cap} enforced inside fundctl`);
  // a non-regular (symlink) fundctl is rejected
  const dir = writeFiles(tempDir(), { 'ops/provision/README.md': 'x\n' });
  fs.mkdirSync(path.join(dir, 'ops', 'fundctl'), { recursive: true });
  makeNonRegularEntry(path.join(dir, 'ops', 'fundctl', 'fundctl'));
  assert.equal(checkRepoTree(collectTree(dir)).ok, false, 'symlinked fundctl rejected');
  assert.deepEqual(checkRepoTree(collectTree(ROOT)), { ok: true, violations: [] }, 'real tree accepted');
});

// ------------------------------------------------------------------ scope guards for this slice
test('P1-S3B scope: no secrets, running services, Co-Invest endpoints or arbitrary MCP registrations were introduced', () => {
  const files = ['contracts/ops-runtime-layout.json', 'src/contracts/ops-layout-checker.mjs', 'tests/live/verify-ops-runtime.mjs', ...OPS_PROVISION_FILES, OPS_FUNDCTL_FILE];
  for (const f of files) {
    const t = readText(...f.split('/'));
    assert.ok(!/-----BEGIN [A-Z ]*PRIVATE KEY-----|\b0x[0-9a-fA-F]{64}\b/.test(t), `${f}: secret-like content`);
    if (/\.sh$/.test(f)) assert.deepEqual(scriptProblems(path.basename(f), t).filter((p) => p === 'service identity'), [], `${f}: service identity reference`);
    assert.ok(!/co[-_ ]?invest[\w\s-]{0,20}(endpoint|direct|url)/i.test(t), `${f}: direct Co-Invest endpoint`);
  }
  // P1-S3B: the provisioner realizes identities, state directories, sentinel and fundctl, and installs/starts no service, unit or process
  const prov = sh('fund-ops-provision.sh').replace(/^\s*#.*$/gm, '');
  assert.ok(!/systemctl|\.service\b|crontab|nohup|setsid|systemd-run/.test(prov), 'provisioner starts or schedules a process');
  assert.match(prov, /useradd --system --gid "\$svc_user"/);
  assert.match(prov, /chown aihf-signerd:aihf-signerd "\$STAGE_ROOT\/sentinel"; chmod 0600/);
  assert.match(prov, /chown root:root "\$STAGE_ROOT\/fundctl"; chmod 0700/);
  // the managed requirements still register no MCP identity and the new work did not touch the project .codex surface
  const req = readText('config', 'codex', 'requirements.fund-ops.toml').replace(/^#.*$/gm, '');
  assert.match(req, /^\[mcp_servers\]\s*$/m);
  assert.ok(!/\[mcp_servers\./.test(req), 'no MCP identity approved');
  // registry: the two new capabilities are registered and the migrated one keeps its id
  const ids = readJson('contracts', 'forbidden-capabilities.json').capabilities.map((c) => c.id);
  for (const id of ['OPS_RUNTIME_BOUNDARY', 'OPS_PROVISION_ISOLATION', 'EARLY_CODEX_CONFIG']) assert.ok(ids.includes(id), id);
});
