import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { ROOT, abs, readJson, clone } from '../helpers.mjs';
import { checkOpsLayout } from '../../src/contracts/ops-layout-checker.mjs';

// P1-S3A: contract-level proof for the riskd/traderd/signerd identities, their private state, the signerd-only secret directory and the
// root-owned inert fundctl. Static only: nothing is provisioned, nothing is executed, no secret material exists.
const LAYOUT = () => readJson('contracts', 'ops-runtime-layout.json');
const mut = (fn) => { const d = clone(LAYOUT()); fn(d); return d; };
const P = (...s) => ['', ...s].join('/');
const entry = (d, p) => d.entries.find((e) => e.path === p);
const ident = (d, id) => d.identities.find((i) => i.id === id);
const rejects = (doc, re, label) => {
  const r = checkOpsLayout(doc);
  assert.equal(r.ok, false, `${label}: must be rejected`);
  assert.ok(r.violations.some((v) => re.test(v.message)), `${label}: expected ${re}, got ${r.violations.map((v) => v.message).join(' | ')}`);
};
const SVC = ['riskd', 'traderd', 'signerd'];
const STATE = (s) => P('var', 'lib', 'aihf', s);
const SECRETS = P('var', 'lib', 'aihf', 'signerd', 'secrets');
const SENTINEL = `${SECRETS}/sentinel`;
const FUNDCTL = P('usr', 'local', 'sbin', 'fundctl');

test('service contract: shipped layout is accepted (positive control)', () => {
  assert.deepEqual(checkOpsLayout(LAYOUT()), { ok: true, violations: [] });
});

test('service contract: identities are non-login, sudo-less, private-group, no supplementary groups, none shared with aihf-ops', () => {
  const d = LAYOUT();
  const ops = ident(d, 'ops');
  const groups = new Set();
  for (const s of SVC) {
    const i = ident(d, s);
    assert.equal(i.user, `aihf-${s}`); assert.equal(i.group, `aihf-${s}`);
    assert.equal(i.shell, '/usr/sbin/nologin'); assert.equal(i.sudo, false); assert.equal(i.password, 'locked');
    assert.deepEqual(i.supplementary_groups, []); assert.equal(i.system_account, true);
    assert.equal(i.home, STATE(s));
    assert.notEqual(i.group, ops.group); groups.add(i.group);
  }
  assert.equal(groups.size, 3);
  rejects(mut((x) => { ident(x, 'riskd').shell = '/bin/bash'; }), /non-login/, 'riskd login shell');
  rejects(mut((x) => { ident(x, 'traderd').sudo = true; }), /no sudo/, 'traderd sudo');
  rejects(mut((x) => { ident(x, 'signerd').password = 'set'; }), /locked/, 'signerd password');
  rejects(mut((x) => { ident(x, 'riskd').supplementary_groups = ['aihf-ops']; }), /supplementary/, 'riskd in the ops group');
  rejects(mut((x) => { ident(x, 'traderd').group = 'aihf-ops'; }), /must be user\/group aihf-traderd|shared/, 'traderd primary group is the ops group');
  rejects(mut((x) => { ident(x, 'signerd').group = 'aihf-riskd'; }), /must be user\/group aihf-signerd|shared/, 'signerd shares the riskd group');
  rejects(mut((x) => { ident(x, 'ops').supplementary_groups = ['aihf-signerd']; }), /supplementary/, 'ops in the signerd group');
  rejects(mut((x) => { x.identities = x.identities.filter((i) => i.id !== 'signerd'); }), /identities must be exactly/, 'signerd identity dropped');
  rejects(mut((x) => { x.identities.push({ ...ident(x, 'riskd'), id: 'extra', user: 'aihf-extra', group: 'aihf-extra' }); }), /identities must be exactly/, 'extra identity');
  rejects(mut((x) => { ident(x, 'riskd').home = STATE('traderd'); }), /private state directory/, 'riskd home is another state dir');
});

test('service contract: separate private state directories (0700, own owner:group) and a signerd-only secret directory (0700) with a 0600 sentinel', () => {
  const d = LAYOUT();
  for (const s of SVC) {
    const e = entry(d, STATE(s));
    assert.deepEqual([e.type, e.owner, e.group, e.mode, e.role], ['dir', `aihf-${s}`, `aihf-${s}`, '0700', 'service_state']);
  }
  const sd = entry(d, SECRETS);
  assert.deepEqual([sd.type, sd.owner, sd.group, sd.mode, sd.role], ['dir', 'aihf-signerd', 'aihf-signerd', '0700', 'signer_secret']);
  const sn = entry(d, SENTINEL);
  assert.deepEqual([sn.type, sn.owner, sn.group, sn.mode, sn.role], ['file', 'aihf-signerd', 'aihf-signerd', '0600', 'signer_secret']);
  // no other secret-bearing entry exists and nothing outside the signerd tree is named like one
  assert.deepEqual(d.entries.filter((e) => e.role === 'signer_secret').map((e) => e.path).sort(), [SECRETS, SENTINEL].sort());
  // mutations: every weakening is rejected
  for (const s of SVC) for (const m of ['0750', '0755', '0770', '0701', '0711']) rejects(mut((x) => { entry(x, STATE(s)).mode = m; }), /0700/, `${s} state mode ${m}`);
  rejects(mut((x) => { entry(x, STATE('riskd')).group = 'aihf-ops'; }), /owns only its private state tree|owned by aihf-riskd/, 'riskd state shared with the ops group');
  rejects(mut((x) => { entry(x, STATE('riskd')).owner = 'aihf-traderd'; }), /owned by aihf-riskd|owns only/, 'riskd state owned by traderd');
  rejects(mut((x) => { entry(x, STATE('traderd')).owner = 'aihf-ops'; entry(x, STATE('traderd')).group = 'aihf-ops'; }), /state directory must be/, 'traderd state owned by ops');
  rejects(mut((x) => { entry(x, SECRETS).mode = '0750'; }), /signer_secret entries are exactly/, 'secret dir group-readable');
  rejects(mut((x) => { entry(x, SENTINEL).mode = '0644'; }), /signer_secret entries are exactly/, 'sentinel world-readable');
  rejects(mut((x) => { entry(x, SECRETS).owner = 'aihf-riskd'; entry(x, SECRETS).group = 'aihf-riskd'; }), /owned by aihf-signerd|owns only/, 'secret dir owned by riskd');
  rejects(mut((x) => { entry(x, SENTINEL).group = 'aihf-traderd'; }), /signerd secret tree is owned|owns only/, 'sentinel readable by the traderd group');
  rejects(mut((x) => { x.entries = x.entries.filter((e) => e.path !== SECRETS); }), /no layout entry/, 'secret dir dropped');
  rejects(mut((x) => { x.entries = x.entries.filter((e) => e.path !== STATE('riskd')); }), /no layout entry/, 'riskd state dropped');
  rejects(mut((x) => { x.entries.push({ path: P('var', 'lib', 'aihf', 'riskd', 'secrets'), type: 'dir', owner: 'aihf-riskd', group: 'aihf-riskd', mode: '0700', role: 'service_state' }); }), /exactly the three private service state|secret-looking/, 'secret directory outside signerd');
  rejects(mut((x) => { x.entries.push({ path: P('var', 'lib', 'aihf', 'signerd', 'secrets', 'wallet.key'), type: 'file', owner: 'aihf-signerd', group: 'aihf-signerd', mode: '0600', role: 'signer_secret' }); }), /signer_secret entries are exactly/, 'extra secret file');
  rejects(mut((x) => { x.entries.push({ path: P('var', 'lib', 'aihf', 'signerd', 'secrets', 'note'), type: 'file', owner: 'root', group: 'root', mode: '0644', role: 'state_parent' }); }), /contains only signer_secret|owned by aihf-signerd/, 'non-secret entry inside the secret tree');
  rejects(mut((x) => { x.entries.push({ path: P('var', 'lib', 'aihf', 'runtime', 'private-key'), type: 'file', owner: 'aihf-ops', group: 'aihf-ops', mode: '0600', role: 'ops_writable' }); }), /secret-looking/, 'secret-looking path in the ops tree');
});

test('service contract: aihf-ops owns and shares nothing of the service trees; no service identity owns anything of ops', () => {
  const d = LAYOUT();
  for (const e of d.entries) {
    const svcOwned = SVC.some((s) => e.owner === `aihf-${s}` || e.group === `aihf-${s}`);
    if (svcOwned) assert.ok(!['aihf-ops'].includes(e.owner) && !['aihf-ops'].includes(e.group), `${e.path}: mixes identities`);
    if (e.owner === 'aihf-ops' || e.group === 'aihf-ops') assert.ok(!SVC.some((s) => e.path.startsWith(STATE(s))), `${e.path}: ops identity inside a service tree`);
  }
  rejects(mut((x) => { x.entries.push({ path: P('var', 'lib', 'aihf', 'ops', 'home', 'x'), type: 'dir', owner: 'aihf-signerd', group: 'aihf-ops', mode: '0770', role: 'state_parent' }); }), /owns only its private state tree/, 'signerd owns a path in the ops tree');
  rejects(mut((x) => { x.entries.push({ path: P('var', 'lib', 'aihf', 'signerd', 'cache'), type: 'dir', owner: 'aihf-ops', group: 'aihf-ops', mode: '0700', role: 'ops_writable' }); }), /ops_writable paths are limited|owned by aihf-signerd/, 'ops-writable directory inside signerd state');
});

test('fundctl contract: root-only, inert, offline, secretless, exact pinned commands, every command NOT_IMPLEMENTED', () => {
  const d = LAYOUT();
  const f = d.fundctl;
  assert.equal(f.install_path, FUNDCTL);
  assert.equal(f.source_path, 'ops/fundctl/fundctl');
  assert.deepEqual([f.owner, f.group, f.mode], ['root', 'root', '0700']);
  assert.deepEqual([f.executable_by_ops, f.network, f.secrets, f.fail_closed, f.exit_nonzero], [false, false, false, true, true]);
  assert.equal(f.command_result, 'NOT_IMPLEMENTED');
  // the command names are the existing pinned operator-control names, identical to the MCP-surface contract (which forbids an MCP equivalent)
  const oc = readJson('contracts', 'mcp-surface.json').operator_controls;
  assert.equal(oc.surface, 'fundctl'); assert.equal(oc.mcp_equivalent_allowed, false);
  assert.deepEqual(f.commands, oc.commands);
  const e = entry(d, FUNDCTL);
  assert.deepEqual([e.type, e.owner, e.group, e.mode, e.role], ['file', 'root', 'root', '0700', 'operator_control']);
  assert.deepEqual([entry(d, P('usr', 'local', 'sbin')).owner, entry(d, P('usr', 'local', 'sbin')).mode], ['root', '0755']);
  // mutations
  for (const m of ['0755', '0750', '0705', '0701', '0500', '4755']) rejects(mut((x) => { entry(x, FUNDCTL).mode = m; }), /root-only file|writable/, `fundctl entry mode ${m}`);
  for (const m of ['0755', '0750', '0705', '0500']) rejects(mut((x) => { x.fundctl.mode = m; }), /fundctl.mode must be 0700/, `fundctl contract mode ${m}`);
  rejects(mut((x) => { entry(x, FUNDCTL).owner = 'aihf-ops'; }), /root:root|ops identity owns/, 'fundctl owned by ops');
  rejects(mut((x) => { entry(x, FUNDCTL).group = 'aihf-ops'; }), /root:root/, 'fundctl group ops');
  rejects(mut((x) => { entry(x, P('usr', 'local', 'sbin')).mode = '0775'; }), /writable/, 'parent group-writable (fundctl replaceable)');
  rejects(mut((x) => { entry(x, P('usr', 'local', 'sbin')).owner = 'aihf-ops'; }), /root:root|ops identity owns/, 'parent owned by ops');
  rejects(mut((x) => { x.fundctl.executable_by_ops = true; }), /executable_by_ops/, 'executable by ops');
  rejects(mut((x) => { x.fundctl.network = true; }), /network/, 'network allowed');
  rejects(mut((x) => { x.fundctl.secrets = true; }), /secrets/, 'secrets allowed');
  rejects(mut((x) => { x.fundctl.commands = x.fundctl.commands.filter((c) => c !== 'halt'); }), /pinned operator commands/, 'command dropped');
  rejects(mut((x) => { x.fundctl.commands.push('exec'); }), /pinned operator commands/, 'command added');
  rejects(mut((x) => { x.fundctl.commands = [...x.fundctl.commands].reverse(); }), /pinned operator commands/, 'commands reordered');
  rejects(mut((x) => { x.fundctl.command_result = 'OK'; }), /NOT_IMPLEMENTED/, 'implemented result');
  rejects(mut((x) => { x.fundctl.fail_closed = false; }), /NOT_IMPLEMENTED/, 'not fail-closed');
  rejects(mut((x) => { x.fundctl.exit_nonzero = false; }), /NOT_IMPLEMENTED/, 'exits zero');
  rejects(mut((x) => { x.fundctl.install_path = P('opt', 'aihf', 'bin', 'fundctl'); }), /install_path/, 'moved into the ops-visible release tree');
  rejects(mut((x) => { x.fundctl.source_path = 'scripts/fundctl'; }), /source_path/, 'source moved');
  rejects(mut((x) => { x.fundctl.extra = true; }), /fundctl shape is closed/, 'extra field');
  rejects(mut((x) => { delete x.fundctl; }), /document shape is closed/, 'fundctl block removed');
  rejects(mut((x) => { x.entries = x.entries.filter((e2) => e2.path !== FUNDCTL); }), /no layout entry/, 'fundctl entry dropped');
});

test('P1-S3A scope: contracts only. No fundctl executable, no provisioning code for service identities, no secret material, no IPC/network policy', () => {
  assert.equal(fs.existsSync(abs('ops', 'fundctl')), false, 'ops/fundctl/fundctl is not written in P1-S3A');
  const tracked = spawnSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8' }).stdout.split('\n');
  assert.deepEqual(tracked.filter((f) => /^ops\/(?!provision\/)/.test(f)), [], 'no ops/ path outside the pinned provisioning directory');
  const text = fs.readFileSync(abs('contracts', 'ops-runtime-layout.json'), 'utf8');
  assert.ok(!/-----BEGIN [A-Z ]*PRIVATE KEY-----|\b0x[0-9a-fA-F]{40,64}\b|\bmnemonic\b|seed phrase/i.test(text), 'no secret-like content in the layout contract');
  assert.ok(!/socket|listen|port|iptables|nftables|proxy|https?:\/\//i.test(text.replace(/"note":[^\n]*/, '')), 'no IPC or network policy is defined here (deferred)');
});
