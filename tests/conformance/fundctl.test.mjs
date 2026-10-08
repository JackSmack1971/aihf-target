import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { ROOT, abs, readJson, readText, tempDir, walk } from '../helpers.mjs';

// P1-S3B: the inert root-only fundctl skeleton. Static properties plus isolated execution of the SOURCE file in a throwaway directory
// (never installed, never as root, never against a system path). Real command semantics are a later slice.
const LAYOUT = () => readJson('contracts', 'ops-runtime-layout.json');
const SRC_REL = 'ops/fundctl/fundctl';
const text = () => fs.readFileSync(abs('ops', 'fundctl', 'fundctl'), 'utf8');
const code = () => text().split('\n').filter((l) => l.trim() && !l.trim().startsWith('#'));
const COMMANDS = ['status', 'arm', 'disarm', 'halt', 'flatten', 'activate-release', 'activate-policy', 'rotate-agent'];

// A POSIX shell by absolute path on Windows (the PATH `bash` may be the WSL launcher, which could boot the operator's default distro).
const GIT_BASH = 'C:\\Program Files\\Git\\bin\\bash.exe';
const SHELL = process.platform === 'win32' ? (fs.existsSync(GIT_BASH) ? GIT_BASH : null) : '/bin/sh';
const SKIP = SHELL ? false : 'UNVERIFIED: no POSIX shell available by absolute path';
const run = (args, cwd) => spawnSync(SHELL, [abs('ops', 'fundctl', 'fundctl'), ...args], { cwd, env: { PATH: '' }, encoding: 'utf8', timeout: 20000 });
const snapshot = (dir) => walk(dir).map((p) => `${path.relative(dir, p)}:${fs.statSync(p).isFile() ? fs.statSync(p).size : 'd'}`).sort().join('|');

test('fundctl: source and install path are pinned to the layout contract and the canonical hash', () => {
  const f = LAYOUT().fundctl;
  assert.equal(f.source_path, SRC_REL);
  assert.equal(f.install_path, '/usr/local/sbin/fundctl');
  assert.deepEqual([f.owner, f.group, f.mode, f.executable_by_ops, f.network, f.secrets], ['root', 'root', '0700', false, false, false]);
  assert.deepEqual(f.commands, COMMANDS);
  const pin = readText('ops', 'provision', 'canonical-artifacts.sha256').trim().split('\n').map((l) => l.split(/\s+/)).find((r) => r[1] === SRC_REL);
  assert.ok(pin, 'fundctl is hash-pinned');
  assert.equal(crypto.createHash('sha256').update(text().replace(/\r\n/g, '\n')).digest('hex'), pin[0], 'fundctl differs from its pin (update the pin in the same reviewed change)');
  // the provisioner installs exactly that source, to exactly that path, root-only, from the pinned hash
  const prov = readText('ops', 'provision', 'fund-ops-provision.sh');
  assert.match(prov, /FC_SRC="\$SRC\/\$AIHF_FUNDCTL_SOURCE"/);
  assert.match(prov, /FC_WANT=\$\(pinned "\$AIHF_FUNDCTL_SOURCE"\)/);
  assert.match(prov, /chown root:root "\$STAGE_ROOT\/fundctl"; chmod 0700 "\$STAGE_ROOT\/fundctl"/);
  assert.match(prov, /mv -T -- "\$STAGE_ROOT\/fundctl" "\$AIHF_FUNDCTL"/);
  const layoutSh = readText('ops', 'provision', 'fund-ops-layout.sh');
  assert.match(layoutSh, /^AIHF_FUNDCTL="\/usr\/local\/sbin\/fundctl"$/m);
  assert.match(layoutSh, /^AIHF_FUNDCTL_SOURCE="ops\/fundctl\/fundctl"$/m);
  assert.ok(!text().includes('\r'), 'LF endings');
  assert.match(text(), /^#!\/bin\/sh\n/, 'plain POSIX sh');
  assert.match(readText('.gitattributes'), /^ops\/fundctl\/fundctl text eol=lf$/m, 'LF is enforced on checkout');
});

test('fundctl: no networking, subprocess, secret, state-mutation or argument-echo behavior (static)', () => {
  const c = code().join('\n');
  assert.ok(!/\b(curl|wget|nc|ncat|netcat|ssh|scp|telnet|ftp|socat|python3?|node|perl|ruby|git|systemctl|service|sudo|su|runuser|kill|tee|cp|mv|rm|mkdir|touch|chmod|chown|dd|ln)\b/.test(c), 'no external command names');
  assert.ok(!/https?:\/\/|\/dev\/(tcp|udp)|\bexec\b|\beval\b|\bsource\b|^\s*\.\s|`|\$\(|>>?\s*[^&\s]|\|/.test(code().filter((l) => !/^\s*[a-z|-]+\)\s*$/.test(l)).join('\n').replace(/2>&1|>&2/g, '')), 'no URLs, exec/eval/source, command substitution, pipes or file redirection');
  assert.ok(!/-----BEGIN|private[_ ]?key|mnemonic|seed[_ ]?phrase|0x[0-9a-fA-F]{64}|\/var\/lib|secrets?\b|sentinel|hyperliquid|exchange/i.test(text().replace(/^#.*$/gm, '').replace(/#.*$/, '')), 'no secret, state, exchange reference');
  // arguments are matched, never echoed or expanded beyond the single case subject
  assert.deepEqual([...c.matchAll(/\$[{(@*#?0-9A-Za-z_]/g)].map((m) => m[0]), ['${'], 'only the case subject ${1-} is expanded');
  assert.match(c, /case "\$\{1-\}" in/);
  // every code line is one of a closed set of shapes: the case frame, the command pattern, echo, exit
  const shapes = [/^case "\$\{1-\}" in$/, /^[a-z|-]+\)$/, /^echo "(NOT_IMPLEMENTED|REFUSED: unknown command)"( >&2)?$/, /^exit \d+ ;;$/, /^\*\)$/, /^esac$/];
  for (const l of code().map((x) => x.trim())) assert.ok(shapes.some((r) => r.test(l)), `unexpected line: ${l}`);
});

test('fundctl: recognizes exactly the eight pinned command names and nothing else (static)', () => {
  const m = /^\s*([a-z|-]+)\)\s*$/m.exec(text());
  assert.ok(m, 'recognized-command pattern present');
  assert.deepEqual(m[1].split('|'), COMMANDS, 'case patterns equal the pinned commands, in order');
  assert.deepEqual(COMMANDS, readJson('contracts', 'mcp-surface.json').operator_controls.commands, 'identical to the MCP-surface operator command pin');
});

test('fundctl: bash -n / sh -n syntax', { skip: SKIP }, () => {
  const r = spawnSync(SHELL, ['-n', abs('ops', 'fundctl', 'fundctl')], { encoding: 'utf8', env: { PATH: '' } });
  assert.ifError(r.error);
  assert.equal(r.status, 0, r.stderr);
});

test('fundctl: all eight commands print NOT_IMPLEMENTED, exit non-zero, and mutate nothing (isolated execution)', { skip: SKIP }, () => {
  const cwd = tempDir();
  const before = [snapshot(cwd), snapshot(abs('ops'))];
  for (const cmd of COMMANDS) {
    for (const extra of [[], ['--force'], ['x', '$(id)', '; id']]) {
      const r = run([cmd, ...extra], cwd);
      assert.ifError(r.error);
      assert.equal(r.stdout, 'NOT_IMPLEMENTED\n', `${cmd} ${extra.join(' ')}`);
      assert.equal(r.stderr, '', `${cmd}: nothing on stderr`);
      assert.notEqual(r.status, 0, `${cmd} must exit non-zero`);
      assert.notEqual(r.status, null);
    }
  }
  assert.deepEqual([snapshot(cwd), snapshot(abs('ops'))], before, 'no file created, removed or resized');
});

test('fundctl: unknown, empty, near-miss and hostile commands fail closed without echoing input', { skip: SKIP }, () => {
  const cwd = tempDir();
  const cases = [[], [''], ['bogus'], ['STATUS'], ['Arm'], [' status'], ['status '], ['status;id'], ['--help'], ['-h'], ['help'], ['--'], ['activate'], ['rotate'], ['activate-release2'],
    ['stat*'], ['*'], ['$(id)'], ['`id`'], ['../status'], ['exec'], ['x'.repeat(5000)]];
  for (const args of cases) {
    const r = run(args, cwd);
    assert.ifError(r.error);
    assert.notEqual(r.status, 0, `[${args.join(' ').slice(0, 30)}] must exit non-zero`);
    assert.notEqual(r.status, null);
    assert.equal(r.stdout, '', `[${JSON.stringify(args).slice(0, 40)}]: nothing on stdout for an unknown command (never a success-looking line)`);
    assert.equal(r.stderr, 'REFUSED: unknown command\n');
  }
  // a trailing newline is not a command match (built inside the shell: Windows argument passing would drop it from a spawn argument)
  const nl = spawnSync(SHELL, ['-c', 'sh "$0" "arm\n"', abs('ops', 'fundctl', 'fundctl')], { cwd, env: { PATH: '/usr/bin:/bin' }, encoding: 'utf8', timeout: 20000 });
  assert.ifError(nl.error);
  assert.equal(nl.stdout, '');
  assert.equal(nl.stderr, 'REFUSED: unknown command\n');
  assert.notEqual(nl.status, 0);
  assert.equal(snapshot(cwd), '', 'no file created');
});

test('fundctl: the ops runtime and Codex surfaces cannot reach it (contract-level)', () => {
  const d = LAYOUT();
  const e = d.entries.find((x) => x.path === d.fundctl.install_path);
  assert.deepEqual([e.owner, e.group, e.mode], ['root', 'root', '0700']);
  // not in the release tree that aihf-ops can read as a runnable path, and no MCP/Codex surface names it as a tool
  assert.ok(!d.fundctl.install_path.startsWith('/opt/aihf'));
  const mcp = readText('contracts', 'mcp-surface.json');
  assert.equal(JSON.parse(mcp).operator_controls.mcp_equivalent_allowed, false);
  assert.ok(fs.existsSync(path.join(ROOT, 'ops', 'fundctl', 'fundctl')));
});
