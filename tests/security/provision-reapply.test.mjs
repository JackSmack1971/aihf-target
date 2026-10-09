import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { abs, readText } from '../helpers.mjs';

// FU-0011 / R15: privileged provisioner re-apply must never follow or trust a filesystem object that a lower-trust identity controls.
// The BEHAVIORAL proof is tests/live/provision-reapply-hostile.sh (root, disposable distro only). These tests pin the structure of the repair so a regression
// toward the old shapes fails offline, and they check that the live harness still covers every required hostile case.
const prov = () => readText('ops', 'provision', 'fund-ops-provision.sh');
const harness = () => readText('tests', 'live', 'provision-reapply-hostile.sh');
const code = (t) => t.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n');

/** Structural hazards of the pre-FU-0011 provisioner. Returns the names of the hazards present in a provisioner script's code. */
export function reapplyHazards(text) {
  const c = code(text);
  const out = [];
  // 1. a layout directory created, chowned or chmodded by PATH (follows a planted link; the old install -d / chmod pair)
  if (/\binstall\s+-d\b[^\n]*"\$p"/.test(c) || /\bchmod\s+(--\s+)?"\$m"\s+"\$p"/.test(c) || /\bchown\b[^\n]*"\$p"/.test(c)) out.push('path-based mutation of a layout directory');
  // 2. the sentinel renamed into a path that traverses a service-owned directory without verification
  if (/\bmv\s+-T\s+(--\s+)?"\$STAGE_ROOT\/sentinel"\s+"\$AIHF_SIGNER_SENTINEL"/.test(c)) out.push('unverified rename into the service-owned secret directory');
  // 3. the process precondition keyed on a name, or skipped when getent fails for any reason
  if (/\bpgrep\b/.test(c)) out.push('name-keyed pgrep');
  if (/if\s+getent\s+passwd\b/.test(c) || /\bif\s+!\s+getent\s+(group|passwd)\b/.test(c)) out.push('getent failure read as absent');
  // 4. recursive ownership or mode changes anywhere except on a root-created staging copy
  for (const m of c.matchAll(/\b(chown|chmod)\s+(-[A-Za-z]*R[A-Za-z]*)\s+[^\n]*/g)) if (!/"\$tmp"|"\$STAGE"/.test(m[0])) out.push('recursive chown/chmod outside a root-created staging copy');
  return out;
}

test('FU-0011: the shipped provisioner has none of the pre-repair hazards', () => {
  assert.deepEqual(reapplyHazards(prov()), []);
});

test('FU-0011: the hazard detector flags every pre-repair shape (deliberate negatives)', () => {
  const base = prov();
  const bad = [
    ['path-based mutation of a layout directory', 'act install -d -o "$o" -g "$g" -m "$m" "$p"\n'],
    ['path-based mutation of a layout directory', 'act chmod "$m" "$p"\n'],
    ['unverified rename into the service-owned secret directory', 'mv -T -- "$STAGE_ROOT/sentinel" "$AIHF_SIGNER_SENTINEL"\n'],
    ['name-keyed pgrep', 'pgrep -u "$AIHF_OPS_USER" >/dev/null 2>&1 && pg=0 || pg=$?\n'],
    ['getent failure read as absent', 'if getent passwd "$AIHF_OPS_USER" >/dev/null; then\n'],
    ['getent failure read as absent', 'if ! getent group "$svc_user" >/dev/null; then\n'],
    ['recursive chown/chmod outside a root-created staging copy', 'chown -R aihf-signerd:aihf-signerd /var/lib/aihf/signerd\n'],
  ];
  for (const [hazard, line] of bad) assert.ok(reapplyHazards(`${base}\n${line}`).includes(hazard), `${hazard}: ${line.trim()}`);
  // the recursion rule does not flag the root-created staging copy
  assert.deepEqual(reapplyHazards(`${base}\nchown -R root:root "$tmp"\nchmod -R go-w "$tmp"\n`), []);
});

test('FU-0011: the repair keeps every refusal and verified-descriptor primitive', () => {
  const t = prov();
  for (const re of [
    /unsafe\(\) \{ die "unsafe path \$1: \$2"; \}/,
    /"is a symbolic link"/, /"is not a directory \(type: \$type\)"/, /"changed between inspection and open"/, /is an ancestor that is neither root-owned/,
    /refusing to chown through it/, /"is not a regular file \(type: \$type\)"/, /"has \$nl hard links"/, /the layout requires \$want/,
    /stat -c "\$PMETA" -- "\$1"/, // non-following metadata
    /exec \{fd\}<"\$cand"/, /\/proc\/self\/fd\/\$prev\/\$\{comps\[\$i\]\}/, // descent relative to the verified descriptor
    /chmod -- "\$m" "\$fdp"/, /chown -- "\$o:\$g" "\$fdp"/, // mutation through the descriptor
    /act safe_dir "\$p" "\$o" "\$g" "\$m"/, /safe_install_file "\$STAGE_ROOT\/sentinel" "\$AIHF_SIGNER_SENTINEL"/, /safe_chmod_root_dir "\$p" "\$m"/,
    /\^Uid:/, /\$ru" = "\$1" \] \|\| \[ "\$eu" = "\$1" \] \|\| \[ "\$su" = "\$1" \] \|\| \[ "\$fu" = "\$1"/, // numeric uid: real, effective, saved, filesystem
    /for row in "\$\{AIHF_SERVICES\[@\]\}"; do read -r svc_u svc_h <<<"\$row"; names\+=\("\$svc_u"\); done/, // every service identity, not just ops
  ]) assert.match(t, re);
  // nothing in the provisioner is added that grants authority: no sudo, no service start, no network
  const sudoCalls = code(t).split('\n').filter((l) => /\bsudo\b/.test(l)).map((l) => l.replace(/"[^"]*"/g, '""').replace(/\bsudo -n -l -U\b/g, ''));
  assert.ok(sudoCalls.every((l) => !/\bsudo\b/.test(l)), 'no sudo use beyond the existing sudo -n -l -U inspection');
});

test('FU-0011: the live hostile harness covers every required hostile and legitimate case, and is guarded to a disposable distro', () => {
  const h = harness();
  assert.ok(!h.includes('\r'), 'LF endings');
  assert.match(h, /AIHF_DISPOSABLE_DISTRO must name a disposable aihf-\* distro/);
  assert.match(h, /WSL_DISTRO_NAME \(\$\{WSL_DISTRO_NAME:-unset\}\) is not the declared disposable distro/);
  assert.match(h, /needs root/);
  // required coverage (task FU-0011 section 4)
  for (const id of [
    'H01-secret-dir-symlink-to-external', 'H02-secret-dir-symlink-to-other-service', 'H03-secret-dir-dangling-symlink', 'H04-secret-dir-replaced-by-file',
    'H05-secret-dir-owned-by-another-identity', 'H06-sentinel-symlink-to-external', 'H07-sentinel-dangling-symlink', 'H08-sentinel-replaced-by-directory',
    'H09-sentinel-hardlink-service-file', 'H10-sentinel-hardlink-external-file', 'H11-sentinel-fifo', 'H22-sentinel-owned-by-another-identity',
    'H17-parent-path-runtime-symlink', 'H18-parent-path-ops-symlink', 'H19-parent-path-aihf-root-symlink', 'H23-ancestor-group-writable', 'H24-ancestor-owned-by-another-identity',
  ]) assert.ok(h.includes(id), id);
  for (const family of ['H12-state-dir-$d-symlink', 'H13-state-dir-$d-dangling-symlink', 'H14-state-dir-$d-replaced-by-file', 'H15-state-dir-$d-foreign-owner', 'H16-dir-$tag-symlink']) assert.ok(h.includes(family), family);
  for (const id of ['N01', 'N02', 'N03', 'N04', 'N05-$u', 'N05-effective', 'N06-getent-$code', 'N07', 'H21']) assert.ok(h.includes(id), id);
  // the four proofs asserted for every hostile case
  for (const proof of ['provisioner refused (exit', 'external target unchanged', 'ownership and modes of protected paths unchanged', 'no secret-like material exposed', 'after unplanting, re-apply succeeds']) assert.ok(h.includes(proof), proof);
  // decoy secret-like strings are generated at run time, never stored in the file
  assert.ok(!/-----BEGIN [A-Z ]*PRIVATE KEY-----|0x[0-9a-fA-F]{64}/.test(h), 'no secret-like literal in the harness source');
  assert.ok(!/\bseed[_ ]?phrase\b|\bmnemonic\b/i.test(h));
});

const LIVE = process.platform === 'linux' && process.getuid?.() === 0 && process.env.AIHF_FU0011_LIVE === '1'
  && /^aihf-[a-z0-9-]{3,40}$/.test(process.env.AIHF_DISPOSABLE_DISTRO ?? '') && process.env.WSL_DISTRO_NAME === process.env.AIHF_DISPOSABLE_DISTRO;
const LIVE_SKIP = LIVE ? false : 'UNVERIFIED here: the hostile re-apply proof needs root inside a disposable distro (AIHF_FU0011_LIVE=1, AIHF_DISPOSABLE_DISTRO=<name>, AIHF_FU0011_CODEX_DIR, AIHF_FU0011_OUT); run tests/live/provision-reapply-hostile.sh there';
test('FU-0011: live hostile re-apply harness passes on a provisioned disposable distro', { skip: LIVE_SKIP }, () => {
  const r = spawnSync('bash', [abs('tests', 'live', 'provision-reapply-hostile.sh'), '--provisioner', abs('ops', 'provision', 'fund-ops-provision.sh'),
    '--codex-dir', process.env.AIHF_FU0011_CODEX_DIR, '--release-id', process.env.AIHF_FU0011_RELEASE_ID ?? 'fu0011-suite', '--out', process.env.AIHF_FU0011_OUT, '--provisioned'], { encoding: 'utf8' });
  assert.ifError(r.error);
  assert.equal(r.status, 0, `${r.stdout.split('\n').filter((l) => l.startsWith('FAIL')).join('\n')}\n${r.stderr}`);
});

// bash -n is never run on Windows (PATH bash may be the WSL launcher and would start the operator's default distro); an explicit SKIP there, never a silent pass.
const BASH_SKIP = process.platform === 'win32' ? 'UNVERIFIED on Windows: PATH bash may be the WSL launcher (would boot the default distro); verified under Linux/WSL' : false;
test('FU-0011: provisioner and live harness are syntactically valid bash', { skip: BASH_SKIP }, () => {
  for (const f of [abs('ops', 'provision', 'fund-ops-provision.sh'), abs('tests', 'live', 'provision-reapply-hostile.sh')]) {
    const r = spawnSync('bash', ['-n', f], { encoding: 'utf8' });
    assert.ifError(r.error);
    assert.equal(r.status, 0, `${f}: ${r.stderr}`);
  }
});
