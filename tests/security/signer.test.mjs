import test from 'node:test';
import assert from 'node:assert/strict';
import { validate } from '../../src/contracts/schema-validator.mjs';
import { checkSignerPolicy, parseRequiredDenials, loadRequiredDenials } from '../../src/contracts/signer-policy-consistency.mjs';
import { schema, readJson, clone, denyTest, srcFiles, scanFile, scanText, scanImports, tempDir, writeFiles, SRC_IMPORT_ALLOWLIST } from '../helpers.mjs';
import fs from 'node:fs';
import path from 'node:path';

const policy = () => readJson('config', 'signer-policy.json');
const S = () => schema('signer-policy');
const ALLOWED = ['SignOrder', 'SignCancelByCloid', 'SignCancelByOid', 'SignScheduleCancel'];

test('signer policy allowlist is exactly the four canonical request types and validates', () => {
  const p = policy();
  assert.deepEqual([...p.allowed_request_types].sort(), [...ALLOWED].sort());
  assert.deepEqual(validate(S(), p).errors, []);
});

denyTest('DENY-SIGNER-NON-ALLOWLISTED-REQUEST', () => {
  for (const extra of ['SignAnyAction', 'SignRawAction', 'SignWithdraw', 'SignUserEip712', 'SignUpdateLeverage', '', 'signorder']) {
    const p = clone(policy()); p.allowed_request_types = [...ALLOWED.slice(0, 3), extra];
    assert.ok(!validate(S(), p).valid, `replacing with "${extra}" must be rejected`);
    const q = clone(policy()); q.allowed_request_types = [...ALLOWED, extra];
    assert.ok(!validate(S(), q).valid, `adding "${extra}" must be rejected`);
  }
  const fewer = clone(policy()); fewer.allowed_request_types = ALLOWED.slice(0, 3);
  assert.ok(!validate(S(), fewer).valid, 'dropping a type changes the versioned policy and must be rejected here');
  const dup = clone(policy()); dup.allowed_request_types = [ALLOWED[0], ALLOWED[0], ALLOWED[1], ALLOWED[2]];
  assert.ok(!validate(S(), dup).valid);
  const extraField = clone(policy()); extraField.allow_raw = true;
  assert.ok(!validate(S(), extraField).valid);
});

// Section 13 "no code path" list -> identifiers that must be denied. Each id is fed to real checkers:
// a policy without the denial (consistency check), a policy allowlisting it (schema), and a source file using it (scanner).
function assertSignerDenies(ids) {
  const p = policy();
  assert.ok(checkSignerPolicy(p).ok, 'positive control: shipped policy passes the pinned-denial check');
  const dir = tempDir();
  for (const id of ids) {
    assert.ok(p.denied_actions.includes(id), `${id} missing from denied_actions`);
    const dropped = clone(p); dropped.denied_actions = dropped.denied_actions.filter((d) => d !== id);
    const r = checkSignerPolicy(dropped);
    assert.ok(!r.ok && r.violations.some((v) => v.includes(id)), `dropping ${id} must be rejected`);
    const bad = clone(p); bad.allowed_request_types = [...ALLOWED.slice(0, 3), id];
    assert.ok(!validate(S(), bad).valid, `allowlisting ${id} must be rejected by schema`);
    const both = clone(p); both.allowed_request_types = [...ALLOWED.slice(0, 3), id];
    assert.ok(!checkSignerPolicy(both).ok, `${id} both allowed and denied must be rejected`);
    const fixtureFile = path.join(writeFiles(dir, { [`${id}.mjs`]: `export const x = ${JSON.stringify(id)};\n` }), `${id}.mjs`);
    assert.ok(scanFile(fixtureFile, [id]).includes(id), `scanner must catch a file containing ${id}`);
    for (const f of srcFiles()) assert.ok(!scanFile(f, [id], SRC_IMPORT_ALLOWLIST[path.basename(f)] ?? []).includes(id), `${id} present in ${f}`);
  }
}
denyTest('DENY-SIGNER-WITHDRAW3', () => assertSignerDenies(['withdraw3']));
denyTest('DENY-SIGNER-USDSEND', () => assertSignerDenies(['usdSend', 'usdClassTransfer']));
denyTest('DENY-SIGNER-SPOTSEND', () => assertSignerDenies(['spotSend']));
denyTest('DENY-SIGNER-SENDASSET', () => assertSignerDenies(['sendAsset', 'perpDexClassTransfer']));
denyTest('DENY-SIGNER-AGENTSENDASSET', () => assertSignerDenies(['agentSendAsset']));
denyTest('DENY-SIGNER-VAULTTRANSFER', () => assertSignerDenies(['vaultTransfer']));
denyTest('DENY-SIGNER-SUBACCOUNT-TRANSFER', () => assertSignerDenies(['subAccountTransfer', 'subAccountSpotTransfer']));
denyTest('DENY-SIGNER-AGENT-APPROVAL-REVOCATION', () => assertSignerDenies(['approveAgent', 'revokeAgent', 'convertToMultiSigUser']));
denyTest('DENY-SIGNER-VAULT-CREATE-MODIFY', () => assertSignerDenies(['createVault', 'modifyVault']));
denyTest('DENY-SIGNER-SUBACCOUNT-CREATE-MODIFY', () => assertSignerDenies(['createSubAccount', 'modifySubAccount']));
denyTest('DENY-SIGNER-STAKING', () => assertSignerDenies(['cDeposit', 'cWithdraw', 'tokenDelegate', 'claimRewards', 'linkStakingUser']));
denyTest('DENY-SIGNER-BUILDER-FEE-APPROVAL', () => assertSignerDenies(['approveBuilderFee']));
denyTest('DENY-SIGNER-RAW-ARBITRARY-ACTION', () => assertSignerDenies(['signRawAction', 'evmUserModify', 'userDexAbstraction', 'spotDeploy', 'perpDeploy', 'setReferrer']));
denyTest('DENY-SIGNER-LEVERAGE-ACCOUNT-MODE', () => assertSignerDenies(['updateLeverage', 'updateIsolatedMargin']));
denyTest('DENY-SIGNER-USER-SIGNED-EIP712', () => assertSignerDenies(['signUserEip712']));

denyTest('DENY-SIGNER-DENY-LIST-INCOMPLETE', () => {
  const side = readJson('contracts', 'signer-denied-actions.json');
  const p = policy();
  assert.ok(checkSignerPolicy(p).ok, 'positive control');
  assert.deepEqual([...side.required].sort(), [...p.denied_actions].sort(), 'shipped policy denies exactly the pinned set');
  for (const id of side.required) {
    const d = clone(p); d.denied_actions = d.denied_actions.filter((x) => x !== id);
    assert.ok(!checkSignerPolicy(d).ok, `dropping ${id} must fail`);
  }
  const empty = clone(p); empty.denied_actions = [];
  assert.ok(!checkSignerPolicy(empty).ok);
  const missing = clone(p); delete missing.denied_actions;
  assert.ok(!checkSignerPolicy(missing).ok);
  assert.ok(!checkSignerPolicy({}).ok);
  assert.ok(checkSignerPolicy(p, ['withdraw3']).ok && !checkSignerPolicy({ ...p, denied_actions: ['x'] }, ['withdraw3']).ok);
  // fail closed on an empty, missing, non-array or malformed required set (an empty list must never mean "nothing is required")
  for (const bad of [[], null, 'withdraw3', {}, 0, [''], [1], [null], ['withdraw3', '']]) {
    const r = checkSignerPolicy(p, bad);
    assert.ok(!r.ok && r.violations.length > 0, `required set ${JSON.stringify(bad)} must fail closed`);
  }
  assert.ok(!checkSignerPolicy({}, []).ok && !checkSignerPolicy(undefined, []).ok, 'empty policy with empty required set');
  for (const bad of [{}, { required: [] }, { required: 'x' }, { required: null }, { required: [''] }, { required: [3] }, null, undefined]) {
    assert.throws(() => parseRequiredDenials(bad), /empty or malformed/, `sidecar ${JSON.stringify(bad)}`);
  }
  assert.deepEqual(parseRequiredDenials(side), side.required, 'positive control');
  assert.deepEqual(loadRequiredDenials(), side.required);
  // extra denials are fail-safe; unverified names are flagged in the sidecar
  assert.ok(checkSignerPolicy({ ...p, denied_actions: [...p.denied_actions, 'extraDenial'] }).ok);
  for (const n of ['usdClassTransfer', 'subAccountSpotTransfer', 'perpDexClassTransfer', 'convertToMultiSigUser', 'claimRewards', 'linkStakingUser', 'cDeposit', 'cWithdraw',
    'tokenDelegate', 'spotDeploy', 'perpDeploy', 'setReferrer', 'evmUserModify', 'userDexAbstraction']) {
    assert.ok(side.required.includes(n), `${n} required`);
    assert.ok(side.verification.UNVERIFIED_HL_DOCS.includes(n), `${n} flagged UNVERIFIED_HL_DOCS`);
  }
});

test('deny list is disjoint from the allowlist and has no duplicates', () => {
  const p = policy();
  assert.equal(new Set(p.denied_actions).size, p.denied_actions.length);
  const lowerAllowed = new Set(p.allowed_request_types.map((s) => s.toLowerCase()));
  for (const d of p.denied_actions) assert.ok(!lowerAllowed.has(d.toLowerCase()), d);
});

denyTest('DENY-GENERIC-SIGNING-ENTRYPOINT', () => {
  const files = srcFiles();
  assert.ok(files.length >= 4, 'src must contain files to scan');
  const ids = policy().denied_actions;
  for (const f of files) {
    assert.deepEqual(scanFile(f, ids, SRC_IMPORT_ALLOWLIST[path.basename(f)] ?? []), [], `${f} contains forbidden identifiers/entrypoints/imports`);
  }
  // real fixtures on disk: each generic entrypoint pattern is caught by the file scanner
  const dir = tempDir();
  const samples = ['export function signAnything() {}', 'const rawAction = 1;', 'const privateKey = x;', 'const mnemonic = 1;', 'personal_sign(x);',
    'fetch(url);', 'new WebSocket(u);', 'export const signRawPayload = 1;'];
  samples.forEach((code, n) => {
    const f = path.join(writeFiles(dir, { [`s${n}.mjs`]: `${code}\n` }), `s${n}.mjs`);
    assert.ok(scanFile(f, []).length > 0, `scanner missed: ${code}`);
  });
  assert.deepEqual(scanFile(path.join(writeFiles(dir, { 'clean.mjs': 'export const ok = 1;\n' }), 'clean.mjs'), []), [], 'clean fixture passes');
});

denyTest('DENY-SRC-UNALLOWED-IMPORT', () => {
  const dir = tempDir();
  const fixture = (name, code) => path.join(writeFiles(dir, { [name]: `${code}\n` }), name);
  const cases = {
    "dynamic import('node:net')": "const m = await import('node:net');",
    "require('net')": "const n = require('net');",
    "import undici": "import { fetch as f } from 'undici';",
    'import node:http': "import http from 'node:http';",
    'import node:child_process': "import { exec } from 'node:child_process';",
    'side-effect import': "import 'evil-pkg';",
    'export-from': "export { x } from 'left-pad';",
    'multiline import': "import {\n a,\n b,\n} from 'node:net';",
    'createRequire': "import { createRequire } from 'node:module';",
    'eval': 'eval(code);',
  };
  for (const [name, code] of Object.entries(cases)) {
    assert.ok(scanFile(fixture(`f${Object.keys(cases).indexOf(name)}.mjs`, code), []).length > 0, `${name} must be flagged`);
  }
  assert.deepEqual(scanImports("import('node:net'); require('net'); import u from 'undici'", []).sort(), ['dynamic import()', 'import undici', 'require('].sort());
  // allowlist is per file: node:fs is fine only where listed, relative ./ imports are fine
  assert.deepEqual(scanImports("import fs from 'node:fs';", ['node:fs']), []);
  assert.deepEqual(scanImports("import fs from 'node:fs';", []), ['import node:fs']);
  assert.deepEqual(scanImports("import { a } from './x.mjs';", []), []);
  assert.ok(scanImports("import { a } from '../x.mjs';", []).length > 0, 'parent-relative import denied');
  // every real src file stays within its allowlist; unlisted files get none
  for (const f of srcFiles()) {
    const allowed = SRC_IMPORT_ALLOWLIST[path.basename(f)];
    assert.ok(allowed, `${f} has no import allowlist entry`);
    assert.deepEqual(scanImports(fs.readFileSync(f, 'utf8'), allowed), [], f);
  }
  assert.ok(scanImports("import fs from 'node:fs';", SRC_IMPORT_ALLOWLIST['unlisted.mjs'] ?? []).length > 0);
  assertLoaderEvasionFlagged();
});

function assertLoaderEvasionFlagged() {
  const dir = tempDir();
  const fixture = (n, code) => path.join(writeFiles(dir, { [`e${n}.mjs`]: `${code}\n` }), `e${n}.mjs`);
  const cases = {
    'process.getBuiltinModule': ["const net = process.getBuiltinModule('node:net');", 'builtin module getter'],
    'aliased getBuiltinModule': ["const g = process.getBuiltinModule; g('node:net');", 'builtin module getter'],
    'optional-call getBuiltinModule': ["process?.getBuiltinModule?.('node:net');", 'builtin module getter'],
    'process.mainModule': ["process.mainModule.require('net');", 'builtin module getter'],
    "globalThis['...']": ["globalThis['req' + 'uire']('net');", 'computed global access'],
    "global['...']": ["global['process'].binding('net');", 'computed global access'],
    "globalThis?.[...]": ["globalThis?.['process'];", 'computed global access'],
    "process['...']": ["process['getBuiltin' + 'Module']('node:net');", 'computed global access'],
    'module.constructor': ["module.constructor._load('net');", 'module/constructor escape'],
    'module.require': ["module.require('net');", 'module/constructor escape'],
    "module['...']": ["module['req' + 'uire']('net');", 'module/constructor escape'],
    'constructor chain': ["(0).constructor.constructor('return process')();", 'module/constructor escape'],
    'aliased require': ["const r = require; r('net');", 'aliased require'],
    'destructured require': ["const { a } = { a: require };", 'aliased require'],
    'require passed as value': ["load(require);", 'aliased require'],
    'aliased import': ["const load = import;", 'aliased import'],
    'import returned': ["export default (x) => x ? import : 0;", 'aliased import'],
    'Reflect.get on process': ["Reflect.get(process, 'getBuiltin' + 'Module');", 'reflective access'],
    'Reflect.apply': ["Reflect.apply(f, process, []);", 'reflective access'],
    'Reflect computed': ["Reflect['get'](globalThis, 'x');", 'reflective access'],
    'getPrototypeOf constructor': ["Object.getPrototypeOf(async () => {}).constructor('return process')();", 'module/constructor escape'],
    '__proto__': ["({}).__proto__.constructor;", 'module/constructor escape'],
    "fs['write...']": ["import fs from 'node:fs'; fs['write' + 'FileSync']('a', 'b');", 'computed fs access'],
    "fs?.[...]": ["fs?.['unlinkSync']('a');", 'computed fs access'],
    'Function constructor call': ["Function('return process')();", 'code-loading construct'],
  };
  let n = 0;
  for (const [name, [code, hit]] of Object.entries(cases)) {
    const f = fixture(n++, code);
    assert.ok(scanFile(f, [], []).includes(hit), `${name} must be flagged as "${hit}": ${scanFile(f, [], []).join(',')}`);
    assert.ok(scanImports(code, ['node:fs']).includes(hit), `${name} flagged even when node:fs is allowlisted`);
  }
  // benign code is not flagged: import.meta, words containing "require", property named constructors on classes
  for (const ok of ['const u = import.meta.url;', 'const required = [1]; const requireState = 2;', 'export const f = () => new URL(import.meta.url);', 'class A { constructor() { this.x = 1; } }']) {
    assert.deepEqual(scanImports(ok, []), [], ok);
  }
}
