import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { abs, readJson, walk, ROOT, countDenyTests, stripComments } from '../helpers.mjs';

const reg = () => readJson('contracts', 'forbidden-capabilities.json').capabilities;
const testSources = () => walk(abs('tests')).filter((p) => /\.test\.mjs$/.test(p)).map((p) => fs.readFileSync(p, 'utf8'));

test('registry entries are well-formed with unique ids and denial tests', () => {
  const r = reg();
  assert.ok(r.length >= 50);
  assert.equal(new Set(r.map((c) => c.id)).size, r.length, 'duplicate ids');
  assert.equal(new Set(r.map((c) => c.denial_test)).size, r.length, 'denial_test ids must be unique');
  for (const c of r) {
    const base = ['blueprint_ref', 'contract', 'denial_test', 'description', 'enforced_in_phase', 'enforcement', 'id'];
    assert.deepEqual(Object.keys(c).sort(), ('runtime_enforced_in_phase' in c ? [...base, 'runtime_enforced_in_phase'] : base).sort(), c.id);
    if ('runtime_enforced_in_phase' in c) assert.ok(Number.isInteger(c.runtime_enforced_in_phase) && c.runtime_enforced_in_phase >= 1 && c.runtime_enforced_in_phase <= 12, `${c.id}: runtime_enforced_in_phase must be an integer >= 1`);
    for (const k of ['blueprint_ref', 'contract', 'denial_test', 'description', 'enforcement', 'id']) assert.ok(typeof c[k] === 'string' && c[k].length > 0, `${c.id}.${k}`);
    assert.ok(['enforced', 'declared'].includes(c.enforcement), `${c.id} enforcement`);
    assert.ok(Number.isInteger(c.enforced_in_phase) && c.enforced_in_phase >= 0 && c.enforced_in_phase <= 12, `${c.id} phase`);
    if (c.enforcement === 'declared') assert.ok(c.enforced_in_phase >= 1, `${c.id}: declared entries must name a later enforcing phase`);
    if (c.enforcement === 'enforced') assert.equal(c.enforced_in_phase, 0, `${c.id}: enforced entries are enforced now`);
    assert.match(c.denial_test, /^DENY-[A-Z0-9-]+$/, c.id);
  }
});

test('every registry contract path exists inside the repo', () => {
  for (const c of reg()) {
    assert.ok(!path.isAbsolute(c.contract) && !c.contract.split('/').includes('..'), `${c.id}: unsafe path`);
    const p = abs(c.contract);
    assert.ok(p.startsWith(ROOT + path.sep), c.id);
    assert.ok(fs.existsSync(p) && fs.statSync(p).isFile(), `${c.id}: contract ${c.contract} missing`);
  }
});

test('every registry denial_test id is the literal name of exactly one test under tests/', () => {
  const sources = testSources();
  assert.ok(sources.length >= 5);
  for (const c of reg()) {
    const n = countDenyTests(sources, c.denial_test);
    assert.equal(n, 1, `${c.id}: denial test ${c.denial_test} found ${n} times`);
  }
});

test('every denyTest id in tests/ is registered (no orphan denial tests)', () => {
  const ids = new Set(reg().map((c) => c.denial_test));
  const found = testSources().map(stripComments).flatMap((s) => [...s.matchAll(/denyTest\(\s*'(DENY-[A-Z0-9-]+)'/g)].map((m) => m[1]));
  for (const f of found) assert.ok(ids.has(f), `${f} not in registry`);
});

test('registry covers every section 13 denied action and every global prohibition', () => {
  const ids = new Set(reg().map((c) => c.id));
  for (const id of ['SIGNER_WITHDRAW3', 'SIGNER_USDSEND', 'SIGNER_SPOTSEND', 'SIGNER_SENDASSET', 'SIGNER_AGENTSENDASSET', 'SIGNER_VAULTTRANSFER',
    'SIGNER_SUBACCOUNT_TRANSFER', 'SIGNER_AGENT_APPROVAL_REVOCATION', 'SIGNER_VAULT_CREATE_MODIFY', 'SIGNER_SUBACCOUNT_CREATE_MODIFY', 'SIGNER_STAKING',
    'SIGNER_BUILDER_FEE_APPROVAL', 'SIGNER_RAW_ARBITRARY_ACTION', 'SIGNER_LEVERAGE_ACCOUNT_MODE', 'SIGNER_USER_SIGNED_EIP712']) assert.ok(ids.has(id), id);
  for (const p of readJson('contracts', 'trust-zones.json').global_prohibitions) assert.ok(ids.has(p.id), p.id);
  for (const f of readJson('contracts', 'governance.json').forbidden) assert.ok(ids.has(f.id), f.id);
  for (const id of ['MCP_FORBIDDEN_TOOL_SURFACE', 'OPERATOR_CONTROLS_NOT_MCP', 'INTENT_EXPIRY_CANCELS_PROTECTION']) assert.ok(ids.has(id), id);
});

test('commented-out denial tests are not counted (// and /* */ are stripped)', () => {
  const call = (id) => 'deny' + `Test('${id}', () => {})`;
  assert.equal(countDenyTests([`// ${call('DENY-X')}`], 'DENY-X'), 0);
  assert.equal(countDenyTests([`/* ${call('DENY-X')} */`], 'DENY-X'), 0);
  assert.equal(countDenyTests([`/*\n ${call('DENY-X')}\n*/\n${call('DENY-X')}`], 'DENY-X'), 1);
  assert.equal(countDenyTests([`${call('DENY-X')} // trailing`], 'DENY-X'), 1);
});

test('registry has zero declared entries; every entry is enforced by a Phase-0 denial and runtime phases are >= 1', () => {
  const r = reg();
  assert.deepEqual(r.filter((c) => c.enforcement === 'declared').map((c) => c.id), [], 'no declared-only entries may remain');
  assert.equal(r.filter((c) => c.enforcement === 'enforced').length, r.length);
  for (const c of r) {
    assert.equal(c.enforced_in_phase, 0, c.id);
    if ('runtime_enforced_in_phase' in c) assert.ok(c.runtime_enforced_in_phase >= 1, c.id);
  }
  // the 12 formerly declared entries and the 12 gate-closure entries keep their later runtime phase
  const later = Object.fromEntries(r.filter((c) => 'runtime_enforced_in_phase' in c).map((c) => [c.id, c.runtime_enforced_in_phase]));
  assert.deepEqual(later, {
    ZONE_CODEX_TRADERD_KEY: 1, ZONE_SIGNING_CODEX_MCP: 1, OPS_MODE_NO_SIGNER_NO_WRITES: 1, GENERIC_EXCHANGE_ENDPOINT_TO_CODEX: 1,
    GENERIC_SIGNER_TO_TRADERD_OR_MCP: 8, THIRD_PARTY_CAPITAL: 7, API_WALLET_MANAGEMENT: 8, CUSTODY_CONFIG_CHANGE: 1,
    RUNTIME_SOURCE_MUTATION: 1, AUTONOMOUS_DEPLOYMENT: 1, SELF_PROMOTION: 6, COINVEST_LIVE_EXECUTION: 2,
    ZONE_SIGNING_ARBITRARY_SHELL: 8, ZONE_SIGNING_GENERAL_NETWORK: 8, ZONE_SIGNING_FILESYSTEM_ESCAPE: 8, ZONE_CODEX_PRODUCTION_SOURCE_WRITES: 1,
    OPS_MODE_GIT_WRITES: 1, OPS_COINVEST_DIRECT_ENDPOINT: 2, COINVEST_PAPER_WRITES: 2, DEV_MODE_PRODUCTION_LEDGER: 3,
    GOV_LLM_CHANGES_RISK_POLICY: 7, GOV_EXECUTOR_CHANGES_POLICY: 8, GOV_AI_RISK_OFFICER_EXECUTES: 4, GOV_MCP_EXPANSION_WIDENS_ALLOWLIST: 1,
    MCP_FORBIDDEN_TOOL_SURFACE: 1, OPERATOR_CONTROLS_NOT_MCP: 1, INTENT_EXPIRY_CANCELS_PROTECTION: 8,
  });
  for (const c of r) if (c.contract === 'contracts/trust-zones.json') assert.equal(c.enforcement, 'enforced', c.id);
});

test('meta: an entry with an invalid runtime_enforced_in_phase or a declared flag is detected by the well-formedness rule', () => {
  const ok = (c) => c.enforcement === 'enforced' && (!('runtime_enforced_in_phase' in c) || (Number.isInteger(c.runtime_enforced_in_phase) && c.runtime_enforced_in_phase >= 1));
  const sample = reg().find((c) => 'runtime_enforced_in_phase' in c);
  assert.ok(ok(sample));
  assert.ok(!ok({ ...sample, runtime_enforced_in_phase: 0 }));
  assert.ok(!ok({ ...sample, enforcement: 'declared' }));
});
