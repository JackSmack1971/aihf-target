import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { readJson, readText, denyTest, clone, ROOT, tempDir, writeFiles, makeNonRegularEntry } from '../helpers.mjs';
import { checkTrustZones, checkCapitalPolicy, checkSignerCapabilityGroups, checkRepoTree, collectTree, loadRules, parseRules, REQUIRED_PROHIBITIONS, REQUIRED_TREE_COVERAGE } from '../../src/contracts/trust-zone-checker.mjs';

const Z = () => readJson('contracts', 'trust-zones.json');
const zone = (n) => Z().zones.find((z) => z.id === n);

test('exactly six trust zones, ids 0-5, each with components', () => {
  const zs = Z().zones;
  assert.deepEqual(zs.map((z) => z.id), [0, 1, 2, 3, 4, 5]);
  for (const z of zs) assert.ok(z.name && z.components.length > 0, String(z.id));
  assert.ok(zone(0).custody_actions && zone(0).ai_process_control === false);
  for (const n of [1, 2, 3, 4, 5]) assert.equal(zone(n).custody_actions, false, `zone ${n} custody`);
});

// ---- Phase-0 checker harness: every denial feeds a violating artifact to the deterministic checker and asserts rejection ----
const mutZ = (fn) => { const d = clone(Z()); fn(d); return d; };
const capsOf = (r) => [...new Set(r.violations.map((v) => v.capability))];
function rejects(result, capability, label) {
  assert.equal(result.ok, false, `${label}: must be rejected`);
  assert.ok(capsOf(result).includes(capability), `${label}: expected ${capability}, got ${capsOf(result).join(',')}`);
}
const treeOf = (files) => checkRepoTree(collectTree(writeFiles(tempDir(), files)));
const policySigner = () => readJson('config', 'signer-policy.json');
const zoneRef = (d, n) => d.zones.find((z) => z.id === n);

test('checker: shipped Phase-0 artifacts are accepted (positive controls)', () => {
  assert.deepEqual(checkTrustZones(Z()), { ok: true, violations: [] });
  assert.deepEqual(checkCapitalPolicy(readJson('config', 'risk-policy.template.json')), { ok: true, violations: [] });
  assert.deepEqual(checkSignerCapabilityGroups(policySigner()), { ok: true, violations: [] });
  assert.deepEqual(checkRepoTree(collectTree(ROOT)), { ok: true, violations: [] });
  assert.deepEqual(treeOf({ 'src/ok.mjs': 'export const ok = 1;\n', 'package.json': '{"scripts":{"test":"node --test"}}' }), { ok: true, violations: [] });
});

test('checker: rules file is pinned (required coverage, mode tables) and malformed rules fail closed', () => {
  const raw = readJson('contracts', 'phase0-checker-rules.json');
  const r = loadRules();
  for (const c of REQUIRED_TREE_COVERAGE) assert.ok(r.tree_rules.some((x) => x.capability === c), `rule for ${c}`);
  assert.deepEqual(REQUIRED_PROHIBITIONS, Z().global_prohibitions.map((p) => p.id));
  assert.deepEqual(Object.keys(raw.mode_rules['fund-dev'].forbidden).sort(), ['coinvest_live_execution', 'coinvest_paper_direct_writes', 'intent_submission', 'mainnet_agent_secret_present', 'production_ledger_present', 'riskd_production_endpoint', 'signerd_present', 'traderd_production_ipc']);
  assert.deepEqual(Object.keys(raw.mode_rules['fund-ops'].forbidden).sort(), ['arbitrary_mcp_servers', 'coinvest_direct_endpoint', 'coinvest_live_execution', 'coinvest_paper_writes', 'direct_exchange_writes', 'git_writes', 'package_installation', 'repository_writes', 'signer_access']);
  assert.deepEqual(raw.mode_rules['fund-dev'].allowed_true, ['repository_writes', 'coinvest_paper_validation_isolated_adapter_only']);
  assert.deepEqual(Object.keys(raw.mode_rules['fund-dev'].required_true), ['coinvest_paper_validation_isolated_adapter_only']);
  assert.deepEqual(raw.mode_rules['fund-ops'].required_true, {});
  assert.deepEqual(raw.mode_rules['fund-ops'].allowed_true, ['intent_submission']);
  const p = policySigner();
  for (const [g, names] of Object.entries(raw.signer_groups)) for (const n of names) assert.ok(p.denied_actions.includes(n), `${g}: ${n} must be in the shipped deny list`);
  // dropping rules / corrupting the rules document throws instead of silently weakening the checker
  const noRules = clone(raw); noRules.tree_rules = noRules.tree_rules.filter((x) => x.capability !== 'SELF_PROMOTION');
  assert.throws(() => parseRules(noRules), /no tree rule covers SELF_PROMOTION/);
  const noGroup = clone(raw); delete noGroup.signer_groups.API_WALLET_MANAGEMENT;
  assert.throws(() => parseRules(noGroup), /signer_groups/);
  const badRe = clone(raw); badRe.tree_rules[0].pattern = '(';
  assert.throws(() => parseRules(badRe));
  const badScope = clone(raw); badScope.tree_rules[0].scope = 'everything';
  assert.throws(() => parseRules(badScope), /malformed/);
  const noModes = clone(raw); delete noModes.mode_rules['fund-ops'];
  assert.throws(() => parseRules(noModes), /fund-ops/);
  assert.throws(() => parseRules(null), /not an object/);
  assert.throws(() => checkSignerCapabilityGroups(policySigner(), {}), /empty/);
  assert.equal(checkTrustZones({}).ok, false);
  assert.equal(checkTrustZones(null).ok, false);
  assert.equal(checkTrustZones({ zones: 'x' }).ok, false);
});

test('checker: code-file scan covers every code file outside tests/, is case-insensitive for key and API-wallet rules, and zone shape is closed', () => {
  const K = 'ZONE_CODEX_TRADERD_KEY';
  for (const [f, code] of [['src/k.mjs', 'export const PRIVATE_KEY = 1;'], ['lib/k.mjs', 'export const SECRET_KEY = 1;'], ['scripts/k.sh', 'export MNEMONIC=x'], ['scripts/k.py', 'SEED_PHRASE = 1']]) {
    rejects(treeOf({ [f]: `${code}\n` }), K, `${f}: ${code}`);
  }
  rejects(treeOf({ 'src/w.mjs': 'export const APPROVE_AGENT = 1;\n' }), 'API_WALLET_MANAGEMENT', 'APPROVE_AGENT');
  rejects(treeOf({ 'lib/w.cjs': 'exports.REVOKE_AGENT = 1;\n' }), 'API_WALLET_MANAGEMENT', 'REVOKE_AGENT in lib');
  rejects(treeOf({ 'lib/x.mjs': 'export const go = (u) => fetch(u);\n' }), 'GENERIC_EXCHANGE_ENDPOINT_TO_CODEX', 'fetch in lib/');
  rejects(treeOf({ 'scripts/ship.sh': 'kubectl apply -f x\n' }), 'AUTONOMOUS_DEPLOYMENT', 'kubectl in scripts/');
  rejects(treeOf({ 'tools/x.ts': 'export function promoteStrategy() {}\n' }), 'SELF_PROMOTION', 'promotion in tools/');
  rejects(treeOf({ 'bin/w.js': "require('fs').writeFileSync('a','b')\n" }), 'RUNTIME_SOURCE_MUTATION', 'file write in bin/');
  const dir = writeFiles(tempDir(), { 'lib/ok.mjs': 'export const x = 1;\n' });
  makeNonRegularEntry(path.join(dir, 'lib', 'link.mjs'));
  rejects(checkRepoTree(collectTree(dir)), 'RUNTIME_SOURCE_MUTATION', 'symlinked code file outside src/');
  // tests/ holds intentional violating fixtures and is not scanned
  assert.equal(treeOf({ 'tests/fixture.mjs': 'export const privateKey = 1;\n' }).ok, true);
  assert.equal(treeOf({ 'lib/ok.mjs': 'export const x = 1;\n', 'README.md': 'privateKey in prose\n' }).ok, true);
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 1).extra_capability = true; })), K, 'unknown zone field');
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 5).raw_exchange_write_allowed = true; })), K, 'unknown zone-5 field');
  for (const c of ['key custody service', 'private key vault', 'trading key store', 'remote signing helper', 'Signer proxy']) {
    for (const n of [1, 2, 3, 4]) {
      const r = checkTrustZones(mutZ((d) => { zoneRef(d, n).components.push(c); }));
      assert.equal(r.ok, false, `zone ${n} component "${c}" must be rejected`);
    }
  }
  assert.equal(checkTrustZones(Z()).ok, true, 'positive control');
});

denyTest('DENY-ZONE-CODEX-TRADERD-KEY', () => {
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 1).holds_trading_key = true; })), 'ZONE_CODEX_TRADERD_KEY', 'zone 1 holds key');
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 4).holds_trading_key = true; })), 'ZONE_CODEX_TRADERD_KEY', 'zone 4 holds key');
  rejects(checkTrustZones(mutZ((d) => { delete zoneRef(d, 4).holds_trading_key; })), 'ZONE_CODEX_TRADERD_KEY', 'zone 4 key flag missing');
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 4).holds_trading_key = 'false'; })), 'ZONE_CODEX_TRADERD_KEY', 'zone 4 key flag non-boolean');
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 1).raw_exchange_write = true; })), 'ZONE_CODEX_TRADERD_KEY', 'zone 1 raw write');
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 4).raw_exchange_write = true; })), 'ZONE_CODEX_TRADERD_KEY', 'zone 4 raw write');
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 4).acts_only_inside_execution_permit = false; })), 'ZONE_CODEX_TRADERD_KEY', 'zone 4 not permit-bound');
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 2).holds_trading_key = true; })), 'ZONE_CODEX_TRADERD_KEY', 'any non-signing zone with a key');
  rejects(checkTrustZones(mutZ((d) => { d.zones = d.zones.filter((z) => z.id !== 4); })), 'ZONE_CODEX_TRADERD_KEY', 'zone dropped');
  rejects(treeOf({ 'src/k.mjs': 'export const privateKey = "x";\n' }), 'ZONE_CODEX_TRADERD_KEY', 'src references key material');
  rejects(treeOf({ 'src/k.mjs': 'const seed_phrase = 1;\n' }), 'ZONE_CODEX_TRADERD_KEY', 'src seed phrase');
  rejects(treeOf({ 'secrets/agent.key': 'x' }), 'ZONE_CODEX_TRADERD_KEY', 'key file in tree');
  rejects(treeOf({ '.env.production': 'X=1' }), 'ZONE_CODEX_TRADERD_KEY', 'env file in tree');
  assert.equal(checkTrustZones(Z()).ok, true, 'positive control');
});

denyTest('DENY-ZONE-SIGNING-CODEX-MCP', () => {
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 5).codex_present = true; })), 'ZONE_SIGNING_CODEX_MCP', 'Codex in zone 5');
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 5).mcp_present = true; })), 'ZONE_SIGNING_CODEX_MCP', 'MCP in zone 5');
  rejects(checkTrustZones(mutZ((d) => { delete zoneRef(d, 5).mcp_present; })), 'ZONE_SIGNING_CODEX_MCP', 'zone 5 mcp flag missing');
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 5).compile_time_action_allowlist = false; })), 'ZONE_SIGNING_CODEX_MCP', 'allowlist off');
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 3).codex_present = true; })), 'ZONE_SIGNING_CODEX_MCP', 'Codex outside zone 1');
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 4).mcp_present = true; })), 'ZONE_CODEX_TRADERD_KEY', 'MCP in traderd zone');
  assert.equal(checkTrustZones(Z()).ok, true, 'positive control');
});

denyTest('DENY-OPS-MODE-CAPABILITIES', () => {
  const rawRules = readJson('contracts', 'phase0-checker-rules.json').mode_rules;
  for (const mode of ['fund-dev', 'fund-ops']) {
    for (const [key, caps] of Object.entries(rawRules[mode].forbidden)) {
      for (const cap of caps) {
        rejects(checkTrustZones(mutZ((d) => { d.operating_modes[mode][key] = true; })), cap, `${mode}.${key}=true`);
        rejects(checkTrustZones(mutZ((d) => { delete d.operating_modes[mode][key]; })), cap, `${mode}.${key} missing`);
      }
    }
  }
  rejects(checkTrustZones(mutZ((d) => { d.operating_modes['fund-ops'].signer_access = true; })), 'OPS_MODE_NO_SIGNER_NO_WRITES', 'ops signer access');
  rejects(checkTrustZones(mutZ((d) => { d.operating_modes['fund-ops'].repository_writes = true; })), 'OPS_MODE_NO_SIGNER_NO_WRITES', 'ops repo writes');
  rejects(checkTrustZones(mutZ((d) => { d.operating_modes['fund-dev'].signerd_present = true; })), 'OPS_MODE_NO_SIGNER_NO_WRITES', 'dev signerd');
  rejects(checkTrustZones(mutZ((d) => { d.operating_modes['fund-dev'].mainnet_agent_secret_present = true; })), 'OPS_MODE_NO_SIGNER_NO_WRITES', 'dev mainnet secret');
  rejects(checkTrustZones(mutZ((d) => { d.operating_modes['fund-ops'].generic_browser_control = true; })), 'OPS_MODE_NO_SIGNER_NO_WRITES', 'unrecognized enabled capability');
  rejects(checkTrustZones(mutZ((d) => { d.operating_modes['fund-ops'].intent_submission = 'yes'; })), 'OPS_MODE_NO_SIGNER_NO_WRITES', 'non-boolean flag');
  rejects(checkTrustZones(mutZ((d) => { delete d.operating_modes['fund-ops']; })), 'OPS_MODE_NO_SIGNER_NO_WRITES', 'ops mode removed');
  rejects(checkTrustZones(mutZ((d) => { d.operating_modes['fund-extra'] = { repository_writes: true }; })), 'OPS_MODE_NO_SIGNER_NO_WRITES', 'extra mode');
  assert.equal(checkTrustZones(Z()).ok, true, 'positive control');
  assert.equal(Z().operating_modes['fund-dev'].repository_writes, true);
  assert.equal(Z().operating_modes['fund-ops'].intent_submission, true);
});

const GLOBAL = {
  'DENY-GLOBAL-GENERIC-EXCHANGE-ENDPOINT': 'GENERIC_EXCHANGE_ENDPOINT_TO_CODEX',
  'DENY-GLOBAL-GENERIC-SIGNER': 'GENERIC_SIGNER_TO_TRADERD_OR_MCP',
  'DENY-GLOBAL-THIRD-PARTY-CAPITAL': 'THIRD_PARTY_CAPITAL',
  'DENY-GLOBAL-API-WALLET-MANAGEMENT': 'API_WALLET_MANAGEMENT',
  'DENY-GLOBAL-CUSTODY-CONFIG-CHANGE': 'CUSTODY_CONFIG_CHANGE',
  'DENY-GLOBAL-RUNTIME-SOURCE-MUTATION': 'RUNTIME_SOURCE_MUTATION',
  'DENY-GLOBAL-AUTONOMOUS-DEPLOYMENT': 'AUTONOMOUS_DEPLOYMENT',
  'DENY-GLOBAL-SELF-PROMOTION': 'SELF_PROMOTION',
  'DENY-GLOBAL-COINVEST-LIVE-EXECUTION': 'COINVEST_LIVE_EXECUTION',
};
assert.equal(Object.keys(GLOBAL).length, Z().global_prohibitions.length, 'every global prohibition has a denial test');

/** The global-prohibition document mutations every one of the nine capabilities must reject. */
function assertProhibitionDocEnforced(key) {
  const p = Z().global_prohibitions.find((x) => x.id === key);
  assert.ok(p && p.description && p.blueprint_ref, `${key} prohibition missing`);
  assert.equal(checkTrustZones(Z()).ok, true, 'positive control');
  rejects(checkTrustZones(mutZ((d) => { d.global_prohibitions = d.global_prohibitions.filter((x) => x.id !== key); })), key, `${key} prohibition removed`);
  rejects(checkTrustZones(mutZ((d) => { d.global_prohibitions.push(clone(p)); })), key, `${key} prohibition duplicated`);
  rejects(checkTrustZones(mutZ((d) => { d.global_prohibitions.find((x) => x.id === key).allowed = true; })), key, `${key} marked permissive`);
  rejects(checkTrustZones(mutZ((d) => { d.global_prohibitions.find((x) => x.id === key).description = ''; })), key, `${key} emptied`);
  rejects(checkTrustZones(mutZ((d) => { delete d.global_prohibitions.find((x) => x.id === key).blueprint_ref; })), key, `${key} lost its blueprint ref`);
  rejects(checkTrustZones(mutZ((d) => { d.global_prohibitions = 'none'; })), key, 'prohibitions replaced by a non-array');
  const reg = readJson('contracts', 'forbidden-capabilities.json').capabilities.find((c) => c.id === key);
  assert.ok(reg && reg.enforcement === 'enforced' && reg.enforced_in_phase === 0, `${key} registry entry`);
  assert.ok(readText('AGENTS.md').includes('contracts/forbidden-capabilities.json'));
}

denyTest('DENY-GLOBAL-GENERIC-EXCHANGE-ENDPOINT', () => {
  const k = GLOBAL['DENY-GLOBAL-GENERIC-EXCHANGE-ENDPOINT'];
  assertProhibitionDocEnforced(k);
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 1).raw_exchange_write = true; })), k, 'Codex plane raw exchange write');
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 1).components.push('generic exchange action endpoint'); })), k, 'generic exchange component in zone 1');
  rejects(treeOf({ 'src/x.mjs': 'export const go = (u) => fetch(u);\n' }), k, 'src fetch transport');
  rejects(treeOf({ 'src/x.mjs': 'export const ws = new WebSocket("wss://api.hyperliquid.xyz/ws");\n' }), k, 'src WebSocket transport');
  rejects(treeOf({ 'src/x.mjs': 'export const rawExchangePost = 1;\n' }), k, 'src raw exchange post');
  assert.match(readText('AGENTS.md'), /generic or raw exchange action/);
});
denyTest('DENY-GLOBAL-GENERIC-SIGNER', () => {
  const k = GLOBAL['DENY-GLOBAL-GENERIC-SIGNER'];
  assertProhibitionDocEnforced(k);
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 4).components.push('signerd'); })), k, 'signer inside traderd zone');
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 1).components.push('generic signer'); })), k, 'signer inside Codex zone');
  const noRaw = policySigner(); noRaw.denied_actions = noRaw.denied_actions.filter((x) => x !== 'signRawAction');
  rejects(checkSignerCapabilityGroups(noRaw), k, 'signer policy no longer denies raw signing');
  const allowRaw = policySigner(); allowRaw.allowed_request_types = [...allowRaw.allowed_request_types, 'signUserEip712'];
  rejects(checkSignerCapabilityGroups(allowRaw), k, 'signer policy allowlists user EIP-712');
  rejects(checkSignerCapabilityGroups({}), k, 'empty signer policy');
  rejects(treeOf({ 'src/s.mjs': 'export function signAnything() {}\n' }), k, 'src generic signer');
  rejects(treeOf({ 'src/s.mjs': 'export const signRawPayload = 1;\n' }), k, 'src raw payload signer');
  rejects(treeOf({ 'src/s.mjs': 'export const personal_sign = 1;\n' }), k, 'src personal_sign');
  assert.match(readText('AGENTS.md'), /generic signer/);
});
denyTest('DENY-GLOBAL-THIRD-PARTY-CAPITAL', () => {
  const k = GLOBAL['DENY-GLOBAL-THIRD-PARTY-CAPITAL'];
  assertProhibitionDocEnforced(k);
  const tpl = readJson('config', 'risk-policy.template.json');
  for (const bad of [true, 'false', 0, null, undefined]) rejects(checkCapitalPolicy({ ...tpl, allow_third_party_capital: bad }), k, `allow_third_party_capital=${String(bad)}`);
  const missing = clone(tpl); delete missing.allow_third_party_capital;
  rejects(checkCapitalPolicy(missing), k, 'flag missing');
  rejects(checkCapitalPolicy(null), k, 'null policy');
  rejects(treeOf({ 'src/c.mjs': 'export const third_party_capital = true;\n' }), k, 'src enables third-party capital');
  rejects(treeOf({ 'src/c.mjs': 'export const acceptOutsideDeposits = 1; export function public_vault() {}\n' }), k, 'src outside deposits');
  assert.match(readText('AGENTS.md'), /third-party capital/);
});
denyTest('DENY-GLOBAL-API-WALLET-MANAGEMENT', () => {
  const k = GLOBAL['DENY-GLOBAL-API-WALLET-MANAGEMENT'];
  assertProhibitionDocEnforced(k);
  for (const name of ['approveAgent', 'revokeAgent']) {
    const dropped = policySigner(); dropped.denied_actions = dropped.denied_actions.filter((x) => x !== name);
    rejects(checkSignerCapabilityGroups(dropped), k, `${name} no longer denied`);
    const allowed = policySigner(); allowed.allowed_request_types = [...allowed.allowed_request_types, name];
    rejects(checkSignerCapabilityGroups(allowed), k, `${name} allowlisted`);
  }
  rejects(treeOf({ 'src/w.mjs': 'export function approveAgentWallet() {}\n' }), k, 'src approves agent');
  rejects(treeOf({ 'src/w.mjs': 'export const rotate_agent_wallet = 1;\n' }), k, 'src rotates wallet');
  assert.match(readText('AGENTS.md'), /agent-approval/);
});
denyTest('DENY-GLOBAL-CUSTODY-CONFIG-CHANGE', () => {
  const k = GLOBAL['DENY-GLOBAL-CUSTODY-CONFIG-CHANGE'];
  assertProhibitionDocEnforced(k);
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 1).custody_actions = true; })), k, 'Codex zone custody action');
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 4).custody_actions = true; })), k, 'traderd zone custody action');
  rejects(checkTrustZones(mutZ((d) => { zoneRef(d, 0).ai_process_control = true; })), k, 'AI controls custody root');
  rejects(checkTrustZones(mutZ((d) => { delete zoneRef(d, 5).custody_actions; })), k, 'custody flag missing');
  const dropped = policySigner(); dropped.denied_actions = dropped.denied_actions.filter((x) => x !== 'convertToMultiSigUser');
  rejects(checkSignerCapabilityGroups(dropped), k, 'multisig conversion no longer denied');
  rejects(treeOf({ 'src/c.mjs': 'export function changeCustodySettings() {}\n' }), k, 'src changes custody');
  rejects(treeOf({ 'src/c.mjs': 'export const custody_config_update = 1;\n' }), k, 'src custody config update');
  assert.match(readText('AGENTS.md'), /custody/i);
});
denyTest('DENY-GLOBAL-RUNTIME-SOURCE-MUTATION', () => {
  const k = GLOBAL['DENY-GLOBAL-RUNTIME-SOURCE-MUTATION'];
  assertProhibitionDocEnforced(k);
  rejects(checkTrustZones(mutZ((d) => { d.operating_modes['fund-ops'].repository_writes = true; })), k, 'ops writes the repository');
  rejects(checkTrustZones(mutZ((d) => { d.operating_modes['fund-ops'].package_installation = true; })), k, 'ops installs packages');
  rejects(treeOf({ 'src/m.mjs': "import fs from 'node:fs'; export const w = () => fs.writeFileSync('src/a.mjs', 'x');\n" }), k, 'src writes a file');
  rejects(treeOf({ 'src/m.mjs': "export const d = (fs) => fs.unlinkSync('src/a.mjs');\n" }), k, 'src deletes a file');
  rejects(treeOf({ 'src/m.mjs': "export const r = (fs) => fs.renameSync('a', 'b');\n" }), k, 'src renames a file');
  const dir = tempDir();
  writeFiles(dir, { 'src/real.mjs': 'export const x = 1;\n' });
  makeNonRegularEntry(path.join(dir, 'src', 'link.mjs'));
  rejects(checkRepoTree(collectTree(dir)), k, 'non-regular file in src is unscannable and rejected');
  assert.match(readText('AGENTS.md'), /mutate live source/);
});
denyTest('DENY-GLOBAL-AUTONOMOUS-DEPLOYMENT', () => {
  const k = GLOBAL['DENY-GLOBAL-AUTONOMOUS-DEPLOYMENT'];
  assertProhibitionDocEnforced(k);
  for (const f of ['.github/workflows/deploy.yml', '.github/workflows/ci.yaml', '.gitlab-ci.yml', 'Jenkinsfile', 'Dockerfile', 'docker-compose.prod.yml', 'deploy.sh',
    'deploy/run.sh', 'infra/main.tf', 'terraform/main.json', 'k8s/app.yaml', '.circleci/config.yml']) {
    rejects(treeOf({ [f]: 'x\n' }), k, `repo contains ${f}`);
  }
  rejects(treeOf({ 'src/d.mjs': 'export const go = () => "kubectl apply -f x";\n' }), k, 'src runs kubectl');
  rejects(treeOf({ 'src/d.mjs': 'export function deployToProduction() {}\n' }), k, 'src deploys to production');
  rejects(treeOf({ 'package.json': '{"scripts":{"deploy":"node x.js"}}' }), k, 'package.json deploy script');
  rejects(treeOf({ 'package.json': '{"scripts":{"postversion":"npm publish"}}' }), k, 'package.json publish script');
  rejects(treeOf({ 'package.json': '{not json' }), k, 'package.json unreadable fails closed');
  assert.match(readText('AGENTS.md'), /deploy to production/);
});
denyTest('DENY-GLOBAL-SELF-PROMOTION', () => {
  const k = GLOBAL['DENY-GLOBAL-SELF-PROMOTION'];
  assertProhibitionDocEnforced(k);
  rejects(treeOf({ 'src/p.mjs': 'export function promoteStrategyToCapital() {}\n' }), k, 'src promotes a strategy');
  rejects(treeOf({ 'src/p.mjs': 'export const strategyPromotion = 1;\n' }), k, 'src strategy promotion');
  rejects(treeOf({ 'src/p.mjs': 'export function allocateCapital() {}\n' }), k, 'src allocates capital');
  rejects(treeOf({ 'src/promote.mjs': 'export const x = 1;\n' }), k, 'promotion module present');
  rejects(treeOf({ 'tools/auto-promote.sh': 'x\n' }), k, 'promotion script present');
  assert.match(readText('AGENTS.md'), /promote a strategy into capital/);
});
denyTest('DENY-GLOBAL-COINVEST-LIVE-EXECUTION', () => {
  const k = GLOBAL['DENY-GLOBAL-COINVEST-LIVE-EXECUTION'];
  assertProhibitionDocEnforced(k);
  for (const mode of ['fund-dev', 'fund-ops']) {
    rejects(checkTrustZones(mutZ((d) => { d.operating_modes[mode].coinvest_live_execution = true; })), k, `${mode} enables Co-Invest live execution`);
    rejects(checkTrustZones(mutZ((d) => { delete d.operating_modes[mode].coinvest_live_execution; })), k, `${mode} flag missing`);
  }
  rejects(treeOf({ 'src/ci.mjs': 'export function coInvestLiveExecute() {}\n' }), k, 'src Co-Invest live execution');
  rejects(treeOf({ 'src/ci.mjs': 'export const submitCoInvestOrder = 1;\n' }), k, 'src submits Co-Invest order');
  rejects(treeOf({ 'src/ci.mjs': 'export const co_invest_live = 1;\n' }), k, 'src co_invest_live');
  assert.match(readText('AGENTS.md'), /Co-Invest live execution/);
});

// ---- section 3 / section 5 capability fields added in the P0-S2 gate closure ----
function zoneFieldDenial(cap, zoneId, field, trees) {
  assert.equal(checkTrustZones(Z()).ok, true, 'positive control');
  assert.equal(zone(zoneId)[field], false, `${field} is explicit and false in the contract`);
  for (const bad of [true, 'false', 0, null, undefined]) {
    rejects(checkTrustZones(mutZ((d) => { zoneRef(d, zoneId)[field] = bad; })), cap, `zone ${zoneId} ${field}=${String(bad)}`);
  }
  rejects(checkTrustZones(mutZ((d) => { delete zoneRef(d, zoneId)[field]; })), cap, `${field} missing`);
  for (const [f, code] of trees) rejects(treeOf({ [f]: `${code}\n` }), cap, `${f}: ${code}`);
  assert.ok(readJson('contracts', 'forbidden-capabilities.json').capabilities.some((c) => c.id === cap && c.enforcement === 'enforced'));
}
denyTest('DENY-ZONE-SIGNING-ARBITRARY-SHELL', () => zoneFieldDenial('ZONE_SIGNING_ARBITRARY_SHELL', 5, 'arbitrary_shell', [['src/s.mjs', "import { exec } from 'node:child_process'; exec('sh');"], ['scripts/s.py', 'import subprocess']]));
denyTest('DENY-ZONE-SIGNING-GENERAL-NETWORK', () => zoneFieldDenial('ZONE_SIGNING_GENERAL_NETWORK', 5, 'general_outbound_network', [['src/n.mjs', "import http from 'node:http';"], ['lib/n.mjs', "import net from 'node:net';"]]));
denyTest('DENY-ZONE-SIGNING-FILESYSTEM-ESCAPE', () => zoneFieldDenial('ZONE_SIGNING_FILESYSTEM_ESCAPE', 5, 'filesystem_outside_state_boundary', [['src/f.mjs', "export const p = '/etc/passwd';"], ['src/f2.mjs', "process.chdir('/');"]]));
denyTest('DENY-ZONE-CODEX-PRODUCTION-SOURCE-WRITES', () => zoneFieldDenial('ZONE_CODEX_PRODUCTION_SOURCE_WRITES', 1, 'production_source_writes', []));

function modeDenial(cap, mode, field, want, trees = []) {
  {
    assert.equal(checkTrustZones(Z()).ok, true, 'positive control');
    assert.equal(Z().operating_modes[mode][field], want, `${mode}.${field} is explicit in the contract`);
    for (const v of [true, 'false', 0, null]) rejects(checkTrustZones(mutZ((d) => { d.operating_modes[mode][field] = v; })), cap, `${mode}.${field}=${String(v)}`);
    rejects(checkTrustZones(mutZ((d) => { delete d.operating_modes[mode][field]; })), cap, `${mode}.${field} missing`);
    for (const [f, code] of trees) rejects(treeOf({ [f]: `${code}\n` }), cap, `${f}: ${code}`);
    assert.ok(readJson('contracts', 'forbidden-capabilities.json').capabilities.some((c) => c.id === cap && c.enforcement === 'enforced'));
  }
}
denyTest('DENY-OPS-MODE-GIT-WRITES', () => modeDenial('OPS_MODE_GIT_WRITES', 'fund-ops', 'git_writes', false, [['src/g.mjs', "export const c = 'git commit -m x';"], ['scripts/g.sh', 'git tag v1']]));
denyTest('DENY-OPS-COINVEST-DIRECT-ENDPOINT', () => modeDenial('OPS_COINVEST_DIRECT_ENDPOINT', 'fund-ops', 'coinvest_direct_endpoint', false, [['src/c.mjs', "export const coInvestDirectEndpoint = 'x';"], ['lib/c.mjs', 'export const coInvestBaseUrl = 1;']]));
denyTest('DENY-DEV-MODE-PRODUCTION-LEDGER', () => modeDenial('DEV_MODE_PRODUCTION_LEDGER', 'fund-dev', 'production_ledger_present', false));
denyTest('DENY-COINVEST-PAPER-WRITES', () => {
  const cap = 'COINVEST_PAPER_WRITES';
  assert.equal(checkTrustZones(Z()).ok, true, 'positive control');
  assert.equal(Z().operating_modes['fund-ops'].coinvest_paper_writes, false);
  assert.equal(Z().operating_modes['fund-dev'].coinvest_paper_validation_isolated_adapter_only, true);
  assert.equal(Z().operating_modes['fund-dev'].coinvest_paper_direct_writes, false);
  rejects(checkTrustZones(mutZ((d) => { d.operating_modes['fund-ops'].coinvest_paper_writes = true; })), cap, 'ops paper writes');
  rejects(checkTrustZones(mutZ((d) => { delete d.operating_modes['fund-ops'].coinvest_paper_writes; })), cap, 'ops paper flag missing');
  rejects(checkTrustZones(mutZ((d) => { d.operating_modes['fund-dev'].coinvest_paper_direct_writes = true; })), cap, 'dev direct paper writes');
  rejects(checkTrustZones(mutZ((d) => { d.operating_modes['fund-dev'].coinvest_paper_validation_isolated_adapter_only = false; })), cap, 'dev paper validation not adapter-only');
  rejects(checkTrustZones(mutZ((d) => { delete d.operating_modes['fund-dev'].coinvest_paper_validation_isolated_adapter_only; })), cap, 'dev adapter-only flag missing');
  rejects(treeOf({ 'src/p.mjs': 'export function coInvestPaperWrite() {}\n' }), cap, 'src Co-Invest paper write');
  rejects(treeOf({ 'lib/p.mjs': 'export const placeCoInvestPaperOrder = 1;\n' }), cap, 'lib Co-Invest paper order');
  const noReq = readJson('contracts', 'phase0-checker-rules.json'); delete noReq.mode_rules['fund-dev'].required_true;
  assert.throws(() => parseRules(noReq), /required_true/);
});

test('tripwire: broadened filesystem, network and shell rules reject evasions and keep the legitimate contracts loader path', () => {
  const FS = 'ZONE_SIGNING_FILESYSTEM_ESCAPE';
  const NET = 'ZONE_SIGNING_GENERAL_NETWORK';
  const SH = 'ZONE_SIGNING_ARBITRARY_SHELL';
  const fsCases = [
    "const p = new URL('../../../secrets', import.meta.url);", "const q = '../../outside';", "const j = path.join(base, '..', '..', 'x');",
    "const r = path.resolve('/');", "const r2 = resolve('/', 'x');", "const a = path.join('/tmp', 'x');", "const b = '/etc/passwd';", "const c = '/dev/null';",
    "const d = '/opt/app';", "const e = '/mnt/data';", "const f = '/srv/x';", "const g = '/var/lib/x';", "const h = '/home/user/.ssh';", "const i = '/root/.aws';",
    "const v = new URL('../../contracts/../x', import.meta.url);", "const w = '../../contracts/' + '../';", "const y = `../../contracts/${up}x`;", "const z = '../../contracts/sub/../../x';", "const q1 = '..';", "const q2 = base + '../';",
    "const k = os.homedir();", "const t = os.tmpdir();", "process.chdir('/');", "const u = new URL('../../contracts/../../etc/passwd', import.meta.url);",
  ];
  fsCases.forEach((code, n) => rejects(treeOf({ [`src/fs${n}.mjs`]: `${code}\n` }), FS, `fs: ${code}`));
  rejects(treeOf({ 'lib/x.mjs': "export const b = '/etc/hosts';\n" }), FS, 'fs outside src/');
  const netCases = [
    "const h = require('http');", "const h2 = require('https');", "const n = require('net');", "const t = require('tls');", "const d = require('dgram');",
    "import http from 'node:http';", "import https from 'https';", "import net from 'node:net';", "import tls from 'node:tls';", "import dgram from 'node:dgram';",
    "import dns from 'node:dns/promises';", "import http2 from 'node:http2';", "const m = await import('http');", "const m2 = await import('node:https');",
    "fetch('x');", "await fetch (u);", "new WebSocket(u);", "import { request } from 'undici';", "const x = new XMLHttpRequest();", "new EventSource(u);",
  ];
  netCases.forEach((code, n) => rejects(treeOf({ [`src/n${n}.mjs`]: `${code}\n` }), NET, `net: ${code}`));
  const shCases = [
    "exec('ls');", "execFile('ls');", "execSync('ls');", "spawn('sh');", "spawnSync('sh');", "fork('x.js');", "cp.spawn('sh');", "cp.execFileSync('sh');",
    "Bun.spawn(['sh']);", "Bun.spawnSync(['sh']);", "new Deno.Command('sh');", "import cp from 'node:child_process';", "const cp = require('child_process');",
  ];
  shCases.forEach((code, n) => rejects(treeOf({ [`src/sh${n}.mjs`]: `${code}\n` }), SH, `shell: ${code}`));
  rejects(treeOf({ 'scripts/x.py': 'import subprocess\n' }), SH, 'python subprocess');
  // legitimate patterns still pass: contracts loader URL, RegExp.exec, relative sibling imports, ordinary strings
  for (const ok of ["const C = new URL('../../contracts/', import.meta.url);", "const m = /a/.exec('a');", "import { x } from './y.mjs';", "export const s = 'http-like words in prose';", "const r = RFC.exec(s);"]) {
    assert.equal(treeOf({ 'src/ok.mjs': `${ok}\n` }).ok, true, ok);
  }
  assert.deepEqual(checkRepoTree(collectTree(ROOT)), { ok: true, violations: [] }, 'shipped tree still passes');
});
