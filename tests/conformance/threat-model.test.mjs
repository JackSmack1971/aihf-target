import test from 'node:test';
import assert from 'node:assert/strict';
import { readJson, readText, denyTest, clone } from '../helpers.mjs';
import { loadRuntimeMachine, exposureIncreaseAllowed, createMachine } from '../../src/contracts/state-machine.mjs';
import { checkSafeStateMapping } from '../../src/contracts/safe-state-mapping.mjs';

// Section 31 inventory: category -> threat ids (counts mirror the blueprint lists: 8, 8, 13, 11).
const EXPECTED = {
  prompt_data: ['PD-01', 'PD-02', 'PD-03', 'PD-04', 'PD-05', 'PD-06', 'PD-07', 'PD-08'],
  model_failure: ['MF-01', 'MF-02', 'MF-03', 'MF-04', 'MF-05', 'MF-06', 'MF-07', 'MF-08'],
  local_compromise: Array.from({ length: 13 }, (_, i) => `LC-${String(i + 1).padStart(2, '0')}`),
  exchange_network: Array.from({ length: 11 }, (_, i) => `EN-${String(i + 1).padStart(2, '0')}`),
};
const SAFE = ['REJECT_INPUT', 'BLOCK_NEW_EXPOSURE', 'DEGRADED', 'SAFE_HALT', 'FAIL_CLOSED_REBUILD', 'DENY_CAPABILITY', 'RECONCILE_BEFORE_RETRY'];
// Keyword anchors that tie each id to its section 31 wording so ids cannot be silently re-pointed.
const ANCHORS = {
  'PD-01': /news|article/i, 'PD-02': /MCP/, 'PD-03': /committee/i, 'PD-04': /metadata|symbol/i, 'PD-05': /oversized|malformed/i,
  'PD-06': /Co-Invest/, 'PD-07': /schema drift/i, 'PD-08': /independence/i,
  'MF-01': /hallucinated/i, 'MF-02': /stale/i, 'MF-03': /contradictory/i, 'MF-04': /role confusion/i, 'MF-05': /delegation/i, 'MF-06': /spam/i, 'MF-07': /collusion/i, 'MF-08': /malformed/i,
  'LC-01': /fund-ops/, 'LC-02': /traderd/, 'LC-03': /MCP/, 'LC-04': /SQLite/, 'LC-05': /log injection/i, 'LC-06': /environment/i, 'LC-07': /dependency/i,
  'LC-08': /\.codex/, 'LC-09': /unsafe permissions/i, 'LC-10': /unrestricted/i, 'LC-11': /bypass/i, 'LC-12': /OAuth/, 'LC-13': /paper/i,
  'EN-01': /REST timeout/i, 'EN-02': /WebSocket/i, 'EN-03': /duplicate/i, 'EN-04': /reorder/i, 'EN-05': /partial batch/i, 'EN-06': /rate limit/i,
  'EN-07': /clock skew/i, 'EN-08': /nonce/i, 'EN-09': /scheduled-cancel/i, 'EN-10': /protective/i, 'EN-11': /spread|liquidity/i,
};

const model = () => readJson('contracts', 'threat-model.json');
const BASE_KEYS = ['category', 'description', 'enforced_in_phase', 'expected_safe_state', 'id'];

/** Returns violations for a threat-model object (used on the real model and on mutated copies). */
function threatViolations(m) {
  const v = [];
  const ids = m.threats.map((t) => t.id);
  if (new Set(ids).size !== ids.length) v.push('duplicate ids');
  if (ids.length !== Object.values(EXPECTED).flat().length) v.push('threat count mismatch');
  for (const t of m.threats) {
    if (!SAFE.includes(t.expected_safe_state)) v.push(`${t.id}: invalid safe state`);
    if (!Number.isInteger(t.enforced_in_phase) || t.enforced_in_phase < 0 || t.enforced_in_phase > 12) v.push(`${t.id}: bad phase`);
    if (typeof t.description !== 'string' || t.description.length <= 5) v.push(`${t.id}: bad description`);
  }
  return v;
}

denyTest('DENY-THREAT-WITHOUT-SAFE-STATE', () => {
  const m = model();
  assert.deepEqual(m.safe_states, SAFE);
  assert.equal(m.threats.length, Object.values(EXPECTED).flat().length);
  const ids = m.threats.map((t) => t.id);
  assert.equal(new Set(ids).size, ids.length, 'duplicate ids');
  for (const [cat, list] of Object.entries(EXPECTED)) {
    assert.deepEqual(m.threats.filter((t) => t.category === cat).map((t) => t.id), list, cat);
  }
  assert.deepEqual(threatViolations(m), [], 'positive control');
  const badSafe = clone(m); badSafe.threats[0].expected_safe_state = 'WHATEVER';
  assert.ok(threatViolations(badSafe).length > 0, 'unknown safe state is rejected');
  const badPhase = clone(m); badPhase.threats[3].enforced_in_phase = 99;
  assert.ok(threatViolations(badPhase).length > 0, 'bad phase is rejected');
  const dropped = clone(m); dropped.threats.pop();
  assert.ok(threatViolations(dropped).length > 0, 'a dropped threat is rejected');
  const dup = clone(m); dup.threats[1].id = dup.threats[0].id;
  assert.ok(threatViolations(dup).length > 0, 'duplicate id is rejected');
  for (const t of m.threats) {
    assert.deepEqual(Object.keys(t).filter((k) => !BASE_KEYS.includes(k)), t.risk_reducing_action_required ? ['risk_reducing_action_required'] : [], t.id);
    for (const k of BASE_KEYS) assert.ok(k in t, `${t.id}.${k}`);
    assert.ok(SAFE.includes(t.expected_safe_state), `${t.id}: invalid safe state ${t.expected_safe_state}`);
    assert.ok(Number.isInteger(t.enforced_in_phase) && t.enforced_in_phase >= 0 && t.enforced_in_phase <= 12, `${t.id} phase`);
    assert.ok(typeof t.description === 'string' && t.description.length > 5, t.id);
    assert.match(t.description, ANCHORS[t.id], `${t.id} anchor`);
  }
  assert.deepEqual(Object.keys(ANCHORS).sort(), [...ids].sort());
});

test('threat-model.md lists every threat id and safe state', () => {
  const md = readText('docs', 'threat-model.md');
  for (const t of model().threats) {
    assert.ok(md.includes(`| ${t.id} |`), t.id);
    assert.ok(md.includes(t.description), `${t.id} description`);
  }
  for (const s of SAFE) assert.ok(md.includes(s), s);
});

test('exposure-affecting threats never map to a safe state weaker than blocking exposure', () => {
  const weak = new Set(['DEGRADED']);
  const m = model();
  for (const id of ['MF-01', 'MF-02', 'EN-07', 'PD-08']) assert.ok(!weak.has(m.threats.find((t) => t.id === id).expected_safe_state), id);
  assert.equal(m.threats.find((t) => t.id === 'EN-08').expected_safe_state, 'SAFE_HALT');
});

denyTest('DENY-SAFE-STATE-UNMAPPED', () => {
  const m = model();
  const rt = loadRuntimeMachine();
  const map = m.safe_state_runtime_mapping;
  assert.deepEqual(Object.keys(map).sort(), [...SAFE].sort(), 'every safe state is mapped, none extra');
  for (const [state, e] of Object.entries(map)) {
    assert.ok(Array.isArray(e.runtime_states), state);
    for (const rs of e.runtime_states) {
      assert.ok(rt.states.has(rs), `${state}: undefined runtime state ${rs}`);
      assert.equal(exposureIncreaseAllowed(rt, rs), false, `${state} maps to ${rs}, which permits exposure increase`);
    }
    assert.equal(e.exposure_increase_allowed, false, state);
    assert.ok(e.runtime_effect && e.intent_effect && e.description, state);
    if (e.runtime_states.length === 0) assert.equal(e.runtime_effect, 'NO_STATE_CHANGE', state);
  }
  assert.equal(map.REJECT_INPUT.intent_effect, 'REJECTED');
  assert.equal(map.REJECT_INPUT.runtime_effect, 'NO_STATE_CHANGE');
  assert.deepEqual(map.SAFE_HALT.runtime_states, ['SAFE_HALT']);
  assert.deepEqual(map.DEGRADED.runtime_states, ['DEGRADED']);
  assert.ok(map.BLOCK_NEW_EXPOSURE.runtime_states.includes('DEGRADED'));
  assert.ok(!map.BLOCK_NEW_EXPOSURE.runtime_states.includes('ARMED'));
  // a mapping that targets ARMED or an undefined state is detectable
  assert.ok(exposureIncreaseAllowed(rt, 'ARMED'), 'sanity: ARMED is the only exposure state');
  assert.ok(!rt.states.has('NOT_A_STATE'));
  // threats whose safe state is not trivially "no state change" must have a runtime-state mapping
  for (const t of m.threats) assert.ok(map[t.expected_safe_state], `${t.id} safe state unmapped`);

  // checker: positive control, then negative mutation fixtures
  const check = (mp, machine = rt, safe = m.safe_states, threats = m.threats) => checkSafeStateMapping(mp, machine, safe, threats);
  assert.deepEqual(check(map), { ok: true, violations: [] }, 'positive control: shipped mapping passes');
  const mutMap = (fn) => { const c = clone(map); fn(c); return c; };
  const rejected = (r, re, label) => { assert.equal(r.ok, false, `${label}: must be rejected`); assert.ok(r.violations.some((x) => re.test(x)), `${label}: ${r.violations.join(' | ')}`); };
  rejected(check(mutMap((c) => { c.BLOCK_NEW_EXPOSURE.runtime_states.push('ARMED'); })), /ARMED/, 'safe state maps to ARMED');
  rejected(check(mutMap((c) => { c.SAFE_HALT.runtime_states = ['ARMED']; })), /ARMED/, 'SAFE_HALT repointed at ARMED');
  rejected(check(mutMap((c) => { c.DEGRADED.runtime_states = ['NOT_A_STATE']; })), /undefined runtime state NOT_A_STATE/, 'safe state maps to an undefined state');
  rejected(check(mutMap((c) => { c.SAFE_HALT.runtime_states = ['armed']; })), /undefined runtime state/, 'case-variant state name');
  rejected(check(mutMap((c) => { c.SAFE_HALT.runtime_states = [null]; })), /undefined runtime state/, 'non-string state');
  rejected(check(mutMap((c) => { delete c.SAFE_HALT; })), /SAFE_HALT is unmapped/, 'safe state dropped from the mapping');
  rejected(check(mutMap((c) => { c.EXTRA = clone(c.SAFE_HALT); })), /unknown safe state EXTRA/, 'extra safe state');
  rejected(check(mutMap((c) => { c.SAFE_HALT.exposure_increase_allowed = true; })), /exposure_increase_allowed must be false/, 'mapping claims exposure allowed');
  rejected(check(mutMap((c) => { c.REJECT_INPUT.runtime_effect = 'SOMETHING_ELSE'; })), /NO_STATE_CHANGE/, 'empty runtime states with a state-changing effect');
  rejected(check(mutMap((c) => { c.SAFE_HALT.runtime_states = 'SAFE_HALT'; })), /runtime_states missing/, 'runtime_states not an array');
  rejected(check(mutMap((c) => { c.SAFE_HALT.description = ''; })), /required/, 'missing description');
  rejected(check(null), /not an object/, 'null mapping');
  rejected(check(map, rt, []), /empty or missing/, 'empty safe-state list');
  rejected(checkSafeStateMapping(map, rt, undefined), /empty or missing/, 'missing safe-state list');
  // a runtime machine that permits exposure in another state makes a mapping to that state invalid
  const widened = clone(rt.def); widened.exposure_increase_allowed_states = ['ARMED', 'DEGRADED'];
  rejected(check(map, createMachine(widened)), /DEGRADED, which permits exposure increase/, 'mapping onto a state the machine allows exposure in');
  // threat -> safe-state mapping: a threat pointing at ARMED or an undefined state is rejected
  const threats = (fn) => { const c = clone(m.threats); fn(c); return c; };
  rejected(check(map, rt, m.safe_states, threats((t) => { t[0].expected_safe_state = 'ARMED'; })), /expected_safe_state ARMED/, 'threat safe state ARMED');
  rejected(check(map, rt, m.safe_states, threats((t) => { t[3].expected_safe_state = 'NOT_A_STATE'; })), /NOT_A_STATE/, 'threat safe state undefined');
  rejected(check(map, rt, m.safe_states, threats((t) => { delete t[5].expected_safe_state; })), /undefined/, 'threat safe state missing');
});

test('EN-10 and LC-04 map to SAFE_HALT with a deterministic risk-reducing action', () => {
  const by = Object.fromEntries(model().threats.map((t) => [t.id, t]));
  for (const id of ['EN-10', 'LC-04']) {
    assert.equal(by[id].expected_safe_state, 'SAFE_HALT', id);
    assert.equal(by[id].risk_reducing_action_required, true, id);
  }
  for (const t of model().threats) if (!['EN-10', 'LC-04'].includes(t.id)) assert.equal(t.risk_reducing_action_required, undefined, t.id);
});
