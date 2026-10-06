import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadRuntimeMachine, loadTradeIntentMachine, createMachine, isAllowedTransition, isHumanGated, exposureIncreaseAllowed, checkRuntimeContract, checkReconcilingGuards, checkProtectiveExitInvariant, guardFor } from '../../src/contracts/state-machine.mjs';
import { readJson, clone, denyTest, tempDir } from '../helpers.mjs';

/** Writes contract overrides into a temp dir (copy of contracts/) and returns a URL base for the loaders. */
function contractsDirWith(overrides) {
  const dir = tempDir('aihf-contracts-');
  for (const f of ['runtime-state-machine.json', 'trade-intent-state-machine.json']) {
    fs.writeFileSync(path.join(dir, f), JSON.stringify(overrides[f] ?? readJson('contracts', f)));
  }
  return pathToFileURL(dir + path.sep);
}

const H = { humanAuthorized: true };
const RT = ['STOPPED', 'BOOTING', 'SYNCING', 'DISARMED', 'ARMING', 'ARMED', 'DEGRADED', 'DRAINING', 'SAFE_HALT'];

test('runtime machine has exactly the section 20 states and valid positive transitions', () => {
  const m = loadRuntimeMachine();
  assert.deepEqual([...m.states].sort(), [...RT].sort());
  for (const [a, b] of [['STOPPED', 'BOOTING'], ['BOOTING', 'SYNCING'], ['SYNCING', 'DISARMED'], ['DISARMED', 'ARMING'], ['ARMING', 'ARMED'],
    ['ARMED', 'DEGRADED'], ['DEGRADED', 'ARMED'], ['ARMED', 'DRAINING'], ['DRAINING', 'SAFE_HALT'], ['SYNCING', 'SAFE_HALT'], ['ARMING', 'DISARMED'], ['ARMING', 'SAFE_HALT'], ['DEGRADED', 'SAFE_HALT'], ['BOOTING', 'SAFE_HALT'], ['DISARMED', 'SAFE_HALT']]) {
    assert.ok(isAllowedTransition(m, a, b, H), `${a}->${b}`);
  }
});

denyTest('DENY-RUNTIME-EXPOSURE-OUTSIDE-ARMED', () => {
  const m = loadRuntimeMachine();
  assert.deepEqual(m.def.exposure_increase_allowed_states, ['ARMED']);
  assert.equal(exposureIncreaseAllowed(m, 'ARMED'), true, 'positive control');
  for (const s of RT.filter((x) => x !== 'ARMED')) assert.equal(exposureIncreaseAllowed(m, s), false, s);
  for (const s of ['armed', 'UNKNOWN', '', undefined, null]) assert.throws(() => exposureIncreaseAllowed(m, s), /unknown state/);
  // a tampered contract that widens exposure to another state is not what the shipped file says
  const forged = clone(m.def); forged.exposure_increase_allowed_states = ['ARMED', 'DEGRADED'];
  assert.equal(exposureIncreaseAllowed(createMachine(forged), 'DEGRADED'), true, 'sanity: table-driven');
  assert.notDeepEqual(readJson('contracts', 'runtime-state-machine.json').exposure_increase_allowed_states, forged.exposure_increase_allowed_states);
  // negative mutation fixtures: the contract checker and the loader reject any exposure set other than exactly ["ARMED"]
  assert.deepEqual(checkRuntimeContract(m.def), [], 'positive control: shipped contract passes');
  const RT_FILE = 'runtime-state-machine.json';
  const mutations = {
    'ARMED plus DEGRADED': ['ARMED', 'DEGRADED'],
    'DEGRADED only': ['DEGRADED'],
    'DRAINING only': ['DRAINING'],
    'SAFE_HALT only': ['SAFE_HALT'],
    'DISARMED plus ARMED': ['DISARMED', 'ARMED'],
    'empty set': [],
    'ARMED twice': ['ARMED', 'ARMED'],
    'every state': [...RT],
  };
  for (const [name, set] of Object.entries(mutations)) {
    const def = clone(m.def); def.exposure_increase_allowed_states = set;
    assert.ok(checkRuntimeContract(def).length > 0, `${name}: checker must reject`);
    assert.throws(() => loadRuntimeMachine(contractsDirWith({ [RT_FILE]: def })), /invalid contract/, `${name}: loader must reject`);
  }
  const missing = clone(m.def); delete missing.exposure_increase_allowed_states;
  assert.ok(checkRuntimeContract(missing).length > 0, 'missing field rejected by checker');
  assert.throws(() => loadRuntimeMachine(contractsDirWith({ [RT_FILE]: missing })), /invalid contract/, 'missing field rejected by loader');
  assert.ok(checkRuntimeContract(null).length > 0);
  assert.equal(loadRuntimeMachine(contractsDirWith({})).def.id, 'runtime', 'loader positive control from a copied contract dir');
});

test('ARMED outgoing edges are exactly DEGRADED and DRAINING (section 20 diagram); no direct SAFE_HALT/DISARMED/STOPPED exit', () => {
  const m = loadRuntimeMachine();
  assert.deepEqual([...m.def.transitions.ARMED].sort(), ['DEGRADED', 'DRAINING']);
  for (const to of RT.filter((x) => !['DEGRADED', 'DRAINING'].includes(x))) assert.equal(isAllowedTransition(m, 'ARMED', to, H), false, `ARMED->${to}`);
  assert.deepEqual(checkRuntimeContract(m.def), []);
  // mutating ARMED's exits (a direct edge, a dropped edge, or a swapped edge) is rejected by the checker and the loader
  for (const exits of [['DEGRADED', 'DRAINING', 'SAFE_HALT'], ['DEGRADED'], ['DRAINING'], ['DEGRADED', 'DISARMED'], ['DEGRADED', 'DRAINING', 'ARMED'], []]) {
    const def = clone(m.def); def.transitions.ARMED = exits;
    assert.ok(checkRuntimeContract(def).length > 0, `ARMED -> ${exits.join(',')} must be rejected`);
    assert.throws(() => loadRuntimeMachine(contractsDirWith({ 'runtime-state-machine.json': def })), /invalid contract/);
  }
});

denyTest('DENY-RUNTIME-SAFE-HALT-TO-ARMED', () => {
  const m = loadRuntimeMachine();
  assert.equal(isAllowedTransition(m, 'SAFE_HALT', 'ARMED'), false);
  assert.equal(isAllowedTransition(m, 'SAFE_HALT', 'ARMING'), false);
  assert.ok(m.def.forbidden_transitions.some((t) => t.from === 'SAFE_HALT' && t.to === 'ARMED'));
  // no path from SAFE_HALT to ARMED that skips the full boot/sync/disarm/arm sequence
  const path = ['SAFE_HALT', 'STOPPED', 'BOOTING', 'SYNCING', 'DISARMED', 'ARMING', 'ARMED'];
  for (let i = 0; i < path.length - 1; i++) assert.ok(isAllowedTransition(m, path[i], path[i + 1], H), `${path[i]}->${path[i + 1]}`);
  assert.equal(isAllowedTransition(m, 'SAFE_HALT', 'ARMED', H), false, 'human authorization does not create an edge');
  // every route to ARMED goes through ARMING or DEGRADED(recover)
  const into = RT.filter((s) => m.def.transitions[s].includes('ARMED'));
  assert.deepEqual(into.sort(), ['ARMING', 'DEGRADED']);
  assert.deepEqual(RT.filter((x) => m.def.transitions[x].includes('ARMING')), ['DISARMED'], 'ARMING has exactly one predecessor');
});

denyTest('DENY-RUNTIME-HUMAN-GATE', () => {
  const m = loadRuntimeMachine();
  const gated = m.def.human_gated_transitions.map((g) => `${g.from}->${g.to}`).sort();
  assert.deepEqual(gated, ['DISARMED->ARMING', 'SAFE_HALT->STOPPED']);
  assert.ok(m.def.human_gated_transitions.find((g) => g.from === 'SAFE_HALT').requires.includes('explicit human recovery acknowledgment'));
  for (const g of m.def.human_gated_transitions) {
    assert.ok(isHumanGated(m, g.from, g.to));
    assert.equal(isAllowedTransition(m, g.from, g.to), false, `${g.from}->${g.to} denied without context`);
    for (const ctx of [{}, undefined, null, { humanAuthorized: false }, { humanAuthorized: 'true' }, { humanAuthorized: 1 }, { operator: true }]) {
      assert.equal(isAllowedTransition(m, g.from, g.to, ctx), false, `${g.from}->${g.to} with ${JSON.stringify(ctx)}`);
    }
    assert.equal(isAllowedTransition(m, g.from, g.to, H), true, 'positive control with explicit human authorization');
  }
  assert.equal(isAllowedTransition(m, 'STOPPED', 'BOOTING'), true, 'non-gated edges need no context');
  assert.equal(isHumanGated(m, 'ARMING', 'ARMED'), false);
  const bad = clone(m.def); bad.human_gated_transitions.push({ from: 'STOPPED', to: 'ARMED', requires: 'x' });
  assert.throws(() => createMachine(bad), /not a defined edge/);
});

test('runtime: undefined transitions are denied and unknown states throw', () => {
  const m = loadRuntimeMachine();
  for (const [a, b] of [['STOPPED', 'ARMED'], ['BOOTING', 'ARMED'], ['SYNCING', 'ARMED'], ['DISARMED', 'ARMED'], ['DRAINING', 'ARMED'], ['DRAINING', 'DISARMED'],
    ['ARMED', 'DISARMED'], ['ARMED', 'ARMED'], ['DEGRADED', 'DISARMED'], ['STOPPED', 'SAFE_HALT']]) {
    assert.equal(isAllowedTransition(m, a, b), false, `${a}->${b}`);
  }
  assert.throws(() => isAllowedTransition(m, 'ARMED', 'FLYING'), /unknown state/);
  assert.throws(() => isAllowedTransition(m, 'FLYING', 'ARMED'), /unknown state/);
});

test('createMachine fails closed on malformed definitions', () => {
  const good = readJson('contracts', 'runtime-state-machine.json');
  const a = clone(good); a.transitions.ARMED.push('NOWHERE');
  assert.throws(() => createMachine(a), /unknown state/);
  const b = clone(good); delete b.transitions.STOPPED;
  assert.throws(() => createMachine(b), /no transition row/);
  const c = clone(good); c.states.push('ARMED');
  assert.throws(() => createMachine(c), /duplicate/);
  const d = clone(good); d.exposure_increase_allowed_states = ['GHOST'];
  assert.throws(() => createMachine(d), /unknown exposure state/);
});

// ---- TradeIntent machine ----
const reachable = (m, start, blocked = new Set()) => {
  const seen = new Set([start]); const q = [start];
  while (q.length) {
    const s = q.shift();
    for (const n of m.def.transitions[s]) if (!seen.has(n) && !blocked.has(n)) { seen.add(n); q.push(n); }
  }
  return seen;
};

test('TradeIntent machine has the section 21 states and the happy path', () => {
  const m = loadTradeIntentMachine();
  const happy = ['DRAFT', 'EVIDENCED', 'PROPOSED', 'AI_RISK_REVIEW', 'PASS', 'POLICY_PRECHECK', 'AUTHORIZATION_PENDING', 'PERMITTED', 'EXECUTION_PLANNING', 'QUEUED',
    'SUBMITTING', 'OPEN', 'FILLED', 'PROTECTING', 'MONITORING', 'EXIT_REQUESTED', 'EXITING', 'CLOSED'];
  for (let i = 0; i < happy.length - 1; i++) assert.ok(isAllowedTransition(m, happy[i], happy[i + 1]), `${happy[i]}->${happy[i + 1]}`);
  assert.ok(isAllowedTransition(m, 'AI_RISK_REVIEW', 'PASS_WITH_CONSTRAINTS'));
  assert.ok(isAllowedTransition(m, 'PASS_WITH_CONSTRAINTS', 'POLICY_PRECHECK'));
  for (const s of ['EXPIRED', 'CANCELED', 'REJECTED', 'SUPERSEDED', 'EXECUTION_ERROR', 'RECONCILING', 'PARTIALLY_FILLED']) assert.ok(m.states.has(s), s);
});

test('TradeIntent: reconciliation cannot skip protection; OPEN can be canceled/expired', () => {
  const m = loadTradeIntentMachine();
  const t = (a, b) => isAllowedTransition(m, a, b);
  assert.equal(t('RECONCILING', 'MONITORING'), false);
  for (const to of ['PROTECTING', 'OPEN', 'CANCELED']) assert.ok(t('RECONCILING', to), `RECONCILING->${to}`);
  for (const to of ['CANCELED', 'EXPIRED']) assert.ok(t('OPEN', to), `OPEN->${to}`);
  assert.deepEqual([...m.states].filter((x) => m.def.transitions[x].includes('MONITORING')), ['PROTECTING']);
  const noProtect = reachable(m, 'DRAFT', new Set(['PROTECTING']));
  assert.ok(!noProtect.has('MONITORING'), 'MONITORING is unreachable without passing PROTECTING');
  assert.match(m.def.protecting_precondition, /Remaining entry quantity is canceled before PROTECTING is entered from PARTIALLY_FILLED/);
  assert.ok(t('PARTIALLY_FILLED', 'PROTECTING'));
});

denyTest('DENY-INTENT-SKIP-AUTHORIZATION', () => {
  const m = loadTradeIntentMachine();
  const preds = (s) => [...m.states].filter((x) => m.def.transitions[x].includes(s));
  assert.deepEqual(preds('PERMITTED'), ['AUTHORIZATION_PENDING']);
  assert.deepEqual(preds('AUTHORIZATION_PENDING'), ['POLICY_PRECHECK']);
  assert.deepEqual(m.def.permit_gate, { state: 'PERMITTED', only_from: 'AUTHORIZATION_PENDING' });
  assert.equal(isAllowedTransition(m, 'AI_RISK_REVIEW', 'PERMITTED'), false);
  assert.equal(isAllowedTransition(m, 'POLICY_PRECHECK', 'PERMITTED'), false);
  assert.equal(isAllowedTransition(m, 'DRAFT', 'SUBMITTING'), false);
  assert.equal(isAllowedTransition(m, 'PROPOSED', 'QUEUED'), false);
  // with PERMITTED removed from the graph no execution state is reachable from any non-execution start
  const blocked = new Set(['PERMITTED']);
  const r = reachable(m, 'DRAFT', blocked);
  for (const e of m.def.execution_states) assert.ok(!r.has(e), `${e} reachable without PERMITTED`);
  assert.ok(reachable(m, 'DRAFT').has('SUBMITTING'), 'positive control: reachable via PERMITTED');
  for (const e of m.def.execution_states) {
    for (const p of [...m.states].filter((x) => m.def.transitions[x].includes(e))) {
      assert.ok(m.def.execution_states.includes(p) || ['PERMITTED', 'EXECUTION_ERROR', 'RECONCILING'].includes(p), `${p}->${e}`);
    }
  }
});

denyTest('DENY-INTENT-TERMINAL-REVIVAL', () => {
  const m = loadTradeIntentMachine();
  assert.deepEqual([...m.def.terminal_states].sort(), ['CANCELED', 'CLOSED', 'EXPIRED', 'REJECTED', 'SUPERSEDED']);
  for (const t of m.def.terminal_states) assert.deepEqual(m.def.transitions[t], [], `${t} must have no exits`);
  assert.ok(isAllowedTransition(m, 'AI_RISK_REVIEW', 'REJECTED'), 'positive control');
  assert.equal(isAllowedTransition(m, 'REJECTED', 'PERMITTED'), false);
  assert.ok(!reachable(m, 'REJECTED').has('PERMITTED'));
  assert.equal(reachable(m, 'REJECTED').size, 1);
  for (const t of m.def.terminal_states) {
    for (const e of [...m.def.execution_states, 'PERMITTED', 'AUTHORIZATION_PENDING']) assert.equal(isAllowedTransition(m, t, e), false, `${t}->${e}`);
  }
  // no state is both terminal and non-terminal; every non-terminal state has an exit
  for (const s of m.states) if (!m.def.terminal_states.includes(s)) assert.ok(m.def.transitions[s].length > 0, s);
});

test('guards: every RECONCILING edge into a terminal state carries a machine-readable guard (no unprotected exposure)', () => {
  const m = loadTradeIntentMachine();
  const toTerminal = m.def.transitions.RECONCILING.filter((to) => m.def.terminal_states.includes(to)).sort();
  assert.deepEqual(toTerminal, ['CANCELED', 'CLOSED']);
  assert.deepEqual(m.def.guards.map((g) => `${g.from}->${g.to}`).sort(), ['RECONCILING->CANCELED', 'RECONCILING->CLOSED']);
  for (const to of toTerminal) {
    const g = guardFor(m, 'RECONCILING', to);
    assert.ok(g, `RECONCILING->${to} guard`);
    assert.match(g.precondition, /no open position and no unprotected exposure/i);
    assert.match(g.evidence, /authoritative/i);
    assert.equal(isAllowedTransition(m, 'RECONCILING', to), true, 'guards are preconditions for the later runtime; the table edge itself is unchanged');
  }
  assert.equal(guardFor(m, 'RECONCILING', 'PROTECTING'), undefined);
  assert.deepEqual(checkReconcilingGuards(m.def), [], 'positive control');
  const TI = 'trade-intent-state-machine.json';
  // removing either guard (or emptying it) is rejected by the checker and the loader
  for (const to of toTerminal) {
    const def = clone(m.def); def.guards = def.guards.filter((g) => g.to !== to);
    assert.ok(checkReconcilingGuards(def).some((x) => x.includes(to)), `dropping the ${to} guard is detected`);
    assert.throws(() => loadTradeIntentMachine(contractsDirWith({ [TI]: def })), /RECONCILING->/);
    const blank = clone(m.def); blank.guards.find((g) => g.to === to).precondition = '  ';
    assert.throws(() => createMachine(blank), /needs a precondition/);
    assert.ok(checkReconcilingGuards(blank).length > 0);
    const noEvidence = clone(m.def); delete noEvidence.guards.find((g) => g.to === to).evidence;
    assert.throws(() => createMachine(noEvidence), /evidence source/);
  }
  const none = clone(m.def); delete none.guards;
  assert.equal(checkReconcilingGuards(none).length, 2);
  // a newly added unguarded RECONCILING -> terminal edge is rejected
  const widened = clone(m.def); widened.transitions.RECONCILING.push('EXPIRED');
  assert.deepEqual(checkReconcilingGuards(widened), ['RECONCILING->EXPIRED has no guard']);
});

test('guards on undefined edges or unknown states are rejected by the loader', () => {
  const good = readJson('contracts', 'trade-intent-state-machine.json');
  const mk = (g) => { const d = clone(good); d.guards = [...d.guards, g]; return d; };
  const ok = { precondition: 'x', evidence: 'y' };
  assert.throws(() => createMachine(mk({ from: 'RECONCILING', to: 'REJECTED', ...ok })), /not a defined edge/);
  assert.throws(() => createMachine(mk({ from: 'DRAFT', to: 'CLOSED', ...ok })), /not a defined edge/);
  assert.throws(() => createMachine(mk({ from: 'RECONCILING', to: 'NOWHERE', ...ok })), /not a defined edge/);
  assert.throws(() => createMachine(mk({ from: 'NOWHERE', to: 'CLOSED', ...ok })), /not a defined edge/);
  assert.throws(() => loadTradeIntentMachine(contractsDirWith({ 'trade-intent-state-machine.json': mk({ from: 'REJECTED', to: 'PERMITTED', ...ok }) })), /not a defined edge/);
  assert.ok(createMachine(mk({ from: 'RECONCILING', to: 'OPEN', ...ok })), 'a guard on a defined edge is accepted');
});

test('loaders require the pinned terminal set and the human gates (no vacuous guards or gates)', () => {
  const TI = 'trade-intent-state-machine.json';
  const RTF = 'runtime-state-machine.json';
  const ti = readJson('contracts', TI);
  const rt = readJson('contracts', RTF);
  const mk = (base, fn) => { const d = clone(base); fn(d); return d; };
  for (const [name, def] of Object.entries({
    'terminal_states missing': mk(ti, (d) => { delete d.terminal_states; }),
    'terminal_states empty': mk(ti, (d) => { d.terminal_states = []; }),
    'terminal_states shrunk (CLOSED removed)': mk(ti, (d) => { d.terminal_states = d.terminal_states.filter((x) => x !== 'CLOSED'); }),
    'terminal_states shrunk (CANCELED removed)': mk(ti, (d) => { d.terminal_states = d.terminal_states.filter((x) => x !== 'CANCELED'); }),
    'terminal_states widened': mk(ti, (d) => { d.terminal_states.push('PROTECTING'); }),
    'terminal state with an exit': mk(ti, (d) => { d.transitions.REJECTED = ['PERMITTED']; }),
  })) {
    assert.ok(checkReconcilingGuards(def).length > 0, `${name}: checker must reject`);
    assert.throws(() => loadTradeIntentMachine(contractsDirWith({ [TI]: def })), /invalid contract/, `${name}: loader must reject`);
  }
  for (const [name, def] of Object.entries({
    'human gates missing': mk(rt, (d) => { delete d.human_gated_transitions; }),
    'human gates empty': mk(rt, (d) => { d.human_gated_transitions = []; }),
    'arm gate dropped': mk(rt, (d) => { d.human_gated_transitions = d.human_gated_transitions.filter((g) => g.to !== 'ARMING'); }),
    'recovery gate dropped': mk(rt, (d) => { d.human_gated_transitions = d.human_gated_transitions.filter((g) => g.from !== 'SAFE_HALT'); }),
    'human gates not an array': mk(rt, (d) => { d.human_gated_transitions = 'DISARMED->ARMING'; }),
  })) {
    assert.ok(checkRuntimeContract(def).length > 0, `${name}: checker must reject`);
    assert.throws(() => loadRuntimeMachine(contractsDirWith({ [RTF]: def })), /invalid contract|gated transition/, `${name}: loader must reject`);
  }
  assert.deepEqual(checkRuntimeContract(rt), []);
  assert.deepEqual(checkReconcilingGuards(ti), []);
});

denyTest('DENY-INTENT-EXPIRY-CANCELS-PROTECTION', () => {
  const TI = 'trade-intent-state-machine.json';
  const ti = readJson('contracts', TI);
  assert.deepEqual(checkProtectiveExitInvariant(ti), [], 'positive control');
  assert.ok(loadTradeIntentMachine());
  const m = loadTradeIntentMachine();
  const exposed = ['PARTIALLY_FILLED', 'FILLED', 'PROTECTING', 'MONITORING', 'EXIT_REQUESTED', 'EXITING'];
  assert.deepEqual([...m.def.protective_exit_invariant.exposed_states].sort(), [...exposed].sort());
  for (const from of exposed) {
    for (const to of ['EXPIRED', 'CANCELED', 'SUPERSEDED', 'REJECTED']) {
      assert.equal(isAllowedTransition(m, from, to), false, `${from}->${to} denied`);
      const def = clone(ti); def.transitions[from] = [...def.transitions[from], to];
      assert.ok(checkProtectiveExitInvariant(def).some((x) => x.includes(`${from}->${to}`)), `${from}->${to}: checker must reject`);
      assert.throws(() => loadTradeIntentMachine(contractsDirWith({ [TI]: def })), /invalid contract/, `${from}->${to}: loader must reject`);
    }
  }
  const noInv = clone(ti); delete noInv.protective_exit_invariant;
  assert.ok(checkProtectiveExitInvariant(noInv).length > 0, 'invariant block removed');
  assert.throws(() => loadTradeIntentMachine(contractsDirWith({ [TI]: noInv })), /invalid contract/);
  const fewer = clone(ti); fewer.protective_exit_invariant.exposed_states = fewer.protective_exit_invariant.exposed_states.filter((x) => x !== 'MONITORING');
  assert.ok(checkProtectiveExitInvariant(fewer).length > 0, 'exposed set shrunk');
  const targets = clone(ti); targets.protective_exit_invariant.forbidden_targets = ['EXPIRED'];
  assert.ok(checkProtectiveExitInvariant(targets).length > 0, 'forbidden targets shrunk');
  const noRow = clone(ti); delete noRow.transitions.MONITORING;
  assert.ok(checkProtectiveExitInvariant(noRow).length > 0, 'missing transition row');
  // OPEN (nothing filled yet) may still expire or be canceled; that is not a protective exit
  assert.equal(isAllowedTransition(m, 'OPEN', 'EXPIRED'), true);
  assert.equal(isAllowedTransition(m, 'OPEN', 'CANCELED'), true);
});
