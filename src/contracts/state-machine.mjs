// Pure table-lookup state machines loaded from contracts/*.json. No I/O beyond loading.
import fs from 'node:fs';

const CONTRACTS = new URL('../../contracts/', import.meta.url);

export function createMachine(def) {
  const states = new Set(def.states);
  if (states.size !== def.states.length) throw new Error(`${def.id}: duplicate states`);
  if (!states.has(def.initial)) throw new Error(`${def.id}: unknown initial state`);
  for (const [from, tos] of Object.entries(def.transitions)) {
    if (!states.has(from)) throw new Error(`${def.id}: transition from unknown state ${from}`);
    for (const to of tos) if (!states.has(to)) throw new Error(`${def.id}: transition to unknown state ${to}`);
  }
  for (const s of states) if (!Object.hasOwn(def.transitions, s)) throw new Error(`${def.id}: state ${s} has no transition row`);
  for (const s of def.exposure_increase_allowed_states ?? []) if (!states.has(s)) throw new Error(`${def.id}: unknown exposure state ${s}`);
  for (const g of [...(def.human_gated_transitions ?? []), ...(def.condition_gated_transitions ?? [])]) {
    if (!states.has(g.from) || !states.has(g.to) || !def.transitions[g.from].includes(g.to)) {
      throw new Error(`${def.id}: gated transition ${g.from}->${g.to} is not a defined edge`);
    }
  }
  for (const g of def.guards ?? []) {
    if (!states.has(g.from) || !states.has(g.to) || !def.transitions[g.from].includes(g.to)) {
      throw new Error(`${def.id}: guard ${g.from}->${g.to} is not a defined edge`);
    }
    if (typeof g.precondition !== 'string' || g.precondition.trim() === '' || typeof g.evidence !== 'string' || g.evidence.trim() === '') {
      throw new Error(`${def.id}: guard ${g.from}->${g.to} needs a precondition and an evidence source`);
    }
  }
  return Object.freeze({ def, states });
}

export function loadMachine(name, dir = CONTRACTS) {
  return createMachine(JSON.parse(fs.readFileSync(new URL(`${name}.json`, dir), 'utf8')));
}

/** Section 20 / 17 inv. 8: exposure only in ARMED; ARMED exits are exactly DEGRADED and DRAINING. @returns {string[]} violations */
export function checkRuntimeContract(def) {
  const v = [];
  const exp = def?.exposure_increase_allowed_states;
  if (!Array.isArray(exp) || exp.length !== 1 || exp[0] !== 'ARMED') v.push('exposure_increase_allowed_states must be exactly ["ARMED"]');
  const gates = Array.isArray(def?.human_gated_transitions) ? def.human_gated_transitions : [];
  for (const [from, to] of [['DISARMED', 'ARMING'], ['SAFE_HALT', 'STOPPED']]) {
    if (!gates.some((g) => g?.from === from && g?.to === to)) v.push(`human_gated_transitions must include ${from}->${to}`);
  }
  const exits = def?.transitions?.ARMED;
  if (!Array.isArray(exits) || JSON.stringify([...exits].sort()) !== JSON.stringify(['DEGRADED', 'DRAINING'])) v.push('ARMED exits must be exactly DEGRADED and DRAINING');
  return v;
}

/** Section 21: every edge from RECONCILING into a terminal state carries a guard. @returns {string[]} violations */
export function checkReconcilingGuards(def) {
  const v = [];
  const terminal = Array.isArray(def?.terminal_states) ? def.terminal_states : [];
  if (JSON.stringify([...terminal].sort()) !== JSON.stringify(['CANCELED', 'CLOSED', 'EXPIRED', 'REJECTED', 'SUPERSEDED'])) {
    v.push('terminal_states must be exactly CANCELED, CLOSED, EXPIRED, REJECTED, SUPERSEDED');
  }
  for (const t of terminal) if (!Array.isArray(def?.transitions?.[t]) || def.transitions[t].length !== 0) v.push(`terminal state ${t} must have no exits`);
  for (const to of def?.transitions?.RECONCILING ?? []) {
    if (!terminal.includes(to)) continue;
    const g = (def.guards ?? []).find((x) => x.from === 'RECONCILING' && x.to === to);
    if (!g || typeof g.precondition !== 'string' || g.precondition.trim() === '' || typeof g.evidence !== 'string' || g.evidence.trim() === '') {
      v.push(`RECONCILING->${to} has no guard`);
    }
  }
  return v;
}

const EXPOSED_STATES = ['PARTIALLY_FILLED', 'FILLED', 'PROTECTING', 'MONITORING', 'EXIT_REQUESTED', 'EXITING'];
const EXPIRY_CANCEL_TARGETS = ['EXPIRED', 'CANCELED', 'SUPERSEDED', 'REJECTED'];

/** Invariant 36: no expiry/cancel edge leaves a position-exposed state, so protective exits are never canceled by expiry. @returns {string[]} violations */
export function checkProtectiveExitInvariant(def) {
  const v = [];
  const inv = def?.protective_exit_invariant;
  if (!inv || JSON.stringify([...(inv.exposed_states ?? [])].sort()) !== JSON.stringify([...EXPOSED_STATES].sort())
    || JSON.stringify([...(inv.forbidden_targets ?? [])].sort()) !== JSON.stringify([...EXPIRY_CANCEL_TARGETS].sort())) {
    v.push('protective_exit_invariant must pin the exposed states and the expiry/cancel targets');
  }
  for (const from of EXPOSED_STATES) {
    const row = def?.transitions?.[from];
    if (!Array.isArray(row)) { v.push(`${from} has no transition row`); continue; }
    for (const to of row) if (EXPIRY_CANCEL_TARGETS.includes(to)) v.push(`${from}->${to} would let expiry or cancellation drop protective exits`);
  }
  return v;
}

function loadChecked(name, check, dir) {
  const m = loadMachine(name, dir);
  const v = check(m.def);
  if (v.length > 0) throw new Error(`${m.def.id}: invalid contract: ${v.join('; ')}`);
  return m;
}
export const loadRuntimeMachine = (dir) => loadChecked('runtime-state-machine', checkRuntimeContract, dir);
export const loadTradeIntentMachine = (dir) => loadChecked('trade-intent-state-machine', (def) => [...checkReconcilingGuards(def), ...checkProtectiveExitInvariant(def)], dir);

/** Machine-readable guard for an edge, or undefined. Guards are preconditions for the later runtime; they do not change isAllowedTransition. */
export function guardFor(machine, from, to) {
  return (machine.def.guards ?? []).find((g) => g.from === from && g.to === to);
}

function requireState(machine, s) {
  if (!machine.states.has(s)) throw new Error(`unknown state: ${String(s)}`);
}

export function isHumanGated(machine, from, to) {
  return (machine.def.human_gated_transitions ?? []).some((g) => g.from === from && g.to === to);
}

/**
 * Human-gated edges are denied unless ctx.humanAuthorized === true (strictly boolean true).
 * Unknown states throw. Undefined edges are denied.
 */
export function isAllowedTransition(machine, from, to, ctx = {}) {
  requireState(machine, from);
  requireState(machine, to);
  if (!machine.def.transitions[from].includes(to)) return false;
  if (isHumanGated(machine, from, to)) return ctx?.humanAuthorized === true;
  return true;
}

/** True only for states listed in the contract (runtime: ARMED only). Unknown states throw. */
export function exposureIncreaseAllowed(machine, state) {
  requireState(machine, state);
  return (machine.def.exposure_increase_allowed_states ?? []).includes(state);
}
