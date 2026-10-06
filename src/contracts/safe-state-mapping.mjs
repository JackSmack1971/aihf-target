// Section 31 checker: every threat safe state maps to defined runtime states, none of which permits exposure increase.
import { exposureIncreaseAllowed } from './state-machine.mjs';

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const nonEmpty = (s) => typeof s === 'string' && s.trim().length > 0;

/**
 * @param {object} mapping   threat-model safe_state_runtime_mapping
 * @param {{states:Set<string>, def:object}} runtimeMachine  a loaded runtime machine
 * @param {string[]} safeStates  the enumerated safe states (threat-model safe_states)
 * @param {{id:string, expected_safe_state:string}[]} [threats]  optional: each threat must name a mapped safe state
 * @returns {{ok:boolean, violations:string[]}}
 */
export function checkSafeStateMapping(mapping, runtimeMachine, safeStates, threats = []) {
  const v = [];
  if (!isObj(mapping)) return { ok: false, violations: ['mapping is not an object'] };
  if (!Array.isArray(safeStates) || safeStates.length === 0) return { ok: false, violations: ['safe state list is empty or missing'] };
  const keys = Object.keys(mapping);
  for (const s of safeStates) if (!keys.includes(s)) v.push(`safe state ${s} is unmapped`);
  for (const k of keys) if (!safeStates.includes(k)) v.push(`mapping has unknown safe state ${k}`);
  for (const [state, e] of Object.entries(mapping)) {
    if (!isObj(e) || !Array.isArray(e.runtime_states)) { v.push(`${state}: runtime_states missing`); continue; }
    for (const rs of e.runtime_states) {
      if (typeof rs !== 'string' || !runtimeMachine.states.has(rs)) v.push(`${state}: undefined runtime state ${String(rs)}`);
      else if (rs === 'ARMED' || exposureIncreaseAllowed(runtimeMachine, rs)) v.push(`${state}: maps to ${rs}, which permits exposure increase`);
    }
    if (e.exposure_increase_allowed !== false) v.push(`${state}: exposure_increase_allowed must be false`);
    if (!nonEmpty(e.runtime_effect) || !nonEmpty(e.intent_effect) || !nonEmpty(e.description)) v.push(`${state}: runtime_effect, intent_effect and description are required`);
    if (e.runtime_states.length === 0 && e.runtime_effect !== 'NO_STATE_CHANGE') v.push(`${state}: empty runtime_states requires NO_STATE_CHANGE`);
  }
  for (const t of threats) {
    if (!safeStates.includes(t?.expected_safe_state) || !Object.hasOwn(mapping, t.expected_safe_state)) v.push(`${t?.id}: expected_safe_state ${String(t?.expected_safe_state)} is not a mapped safe state`);
  }
  return { ok: v.length === 0, violations: v };
}
