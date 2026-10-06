// Pinned-denial check for the signer policy. The required denial set lives in
// contracts/signer-denied-actions.json (not in src) so that src carries no action identifiers.
import fs from 'node:fs';

const REQUIRED_FILE = new URL('../../contracts/signer-denied-actions.json', import.meta.url);

/** Validates a parsed sidecar document; throws when the required set is missing, not an array, empty, or holds a non-string/empty entry. */
export function parseRequiredDenials(doc) {
  const list = doc?.required;
  if (!Array.isArray(list) || list.length === 0 || !list.every((r) => typeof r === 'string' && r.length > 0)) throw new Error('required denial set is empty or malformed');
  return list;
}

export function loadRequiredDenials() {
  return parseRequiredDenials(JSON.parse(fs.readFileSync(REQUIRED_FILE, 'utf8')));
}

/** Fails closed when `required` is empty, not an array, or malformed (only an omitted argument loads the pinned file). @returns {{ok: boolean, violations: string[]}} */
export function checkSignerPolicy(policy, required = loadRequiredDenials()) {
  const v = [];
  if (!Array.isArray(required) || required.length === 0 || !required.every((r) => typeof r === 'string' && r.length > 0)) {
    return { ok: false, violations: ['required denial set is empty, missing or malformed'] };
  }
  const denied = Array.isArray(policy?.denied_actions) ? policy.denied_actions : [];
  const allowed = Array.isArray(policy?.allowed_request_types) ? policy.allowed_request_types : [];
  for (const r of required) if (!denied.includes(r)) v.push(`denied_actions is missing required entry ${r}`);
  const deniedLower = new Set(denied.map((d) => String(d).toLowerCase()));
  for (const a of allowed) if (deniedLower.has(String(a).toLowerCase())) v.push(`${a} is both allowed and denied`);
  return { ok: v.length === 0, violations: v };
}
