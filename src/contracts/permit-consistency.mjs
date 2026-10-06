// Deterministic cross-field checks for an ExecutionPermit that the schema subset cannot express.
// Fails closed: any missing/invalid input produces a violation.

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|([+-])(\d{2}):(\d{2}))$/;

function daysInMonth(y, m) {
  if (m === 2) return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 29 : 28;
  return [4, 6, 9, 11].includes(m) ? 30 : 31;
}

/** Strict RFC 3339 date-time parser. Returns epoch milliseconds or null when invalid. */
export function parseRfc3339(s) {
  if (typeof s !== 'string') return null;
  const m = RFC3339.exec(s);
  if (!m) return null;
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number);
  if (mo < 1 || mo > 12 || d < 1 || d > daysInMonth(y, mo) || h > 23 || mi > 59 || se > 59) return null;
  let offsetMin = 0;
  if (m[8] !== 'Z') {
    const oh = Number(m[10]);
    const om = Number(m[11]);
    if (oh > 23 || om > 59) return null;
    offsetMin = (m[9] === '-' ? -1 : 1) * (oh * 60 + om);
  }
  const frac = m[7] ? Math.floor(Number(`0${m[7]}`) * 1000) : 0;
  return Date.UTC(y, mo - 1, d, h, mi, se, frac) - offsetMin * 60000;
}

/**
 * @param {object} permit schema-valid permit
 * @param {{maxPermitTtlMs: number|null|undefined}} policy REQUIRED policy input; null/absent fails closed
 * @returns {{ok: boolean, violations: string[]}}
 */
export function checkPermitConsistency(permit, policy) {
  const v = [];
  const pc = permit?.price_constraint;
  if (permit?.side === 'buy') {
    if (pc?.kind !== 'limit_cap') v.push('buy permit requires price_constraint.kind limit_cap');
  } else if (permit?.side === 'sell') {
    if (pc?.kind !== 'limit_floor') v.push('sell permit requires price_constraint.kind limit_floor');
  } else v.push('side must be buy or sell');
  if (pc?.kind === 'limit_cap' && typeof pc.max_price !== 'string') v.push('limit_cap requires max_price');
  if (pc?.kind === 'limit_floor' && typeof pc.min_price !== 'string') v.push('limit_floor requires min_price');
  if (pc?.kind === 'limit_cap' && 'min_price' in pc) v.push('limit_cap must not carry min_price');
  if (pc?.kind === 'limit_floor' && 'max_price' in pc) v.push('limit_floor must not carry max_price');

  if (permit?.effect === 'reduce') {
    if (permit.reduce_only !== true) v.push('effect reduce requires reduce_only true');
  } else if (permit?.effect !== 'increase') v.push('effect must be increase or reduce');
  else if (permit.reduce_only !== false) v.push('effect increase requires reduce_only false');

  const issued = parseRfc3339(permit?.issued_at);
  const expires = parseRfc3339(permit?.expires_at);
  if (issued === null) v.push('issued_at missing or not a valid RFC 3339 date-time');
  if (expires === null) v.push('expires_at missing or not a valid RFC 3339 date-time');
  const ceiling = policy?.maxPermitTtlMs;
  const ceilingOk = typeof ceiling === 'number' && Number.isFinite(ceiling) && ceiling > 0;
  if (!ceilingOk) v.push('permit TTL ceiling is unset (REQUIRED policy input); failing closed');
  if (issued !== null && expires !== null) {
    if (expires <= issued) v.push('expires_at must be after issued_at');
    else if (ceilingOk && expires - issued > ceiling) v.push('permit lifetime exceeds TTL ceiling');
  }
  return { ok: v.length === 0, violations: v };
}
