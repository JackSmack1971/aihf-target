import test from 'node:test';
import assert from 'node:assert/strict';
import { validate } from '../../src/contracts/schema-validator.mjs';
import { checkPermitConsistency, parseRfc3339 } from '../../src/contracts/permit-consistency.mjs';
import { schema, readJson, clone, denyTest, validIntent, validPermit } from '../helpers.mjs';

const intentSchema = () => schema('trade-intent');
const permitSchema = () => schema('execution-permit');

const LLM_FORBIDDEN = ['asset_index', 'nonce', 'cloid', 'raw_action', 'signature', 'final_size',
  'tick_size', 'lot_size', 'rounded_price', 'rounded_size', 'rounded_tick', 'rounded_lot'];

denyTest('DENY-INTENT-LLM-EXCHANGE-FIELDS', () => {
  const s = intentSchema();
  assert.ok(validate(s, validIntent()).valid, 'positive control');
  for (const f of LLM_FORBIDDEN) {
    assert.ok(!(f in s.properties), `${f} must not be a declared property`);
    const top = clone(validIntent()); top[f] = 'x';
    assert.ok(!validate(s, top).valid, `top-level ${f} must be rejected`);
    const nested = clone(validIntent()); nested.risk[f] = 'x';
    assert.ok(!validate(s, nested).valid, `nested ${f} must be rejected`);
    const ec = clone(validIntent()); ec.execution_constraints[f] = 'x';
    assert.ok(!validate(s, ec).valid, `execution_constraints.${f} must be rejected`);
  }
});

denyTest('DENY-INTENT-UNKNOWN-FIELD', () => {
  const s = intentSchema();
  const t = clone(validIntent()); t.surprise = 1;
  assert.ok(!validate(s, t).valid);
  for (const k of ['entry', 'invalidation', 'risk', 'execution_constraints']) {
    const n = clone(validIntent()); n[k].surprise = 1;
    assert.ok(!validate(s, n).valid, k);
  }
  const e = clone(validIntent()); e.exit_conditions = [{ kind: 'stop', surprise: 1 }];
  assert.ok(!validate(s, e).valid, 'exit_conditions item');
});

test('TradeIntent rejects market order types and missing required fields', () => {
  const s = intentSchema();
  const m = clone(validIntent()); m.execution_constraints.allowed_order_types = ['market'];
  assert.ok(!validate(s, m).valid);
  for (const k of s.required) {
    const t = clone(validIntent()); delete t[k];
    assert.ok(!validate(s, t).valid, `missing ${k}`);
  }
});

const PERMIT_REQUIRED = ['permit_id', 'trade_intent_id', 'strategy_id', 'strategy_version', 'account', 'instrument', 'side', 'effect',
  'max_total_size', 'max_notional_usd', 'price_constraint', 'max_slippage_bps', 'allowed_order_types', 'reduce_only', 'issued_at',
  'expires_at', 'policy_hash', 'activation_hash', 'single_use_nonce', 'authorization'];

denyTest('DENY-PERMIT-UNBOUNDED', () => {
  const s = permitSchema();
  assert.ok(validate(s, validPermit()).valid, 'positive control');
  for (const k of PERMIT_REQUIRED) assert.ok(s.required.includes(k), `schema must require ${k}`);
  for (const k of PERMIT_REQUIRED) {
    const p = clone(validPermit()); delete p[k];
    assert.ok(!validate(s, p).valid, `permit missing ${k} must be rejected`);
  }
  for (const k of ['expires_at', 'policy_hash', 'activation_hash', 'single_use_nonce', 'authorization', 'max_total_size', 'max_notional_usd']) {
    const p = clone(validPermit()); p[k] = null;
    assert.ok(!validate(s, p).valid, `null ${k} must be rejected`);
  }
  const bad = clone(validPermit()); bad.max_notional_usd = 'unlimited';
  assert.ok(!validate(s, bad).valid);
  const weak = clone(validPermit()); weak.single_use_nonce = 'short';
  assert.ok(!validate(s, weak).valid);
});

denyTest('DENY-PERMIT-MARKET-ORDER', () => {
  const s = permitSchema();
  const allowed = s.properties.allowed_order_types.items.enum;
  assert.deepEqual([...allowed].sort(), ['limit_gtc', 'limit_ioc']);
  for (const t of ['market', 'MARKET', 'market_ioc', 'stop_market', 'take_market', 'trigger']) {
    const p = clone(validPermit()); p.allowed_order_types = [t];
    assert.ok(!validate(s, p).valid, `${t} must be rejected`);
    const q = clone(validPermit()); q.allowed_order_types = ['limit_gtc', t];
    assert.ok(!validate(s, q).valid, `limit_gtc+${t} must be rejected`);
  }
  const empty = clone(validPermit()); empty.allowed_order_types = [];
  assert.ok(!validate(s, empty).valid);
});

denyTest('DENY-PERMIT-UNKNOWN-FIELD', () => {
  const s = permitSchema();
  for (const f of ['raw_action', 'signature', 'cloid', 'asset_index', 'extra']) {
    const p = clone(validPermit()); p[f] = 'x';
    assert.ok(!validate(s, p).valid, f);
  }
  const n = clone(validPermit()); n.price_constraint.extra = 1;
  assert.ok(!validate(s, n).valid);
});

// ---- B1: closed price bound ----
denyTest('DENY-PERMIT-PRICE-BOUND', () => {
  const s = permitSchema();
  assert.ok(validate(s, validPermit()).valid, 'positive control (cap)');
  const floor = clone(validPermit()); floor.side = 'sell'; floor.price_constraint = { kind: 'limit_floor', min_price: '90000' };
  assert.ok(validate(s, floor).valid, 'positive control (floor)');
  for (const bad of [
    { kind: 'limit_cap' }, { kind: 'limit_floor' }, {}, { kind: 'limit_cap', min_price: '1' }, { kind: 'limit_floor', max_price: '1' },
    { kind: 'limit_cap', max_price: '1', min_price: '1' }, { kind: 'limit_floor', max_price: '1', min_price: '1' },
    { kind: 'limit_cap', max_price: '1', extra: 1 }, { kind: 'market', max_price: '1' }, { kind: 'limit_cap', max_price: 'abc' }, { kind: 'limit_cap', max_price: null },
  ]) {
    const p = clone(validPermit()); p.price_constraint = bad;
    assert.ok(!validate(s, p).valid, JSON.stringify(bad));
  }
  const none = clone(validPermit()); delete none.price_constraint;
  assert.ok(!validate(s, none).valid);
});

const POLICY = { maxPermitTtlMs: 120000 }; // FIXTURE ceiling for tests only; the real value is a REQUIRED unset policy input
const withPermit = (f) => { const p = clone(validPermit()); f(p); return p; };

denyTest('DENY-PERMIT-INCONSISTENT', () => {
  const s = permitSchema();
  assert.deepEqual(checkPermitConsistency(validPermit(), POLICY).violations, [], 'positive control');
  const sellOk = withPermit((p) => { p.side = 'sell'; p.price_constraint = { kind: 'limit_floor', min_price: '9' }; });
  assert.ok(checkPermitConsistency(sellOk, POLICY).ok);
  const cases = {
    'buy + limit_floor': withPermit((p) => { p.price_constraint = { kind: 'limit_floor', min_price: '1' }; }),
    'sell + limit_cap': withPermit((p) => { p.side = 'sell'; }),
    'reduce without reduce_only': withPermit((p) => { p.effect = 'reduce'; p.reduce_only = false; }),
    'increase with reduce_only': withPermit((p) => { p.reduce_only = true; }),
  };
  for (const [name, p] of Object.entries(cases)) {
    assert.ok(validate(s, p).valid, `${name}: schema alone cannot catch this`);
    assert.ok(!checkPermitConsistency(p, POLICY).ok, `${name} must be rejected by the consistency check`);
  }
  assert.ok(!checkPermitConsistency({}, POLICY).ok);
  assert.ok(!checkPermitConsistency(null, POLICY).ok);
});

denyTest('DENY-PERMIT-WINDOW', () => {
  const s = permitSchema();
  const missing = withPermit((p) => { delete p.issued_at; });
  assert.ok(!validate(s, missing).valid, 'schema requires issued_at');
  assert.ok(!checkPermitConsistency(missing, POLICY).ok, 'checker also rejects');
  const bad = {
    'expires equals issued': withPermit((p) => { p.expires_at = p.issued_at; }),
    'inverted window': withPermit((p) => { p.expires_at = '2026-10-06T11:59:00Z'; }),
    'lifetime above ceiling': withPermit((p) => { p.expires_at = '2026-10-06T12:02:00.001Z'; }),
    'month 99': withPermit((p) => { p.issued_at = '2026-99-06T12:00:00Z'; }),
    'feb 30': withPermit((p) => { p.expires_at = '2026-02-30T12:00:00Z'; }),
    'hour 24': withPermit((p) => { p.expires_at = '2026-10-06T24:00:00Z'; }),
    'second 60': withPermit((p) => { p.expires_at = '2026-10-06T12:00:60Z'; }),
    'offset 99:00': withPermit((p) => { p.expires_at = '2026-10-06T12:01:00+99:00'; }),
    'not a date': withPermit((p) => { p.expires_at = 'tomorrow'; }),
  };
  for (const [name, p] of Object.entries(bad)) assert.ok(!checkPermitConsistency(p, POLICY).ok, name);
  assert.ok(validate(s, bad['month 99']).valid, 'pattern-only schema accepts month 99; checker is the strict gate');
  assert.ok(checkPermitConsistency(withPermit((p) => { p.expires_at = '2026-10-06T12:02:00Z'; }), POLICY).ok, 'exactly at ceiling is allowed');
  assert.ok(checkPermitConsistency(withPermit((p) => { p.issued_at = '2028-02-29T12:00:00Z'; p.expires_at = '2028-02-29T12:01:00Z'; }), POLICY).ok, 'leap day');
  assert.equal(parseRfc3339('2026-10-06T14:00:00+02:00'), parseRfc3339('2026-10-06T12:00:00Z'));
  assert.equal(parseRfc3339('2026-02-29T00:00:00Z'), null);
});

denyTest('DENY-PERMIT-TTL-UNSET', () => {
  const ps = schema('permit-policy');
  const tpl = readJson('config', 'permit-policy.template.json');
  assert.equal(tpl.max_permit_ttl_ms, null);
  assert.ok(!validate(ps, tpl).valid, 'null template must fail activation validation');
  assert.ok(validate(ps, { max_permit_ttl_ms: 1 }).valid, 'positive control');
  for (const bad of [{}, { max_permit_ttl_ms: 0 }, { max_permit_ttl_ms: -5 }, { max_permit_ttl_ms: '60000' }, { max_permit_ttl_ms: 1, extra: 1 }]) assert.ok(!validate(ps, bad).valid, JSON.stringify(bad));
  for (const c of [undefined, null, 0, -1, NaN, Infinity, '60000']) {
    const r = checkPermitConsistency(validPermit(), { maxPermitTtlMs: c });
    assert.ok(!r.ok && r.violations.some((x) => /TTL ceiling is unset/.test(x)), String(c));
  }
  assert.ok(!checkPermitConsistency(validPermit(), undefined).ok);
});

// ---- S8/S9: structural size bounds ----
denyTest('DENY-INPUT-SIZE-BOUNDS', () => {
  const is = intentSchema(); const ps = permitSchema();
  const intentCase = (f) => { const i = clone(validIntent()); f(i); return i; };
  assert.ok(validate(is, intentCase((i) => { i.thesis = 'x'.repeat(4000); })).valid, 'boundary control');
  const badIntents = {
    thesis: intentCase((i) => { i.thesis = 'x'.repeat(4001); }),
    'evidence_refs count': intentCase((i) => { i.evidence_refs = Array.from({ length: 65 }, (_, n) => `e${n}`); }),
    'evidence_ref length': intentCase((i) => { i.evidence_refs = ['x'.repeat(513)]; }),
    'exit_conditions count': intentCase((i) => { i.exit_conditions = Array.from({ length: 33 }, () => ({ kind: 'k' })); }),
    'exit kind length': intentCase((i) => { i.exit_conditions = [{ kind: 'k'.repeat(65) }]; }),
    'exit description length': intentCase((i) => { i.exit_conditions = [{ kind: 'k', description: 'd'.repeat(1001) }]; }),
    'strategy_id length': intentCase((i) => { i.strategy_id = 's'.repeat(129); }),
    'trade_intent_id length': intentCase((i) => { i.trade_intent_id = `TI-20261006-000017${'0'.repeat(200)}`; }),
    'decimal length': intentCase((i) => { i.risk.max_loss_usd = '1'.repeat(41); }),
    'slippage above structural max': intentCase((i) => { i.execution_constraints.max_slippage_bps = 10001; }),
  };
  for (const [n, i] of Object.entries(badIntents)) assert.ok(!validate(is, i).valid, n);
  assert.ok(validate(is, intentCase((i) => { i.execution_constraints.max_slippage_bps = 10000; })).valid, 'structural max itself is allowed');
  const badPermits = {
    slippage: withPermit((p) => { p.max_slippage_bps = 10001; }),
    account: withPermit((p) => { p.account = 'a'.repeat(129); }),
    instrument: withPermit((p) => { p.instrument = 'a'.repeat(129); }),
    authorization: withPermit((p) => { p.authorization = 'a'.repeat(513); }),
    nonce: withPermit((p) => { p.single_use_nonce = 'n'.repeat(257); }),
    size: withPermit((p) => { p.max_total_size = '1'.repeat(41); }),
  };
  for (const [n, p] of Object.entries(badPermits)) assert.ok(!validate(ps, p).valid, `permit ${n}`);
  assert.match(ps.properties.max_slippage_bps.description, /structural bound, not a trading default/);
});
