import test from 'node:test';
import assert from 'node:assert/strict';
import { validate } from '../../src/contracts/schema-validator.mjs';
import { schema, readJson, clone, denyTest, validRiskPolicy, NUMERIC_LIMITS } from '../helpers.mjs';

const S = () => schema('risk-policy');
const BLUEPRINT_NUMERICS = ['max_order_notional_pct_nav', 'max_position_notional_pct_nav', 'max_gross_notional_pct_nav', 'max_net_notional_pct_nav',
  'max_position_leverage', 'max_margin_utilization_pct', 'max_loss_at_invalidation_pct_nav', 'max_strategy_daily_loss_pct_nav',
  'max_fund_daily_drawdown_pct_nav', 'max_concurrent_positions', 'max_correlated_cluster_pct_nav', 'min_liquidation_buffer_bps', 'max_spread_bps',
  'max_book_impact_bps', 'max_entry_slippage_bps', 'max_data_staleness_ms', 'max_clock_skew_ms', 'protection_gap_ms', 'min_emergency_rate_limit_reserve'];

test('template carries every section 18 numeric field, all null, and the fixed flags', () => {
  const t = readJson('config', 'risk-policy.template.json');
  assert.deepEqual([...NUMERIC_LIMITS].sort(), [...BLUEPRINT_NUMERICS].sort());
  for (const k of BLUEPRINT_NUMERICS) assert.equal(t[k], null, k);
  assert.equal(t.allow_market_entry_orders, false);
  assert.equal(t.allow_protective_emergency_orders, true);
  assert.equal(t.allow_withdrawals, false);
  assert.equal(t.allow_transfers, false);
  assert.equal(t.allow_unlisted_assets, false);
  assert.equal(t.allow_third_party_capital, false);
});

denyTest('DENY-POLICY-UNSET-LIMITS', () => {
  assert.ok(validate(S(), validRiskPolicy()).valid, 'positive control');
  const r = validate(S(), readJson('config', 'risk-policy.template.json'));
  assert.ok(!r.valid, 'null template must fail activation validation');
  assert.ok(r.errors.length >= BLUEPRINT_NUMERICS.length);
  for (const k of BLUEPRINT_NUMERICS) {
    const m = clone(validRiskPolicy()); delete m[k];
    assert.ok(!validate(S(), m).valid, `missing ${k}`);
    const n = clone(validRiskPolicy()); n[k] = null;
    assert.ok(!validate(S(), n).valid, `null ${k}`);
    const z = clone(validRiskPolicy()); z[k] = 0;
    assert.ok(!validate(S(), z).valid, `zero ${k}`);
    const neg = clone(validRiskPolicy()); neg[k] = -1;
    assert.ok(!validate(S(), neg).valid, `negative ${k}`);
    const str = clone(validRiskPolicy()); str[k] = '5';
    assert.ok(!validate(S(), str).valid, `string ${k}`);
  }
  const frac = clone(validRiskPolicy()); frac.max_concurrent_positions = 1.5;
  assert.ok(!validate(S(), frac).valid, 'non-integer position count');
});

function flagDenied(flag, bad) {
  assert.ok(validate(S(), validRiskPolicy()).valid, 'positive control');
  const p = clone(validRiskPolicy()); p[flag] = bad;
  assert.ok(!validate(S(), p).valid, `${flag}=${bad} must be rejected`);
  const m = clone(validRiskPolicy()); delete m[flag];
  assert.ok(!validate(S(), m).valid, `${flag} must be required`);
  const s = clone(validRiskPolicy()); s[flag] = String(bad);
  assert.ok(!validate(S(), s).valid, `${flag} as string must be rejected`);
}
denyTest('DENY-POLICY-WITHDRAWALS', () => flagDenied('allow_withdrawals', true));
denyTest('DENY-POLICY-TRANSFERS', () => flagDenied('allow_transfers', true));
denyTest('DENY-POLICY-THIRD-PARTY-CAPITAL', () => flagDenied('allow_third_party_capital', true));
denyTest('DENY-POLICY-MARKET-ENTRY-ORDERS', () => flagDenied('allow_market_entry_orders', true));
denyTest('DENY-POLICY-UNLISTED-ASSETS', () => flagDenied('allow_unlisted_assets', true));
denyTest('DENY-POLICY-EMERGENCY-PROTECTION-DISABLED', () => flagDenied('allow_protective_emergency_orders', false));

test('risk policy rejects unknown fields', () => {
  const p = clone(validRiskPolicy()); p.allow_leverage_updates = true;
  assert.ok(!validate(S(), p).valid);
});
