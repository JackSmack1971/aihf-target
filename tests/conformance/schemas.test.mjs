import test from 'node:test';
import assert from 'node:assert/strict';
import { validate, assertSchemaSupported } from '../../src/contracts/schema-validator.mjs';
import { schema, readJson, validIntent, validPermit, validRiskPolicy, clone } from '../helpers.mjs';

for (const n of ['trade-intent', 'execution-permit', 'risk-policy', 'signer-policy', 'permit-policy']) {
  test(`schema ${n} uses only supported keywords and is closed`, () => {
    const s = schema(n);
    assertSchemaSupported(s);
    assert.equal(s.additionalProperties, false);
  });
}

test('positive: valid TradeIntent passes', () => {
  const r = validate(schema('trade-intent'), validIntent());
  assert.deepEqual(r.errors, []);
  assert.ok(r.valid);
});
test('positive: valid ExecutionPermit passes (both order types, reduce-only variant)', () => {
  const s = schema('execution-permit');
  assert.ok(validate(s, validPermit()).valid);
  const p = clone(validPermit());
  p.side = 'sell'; p.effect = 'reduce'; p.reduce_only = true; p.allowed_order_types = ['limit_ioc'];
  p.price_constraint = { kind: 'limit_floor', min_price: '90000' };
  assert.deepEqual(validate(s, p).errors, []);
});
test('positive: fixture RiskPolicy passes', () => {
  assert.deepEqual(validate(schema('risk-policy'), validRiskPolicy()).errors, []);
});
test('positive: shipped signer policy passes', () => {
  assert.deepEqual(validate(schema('signer-policy'), readJson('config', 'signer-policy.json')).errors, []);
});
test('negative control: wrong types and malformed timestamps/decimals are rejected', () => {
  const i = clone(validIntent());
  i.created_at = 'yesterday';
  i.risk.max_loss_usd = '-5';
  i.evidence_refs = [];
  const r = validate(schema('trade-intent'), i);
  assert.ok(!r.valid);
  assert.ok(r.errors.length >= 3, r.errors.join('; '));
});
