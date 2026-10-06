import test from 'node:test';
import assert from 'node:assert/strict';
import { validate, assertSchemaSupported, SchemaError } from '../../src/contracts/schema-validator.mjs';
import { denyTest } from '../helpers.mjs';

denyTest('DENY-VALIDATOR-UNKNOWN-KEYWORD', () => {
  for (const kw of ['anyOf', 'allOf', 'not', 'if', 'patternProperties', 'format', 'exclusiveMaximum', 'minProperties', 'maxProperties', 'multipleOf', 'contains', 'dependentRequired', 'x-custom']) {
    assert.throws(() => validate({ type: 'string', [kw]: [] }, 'x'), SchemaError, kw);
    assert.throws(() => validate({ type: 'object', properties: { a: { [kw]: 1 } } }, {}), SchemaError, `nested ${kw}`);
    assert.throws(() => validate({ type: 'object', $defs: { d: { [kw]: 1 } } }, {}), SchemaError, `$defs ${kw}`);
    assert.throws(() => validate({ type: 'array', items: { [kw]: 1 } }, []), SchemaError, `items ${kw}`);
  }
  assert.ok(validate({ type: 'string', title: 'ok', description: 'metadata is permitted' }, 'x').valid, 'positive control');
  assert.throws(() => validate({ type: 'banana' }, 1), SchemaError);
  assert.throws(() => validate({ $ref: 'http://example.com/s' }, 1), SchemaError);
  assert.throws(() => validate({ $ref: '#/$defs/missing' }, 1), SchemaError);
  assert.throws(() => validate({ type: 'object', additionalProperties: { type: 'string' } }, {}), SchemaError);
  assert.throws(() => validate({ $defs: { a: { type: 'string' } }, $ref: '#/$defs/a', minLength: 1 }, 'x'), SchemaError);
  assert.throws(() => validate({ pattern: '(' }, 'x'));
  assert.throws(() => assertSchemaSupported(null), SchemaError);
});

test('validator semantics: type, required, enum, const, pattern, items, bounds, uniqueness, $ref', () => {
  const s = { $defs: { id: { type: 'string', pattern: '^[a-z]+$', minLength: 2 } }, type: 'object', additionalProperties: false, required: ['a'],
    properties: { a: { $ref: '#/$defs/id' }, n: { type: ['number', 'null'], minimum: 0 }, i: { type: 'integer', exclusiveMinimum: 0 }, c: { const: 'k' },
      e: { enum: ['x', 'y'] }, l: { type: 'array', minItems: 1, maxItems: 2, uniqueItems: true, items: { type: 'string' } } } };
  assert.ok(validate(s, { a: 'ab', n: null, i: 1, c: 'k', e: 'x', l: ['p'] }).valid);
  for (const bad of [{}, { a: 'A' }, { a: 'a' }, { a: 'ab', z: 1 }, { a: 'ab', n: -1 }, { a: 'ab', i: 0 }, { a: 'ab', i: 1.5 }, { a: 'ab', c: 'j' },
    { a: 'ab', e: 'z' }, { a: 'ab', l: [] }, { a: 'ab', l: ['a', 'b', 'c'] }, { a: 'ab', l: ['a', 'a'] }, { a: 'ab', l: [1] }, 'str', [], null]) {
    assert.ok(!validate(s, bad).valid, JSON.stringify(bad));
  }
  assert.ok(!validate({ type: 'number' }, NaN).valid);
  assert.ok(!validate({ type: 'number' }, '1').valid);
  assert.ok(!validate({ type: 'object' }, []).valid);
  assert.ok(validate({ const: { a: 1, b: 2 } }, { b: 2, a: 1 }).valid);
});

test('oneOf is fail-closed: exactly one branch must match', () => {
  const s = { oneOf: [{ type: 'object', additionalProperties: false, required: ['a'], properties: { a: { type: 'string' } } },
    { type: 'object', additionalProperties: false, required: ['b'], properties: { b: { type: 'string' } } }] };
  assert.ok(validate(s, { a: 'x' }).valid);
  assert.ok(validate(s, { b: 'x' }).valid);
  assert.ok(!validate(s, {}).valid, 'zero branches match');
  assert.ok(!validate(s, { a: 'x', b: 'y' }).valid, 'no branch matches a mixed object (closed branches)');
  const overlap = { oneOf: [{ type: 'string' }, { type: 'string', minLength: 1 }] };
  assert.ok(!validate(overlap, 'x').valid, 'two branches match -> rejected');
  assert.ok(validate(overlap, '').valid, 'exactly one branch matches');
  assert.throws(() => validate({ oneOf: [] }, 1), SchemaError);
  assert.throws(() => validate({ oneOf: [{ type: 'string' }] }, 'x'), SchemaError, 'single-branch oneOf is suspicious');
  assert.throws(() => validate({ oneOf: [{ type: 'string' }, { bogus: 1 }] }, 'x'), SchemaError, 'unknown keyword inside a branch');
  assert.throws(() => validate({ oneOf: 'x' }, 'x'), SchemaError);
});

test('maximum, maxLength and maxItems are enforced', () => {
  assert.ok(validate({ type: 'number', maximum: 5 }, 5).valid);
  assert.ok(!validate({ type: 'number', maximum: 5 }, 5.01).valid);
  assert.ok(validate({ type: 'string', maxLength: 2 }, 'ab').valid);
  assert.ok(!validate({ type: 'string', maxLength: 2 }, 'abc').valid);
  assert.ok(validate({ type: 'array', maxItems: 1 }, [1]).valid);
  assert.ok(!validate({ type: 'array', maxItems: 1 }, [1, 2]).valid);
  assert.throws(() => validate({ type: 'number', maximum: '5' }, 1), SchemaError);
  assert.throws(() => validate({ type: 'string', maxLength: 'x' }, 'a'), SchemaError);
});
