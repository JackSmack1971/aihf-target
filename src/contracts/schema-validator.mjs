// Minimal, fail-closed JSON-Schema-subset validator. Zero dependencies.
// Any schema keyword outside the supported set THROWS (never silently ignored).

const METADATA = new Set(['$schema', '$id', '$comment', 'title', 'description']);
const KEYWORDS = new Set([
  '$defs', '$ref', 'type', 'required', 'properties', 'additionalProperties', 'enum', 'const',
  'pattern', 'items', 'minItems', 'maxItems', 'uniqueItems', 'minLength', 'maxLength', 'minimum', 'maximum', 'exclusiveMinimum',
  'oneOf',
]);
const TYPES = new Set(['object', 'array', 'string', 'number', 'integer', 'boolean', 'null']);

export class SchemaError extends Error {}

function isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function typeMatches(t, v) {
  switch (t) {
    case 'object': return isPlainObject(v);
    case 'array': return Array.isArray(v);
    case 'string': return typeof v === 'string';
    case 'number': return typeof v === 'number' && Number.isFinite(v);
    case 'integer': return typeof v === 'number' && Number.isInteger(v);
    case 'boolean': return typeof v === 'boolean';
    case 'null': return v === null;
    default: throw new SchemaError(`unsupported type: ${t}`);
  }
}

function deepEqual(a, b) {
  return JSON.stringify(canon(a)) === JSON.stringify(canon(b));
}
function canon(v) {
  if (Array.isArray(v)) return v.map(canon);
  if (isPlainObject(v)) return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])]));
  return v;
}

/** Throws SchemaError if the schema uses anything unsupported. */
export function assertSchemaSupported(schema, root = schema, path = '#') {
  if (!isPlainObject(schema)) throw new SchemaError(`${path}: schema must be an object`);
  for (const key of Object.keys(schema)) {
    if (METADATA.has(key)) continue;
    if (!KEYWORDS.has(key)) throw new SchemaError(`${path}: unsupported keyword "${key}"`);
  }
  if ('$ref' in schema) {
    const extra = Object.keys(schema).filter((k) => !METADATA.has(k) && k !== '$ref');
    if (extra.length) throw new SchemaError(`${path}: $ref may not have sibling keyword(s): ${extra.join(', ')}`);
    resolveRef(schema.$ref, root);
  }
  if ('type' in schema) {
    const ts = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (ts.length === 0) throw new SchemaError(`${path}: empty type list`);
    for (const t of ts) if (!TYPES.has(t)) throw new SchemaError(`${path}: unsupported type "${t}"`);
  }
  if ('required' in schema && !(Array.isArray(schema.required) && schema.required.every((r) => typeof r === 'string'))) {
    throw new SchemaError(`${path}: required must be an array of strings`);
  }
  if ('enum' in schema && !Array.isArray(schema.enum)) throw new SchemaError(`${path}: enum must be an array`);
  if ('pattern' in schema) {
    if (typeof schema.pattern !== 'string') throw new SchemaError(`${path}: pattern must be a string`);
    new RegExp(schema.pattern, 'u');
  }
  if ('additionalProperties' in schema && typeof schema.additionalProperties !== 'boolean') {
    throw new SchemaError(`${path}: additionalProperties must be a boolean`);
  }
  if ('uniqueItems' in schema && typeof schema.uniqueItems !== 'boolean') {
    throw new SchemaError(`${path}: uniqueItems must be a boolean`);
  }
  for (const k of ['minItems', 'maxItems', 'minLength', 'maxLength', 'minimum', 'maximum', 'exclusiveMinimum']) {
    if (k in schema && typeof schema[k] !== 'number') throw new SchemaError(`${path}: ${k} must be a number`);
  }
  if ('properties' in schema) {
    if (!isPlainObject(schema.properties)) throw new SchemaError(`${path}: properties must be an object`);
    for (const [k, s] of Object.entries(schema.properties)) assertSchemaSupported(s, root, `${path}/properties/${k}`);
  }
  if ('items' in schema) assertSchemaSupported(schema.items, root, `${path}/items`);
  if ('oneOf' in schema) {
    if (!Array.isArray(schema.oneOf) || schema.oneOf.length < 2) throw new SchemaError(`${path}: oneOf must be an array of at least two schemas`);
    schema.oneOf.forEach((s, i) => assertSchemaSupported(s, root, `${path}/oneOf/${i}`));
  }
  if ('$defs' in schema) {
    if (!isPlainObject(schema.$defs)) throw new SchemaError(`${path}: $defs must be an object`);
    for (const [k, s] of Object.entries(schema.$defs)) assertSchemaSupported(s, root, `${path}/$defs/${k}`);
  }
}

function resolveRef(ref, root) {
  const m = /^#\/\$defs\/([A-Za-z0-9_-]+)$/.exec(ref);
  if (!m) throw new SchemaError(`unsupported $ref (only local #/$defs/<name>): ${ref}`);
  const target = root.$defs && root.$defs[m[1]];
  if (!target) throw new SchemaError(`unresolved $ref: ${ref}`);
  return target;
}

function check(schema, data, root, path, errors) {
  if ('$ref' in schema) return check(resolveRef(schema.$ref, root), data, root, path, errors);
  if ('oneOf' in schema) {
    // Exactly one branch must match; zero or several fails closed.
    const matching = schema.oneOf.filter((b) => {
      const e = [];
      check(b, data, root, path, e);
      return e.length === 0;
    }).length;
    if (matching !== 1) errors.push(`${path}: oneOf requires exactly one matching branch (matched ${matching})`);
  }
  if ('type' in schema) {
    const ts = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!ts.some((t) => typeMatches(t, data))) {
      errors.push(`${path}: expected type ${ts.join('|')}`);
      return;
    }
  }
  if ('const' in schema && !deepEqual(schema.const, data)) errors.push(`${path}: must equal ${JSON.stringify(schema.const)}`);
  if ('enum' in schema && !schema.enum.some((e) => deepEqual(e, data))) errors.push(`${path}: not in enum`);
  if (typeof data === 'string') {
    if ('pattern' in schema && !new RegExp(schema.pattern, 'u').test(data)) errors.push(`${path}: pattern mismatch`);
    if ('minLength' in schema && [...data].length < schema.minLength) errors.push(`${path}: shorter than minLength`);
    if ('maxLength' in schema && [...data].length > schema.maxLength) errors.push(`${path}: longer than maxLength`);
  }
  if (typeof data === 'number') {
    if ('minimum' in schema && !(data >= schema.minimum)) errors.push(`${path}: below minimum`);
    if ('exclusiveMinimum' in schema && !(data > schema.exclusiveMinimum)) errors.push(`${path}: not above exclusiveMinimum`);
    if ('maximum' in schema && !(data <= schema.maximum)) errors.push(`${path}: above maximum`);
  }
  if (Array.isArray(data)) {
    if ('minItems' in schema && data.length < schema.minItems) errors.push(`${path}: fewer than minItems`);
    if ('maxItems' in schema && data.length > schema.maxItems) errors.push(`${path}: more than maxItems`);
    if (schema.uniqueItems) {
      const seen = new Set(data.map((d) => JSON.stringify(canon(d))));
      if (seen.size !== data.length) errors.push(`${path}: items not unique`);
    }
    if ('items' in schema) data.forEach((d, i) => check(schema.items, d, root, `${path}/${i}`, errors));
  }
  if (isPlainObject(data)) {
    for (const r of schema.required ?? []) if (!Object.hasOwn(data, r)) errors.push(`${path}: missing required "${r}"`);
    const props = schema.properties ?? {};
    for (const [k, v] of Object.entries(data)) {
      if (Object.hasOwn(props, k)) check(props[k], v, root, `${path}/${k}`, errors);
      else if (schema.additionalProperties === false) errors.push(`${path}: unknown property "${k}"`);
    }
  }
}

/** @returns {{valid: boolean, errors: string[]}} Throws SchemaError for unsupported schemas. */
export function validate(schema, data) {
  assertSchemaSupported(schema);
  const errors = [];
  check(schema, data, schema, '#', errors);
  return { valid: errors.length === 0, errors };
}
