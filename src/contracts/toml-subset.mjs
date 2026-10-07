// Strict, zero-dependency TOML subset parser for reviewed Codex configuration artifacts.
// Supported: comments, [tables], dotted/quoted keys, basic/literal/multi-line strings, integers, booleans, arrays, single-line inline tables.
// Everything else (floats, dates, [[array tables]], duplicate keys, redefined tables, control characters) throws: unsupported syntax fails closed.

export class TomlError extends Error {}

const BAD_KEYS = new Set([['__pro', 'to__'].join(''), 'constructor', 'prototype']);
const ESCAPES = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', '"': '"', '\\': '\\' };
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const DOT = String.fromCharCode(46);

export function parseToml(input) {
  if (typeof input !== 'string') throw new TomlError('input must be a string');
  // A byte-order mark (e.g. from Windows PowerShell 5.1 Out-File) is rejected: how each TOML consumer treats it is not provable, so fail closed.
  if (input.charCodeAt(0) === 0xfeff) throw new TomlError('byte-order mark is not allowed');
  const s = input;
  const n = s.length;
  let i = 0;
  const root = {};
  const explicit = new WeakSet(); // tables opened by a [header]
  const closed = new WeakSet(); // tables made by dotted keys or inline tables: may not be reopened by a header
  const inline = new WeakSet(); // inline tables: fully self-contained, never extended

  const fail = (msg) => {
    const line = s.slice(0, i).split('\n').length;
    throw new TomlError(`line ${line}: ${msg}`);
  };
  const peek = (k = 0) => s[i + k];
  const isWs = (c) => c === ' ' || c === '\t';
  const skipWs = () => { while (i < n && isWs(s[i])) i++; };
  const skipComment = () => {
    if (s[i] === '#') {
      while (i < n && s[i] !== '\n') {
        const c = s.charCodeAt(i);
        if ((c < 0x20 && c !== 0x09 && c !== 0x0d) || c === 0x7f) fail('control character in comment');
        i++;
      }
    }
  };
  const skipBlank = () => {
    for (;;) {
      skipWs();
      if (s[i] === '#') skipComment();
      if (s[i] === '\r' && s[i + 1] === '\n') i++;
      if (s[i] === '\n') { i++; continue; }
      if (i >= n || (s[i] !== ' ' && s[i] !== '\t' && s[i] !== '#')) return;
    }
  };
  const endOfLine = () => {
    skipWs();
    if (s[i] === '#') skipComment();
    if (i >= n) return;
    if (s[i] === '\r' && s[i + 1] === '\n') i++;
    if (s[i] !== '\n') fail('expected end of line');
    i++;
  };
  const checkKey = (k) => { if (BAD_KEYS.has(k)) fail(`forbidden key ${k}`); return k; };

  function readBasicString(multi) {
    let out = '';
    for (;;) {
      if (i >= n) fail('unterminated string');
      const c = s[i];
      const code = s.charCodeAt(i);
      if (multi) {
        if (c === '"' && s[i + 1] === '"' && s[i + 2] === '"') {
          i += 3;
          let extra = 0;
          while (s[i] === '"' && extra < 2) { out += '"'; i++; extra++; }
          return out;
        }
      } else if (c === '"') { i++; return out; }
      if (c === '\\') {
        i++;
        const e = s[i];
        if (e in ESCAPES) { out += ESCAPES[e]; i++; continue; }
        if (e === 'u' || e === 'U') {
          const len = e === 'u' ? 4 : 8;
          const hex = s.slice(i + 1, i + 1 + len);
          if (!new RegExp(`^[0-9a-fA-F]{${len}}$`).test(hex)) fail('bad unicode escape');
          const cp = parseInt(hex, 16);
          if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) fail('bad unicode scalar');
          out += String.fromCodePoint(cp);
          i += 1 + len;
          continue;
        }
        if (multi && (isWs(e) || e === '\n' || e === '\r')) {
          let j = i;
          while (isWs(s[j])) j++;
          if (s[j] === '\r' && s[j + 1] === '\n') j++;
          if (s[j] !== '\n') fail('invalid line-ending backslash');
          while (j < n && (isWs(s[j]) || s[j] === '\n' || s[j] === '\r')) j++;
          i = j;
          continue;
        }
        fail('invalid escape');
      }
      if (c === '\n' || c === '\r') {
        if (!multi) fail('newline in single-line string');
        if (c === '\r') { if (s[i + 1] !== '\n') fail('bare carriage return'); i++; continue; }
      } else if ((code < 0x20 && code !== 0x09) || code === 0x7f) fail('control character in string');
      out += c;
      i++;
    }
  }
  function readLiteralString(multi) {
    let out = '';
    for (;;) {
      if (i >= n) fail('unterminated string');
      const c = s[i];
      const code = s.charCodeAt(i);
      if (multi) {
        if (c === "'" && s[i + 1] === "'" && s[i + 2] === "'") {
          i += 3;
          let extra = 0;
          while (s[i] === "'" && extra < 2) { out += "'"; i++; extra++; }
          return out;
        }
      } else if (c === "'") { i++; return out; }
      if (c === '\n' || c === '\r') {
        if (!multi) fail('newline in single-line string');
        if (c === '\r') { if (s[i + 1] !== '\n') fail('bare carriage return'); i++; continue; }
      } else if ((code < 0x20 && code !== 0x09) || code === 0x7f) fail('control character in string');
      out += c;
      i++;
    }
  }
  function readString() {
    const q = s[i];
    if (s.startsWith(q.repeat(3), i)) {
      i += 3;
      if (s[i] === '\r' && s[i + 1] === '\n') i += 2; else if (s[i] === '\n') i++;
      return q === '"' ? readBasicString(true) : readLiteralString(true);
    }
    i++;
    return q === '"' ? readBasicString(false) : readLiteralString(false);
  }
  function readKeyPart() {
    skipWs();
    const c = s[i];
    if (c === '"' || c === "'") {
      if (s.startsWith(c.repeat(3), i)) fail('multi-line string used as key');
      return checkKey(readString());
    }
    const m = /^[A-Za-z0-9_-]+/.exec(s.slice(i, i + 256));
    if (!m) fail('expected key');
    i += m[0].length;
    return checkKey(m[0]);
  }
  function readKeyPath() {
    const path = [readKeyPart()];
    for (;;) {
      skipWs();
      if (s[i] !== DOT) return path;
      i++;
      path.push(readKeyPart());
    }
  }

  function readValue() {
    skipWs();
    const c = s[i];
    if (c === '"' || c === "'") return readString();
    if (c === '[') return readArray();
    if (c === '{') return readInline();
    const m = /^[A-Za-z0-9_+\-.:]+/.exec(s.slice(i, i + 64));
    if (!m) fail('expected value');
    const tok = m[0];
    if (tok === 'true' || tok === 'false') { i += tok.length; return tok === 'true'; }
    if (/^[+-]?(0|[1-9](_?[0-9])*)$/.test(tok)) {
      i += tok.length;
      const v = Number(tok.replace(/_/g, ''));
      if (!Number.isSafeInteger(v)) fail('integer out of range');
      return v;
    }
    fail(`unsupported value ${tok.slice(0, 20)}`);
    return undefined;
  }
  function readArray() {
    i++;
    const out = [];
    for (;;) {
      skipBlank();
      if (s[i] === ']') { i++; return out; }
      out.push(readValue());
      skipBlank();
      if (s[i] === ',') { i++; continue; }
      skipBlank();
      if (s[i] === ']') { i++; return out; }
      fail('expected , or ] in array');
    }
  }
  function assign(table, path, value) {
    let t = table;
    for (const k of path.slice(0, -1)) {
      if (!Object.hasOwn(t, k)) { t[k] = {}; closed.add(t[k]); }
      else if (!isObj(t[k]) || inline.has(t[k]) || explicit.has(t[k])) fail(`key ${k} conflicts with an existing definition`);
      t = t[k];
    }
    const last = path[path.length - 1];
    if (Object.hasOwn(t, last)) fail(`duplicate key ${last}`);
    t[last] = value;
  }
  function readInline() {
    i++;
    const t = {};
    closed.add(t);
    inline.add(t);
    skipWs();
    if (s[i] === '}') { i++; return t; }
    for (;;) {
      const path = readKeyPath();
      skipWs();
      if (s[i] !== '=') fail('expected =');
      i++;
      assign(t, path, readValue());
      skipWs();
      if (s[i] === ',') { i++; skipWs(); continue; }
      if (s[i] === '}') { i++; return t; }
      fail('expected , or } in inline table');
    }
  }

  function openTable(path) {
    let t = root;
    for (let idx = 0; idx < path.length; idx++) {
      const k = path[idx];
      if (!Object.hasOwn(t, k)) t[k] = {};
      else if (!isObj(t[k])) fail(`table ${k} conflicts with a non-table`);
      else if (closed.has(t[k])) fail(`table ${k} was defined by a dotted key or inline table`);
      t = t[k];
    }
    if (explicit.has(t)) fail(`table ${path.join(DOT)} defined twice`);
    explicit.add(t);
    return t;
  }

  let cur = root;
  for (;;) {
    skipBlank();
    if (i >= n) break;
    if (s[i] === '[') {
      if (s[i + 1] === '[') fail('array of tables is not supported');
      i++;
      const path = readKeyPath();
      skipWs();
      if (s[i] !== ']') fail('expected ]');
      i++;
      cur = openTable(path);
      endOfLine();
      continue;
    }
    const path = readKeyPath();
    skipWs();
    if (s[i] !== '=') fail('expected =');
    i++;
    assign(cur, path, readValue());
    endOfLine();
  }
  return root;
}
