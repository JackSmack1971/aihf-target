// Deterministic Phase-0 checker for the trust-zone contract, operating modes, global prohibitions,
// capital and signer policy capability groups, and a static repo-tree tripwire.
// It only parses data and reads files; it never imports or executes what it scans. Rule data lives in
// contracts/phase0-checker-rules.json (outside src/). Runtime enforcement of these capabilities is a later phase.
import fs from 'node:fs';
import path from 'node:path';

const RULES_FILE = new URL('../../contracts/phase0-checker-rules.json', import.meta.url);

const KEY = 'ZONE_CODEX_TRADERD_KEY';
const SIGNING = 'ZONE_SIGNING_CODEX_MCP';
const OPS = 'OPS_MODE_NO_SIGNER_NO_WRITES';
const EXCHANGE = 'GENERIC_EXCHANGE_ENDPOINT_TO_CODEX';
const SIGNER = 'GENERIC_SIGNER_TO_TRADERD_OR_MCP';
const CAPITAL = 'THIRD_PARTY_CAPITAL';
const CUSTODY_CHANGE = 'CUSTODY_CONFIG_CHANGE';

const ZONE5_FALSE = Object.freeze({
  arbitrary_shell: 'ZONE_SIGNING_ARBITRARY_SHELL',
  general_outbound_network: 'ZONE_SIGNING_GENERAL_NETWORK',
  filesystem_outside_state_boundary: 'ZONE_SIGNING_FILESYSTEM_ESCAPE',
});

/** Global prohibitions that trust-zones.json must carry (one entry each, exact shape). */
export const REQUIRED_PROHIBITIONS = Object.freeze([
  EXCHANGE, SIGNER, CAPITAL, 'API_WALLET_MANAGEMENT', CUSTODY_CHANGE, 'RUNTIME_SOURCE_MUTATION',
  'AUTONOMOUS_DEPLOYMENT', 'SELF_PROMOTION', 'COINVEST_LIVE_EXECUTION',
]);
/** Capabilities whose rules file coverage is pinned here so deleting rules from the data file fails closed. */
export const REQUIRED_TREE_COVERAGE = Object.freeze([
  KEY, EXCHANGE, SIGNER, CAPITAL, 'API_WALLET_MANAGEMENT', CUSTODY_CHANGE, 'RUNTIME_SOURCE_MUTATION',
  'AUTONOMOUS_DEPLOYMENT', 'SELF_PROMOTION', 'COINVEST_LIVE_EXECUTION',
  ...Object.values(ZONE5_FALSE), 'OPS_MODE_GIT_WRITES', 'COINVEST_PAPER_WRITES', 'OPS_COINVEST_DIRECT_ENDPOINT', 'OPS_PROVISION_ISOLATION',
]);
export const REQUIRED_SIGNER_GROUPS = Object.freeze(['API_WALLET_MANAGEMENT', CUSTODY_CHANGE, SIGNER]);

const SCOPES = new Set(['path', 'code', 'package_json']);
const CODE_FILE = /\.(mjs|cjs|js|jsx|ts|mts|cts|tsx|sh|bash|zsh|py|rb|pl|ps1)$/i;
/** Code files anywhere outside tests/ (tests hold fixtures that intentionally contain violations). */
export const isCodePath = (p) => CODE_FILE.test(p) && !p.startsWith('tests/');
const ZONE_KEYS = new Set(['id', 'name', 'components', 'codex_present', 'mcp_present', 'holds_trading_key', 'raw_exchange_write', 'custody_actions',
  'ai_process_control', 'treats_llm_output_as_hostile', 'issues_execution_permit', 'acts_only_inside_execution_permit', 'compile_time_action_allowlist',
  'production_source_writes', 'arbitrary_shell', 'general_outbound_network', 'filesystem_outside_state_boundary']);
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const nonEmpty = (s) => typeof s === 'string' && s.trim().length > 0;
const V = (capability, message) => ({ capability, message });
const done = (violations) => ({ ok: violations.length === 0, violations });

/** Validates and compiles the rules document. Throws on any malformed or under-covering input (fail closed). */
export function parseRules(json) {
  const fail = (m) => { throw new Error(`phase0 rules: ${m}`); };
  if (!isObj(json)) fail('not an object');
  if (!isObj(json.mode_rules)) fail('mode_rules missing');
  const mode_rules = {};
  for (const mode of ['fund-dev', 'fund-ops']) {
    const r = json.mode_rules[mode];
    if (!isObj(r) || !isObj(r.forbidden) || Object.keys(r.forbidden).length === 0 || !Array.isArray(r.allowed_true)) fail(`mode_rules.${mode} malformed`);
    for (const [k, caps] of Object.entries(r.forbidden)) {
      if (!Array.isArray(caps) || caps.length === 0 || !caps.every(nonEmpty)) fail(`mode_rules.${mode}.forbidden.${k} malformed`);
    }
    if (!r.allowed_true.every(nonEmpty)) fail(`mode_rules.${mode}.allowed_true malformed`);
    if (!isObj(r.required_true)) fail(`mode_rules.${mode}.required_true malformed`);
    for (const [k, caps] of Object.entries(r.required_true)) {
      if (!Array.isArray(caps) || caps.length === 0 || !caps.every(nonEmpty) || !r.allowed_true.includes(k)) fail(`mode_rules.${mode}.required_true.${k} malformed`);
    }
    mode_rules[mode] = r;
  }
  if (Object.keys(json.mode_rules).length !== 2) fail('mode_rules has unexpected modes');
  if (!isObj(json.signer_groups)) fail('signer_groups missing');
  for (const g of REQUIRED_SIGNER_GROUPS) {
    const list = json.signer_groups[g];
    if (!Array.isArray(list) || list.length === 0 || !list.every(nonEmpty)) fail(`signer_groups.${g} missing or empty`);
  }
  if (!Array.isArray(json.tree_rules)) fail('tree_rules missing');
  const tree_rules = json.tree_rules.map((r, i) => {
    if (!isObj(r) || !nonEmpty(r.capability) || !SCOPES.has(r.scope) || !nonEmpty(r.pattern) || !['', 'i'].includes(r.flags) || !nonEmpty(r.description)) fail(`tree_rules[${i}] malformed`);
    return { capability: r.capability, scope: r.scope, description: r.description, re: new RegExp(r.pattern, r.flags) };
  });
  for (const c of REQUIRED_TREE_COVERAGE) if (!tree_rules.some((r) => r.capability === c)) fail(`no tree rule covers ${c}`);
  return Object.freeze({ mode_rules, signer_groups: json.signer_groups, tree_rules });
}

export function loadRules() {
  return parseRules(JSON.parse(fs.readFileSync(RULES_FILE, 'utf8')));
}

/** Zones, operating modes and global prohibitions. @returns {{ok:boolean, violations:{capability:string,message:string}[]}} */
export function checkTrustZones(doc, rules = loadRules()) {
  const out = [];
  if (!isObj(doc) || !Array.isArray(doc.zones)) {
    for (const c of [KEY, SIGNING, OPS, ...REQUIRED_PROHIBITIONS]) out.push(V(c, 'trust-zones document is malformed'));
    return done(out);
  }
  const ids = doc.zones.map((z) => z?.id);
  if (JSON.stringify([...ids].sort()) !== JSON.stringify([0, 1, 2, 3, 4, 5])) out.push(V(KEY, 'zones must be exactly ids 0-5, once each'));
  for (const z of doc.zones) {
    if (!isObj(z)) { out.push(V(KEY, 'zone entry is not an object')); continue; }
    const id = z.id;
    const tag = `zone ${String(id)}`;
    for (const k of Object.keys(z)) if (!ZONE_KEYS.has(k)) out.push(V(KEY, `${tag}: unknown field ${k} (zone shape is closed)`));
    if (z.raw_exchange_write !== false) {
      out.push(V(KEY, `${tag}: raw_exchange_write must be false`));
      if (id === 1) out.push(V(EXCHANGE, `${tag}: Codex plane must not hold a raw exchange write`));
    }
    if (id !== 5 && z.holds_trading_key !== false) out.push(V(KEY, `${tag}: holds_trading_key must be false`));
    if (id !== 0 && z.custody_actions !== false) out.push(V(CUSTODY_CHANGE, `${tag}: custody_actions must be false`));
    if (id === 0 && z.ai_process_control !== false) out.push(V(CUSTODY_CHANGE, `${tag}: ai_process_control must be false`));
    if (id !== 1 && z.codex_present !== false) out.push(V(SIGNING, `${tag}: Codex is present outside zone 1`));
    if (id !== 1 && z.mcp_present !== false) out.push(V(id === 5 ? SIGNING : KEY, `${tag}: mcp_present must be false`));
    if (id === 4 && z.acts_only_inside_execution_permit !== true) out.push(V(KEY, `${tag}: must act only inside an ExecutionPermit`));
    if (id === 1 && z.production_source_writes !== false) out.push(V('ZONE_CODEX_PRODUCTION_SOURCE_WRITES', `${tag}: production_source_writes must be false`));
    if (id === 5) for (const [k, cap] of Object.entries(ZONE5_FALSE)) if (z[k] !== false) out.push(V(cap, `${tag}: ${k} must be false`));
    if (id === 5 && z.compile_time_action_allowlist !== true) out.push(V(SIGNING, `${tag}: compile-time action allowlist required`));
    if (!Array.isArray(z.components) || z.components.length === 0 || !z.components.every(nonEmpty)) {
      out.push(V(KEY, `${tag}: components malformed`));
      continue;
    }
    if (id !== 5 && z.components.some((c) => /signer|signing/i.test(c))) out.push(V(SIGNER, `${tag}: signing component outside zone 5`));
    if (id >= 1 && id <= 4 && z.components.some((c) => /key\s+custody|private\s+key|trading\s+key/i.test(c))) out.push(V(KEY, `${tag}: key custody component outside zone 5`));
    if (id === 1 && z.components.some((c) => /(raw|generic)[^|]*(exchange|action)|exchange\s*(write|action|endpoint)/i.test(c))) {
      out.push(V(EXCHANGE, `${tag}: generic exchange component exposed to Codex`));
    }
  }

  const probs = Array.isArray(doc.global_prohibitions) ? doc.global_prohibitions : [];
  for (const id of REQUIRED_PROHIBITIONS) {
    const hits = probs.filter((p) => isObj(p) && p.id === id);
    if (hits.length !== 1) out.push(V(id, `global prohibition ${id} must appear exactly once`));
  }
  for (const p of probs) {
    if (!isObj(p) || !REQUIRED_PROHIBITIONS.includes(p.id)) continue;
    if (JSON.stringify(Object.keys(p).sort()) !== JSON.stringify(['blueprint_ref', 'description', 'id']) || !nonEmpty(p.description) || !nonEmpty(p.blueprint_ref)) {
      out.push(V(p.id, `global prohibition ${p.id} has a non-canonical shape (extra, missing or empty field)`));
    }
  }

  const modes = isObj(doc.operating_modes) ? doc.operating_modes : null;
  if (!modes || Object.keys(modes).length !== 2) out.push(V(OPS, 'operating_modes must define exactly fund-dev and fund-ops'));
  for (const [mode, rule] of Object.entries(rules.mode_rules)) {
    const m = modes?.[mode];
    if (!isObj(m)) { out.push(V(OPS, `operating mode ${mode} missing`)); continue; }
    for (const [key, caps] of Object.entries(rule.forbidden)) {
      if (m[key] !== false) for (const c of caps) out.push(V(c, `${mode}.${key} must be false`));
    }
    for (const [key, caps] of Object.entries(rule.required_true)) {
      if (m[key] !== true) for (const c of caps) out.push(V(c, `${mode}.${key} must be true`));
    }
    for (const [key, val] of Object.entries(m)) {
      if (Object.hasOwn(rule.forbidden, key) || Object.hasOwn(rule.required_true, key)) continue;
      if (typeof val !== 'boolean') out.push(V(OPS, `${mode}.${key} must be boolean`));
      else if (val && !rule.allowed_true.includes(key)) out.push(V(OPS, `${mode}.${key} enables an unrecognized capability`));
    }
  }
  return done(out);
}

/** Risk policy capital flags. */
export function checkCapitalPolicy(policy) {
  const out = [];
  if (!isObj(policy) || policy.allow_third_party_capital !== false) out.push(V(CAPITAL, 'allow_third_party_capital must be exactly false'));
  return done(out);
}

/** Signer policy must deny, and never allow, each capability group's actions. */
export function checkSignerCapabilityGroups(policy, groups = loadRules().signer_groups) {
  const out = [];
  if (!isObj(groups) || Object.keys(groups).length === 0) throw new Error('signer capability groups are empty');
  const denied = Array.isArray(policy?.denied_actions) ? policy.denied_actions : [];
  const allowed = new Set((Array.isArray(policy?.allowed_request_types) ? policy.allowed_request_types : []).map((a) => String(a).toLowerCase()));
  for (const [capability, names] of Object.entries(groups)) {
    for (const n of names) {
      if (!denied.includes(n)) out.push(V(capability, `denied_actions is missing ${n}`));
      if (allowed.has(String(n).toLowerCase())) out.push(V(capability, `${n} is allowlisted`));
    }
  }
  return done(out);
}

/** Reads a directory into [{path (posix, relative), text}]; text is read for every code file outside tests/ and for package.json (null if unreadable). */
export function collectTree(dir) {
  const entries = [];
  const walkDir = (abs, rel) => {
    for (const e of fs.readdirSync(abs, { withFileTypes: true })) {
      if (rel === '' && (e.name === '.git' || e.name === 'node_modules')) continue;
      const r = rel === '' ? e.name : `${rel}/${e.name}`;
      const p = path.join(abs, e.name);
      if (e.isDirectory()) { entries.push({ path: r, text: undefined }); walkDir(p, r); continue; }
      let text;
      if (isCodePath(r) || r === 'package.json') {
        try { text = e.isFile() ? fs.readFileSync(p, 'utf8') : null; } catch { text = null; }
      }
      entries.push({ path: r, text });
    }
  };
  walkDir(dir, '');
  return entries;
}

// ---- the pinned provisioning directory: the SOLE repository location for human-run privileged host provisioning artifacts (decision D-0007).
// The exemption is deliberately tiny: exact pinned file paths, and only the two capabilities listed below. Everything else (shell/network/
// file-write/deploy/key rules, the deploy* path rule) still applies to these files, and an equivalent privileged script anywhere else is rejected.
// Adding a file to the pinned provisioning directory requires editing this pinned list (review-visible) and its tests.
const OPS_ISOLATION = 'OPS_PROVISION_ISOLATION';
const OPS_DIR = ['ops', 'provision'].join('/');
export const OPS_PROVISION_FILES = Object.freeze([
  'README.md', 'canonical-artifacts.sha256', 'wsl.conf.fund-ops', ...['layout', 'provision', 'validate', 'verify'].map((n) => `fund-ops-${n}.sh`),
].map((f) => `${OPS_DIR}/${f}`));
const OPS_PROVISION_EXEMPT = Object.freeze(new Set(['ZONE_SIGNING_FILESYSTEM_ESCAPE', OPS_ISOLATION]));
const OPS_TOP = /^ops(\/|$)/i;

/** Static tripwire over repo paths, src/ text and package.json scripts. */
export function checkRepoTree(entries, rules = loadRules()) {
  const out = [];
  for (const e of entries) {
    // anything under ops/ other than the pinned provisioning directory and files is rejected
    if (OPS_TOP.test(e.path) && e.path !== 'ops' && e.path !== OPS_DIR && !OPS_PROVISION_FILES.includes(e.path)) {
      out.push(V(OPS_ISOLATION, `${e.path}: only the pinned files under ${OPS_DIR} may exist beneath ops/`));
    }
    const pinnedProvision = OPS_PROVISION_FILES.includes(e.path);
    const inCode = isCodePath(e.path) && e.text !== undefined;
    if (inCode && typeof e.text !== 'string') out.push(V('RUNTIME_SOURCE_MUTATION', `${e.path}: unreadable or non-regular code file`));
    let scripts = null;
    if (e.path === 'package.json' && typeof e.text === 'string') {
      try { scripts = JSON.stringify(JSON.parse(e.text).scripts ?? {}); } catch { out.push(V('AUTONOMOUS_DEPLOYMENT', 'package.json is not valid JSON')); }
    }
    for (const r of rules.tree_rules) {
      if (pinnedProvision && r.scope === 'code' && OPS_PROVISION_EXEMPT.has(r.capability)) continue;
      const subject = r.scope === 'path' ? e.path : r.scope === 'code' ? (inCode ? e.text : null) : (scripts);
      if (typeof subject === 'string' && r.re.test(subject)) out.push(V(r.capability, `${e.path}: ${r.description}`));
    }
  }
  return done(out);
}

// ---- governance (section 17 invariants 43, 44, 45, 49): fail-closed per-actor allowlists ----
// Everything below is pinned in code: the class enum, the actor->class map, the closed authority vocabulary, the per-class
// permitted authorities and the four forbidden rows. Weakening contracts/governance.json cannot weaken the check.
const CLASS_CAP = Object.freeze({
  llm: 'GOV_LLM_CHANGES_RISK_POLICY',
  executor: 'GOV_EXECUTOR_CHANGES_POLICY',
  ai_risk_officer: 'GOV_AI_RISK_OFFICER_EXECUTES',
  mcp_server: 'GOV_MCP_EXPANSION_WIDENS_ALLOWLIST',
});
const GOV_IDS = Object.freeze(Object.values(CLASS_CAP));
const CLASS_ENUM = Object.freeze([...Object.keys(CLASS_CAP), 'human']);
const PINNED_ACTORS = Object.freeze({
  'codex-cio': 'llm', 'committee-member': 'llm', traderd: 'executor', 'ai-risk-officer': 'ai_risk_officer', 'remote-mcp-server': 'mcp_server',
});
const PINNED_AUTHORITIES = Object.freeze({
  'codex-cio': ['propose_risk_policy_change', 'submit_trade_intent'],
  'committee-member': ['produce_research_opinion'],
  traderd: ['submit_order_within_permit'],
  'ai-risk-officer': ['issue_risk_review_verdict'],
  'remote-mcp-server': ['propose_allowlist_extension_for_human_review'],
});
const CLASS_PERMITTED = Object.freeze({
  llm: ['submit_trade_intent', 'propose_risk_policy_change', 'produce_research_opinion'],
  executor: ['submit_order_within_permit'],
  ai_risk_officer: ['issue_risk_review_verdict'],
  mcp_server: ['propose_allowlist_extension_for_human_review'],
  human: ['change_active_risk_policy', 'widen_production_allowlist'],
});
const PINNED_FORBIDDEN = Object.freeze([
  {
    "id": "GOV_LLM_CHANGES_RISK_POLICY",
    "actor_class": "llm",
    "authority": "change_active_risk_policy",
    "pattern": "^(change|modify|update|set|edit|raise|lower|adjust|activate|write|override|approve|relax|disable|bypass)_.*(polic|limit|leverage|budget|threshold|cap)|polic\\w*_(update|change|edit|write|override|set)|(risk|limit|leverage|budget)\\w*_(update|change|edit|override|raise|lower)",
    "blueprint_ref": "section 17 inv. 43"
  },
  {
    "id": "GOV_EXECUTOR_CHANGES_POLICY",
    "actor_class": "executor",
    "authority": "change_policy",
    "pattern": "^(change|modify|update|set|edit|raise|lower|adjust|activate|write|override|approve|relax|disable|bypass)_.*(polic|limit|leverage|budget|threshold|cap)|polic\\w*_(update|change|edit|write|override|set)|(risk|limit|leverage|budget)\\w*_(update|change|edit|override|raise|lower)",
    "blueprint_ref": "section 17 inv. 44"
  },
  {
    "id": "GOV_AI_RISK_OFFICER_EXECUTES",
    "actor_class": "ai_risk_officer",
    "authority": "execute_order",
    "pattern": "(^|_)(execute|execution|submit|place|cancel|modify|sign|send|close|flatten|liquidate|reduce|trade|order)(_|$)",
    "blueprint_ref": "section 17 inv. 45"
  },
  {
    "id": "GOV_MCP_EXPANSION_WIDENS_ALLOWLIST",
    "actor_class": "mcp_server",
    "authority": "widen_production_allowlist",
    "pattern": "^(widen|expand|extend|add|modify|update|grant|auto|register|install|enable)_.*(allowlist|capabilit|tool|server|permission)|(allowlist|tool|capabilit|permission)s?_(add|update|register|expand|widen|grant)",
    "blueprint_ref": "section 17 inv. 49"
  }
]);
const PINNED_VOCABULARY = Object.freeze([...new Set([...Object.values(CLASS_PERMITTED).flat(), ...PINNED_FORBIDDEN.map((f) => f.authority)])].sort());
const PINNED_RE = PINNED_FORBIDDEN.map((f) => ({ ...f, re: new RegExp(f.pattern, 'i') }));
const sameJson = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const sortedObj = (o) => Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k]]));

/** Fail closed: an authority is granted only if it is in the closed vocabulary AND permitted for the actor's class AND matches no forbidden rule.
 * @returns {{ok:boolean, violations:{capability:string,message:string}[]}} */
export function checkGovernance(doc) {
  const out = [];
  if (!isObj(doc) || !Array.isArray(doc.actors) || !Array.isArray(doc.forbidden) || !Array.isArray(doc.authority_vocabulary)) {
    for (const id of GOV_IDS) out.push(V(id, 'governance document is malformed'));
    return done(out);
  }
  if (!sameJson([...doc.authority_vocabulary].sort(), PINNED_VOCABULARY)) for (const id of GOV_IDS) out.push(V(id, 'authority_vocabulary differs from the pinned closed vocabulary'));
  for (const row of PINNED_FORBIDDEN) {
    const hits = doc.forbidden.filter((f) => isObj(f) && f.id === row.id);
    if (hits.length !== 1 || !sameJson(sortedObj(hits[0]), sortedObj(row))) out.push(V(row.id, `forbidden row ${row.id} is missing, duplicated or differs from the pinned row`));
  }
  if (doc.forbidden.some((f) => !isObj(f) || !PINNED_FORBIDDEN.some((r) => r.id === f.id))) for (const id of GOV_IDS) out.push(V(id, 'unrecognized forbidden row'));
  const seen = new Map();
  for (const a of doc.actors) {
    if (!isObj(a) || !nonEmpty(a.id) || seen.has(a.id) || !sameJson(Object.keys(a).sort(), ['allowed_authorities', 'class', 'id']) || !Array.isArray(a.allowed_authorities)) {
      for (const id of GOV_IDS) out.push(V(id, 'actor entry malformed, duplicated or has extra fields'));
      continue;
    }
    seen.set(a.id, a.class);
    if (!Object.hasOwn(PINNED_ACTORS, a.id)) { for (const id of GOV_IDS) out.push(V(id, `actor ${a.id} is not in the pinned actor list`)); continue; }
    if (!sameJson([...a.allowed_authorities].sort(), PINNED_AUTHORITIES[a.id])) {
      for (const id of GOV_IDS) out.push(V(id, `actor ${a.id}: allowed_authorities must equal the pinned list exactly`));
    }
    if (!CLASS_ENUM.includes(a.class)) { for (const id of GOV_IDS) out.push(V(id, `actor ${a.id}: unknown class ${String(a.class)}`)); continue; }
    const cap = CLASS_CAP[a.class];
    const caps = cap ? [cap] : [];
    if (Object.hasOwn(PINNED_ACTORS, a.id) && PINNED_ACTORS[a.id] !== a.class) {
      for (const c of [...new Set([CLASS_CAP[PINNED_ACTORS[a.id]], ...caps])]) out.push(V(c, `actor ${a.id} must be class ${PINNED_ACTORS[a.id]}`));
    }
    if (new Set(a.allowed_authorities).size !== a.allowed_authorities.length) for (const id of GOV_IDS) out.push(V(id, `actor ${a.id}: duplicate authority`));
    for (const raw of a.allowed_authorities) {
      const auth = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
      const targets = caps.length > 0 ? caps : GOV_IDS;
      if (!PINNED_VOCABULARY.includes(auth) || auth !== raw) { for (const c of targets) out.push(V(c, `actor ${a.id}: authority ${String(raw)} is not in the closed vocabulary`)); continue; }
      if (!CLASS_PERMITTED[a.class].includes(auth)) for (const c of targets) out.push(V(c, `actor ${a.id}: authority ${auth} is not permitted for class ${a.class}`));
      if (a.class !== 'human') {
        for (const f of PINNED_RE) {
          if (auth === f.authority) out.push(V(f.id, `non-human actor ${a.id} must never hold ${auth}`));
          else if (f.actor_class === a.class && !CLASS_PERMITTED[a.class].includes(auth) && f.re.test(auth)) out.push(V(f.id, `${a.id}: ${auth} matches the ${f.id} deny pattern`));
        }
      }
    }
  }
  for (const [id, cls] of Object.entries(PINNED_ACTORS)) {
    if (!seen.has(id)) out.push(V(CLASS_CAP[cls], `pinned actor ${id} is missing`));
  }
  return done(out);
}
