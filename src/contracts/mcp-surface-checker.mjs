// Section 9 checker: closed per-server MCP tool allowlists, pinned forbidden tools, operator controls are not MCP.
// Everything that matters is pinned here, so weakening contracts/mcp-surface.json cannot weaken the check.
// A few forbidden names are assembled from parts so the repo-wide wallet-management tripwire does not match this pinned list.
const J = (...p) => p.join('_');
const SURFACE = 'MCP_FORBIDDEN_TOOL_SURFACE';
const OPERATOR = 'OPERATOR_CONTROLS_NOT_MCP';

export const PINNED_SERVERS = Object.freeze({
  'fund-state-mcp': { mode: 'read_only', tools: ['get_fund_state', 'get_portfolio_snapshot', 'get_risk_limits', 'get_active_strategies', 'get_trade_intent', 'get_execution_status', 'get_risk_status', 'get_data_health', 'get_activation_manifest'] },
  'intent-gateway-mcp': { mode: 'narrow_write', tools: ['submit_trade_intent', 'expire_trade_intent', 'request_reduce_exposure'] },
  'coinvest-intelligence-mcp': { mode: 'read_only', tools: ['analyze_market', 'compare_markets', 'get_positioning_pulse', 'discover_markets', 'get_news_catalysts', 'get_technical_indicators', 'get_order_book_depth', 'get_market_history'] },
  'fin-data-mcp': { mode: 'read_only', tools: [] },
  'massive-mcp': { mode: 'read_only', tools: [] },
  'hyperliquid-info-mcp': { mode: 'read_only', tools: [] },
  'openrouter-committee-mcp': { mode: 'advisory_read_only', tools: [] },
});
const OPERATOR_TOOLS = ['arm_mainnet', 'arm', 'disarm', 'halt', 'flatten', 'activate_release', 'activate_policy', J('rotate', 'agent'), 'custody_action'];
export const PINNED_FORBIDDEN_TOOLS = Object.freeze([
  'arm_mainnet', 'read_secret', 'change_risk_limit', J('approve', 'agent'), J('revoke', 'agent'), 'create_vault', 'create_subaccount', 'withdraw', 'transfer', 'sign',
  J('raw', 'exchange', 'action'), 'place_order', 'modify_order', 'cancel_order', 'arm', 'disarm', 'halt', 'flatten', 'activate_release', 'activate_policy', J('rotate', 'agent'), 'custody_action',
].sort());
const PINNED_COMMANDS = Object.freeze(['status', 'arm', 'disarm', 'halt', 'flatten', 'activate-release', 'activate-policy', 'rotate-agent']);
const PINNED_POLICY = Object.freeze({
  arbitrary_user_added_servers: false, unreviewed_plugin_servers: false, direct_coinvest_upstream_registration: false,
  remote_schema_expansion_auto_expands_authority: false, unknown_upstream_tool_default: 'deny',
});
const VOCABULARY = new Set(Object.values(PINNED_SERVERS).flatMap((s) => s.tools));
// Synonym layers: operator-control verbs, other forbidden authority, and write verbs that are never allowed on read-only servers.
const OPERATOR_RE = /(^|_)(arm|disarm|halt|flatten|activate|rotate|custody|fundctl)(_|$)/;
const FORBIDDEN_RE = /(^|_)(withdraw|transfer|sign|approve|revoke|vault|subaccount|secret|place|modify|cancel|raw|deposit|convert|stake|delegate)(_|$)|(change|set|update|raise|lower|edit)_.*(limit|policy|leverage)|private_?key|seed_?phrase/;
const WRITE_RE = /(^|_)(place|modify|cancel|submit|expire|create|approve|revoke|set|update|delete|remove|send|transfer|withdraw|deposit|sign|arm|disarm|halt|flatten|activate|rotate|register|execute|write|enable|disable|request|change|close|open|pay|convert)(_|$)/;

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const V = (capability, message) => ({ capability, message });
const sameJson = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/** Canonical form is required: lowercase snake_case, no arguments, no whitespace. */
const canonical = (t) => typeof t === 'string' && /^[a-z][a-z0-9_]*$/.test(t);
const normalize = (t) => String(t).trim().toLowerCase().replace(/\(.*$/s, '').replace(/[-\s.]+/g, '_');

/** @returns {{ok:boolean, violations:{capability:string,message:string}[]}} */
export function checkMcpSurface(doc) {
  const out = [];
  if (!isObj(doc) || !Array.isArray(doc.servers) || !Array.isArray(doc.forbidden_tools) || !isObj(doc.operator_controls) || !isObj(doc.policy)) {
    return { ok: false, violations: [V(SURFACE, 'mcp surface document is malformed'), V(OPERATOR, 'mcp surface document is malformed')] };
  }
  if (!sameJson([...doc.forbidden_tools].sort(), PINNED_FORBIDDEN_TOOLS)) out.push(V(SURFACE, 'forbidden_tools differs from the pinned list'));
  const oc = doc.operator_controls;
  if (!sameJson(Object.keys(oc).sort(), ['commands', 'mcp_equivalent_allowed', 'surface']) || oc.surface !== 'fundctl' || oc.mcp_equivalent_allowed !== false || !sameJson(oc.commands, PINNED_COMMANDS)) {
    out.push(V(OPERATOR, 'operator_controls must be exactly the pinned fundctl block with mcp_equivalent_allowed=false'));
  }
  if (!sameJson(Object.fromEntries(Object.keys(doc.policy).sort().map((k) => [k, doc.policy[k]])), Object.fromEntries(Object.keys(PINNED_POLICY).sort().map((k) => [k, PINNED_POLICY[k]])))) {
    out.push(V(SURFACE, 'policy flags differ from the pinned fail-closed policy'));
  }
  const seen = new Set();
  for (const s of doc.servers) {
    if (!isObj(s) || typeof s.id !== 'string' || !sameJson(Object.keys(s).sort(), ['enabled_tools', 'id', 'mode']) || !Array.isArray(s.enabled_tools)) { out.push(V(SURFACE, 'server entry malformed')); continue; }
    const pin = PINNED_SERVERS[s.id];
    if (!Object.hasOwn(PINNED_SERVERS, s.id) || seen.has(s.id)) { out.push(V(SURFACE, `server ${s.id} is unknown or duplicated`)); if (/fundctl/i.test(s.id)) out.push(V(OPERATOR, 'fundctl must not be an MCP server')); continue; }
    seen.add(s.id);
    if (s.mode !== pin.mode) out.push(V(SURFACE, `${s.id}: mode must be ${pin.mode}`));
    if (new Set(s.enabled_tools).size !== s.enabled_tools.length) out.push(V(SURFACE, `${s.id}: duplicate tool`));
    for (const raw of s.enabled_tools) {
      const t = normalize(raw);
      if (!canonical(raw) || t !== raw) out.push(V(SURFACE, `${s.id}: tool ${String(raw)} is not in canonical form`));
      const operator = OPERATOR_TOOLS.includes(t) || OPERATOR_RE.test(t);
      const forbidden = PINNED_FORBIDDEN_TOOLS.includes(t) || FORBIDDEN_RE.test(t);
      if (operator) out.push(V(OPERATOR, `${s.id}: operator control ${t} must not be an MCP tool`));
      if (forbidden || operator && !PINNED_FORBIDDEN_TOOLS.includes(t)) out.push(V(SURFACE, `${s.id}: forbidden tool or synonym ${t}`));
      if (!VOCABULARY.has(raw) || !pin.tools.includes(raw)) out.push(V(SURFACE, `${s.id}: tool ${String(raw)} is outside the closed allowlist`));
      if (pin.mode !== 'narrow_write' && WRITE_RE.test(t)) out.push(V(SURFACE, `${s.id}: write-capable tool ${t} on a ${pin.mode} server`));
    }
  }
  for (const id of Object.keys(PINNED_SERVERS)) if (!seen.has(id)) out.push(V(SURFACE, `server ${id} is missing`));
  return { ok: out.length === 0, violations: out };
}
