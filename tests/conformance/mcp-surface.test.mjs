import test from 'node:test';
import assert from 'node:assert/strict';
import { readJson, denyTest, clone } from '../helpers.mjs';
import { checkMcpSurface, PINNED_SERVERS, PINNED_FORBIDDEN_TOOLS } from '../../src/contracts/mcp-surface-checker.mjs';

const M = () => readJson('contracts', 'mcp-surface.json');
const mut = (fn) => { const d = clone(M()); fn(d); return d; };
const server = (d, id) => d.servers.find((s) => s.id === id);
const capsOf = (r) => [...new Set(r.violations.map((v) => v.capability))];
function rejects(r, cap, label) {
  assert.equal(r.ok, false, `${label}: must be rejected`);
  assert.ok(capsOf(r).includes(cap), `${label}: expected ${cap}, got ${capsOf(r).join(',')}`);
}
const withTool = (id, tool) => mut((d) => { server(d, id).enabled_tools.push(tool); });
const S = 'MCP_FORBIDDEN_TOOL_SURFACE';
const O = 'OPERATOR_CONTROLS_NOT_MCP';
const SERVER_IDS = ['fund-state-mcp', 'intent-gateway-mcp', 'coinvest-intelligence-mcp', 'fin-data-mcp', 'massive-mcp', 'hyperliquid-info-mcp', 'openrouter-committee-mcp'];

test('mcp surface: shipped contract is accepted and matches section 9', () => {
  assert.deepEqual(checkMcpSurface(M()), { ok: true, violations: [] });
  const d = M();
  assert.deepEqual(d.servers.map((s) => s.id), SERVER_IDS);
  assert.deepEqual(server(d, 'fund-state-mcp').enabled_tools, ['get_fund_state', 'get_portfolio_snapshot', 'get_risk_limits', 'get_active_strategies', 'get_trade_intent', 'get_execution_status', 'get_risk_status', 'get_data_health', 'get_activation_manifest']);
  assert.deepEqual(server(d, 'intent-gateway-mcp').enabled_tools, ['submit_trade_intent', 'expire_trade_intent', 'request_reduce_exposure']);
  assert.equal(server(d, 'intent-gateway-mcp').mode, 'narrow_write');
  for (const s of d.servers.filter((x) => x.id !== 'intent-gateway-mcp')) assert.ok(s.mode.endsWith('read_only'), s.id);
  assert.deepEqual([...d.forbidden_tools].sort(), [...PINNED_FORBIDDEN_TOOLS]);
  for (const bad of [null, {}, { servers: [], forbidden_tools: [], operator_controls: {}, policy: 'x' }]) assert.equal(checkMcpSurface(bad).ok, false);
  assert.deepEqual(Object.keys(PINNED_SERVERS), SERVER_IDS);
});

const FORBIDDEN = ['arm_mainnet', 'read_secret', 'change_risk_limit', 'approve_agent', 'revoke_agent', 'create_vault', 'create_subaccount', 'withdraw', 'transfer', 'sign',
  'raw_exchange_action', 'place_order', 'modify_order', 'cancel_order'];
const OPERATOR = ['arm', 'disarm', 'halt', 'flatten', 'activate_release', 'activate_policy', 'rotate_agent', 'custody_action', 'arm_mainnet'];
const SYNONYMS = ['Withdraw', ' withdraw', 'withdraw()', 'withdraw(amount)', 'approve-agent', 'sign_order', 'sign_payload', 'transfer_funds', 'send_transfer', 'set_risk_limit', 'update_risk_limits',
  'raise_max_leverage', 'edit_policy', 'rotate_api_wallet', 'activate-policy', 'custody_withdraw', 'create_vault_account', 'place_limit_order', 'cancel_all', 'read_secret_key', 'get_private_key', 'raw_action', 'fundctl_arm'];

denyTest('DENY-MCP-FORBIDDEN-TOOL-SURFACE', () => {
  assert.equal(checkMcpSurface(M()).ok, true, 'positive control');
  for (const id of SERVER_IDS) {
    for (const t of [...FORBIDDEN, ...SYNONYMS]) rejects(checkMcpSurface(withTool(id, t)), S, `${id} + ${t}`);
  }
  // tools outside the closed vocabulary, or from another server's allowlist, are rejected
  for (const t of ['get_something_new', 'register_tool', 'list_everything', 'proxy_any_tool', '*', '', 'get_fund_state ']) rejects(checkMcpSurface(withTool('fund-state-mcp', t)), S, `unknown tool "${t}"`);
  rejects(checkMcpSurface(withTool('fund-state-mcp', 'submit_trade_intent')), S, 'write tool of the gateway on a read-only server');
  rejects(checkMcpSurface(withTool('intent-gateway-mcp', 'get_fund_state')), S, 'read tool outside the gateway allowlist');
  rejects(checkMcpSurface(withTool('coinvest-intelligence-mcp', 'get_fund_state')), S, 'cross-server tool');
  for (const t of ['analyze_market', 'get_news_catalysts']) rejects(checkMcpSurface(withTool('fin-data-mcp', t)), S, `${t} on a server with an empty section 9 allowlist`);
  for (const t of ['place_trade', 'execute_trade', 'close_position', 'set_paper_mode', 'enable_automated_trading', 'deposit_funds', 'convert_assets', 'update_preferences']) {
    rejects(checkMcpSurface(withTool('coinvest-intelligence-mcp', t)), S, `coinvest write tool ${t}`);
  }
  // write-capable tools never pass on read-only servers even if a name is added to the pinned vocabulary shape
  rejects(checkMcpSurface(withTool('hyperliquid-info-mcp', 'submit_trade_intent')), S, 'write tool on hyperliquid-info');
  // servers: unknown, duplicated, missing, retyped, extra fields
  rejects(checkMcpSurface(mut((d) => { d.servers.push({ id: 'coinvest-direct-mcp', mode: 'read_only', enabled_tools: [] }); })), S, 'unknown server');
  rejects(checkMcpSurface(mut((d) => { d.servers.push({ id: 'coinvest-paper-adapter', mode: 'narrow_write', enabled_tools: [] }); })), S, 'paper adapter registered in the production allowlist');
  rejects(checkMcpSurface(mut((d) => { d.servers.push(clone(server(d, 'massive-mcp'))); })), S, 'duplicate server');
  rejects(checkMcpSurface(mut((d) => { d.servers = d.servers.filter((s) => s.id !== 'fund-state-mcp'); })), S, 'server missing');
  rejects(checkMcpSurface(mut((d) => { server(d, 'fund-state-mcp').mode = 'narrow_write'; })), S, 'read-only server retyped as writable');
  rejects(checkMcpSurface(mut((d) => { server(d, 'fund-state-mcp').extra = true; })), S, 'extra server field');
  rejects(checkMcpSurface(mut((d) => { server(d, 'fund-state-mcp').enabled_tools.push('get_fund_state'); })), S, 'duplicate tool');
  // forbidden list and policy flags are pinned
  for (const t of FORBIDDEN) rejects(checkMcpSurface(mut((d) => { d.forbidden_tools = d.forbidden_tools.filter((x) => x !== t); })), S, `forbidden list drops ${t}`);
  rejects(checkMcpSurface(mut((d) => { d.forbidden_tools.push('extra'); })), S, 'forbidden list altered');
  for (const k of ['arbitrary_user_added_servers', 'unreviewed_plugin_servers', 'direct_coinvest_upstream_registration', 'remote_schema_expansion_auto_expands_authority']) {
    rejects(checkMcpSurface(mut((d) => { d.policy[k] = true; })), S, `policy ${k}=true`);
    rejects(checkMcpSurface(mut((d) => { delete d.policy[k]; })), S, `policy ${k} missing`);
  }
  rejects(checkMcpSurface(mut((d) => { d.policy.unknown_upstream_tool_default = 'allow'; })), S, 'unknown upstream tools allowed');
  assert.ok(readJson('contracts', 'forbidden-capabilities.json').capabilities.some((c) => c.id === S && c.enforcement === 'enforced' && c.runtime_enforced_in_phase === 1));
});

denyTest('DENY-OPERATOR-CONTROLS-NOT-MCP', () => {
  assert.equal(checkMcpSurface(M()).ok, true, 'positive control');
  for (const id of SERVER_IDS) for (const t of [...OPERATOR, 'activate-policy', 'rotate-agent', 'activate_release()', 'Arm', 'disarm_fund', 'flatten_all', 'halt_trading', 'custody_change', 'fundctl_status']) {
    rejects(checkMcpSurface(withTool(id, t)), O, `${id} + ${t}`);
  }
  rejects(checkMcpSurface(mut((d) => { d.servers.push({ id: 'fundctl', mode: 'narrow_write', enabled_tools: ['arm'] }); })), O, 'fundctl registered as an MCP server');
  rejects(checkMcpSurface(mut((d) => { d.operator_controls.mcp_equivalent_allowed = true; })), O, 'MCP equivalent allowed');
  rejects(checkMcpSurface(mut((d) => { delete d.operator_controls.mcp_equivalent_allowed; })), O, 'flag missing');
  rejects(checkMcpSurface(mut((d) => { d.operator_controls.surface = 'mcp'; })), O, 'surface changed');
  rejects(checkMcpSurface(mut((d) => { d.operator_controls.commands = d.operator_controls.commands.filter((c) => c !== 'rotate-agent'); })), O, 'command dropped');
  rejects(checkMcpSurface(mut((d) => { d.operator_controls.commands.push('wire-funds'); })), O, 'command added');
  rejects(checkMcpSurface(mut((d) => { d.operator_controls.extra = 1; })), O, 'extra field');
  rejects(checkMcpSurface(mut((d) => { delete d.operator_controls; })), O, 'block missing');
  assert.deepEqual(M().operator_controls.commands, ['status', 'arm', 'disarm', 'halt', 'flatten', 'activate-release', 'activate-policy', 'rotate-agent']);
  assert.ok(readJson('contracts', 'forbidden-capabilities.json').capabilities.some((c) => c.id === O && c.enforcement === 'enforced' && c.runtime_enforced_in_phase === 1));
});
