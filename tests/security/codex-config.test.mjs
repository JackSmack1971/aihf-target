import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { readText, codexFiles, ROOT } from '../helpers.mjs';
import { parseToml } from '../../src/contracts/toml-subset.mjs';
import {
  AGENT_ROLES, BOUNDARY_CLAUSE, FEATURE_PINS, REQUIREMENTS_FEATURE_PINS, checkProjectCodex, checkFundOpsRequirements, checkProfile, expectedAuthority,
} from '../../src/contracts/codex-config-checker.mjs';

const REQ = () => readText('config', 'codex', 'requirements.fund-ops.toml');
const OPS = () => readText('config', 'codex', 'fund-ops.config.toml');
const DEV = () => readText('config', 'codex', 'fund-dev.config.toml');
const AGENT = (r) => readText('.codex', 'agents', `${r}.toml`);
const swap = (t, from, to) => {
  assert.ok(t.includes(from), `fixture anchor missing: ${from}`);
  return t.split(from).join(to);
};
// Replace one whole `key = false` line (a plain substring swap would also hit allow_browser_and_computer_use).
const swapLine = (t, key, to) => {
  const re = new RegExp(`^${key} = false\\r?$`, 'm');
  assert.ok(re.test(t), `fixture line missing: ${key}`);
  return t.replace(re, () => to);
};
// Remove one whole top-level `key = ...` line under either LF or CRLF (`.` never matches a carriage return, so the EOL is matched explicitly).
const dropLine = (t, key) => t.replace(new RegExp(`^${key} = .*(?:\r?\n|$)`, 'm'), '');
const toLF = (t) => t.replace(/\r\n/g, '\n');
const toCRLF = (t) => toLF(t).replace(/\n/g, '\r\n');
const add = (t, extra) => `${t}\n${extra}\n`;
const capsOf = (r) => [...new Set(r.violations.map((v) => v.capability))];
function rejects(r, cap, label) {
  assert.equal(r.ok, false, `${label}: must be rejected`);
  assert.ok(capsOf(r).includes(cap), `${label}: expected ${cap}, got ${capsOf(r).join(',')}`);
}
const accepts = (r, label) => assert.deepEqual(r, { ok: true, violations: [] }, `${label}: ${JSON.stringify(r.violations)}`);
const P = 'CODEX_REQUIREMENTS_POLICY';
const ID = 'CODEX_MCP_IDENTITY';
const EX = 'CODEX_MCP_TOOL_EXPOSURE';
const PR = 'CODEX_PROFILE_POLICY';
const AG = 'CODEX_AGENT_CONTRACT';
const AU = 'CODEX_AGENT_AUTHORITY';
const SU = 'CODEX_PROJECT_SURFACE';
const CI = 'CODEX_COINVEST_DIRECT_REGISTRATION';
const IV = 'CODEX_TOML_INVALID';

// ------------------------------------------------------------------ managed requirements
test('requirements: full/danger access, weaker approvals, live web and browser/computer use are each rejected', () => {
  accepts(checkFundOpsRequirements(REQ()), 'positive control');
  const R = REQ();
  const cases = [
    ['default danger', swap(R, 'default_permissions = ":read-only"', 'default_permissions = ":danger-full-access"')],
    ['default workspace', swap(R, 'default_permissions = ":read-only"', 'default_permissions = ":workspace"')],
    ['default dropped', swap(R, 'default_permissions = ":read-only"\n', '')],
    ['danger profile allowed', swap(R, '":read-only" = true\n', '":read-only" = true\n":danger-full-access" = true\n')],
    ['workspace profile allowed', swap(R, '":read-only" = true\n', '":read-only" = true\n":workspace" = true\n')],
    ['custom profile allowed', swap(R, '":read-only" = true\n', '":read-only" = true\nmine = true\n')],
    ['profile allowlist dropped (absent = unrestricted)', swap(R, '[allowed_permission_profiles]\n":read-only" = true\n', '')],
    ['legacy sandbox pin dropped', swap(R, 'allowed_sandbox_modes = ["read-only"]\n', '')],
    ['legacy sandbox danger', swap(R, 'allowed_sandbox_modes = ["read-only"]', 'allowed_sandbox_modes = ["read-only", "danger-full-access"]')],
    ['legacy sandbox workspace-write', swap(R, 'allowed_sandbox_modes = ["read-only"]', 'allowed_sandbox_modes = ["read-only", "workspace-write"]')],
    ['approval never', swap(R, 'allowed_approval_policies = ["on-request"]', 'allowed_approval_policies = ["on-request", "never"]')],
    ['approval granular', swap(R, 'allowed_approval_policies = ["on-request"]', 'allowed_approval_policies = ["granular"]')],
    ['approval dropped', swap(R, 'allowed_approval_policies = ["on-request"]\n', '')],
    ['model reviewer', swap(R, 'allowed_approvals_reviewers = ["user"]', 'allowed_approvals_reviewers = ["user", "auto_review"]')],
    ['live web', swap(R, 'allowed_web_search_modes = ["cached"]', 'allowed_web_search_modes = ["cached", "live"]')],
    ['indexed web', swap(R, 'allowed_web_search_modes = ["cached"]', 'allowed_web_search_modes = ["indexed"]')],
    ['project hooks allowed', swap(R, 'allow_managed_hooks_only = true', 'allow_managed_hooks_only = false')],
    ['browser/computer allowed', swap(R, 'allow_browser_and_computer_use = false', 'allow_browser_and_computer_use = true')],
    ['browser/computer unset', swap(R, 'allow_browser_and_computer_use = false\n', '')],
    ['unelevated sandbox', swap(R, 'allowed_sandbox_implementations = ["elevated"]', 'allowed_sandbox_implementations = ["elevated", "unelevated"]')],
  ];
  for (const [label, text] of cases) rejects(checkFundOpsRequirements(text), P, label);
  for (const k of Object.keys(REQUIREMENTS_FEATURE_PINS)) rejects(checkFundOpsRequirements(swapLine(R, k, `${k} = true`)), P, `feature ${k}=true`);
  for (const k of Object.keys(REQUIREMENTS_FEATURE_PINS)) rejects(checkFundOpsRequirements(swapLine(R, k, '')), P, `feature ${k} unpinned`);
});

test('requirements: unreviewed keys, an absent MCP table and malformed TOML are rejected', () => {
  const R = REQ();
  rejects(checkFundOpsRequirements(swap(R, '[mcp_servers]\n', '')), P, 'absent mcp_servers table leaves MCP unrestricted');
  rejects(checkFundOpsRequirements(`model_provider = "x"\n${R}`), P, 'unreviewed model_provider key');
  rejects(checkFundOpsRequirements(add(R, '[rules]\nprefix_rules = []')), P, 'unreviewed rules table');
  rejects(checkFundOpsRequirements(add(R, '[apps.x]\nenabled = true')), P, 'unreviewed apps table');
  rejects(checkFundOpsRequirements(add(R, '[marketplaces]\nrestrict_to_allowed_sources = false')), P, 'unreviewed marketplaces table');
  rejects(checkFundOpsRequirements('allowed_sandbox_modes = [\n'), IV, 'malformed');
  rejects(checkFundOpsRequirements(`default_permissions = ":read-only"\n${R}`), IV, 'duplicate key');
  rejects(checkFundOpsRequirements(add(R, '[[hooks.PreToolUse]]\nmatcher = "x"')), IV, 'array tables are unsupported');
  rejects(checkFundOpsRequirements(''), P, 'empty file');
});

// ------------------------------------------------------------------ MCP identity (authorization) vs tool exposure
const exe = '/opt/aihf/mcp/fund-state-mcp';
const goodIdentity = (id = 'fund-state-mcp') => `[mcp_servers.${id}.identity]\ncommand = { executable = "${exe}", args = [ { match = "exact", value = "serve" } ] }`;
const goodProfileServer = (id = 'fund-state-mcp', tools = '["get_fund_state", "get_risk_status"]') => `[mcp_servers.${id}]\ncommand = "${exe}"\nargs = ["serve"]\nenabled_tools = ${tools}`;

test('mcp identity: a structured exact identity is accepted; every weaker or unapproved identity is rejected', () => {
  accepts(checkFundOpsRequirements(add(REQ(), goodIdentity())), 'structured exact stdio identity (positive control)');
  accepts(checkFundOpsRequirements(add(REQ(), '[mcp_servers.fund-state-mcp.identity]\nurl = "https://127.0.0.1:8443/mcp"')), 'exact https url identity (positive control)');
  accepts(checkFundOpsRequirements(add(REQ(), '[mcp_servers.fund-state-mcp.identity]\nurl = { match = "exact", value = "http://127.0.0.1:8123/mcp" }')), 'exact loopback url (positive control)');
  accepts(checkFundOpsRequirements(add(add(REQ(), goodIdentity()), goodIdentity('intent-gateway-mcp'))), 'both approvable servers');
  const weak = {
    'bare command string (ignores args)': '[mcp_servers.fund-state-mcp.identity]\ncommand = "fund-state-mcp"',
    'prefix arg': `[mcp_servers.fund-state-mcp.identity]\ncommand = { executable = "${exe}", args = [ { match = "prefix", value = "--x=" } ] }`,
    'regex arg': `[mcp_servers.fund-state-mcp.identity]\ncommand = { executable = "${exe}", args = [ { match = "regex", expression = ".*" } ] }`,
    'no args': `[mcp_servers.fund-state-mcp.identity]\ncommand = { executable = "${exe}", args = [] }`,
    'args absent': `[mcp_servers.fund-state-mcp.identity]\ncommand = { executable = "${exe}" }`,
    'relative executable': '[mcp_servers.fund-state-mcp.identity]\ncommand = { executable = "node", args = [ { match = "exact", value = "x.js" } ] }',
    'traversal executable': '[mcp_servers.fund-state-mcp.identity]\ncommand = { executable = "/opt/../bin/sh", args = [ { match = "exact", value = "-c" } ] }',
    'url prefix': '[mcp_servers.fund-state-mcp.identity]\nurl = { match = "prefix", value = "https://example.com/" }',
    'url regex': '[mcp_servers.fund-state-mcp.identity]\nurl = { match = "regex", expression = "https://.*" }',
    'url wildcard': '[mcp_servers.fund-state-mcp.identity]\nurl = "https://*.example.com/mcp"',
    'plain http non-loopback': '[mcp_servers.fund-state-mcp.identity]\nurl = "http://example.com/mcp"',
    'both command and url': `[mcp_servers.fund-state-mcp.identity]\nurl = "https://127.0.0.1/mcp"\ncommand = { executable = "${exe}", args = [ { match = "exact", value = "serve" } ] }`,
    'empty identity': '[mcp_servers.fund-state-mcp.identity]',
    'extra entry key': `${goodIdentity()}\n[mcp_servers.fund-state-mcp]\nenabled_tools = ["get_fund_state"]`,
  };
  for (const [label, block] of Object.entries(weak)) rejects(checkFundOpsRequirements(add(REQ(), block)), ID, label);
  for (const id of ['evil-mcp', 'fundctl', 'coinvest-paper-adapter', 'fin-data-mcp', 'massive-mcp', 'hyperliquid-info-mcp', 'openrouter-committee-mcp']) {
    rejects(checkFundOpsRequirements(add(REQ(), goodIdentity(id))), ID, `unapproved or empty-allowlist server ${id}`);
  }
  rejects(checkFundOpsRequirements(add(REQ(), goodIdentity('coinvest-intelligence-mcp'))), ID, 'provisional Co-Invest proxy stays unregistered until Phase 2 grounds its schema');
  rejects(checkFundOpsRequirements(add(REQ(), '[mcp_servers.fund-state-mcp.identity]\nurl = "https://coinvest-computer.liquid.trade/mcp"')), CI, 'direct Co-Invest upstream');
  rejects(checkFundOpsRequirements(add(REQ(), '[mcp_servers.fund-state-mcp.identity]\nurl = "https://coinvest-main.example.com/mcp"')), CI, 'Co-Invest Main endpoint');
  rejects(checkFundOpsRequirements(add(REQ(), `[mcp_servers.fund-state-mcp.identity]\ncommand = { executable = "${exe}", args = [ { match = "exact", value = "https://coinvest-restricted.example.com" } ] }`)), CI, 'Co-Invest Restricted in args');
});

test('mcp exposure: unmanaged servers fail closed and tool allowlists are never default-open', () => {
  const R = add(REQ(), goodIdentity());
  accepts(checkProfile('fund-ops', add(OPS(), goodProfileServer()), R), 'managed identity + non-empty allowlist (positive control)');
  accepts(checkProfile('fund-ops', add(OPS(), goodProfileServer('fund-state-mcp', '["get_fund_state"]')), R), 'single tool (positive control)');
  // unmanaged: no identity at all, or the shipped empty allowlist
  rejects(checkProfile('fund-ops', add(OPS(), goodProfileServer()), REQ()), ID, 'server registered but requirements allowlist is empty');
  rejects(checkProfile('fund-ops', add(OPS(), goodProfileServer()), add(REQ(), goodIdentity('intent-gateway-mcp'))), ID, 'identity exists only for another server');
  rejects(checkProfile('fund-ops', add(OPS(), goodProfileServer())), ID, 'no requirements supplied: nothing is managed');
  rejects(checkProfile('fund-ops', add(OPS(), goodProfileServer('evil-mcp')), R), ID, 'unknown server name');
  rejects(checkProfile('fund-ops', add(OPS(), goodProfileServer('coinvest-intelligence-mcp', '["analyze_market"]')), R), ID, 'provisional Co-Invest proxy');
  rejects(checkProfile('fund-ops', add(OPS(), goodProfileServer('fin-data-mcp', '["analyze_market"]')), R), ID, 'server with an empty section 9 allowlist');
  // identity drift: the configured launch differs from the managed identity
  rejects(checkProfile('fund-ops', add(OPS(), swap(goodProfileServer(), 'args = ["serve"]', 'args = ["serve", "--extra"]')), R), ID, 'extra arg');
  rejects(checkProfile('fund-ops', add(OPS(), swap(goodProfileServer(), `command = "${exe}"`, 'command = "/opt/aihf/mcp/other"')), R), ID, 'other executable');
  rejects(checkProfile('fund-ops', add(OPS(), '[mcp_servers.fund-state-mcp]\nurl = "https://127.0.0.1:9/mcp"\nenabled_tools = ["get_fund_state"]'), R), ID, 'url where a command identity exists');
  // default-open and over-broad exposure
  const noTools = `[mcp_servers.fund-state-mcp]\ncommand = "${exe}"\nargs = ["serve"]`;
  rejects(checkProfile('fund-ops', add(OPS(), noTools), R), EX, 'no enabled_tools (exposes every tool)');
  rejects(checkProfile('fund-ops', add(OPS(), goodProfileServer('fund-state-mcp', '[]')), R), EX, 'empty enabled_tools');
  rejects(checkProfile('fund-ops', add(OPS(), `${noTools}\ndisabled_tools = ["get_fund_state"]`), R), EX, 'deny-list only');
  rejects(checkProfile('fund-ops', add(OPS(), goodProfileServer('fund-state-mcp', '["get_fund_state", "get_fund_state"]')), R), EX, 'duplicate tool');
  rejects(checkProfile('fund-ops', add(OPS(), goodProfileServer('fund-state-mcp', '["*"]')), R), EX, 'wildcard tool');
  for (const t of ['submit_trade_intent', 'place_order', 'withdraw', 'sign', 'read_secret', 'arm', 'activate_policy', 'analyze_market', 'get_something_new']) {
    rejects(checkProfile('fund-ops', add(OPS(), goodProfileServer('fund-state-mcp', `["get_fund_state", "${t}"]`)), R), EX, `fund-state-mcp + ${t}`);
  }
  for (const t of ['get_fund_state', 'place_order', 'modify_order', 'cancel_order', 'withdraw', 'transfer', 'sign', 'raw_exchange_action', 'arm_mainnet', 'read_secret', 'change_risk_limit']) {
    rejects(checkProfile('fund-ops', add(OPS(), goodProfileServer('intent-gateway-mcp', `["${t}"]`)), add(REQ(), goodIdentity('intent-gateway-mcp'))), EX, `intent-gateway-mcp + ${t}`);
  }
  accepts(checkProfile('fund-ops', add(OPS(), goodProfileServer('intent-gateway-mcp', '["submit_trade_intent", "expire_trade_intent", "request_reduce_exposure"]')), add(REQ(), goodIdentity('intent-gateway-mcp'))), 'intent gateway narrow surface (positive control)');
  // secret-bearing or ambient-authority keys are not allowed in the version-controlled profile
  for (const extra of ['env = { TOKEN = "x" }', 'env_vars = ["TOKEN"]', 'cwd = "/"', 'http_headers = { a = "b" }', 'bearer_token_env_var = "T"', 'scopes = ["x"]', 'experimental_environment = "x"']) {
    rejects(checkProfile('fund-ops', add(OPS(), `${goodProfileServer()}\n${extra}`), R), EX, `server key ${extra}`);
  }
  rejects(checkProfile('fund-ops', add(OPS(), `${goodProfileServer()}\nurl = "https://127.0.0.1/mcp"`), R), EX, 'both command and url');
  rejects(checkProfile('fund-ops', add(OPS(), '[mcp_servers.fund-state-mcp]\nurl = "https://coinvest-computer.liquid.trade/mcp"\nenabled_tools = ["get_fund_state"]'), add(REQ(), '[mcp_servers.fund-state-mcp.identity]\nurl = "https://127.0.0.1/mcp"')), CI, 'direct Co-Invest upstream in a profile');
});

// ------------------------------------------------------------------ profiles
test('profile check validates the requirements it trusts (weak or malformed identities cannot legitimise a server)', () => {
  const weak = `[mcp_servers.fund-state-mcp.identity]
command = { executable = "${exe}", args = [ { match = "prefix", value = "serve" } ] }`;
  rejects(checkProfile('fund-ops', add(OPS(), goodProfileServer()), add(REQ(), weak)), ID, 'prefix identity in requirements');
  const noArgs = `[mcp_servers.fund-state-mcp.identity]
command = { executable = "${exe}" }`;
  rejects(checkProfile('fund-ops', add(OPS(), goodProfileServer()), add(REQ(), noArgs)), ID, 'identity without args must not throw');
  rejects(checkProfile('fund-ops', OPS(), swap(REQ(), 'default_permissions = ":read-only"', 'default_permissions = ":danger-full-access"')), P, 'weakened requirements are reported through the profile check');
});
test('fund-ops profile cannot request forbidden local authority or weaken the defaults', () => {
  accepts(checkProfile('fund-ops', OPS(), REQ()), 'positive control');
  const O = OPS();
  const cases = [
    ['sandbox_mode key (legacy path)', `sandbox_mode = "danger-full-access"\n${O}`],
    ['sandbox_mode read-only key (still switches the mechanism)', `sandbox_mode = "read-only"\n${O}`],
    ['danger default', swap(O, 'default_permissions = ":read-only"', 'default_permissions = ":danger-full-access"')],
    ['workspace default', swap(O, 'default_permissions = ":read-only"', 'default_permissions = ":workspace"')],
    ['custom profile name', swap(O, 'default_permissions = ":read-only"', 'default_permissions = "mine"')],
    ['approval never', swap(O, 'approval_policy = "on-request"', 'approval_policy = "never"')],
    ['approval untrusted (retired)', swap(O, 'approval_policy = "on-request"', 'approval_policy = "untrusted"')],
    ['model reviewer', swap(O, 'approvals_reviewer = "user"', 'approvals_reviewer = "auto_review"')],
    ['live web', swap(O, 'web_search = "cached"', 'web_search = "live"')],
    ['permissions table', add(O, '[permissions.mine]\nextends = ":workspace"')],
    ['profile selector', `profile = "fund-dev"\n${O}`],
    ['legacy profiles table', add(O, '[profiles.x]\nmodel = "x"')],
    ['project trust table', add(O, '[projects."C:/x"]\ntrust_level = "trusted"')],
    ['hooks', add(O, '[hooks]\nmanaged_dir = "/x"')],
    ['model provider', `model_provider = "x"\n${O}`],
    ['shell environment', add(O, '[shell_environment_policy]\ninherit = "all"')],
    ['sandbox_workspace_write', add(O, '[sandbox_workspace_write]\nnetwork_access = true')],
    ['features dropped', swap(O, /\[features\][\s\S]*?(?=\n# MCP)/.exec(O)[0], '')],
  ];
  for (const [label, text] of cases) rejects(checkProfile('fund-ops', text, REQ()), PR, label);
  for (const k of Object.keys(FEATURE_PINS)) rejects(checkProfile('fund-ops', swapLine(O, k, `${k} = true`), REQ()), PR, `feature ${k}=true`);
  rejects(checkProfile('fund-ops', 'x = ', REQ()), IV, 'malformed');
  rejects(checkProfile('fund-ops', O, 'x = '), IV, 'malformed requirements');
  rejects(checkProfile('other', OPS(), REQ()), PR, 'unknown kind');
});

test('fund-dev profile has no production authority: no full access, no never-approvals, no intent/signer surface', () => {
  accepts(checkProfile('fund-dev', DEV()), 'positive control');
  accepts(checkProfile('fund-dev', swap(DEV(), 'default_permissions = ":workspace"', 'default_permissions = ":read-only"')), 'read-only dev (positive control)');
  const D = DEV();
  const cases = [
    ['danger default', swap(D, 'default_permissions = ":workspace"', 'default_permissions = ":danger-full-access"')],
    ['approval never', swap(D, 'approval_policy = "on-request"', 'approval_policy = "never"')],
    ['model reviewer', swap(D, 'approvals_reviewer = "user"', 'approvals_reviewer = "auto_review"')],
    ['live web', swap(D, 'web_search = "cached"', 'web_search = "live"')],
    ['sandbox_mode key', `sandbox_mode = "danger-full-access"\n${D}`],
    ['features table', add(D, '[features]\nplugins = true')],
    ['profile selector', `profile = "fund-ops"\n${D}`],
  ];
  for (const [label, text] of cases) rejects(checkProfile('fund-dev', text), PR, label);
  rejects(checkProfile('fund-dev', add(D, goodProfileServer('intent-gateway-mcp', '["submit_trade_intent"]'))), ID, 'intent gateway in dev (intent submission DISABLED)');
  rejects(checkProfile('fund-dev', add(D, goodProfileServer('fund-state-mcp'))), ID, 'production fund-state server in dev (no riskd/ledger surface in the dev plane)');
  rejects(checkProfile('fund-dev', add(D, `[mcp_servers.fund-state-mcp]
url = "https://prod.example.com/mcp"
enabled_tools = ["get_risk_status"]`)), ID, 'fund-state pointed at a production URL');
  rejects(checkProfile('fund-dev', add(D, goodProfileServer('coinvest-intelligence-mcp', '["analyze_market"]'))), ID, 'provisional proxy in dev');
  for (const id of ['signerd', 'traderd', 'riskd', 'signer-mcp', 'coinvest-paper-adapter', 'coinvest-computer-mcp']) {
    rejects(checkProfile('fund-dev', add(D, goodProfileServer(id, '["x"]'))), ID, `dev server ${id}`);
  }
});

// ------------------------------------------------------------------ project agents
const real = () => codexFiles(ROOT);
const withAgent = (role, text) => ({ ...real(), [`.codex/agents/${role}.toml`]: text });
const agentDoc = (role) => parseToml(AGENT(role));
const tomlString = (s) => `"""\n${s}\n"""`;
const rebuild = (role, instructions) => `name = "${role}"\ndescription = "d${'x'.repeat(20)}"\ndeveloper_instructions = ${tomlString(instructions)}\n`;
const instr = (role) => agentDoc(role).developer_instructions;

test('agents: required-field removal is rejected under LF and CRLF input, and the real files pass under both', () => {
  const base = AGENT('risk');
  for (const [eol, conv] of [['LF', toLF], ['CRLF', toCRLF]]) {
    const b = conv(base);
    assert.equal(b.includes('\r'), eol === 'CRLF', `${eol} fixture has the intended line endings`);
    accepts(checkProjectCodex(withAgent('risk', b)), `${eol} positive control`);
    for (const key of ['description', 'name']) {
      const m = dropLine(b, key);
      assert.notEqual(m, b, `${eol}: ${key} line was actually removed`);
      rejects(checkProjectCodex(withAgent('risk', m)), AG, `${eol}: ${key} missing`);
    }
  }
  for (const role of AGENT_ROLES) {
    accepts(checkProjectCodex(withAgent(role, toLF(AGENT(role)))), `${role} LF`);
    accepts(checkProjectCodex(withAgent(role, toCRLF(AGENT(role)))), `${role} CRLF`);
  }
});

test('gitattributes: .codex/** is pinned to LF and no blanket line-ending rule exists', () => {
  const rules = readFileSync(join(ROOT, '.gitattributes'), 'utf8').split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith('#'));
  assert.ok(rules.some((l) => l.split(/\s+/).join(' ') === '.codex/** text eol=lf'), '.codex/** text eol=lf present');
  assert.ok(!rules.some((l) => /^\*(\s|$)/.test(l)), 'no repository-wide `*` attribute rule');
});

test('agents: extra keys (sandbox, MCP, model, permissions, approvals, features, hooks, skills) are rejected', () => {
  accepts(checkProjectCodex(real()), 'positive control');
  const base = AGENT('risk');
  const injected = ['sandbox_mode = "danger-full-access"', 'model = "x"', 'model_reasoning_effort = "high"', 'approval_policy = "never"', 'default_permissions = ":danger-full-access"',
    'web_search = "live"', 'mcp_servers = {}', 'skills = {}', 'features = {}', 'hooks = {}', 'permissions = {}', 'tools = {}', 'nickname_candidates = ["x"]'];
  for (const line of injected) rejects(checkProjectCodex(withAgent('risk', `${line}\n${base}`)), AG, line);
  rejects(checkProjectCodex(withAgent('risk', `${base}\n[mcp_servers.x]\ncommand = "x"`)), AG, 'mcp_servers table');
  rejects(checkProjectCodex(withAgent('risk', `${base}\n[permissions.x]\nextends = ":workspace"`)), AG, 'permissions table');
  rejects(checkProjectCodex(withAgent('risk', swap(base, 'name = "risk"', 'name = "other"'))), AG, 'name differs from file');
  rejects(checkProjectCodex(withAgent('risk', dropLine(base, 'description'))), AG, 'description missing');
  rejects(checkProjectCodex(withAgent('risk', dropLine(base, 'name'))), AG, 'name missing');
  rejects(checkProjectCodex(withAgent('risk', `name = "risk"\ndescription = "${'x'.repeat(301)}"\ndeveloper_instructions = ${tomlString(instr('risk'))}\n`)), AG, 'long description');
  rejects(checkProjectCodex(withAgent('risk', rebuild('risk', 'x'.repeat(3001)))), AG, 'oversized instructions');
  rejects(checkProjectCodex(withAgent('risk', 'name = "risk"')), AG, 'incomplete file');
  rejects(checkProjectCodex(withAgent('risk', 'x')), IV, 'not TOML');
  rejects(checkProjectCodex(withAgent('risk', swap(base, 'description = "', 'description = "see https://example.com '))), AG, 'URL in description');
});

test('agents: boundary clause and the section 8 authority row cannot be altered, duplicated or escalated', () => {
  for (const role of AGENT_ROLES) {
    const i = instr(role);
    rejects(checkProjectCodex(withAgent(role, rebuild(role, i.replace(BOUNDARY_CLAUSE, '')))), AG, `${role}: boundary removed`);
    rejects(checkProjectCodex(withAgent(role, rebuild(role, i.replace('Never sign anything.', 'Signing is allowed.')))), AG, `${role}: boundary altered`);
    rejects(checkProjectCodex(withAgent(role, rebuild(role, i.replace(expectedAuthority(role), '')))), AU, `${role}: authority line removed`);
    rejects(checkProjectCodex(withAgent(role, rebuild(role, `${i}\n${expectedAuthority(role)}`))), AU, `${role}: authority line duplicated`);
    for (const [k, v] of [['sign', 'yes'], ['key_access', 'yes'], ['policy_change', 'yes'], ['transfer', 'yes'], ['coinvest_writes', 'yes'], ['market_data', 'write']]) {
      const line = expectedAuthority(role).replace(new RegExp(`${k}=\\w+`), `${k}=${v}`);
      rejects(checkProjectCodex(withAgent(role, rebuild(role, i.replace(expectedAuthority(role), line)))), AU, `${role}: ${k}=${v}`);
    }
  }
  rejects(checkProjectCodex(withAgent('data', rebuild('data', `${instr('data')}
 Authority: sign=yes`))), AU, 'whitespace-prefixed second Authority line');
  // exactly one role holds each unique authority; flipping any other row is rejected
  for (const [role, k] of [['data', 'submit_intent'], ['macro', 'submit_intent'], ['risk', 'submit_intent'], ['execution', 'submit_intent'], ['pm', 'risk_verdict'],
    ['data', 'risk_verdict'], ['pm', 'exec_recommendation'], ['risk', 'exec_recommendation'], ['execution', 'coinvest_read'], ['data', 'openrouter'], ['auditor', 'scratch']]) {
    const line = expectedAuthority(role).replace(new RegExp(`${k}=(yes|no)`), (m, cur) => `${k}=${cur === 'yes' ? 'no' : 'yes'}`);
    rejects(checkProjectCodex(withAgent(role, rebuild(role, instr(role).replace(expectedAuthority(role), line)))), AU, `${role}: flipped ${k}`);
  }
});

test('agents: instructions outside the pinned clause cannot reference out-of-vocabulary tools, endpoints, secrets or operator controls', () => {
  const add2 = (role, text) => withAgent(role, rebuild(role, `${instr(role)}\n${text}`));
  accepts(checkProjectCodex(add2('pm', 'You may use submit_trade_intent when enabled.')), 'pm may name an intent-gateway tool (positive control)');
  accepts(checkProjectCodex(add2('risk', 'Read get_fund_state and get_risk_status.')), 'read tools (positive control)');
  for (const t of ['place_order', 'withdraw_funds', 'raw_exchange_action', 'sign_payload', 'arm_mainnet', 'read_secret', 'some_new_tool', 'activate_policy']) {
    rejects(checkProjectCodex(add2('pm', `Call ${t}.`)), AG, `unknown identifier ${t}`);
  }
  for (const role of AGENT_ROLES.filter((r) => r !== 'pm')) {
    for (const t of ['submit_trade_intent', 'expire_trade_intent', 'request_reduce_exposure']) rejects(checkProjectCodex(add2(role, `Use ${t}.`)), AU, `${role} references ${t}`);
  }
  rejects(checkProjectCodex(add2('execution', 'Use analyze_market for context.')), AU, 'execution referencing a Co-Invest tool');
  accepts(checkProjectCodex(add2('structure', 'Use analyze_market for context.')), 'structure may reference a Co-Invest read tool (positive control)');
  for (const text of ['See https://example.com/x', 'Use http://127.0.0.1/mcp', 'Endpoint coinvest-computer is fine', 'Use liquid.trade', 'Ask fundctl to arm', 'Use the private key', 'Store the seed phrase',
    'The mnemonic is below', 'api wallet secret', `0x${'a'.repeat(40)}`, ['-----BEGIN', 'PRIVATE', 'KEY-----'].join(' ')]) {
    assert.equal(checkProjectCodex(add2('data', text)).ok, false, text);
  }
});

test('project surface: any other .codex file, a missing reviewed file, or config drift is rejected', () => {
  const f = real();
  accepts(checkProjectCodex(f), 'positive control');
  for (const extra of ['.codex/hooks.json', '.codex/rules/x.rules', '.codex/agents/extra.toml', '.codex/skills/x/SKILL.md', '.codex/Config.toml', '.codex/agents/DATA.toml', '.codex/agents/pm.toml.bak', '.codex/profiles/x.toml']) {
    rejects(checkProjectCodex({ ...f, [extra]: 'x' }), SU, extra);
  }
  for (const file of Object.keys(f)) {
    const g = { ...f };
    delete g[file];
    rejects(checkProjectCodex(g), SU, `missing ${file}`);
  }
  const cfg = (extra) => `[agents]\nenabled = true\nmax_concurrent_threads_per_session = 4\n${extra}\n`;
  for (const extra of ['sandbox_mode = "danger-full-access"', '[features]\nplugins = true', '[mcp_servers.x]\ncommand = "x"', 'approval_policy = "never"', 'default_permissions = ":danger-full-access"',
    'profile = "fund-dev"', '[hooks]\nmanaged_dir = "/x"', '[permissions.x]\nextends = ":workspace"']) {
    rejects(checkProjectCodex({ ...f, '.codex/config.toml': cfg(extra) }), SU, extra);
  }
  rejects(checkProjectCodex({ ...f, '.codex/config.toml': '[agents]\nenabled = true\nmax_concurrent_threads_per_session = 9\n' }), SU, 'thread cap raised');
  rejects(checkProjectCodex({ ...f, '.codex/config.toml': '[agents]\nenabled = false\nmax_concurrent_threads_per_session = 4\n' }), SU, 'agents disabled');
  rejects(checkProjectCodex({ ...f, '.codex/config.toml': '[agents]\nenabled = true\nmax_threads = 4\n' }), SU, 'legacy alias');
  rejects(checkProjectCodex(null), SU, 'malformed map');
});
