import test from 'node:test';
import assert from 'node:assert/strict';
import { readJson, denyTest, clone } from '../helpers.mjs';
import { checkGovernance } from '../../src/contracts/trust-zone-checker.mjs';

const G = () => readJson('contracts', 'governance.json');
const mut = (fn) => { const d = clone(G()); fn(d); return d; };
const capsOf = (r) => [...new Set(r.violations.map((v) => v.capability))];
function rejects(r, cap, label) {
  assert.equal(r.ok, false, `${label}: must be rejected`);
  assert.ok(capsOf(r).includes(cap), `${label}: expected ${cap}, got ${capsOf(r).join(',')}`);
}
const actor = (d, id) => d.actors.find((a) => a.id === id);
const grant = (id, authority) => mut((d) => { actor(d, id).allowed_authorities.push(authority); });
const ALL = ['GOV_LLM_CHANGES_RISK_POLICY', 'GOV_EXECUTOR_CHANGES_POLICY', 'GOV_AI_RISK_OFFICER_EXECUTES', 'GOV_MCP_EXPANSION_WIDENS_ALLOWLIST'];
const FORBIDDEN_AUTH = { GOV_LLM_CHANGES_RISK_POLICY: 'change_active_risk_policy', GOV_EXECUTOR_CHANGES_POLICY: 'change_policy', GOV_AI_RISK_OFFICER_EXECUTES: 'execute_order', GOV_MCP_EXPANSION_WIDENS_ALLOWLIST: 'widen_production_allowlist' };
const SYNONYMS = ['risk_policy_update', 'edit_policy', 'set_limits', 'raise_max_leverage', 'close_position', 'flatten_position', 'order_execute', 'register_tool',
  'Change_Policy', ' change_policy', 'change_policy ', 'update_allowlist', '*', 'all', 'admin', ''];
const CLASS_OF = { 'codex-cio': 'llm', 'committee-member': 'llm', traderd: 'executor', 'ai-risk-officer': 'ai_risk_officer', 'remote-mcp-server': 'mcp_server' };
const CAP_OF = { llm: ALL[0], executor: ALL[1], ai_risk_officer: ALL[2], mcp_server: ALL[3] };

test('governance: shipped contract is accepted and is a closed per-actor allowlist over a closed vocabulary', () => {
  assert.deepEqual(checkGovernance(G()), { ok: true, violations: [] });
  const d = G();
  assert.deepEqual(d.forbidden.map((f) => f.id).sort(), [...ALL].sort());
  for (const a of d.actors) {
    assert.equal(a.class, CLASS_OF[a.id], a.id);
    for (const x of a.allowed_authorities) assert.ok(d.authority_vocabulary.includes(x), `${a.id}: ${x} in vocabulary`);
    for (const f of Object.values(FORBIDDEN_AUTH)) assert.ok(!a.allowed_authorities.includes(f), `${a.id} must not hold ${f}`);
  }
  assert.equal('grants' in d, false, 'no open-ended grants list remains');
  for (const bad of [null, {}, { actors: [], forbidden: [], authority_vocabulary: 'x' }, { actors: [], forbidden: [] }]) assert.equal(checkGovernance(bad).ok, false);
});

function tableMutations(id, cls, actorId) {
  const row = (d) => d.forbidden.find((f) => f.id === id);
  rejects(checkGovernance(mut((d) => { d.forbidden = d.forbidden.filter((f) => f.id !== id); })), id, 'row removed');
  rejects(checkGovernance(mut((d) => { d.forbidden.push(clone(row(d))); })), id, 'row duplicated');
  rejects(checkGovernance(mut((d) => { row(d).actor_class = 'someone_else'; })), id, 'row retargeted to another class');
  rejects(checkGovernance(mut((d) => { row(d).pattern = '^$'; })), id, 'weakened pattern');
  rejects(checkGovernance(mut((d) => { row(d).pattern = '('; })), id, 'invalid pattern');
  rejects(checkGovernance(mut((d) => { row(d).authority = 'something_else'; })), id, 'authority renamed');
  rejects(checkGovernance(mut((d) => { row(d).enabled = false; })), id, 'extra field on a row');
  rejects(checkGovernance(mut((d) => { d.forbidden.push({ id: 'GOV_EXTRA', actor_class: cls, authority: 'x', pattern: 'x', blueprint_ref: 'x' }); })), id, 'unrecognized extra row');
  // reclassification dodges: unknown class, another valid class, or a placeholder actor keeping the class populated
  rejects(checkGovernance(mut((d) => { for (const a of d.actors) if (a.class === cls) a.class = 'placeholder'; })), id, 'reclassified to an unknown class');
  rejects(checkGovernance(mut((d) => { actor(d, actorId).class = 'human'; })), id, 'reclassified to human');
  rejects(checkGovernance(mut((d) => { actor(d, actorId).class = cls === 'llm' ? 'executor' : 'llm'; })), id, 'reclassified to another valid class');
  rejects(checkGovernance(mut((d) => { actor(d, actorId).class = 'placeholder'; d.actors.push({ id: 'stub', class: cls, allowed_authorities: [] }); })), id, 'placeholder reclassification with a stub keeping the class populated');
  rejects(checkGovernance(mut((d) => { d.actors = d.actors.filter((a) => a.id !== actorId); d.actors.push({ id: 'stub', class: cls, allowed_authorities: [] }); })), id, 'pinned actor replaced by a stub');
  // vocabulary is closed and pinned
  rejects(checkGovernance(mut((d) => { d.authority_vocabulary.push('register_tool'); })), id, 'vocabulary widened');
  rejects(checkGovernance(mut((d) => { d.authority_vocabulary.pop(); })), id, 'vocabulary shrunk');
  // allowlist hygiene
  rejects(checkGovernance(mut((d) => { actor(d, actorId).allowed_authorities.push(actor(d, actorId).allowed_authorities[0]); })), id, 'duplicate authority');
  rejects(checkGovernance(mut((d) => { actor(d, actorId).extra = 1; })), id, 'extra actor field');
  rejects(checkGovernance(mut((d) => { delete actor(d, actorId).allowed_authorities; })), id, 'allowlist missing');
  rejects(checkGovernance(mut((d) => { d.actors.push(clone(actor(d, actorId))); })), id, 'duplicate actor id');
  // synonyms, wildcards and case/whitespace variants never pass, for every actor
  for (const s of SYNONYMS) rejects(checkGovernance(grant(actorId, s)), id, `${actorId} granted "${s}"`);
  // forbidden authorities never appear in any non-human actor's allowlist
  for (const [fid, fa] of Object.entries(FORBIDDEN_AUTH)) rejects(checkGovernance(grant(actorId, fa)), fid, `${actorId} granted ${fa}`);
  // authorities permitted for another class are not permitted here
  for (const other of Object.keys(CAP_OF).filter((c) => c !== cls)) {
    const o = G().actors.find((a) => a.class === other).allowed_authorities[0];
    rejects(checkGovernance(grant(actorId, o)), id, `${actorId} granted ${other}'s authority ${o}`);
  }
  assert.equal(checkGovernance(G()).ok, true, 'positive control');
}

denyTest('DENY-GOV-LLM-RISK-POLICY', () => {
  for (const a of ['change_active_risk_policy', 'activate_risk_policy', 'update_policy', 'override_risk_policy', 'write_policy_file']) {
    rejects(checkGovernance(grant('codex-cio', a)), 'GOV_LLM_CHANGES_RISK_POLICY', `codex-cio ${a}`);
    rejects(checkGovernance(grant('committee-member', a)), 'GOV_LLM_CHANGES_RISK_POLICY', `committee-member ${a}`);
  }
  // intra-class widening is rejected: every actor's allowlist is pinned exactly
  for (const [id, auth] of [['committee-member', 'submit_trade_intent'], ['committee-member', 'propose_risk_policy_change'], ['codex-cio', 'produce_research_opinion']]) {
    rejects(checkGovernance(grant(id, auth)), 'GOV_LLM_CHANGES_RISK_POLICY', `${id} widened with ${auth}`);
  }
  rejects(checkGovernance(mut((d) => { actor(d, 'codex-cio').allowed_authorities = ['submit_trade_intent']; })), 'GOV_LLM_CHANGES_RISK_POLICY', 'codex-cio narrowed (allowlist must equal the pinned list)');
  rejects(checkGovernance(mut((d) => { d.actors.push({ id: 'new-llm', class: 'llm', allowed_authorities: ['produce_research_opinion'] }); })), 'GOV_LLM_CHANGES_RISK_POLICY', 'unpinned llm actor');
  tableMutations('GOV_LLM_CHANGES_RISK_POLICY', 'llm', 'codex-cio');
  tableMutations('GOV_LLM_CHANGES_RISK_POLICY', 'llm', 'committee-member');
});
denyTest('DENY-GOV-EXECUTOR-POLICY', () => {
  for (const a of ['change_policy', 'modify_risk_policy', 'activate_policy', 'set_limits']) rejects(checkGovernance(grant('traderd', a)), 'GOV_EXECUTOR_CHANGES_POLICY', `traderd ${a}`);
  tableMutations('GOV_EXECUTOR_CHANGES_POLICY', 'executor', 'traderd');
});
denyTest('DENY-GOV-AI-RISK-OFFICER-EXECUTES', () => {
  for (const a of ['execute_order', 'submit_order', 'place_order', 'cancel_order', 'sign_action', 'send_order', 'order_execute', 'close_position', 'flatten_position']) {
    rejects(checkGovernance(grant('ai-risk-officer', a)), 'GOV_AI_RISK_OFFICER_EXECUTES', `ai-risk-officer ${a}`);
  }
  tableMutations('GOV_AI_RISK_OFFICER_EXECUTES', 'ai_risk_officer', 'ai-risk-officer');
});
denyTest('DENY-GOV-MCP-ALLOWLIST-WIDENING', () => {
  for (const a of ['widen_production_allowlist', 'expand_allowlist', 'add_tool_to_allowlist', 'auto_register_capability', 'register_tool', 'update_allowlist']) {
    rejects(checkGovernance(grant('remote-mcp-server', a)), 'GOV_MCP_EXPANSION_WIDENS_ALLOWLIST', `remote-mcp-server ${a}`);
  }
  tableMutations('GOV_MCP_EXPANSION_WIDENS_ALLOWLIST', 'mcp_server', 'remote-mcp-server');
});

test('governance: unpinned actors are rejected, especially class human holding policy or allowlist authority', () => {
  for (const [auth, id] of [['change_active_risk_policy', 'GOV_LLM_CHANGES_RISK_POLICY'], ['widen_production_allowlist', 'GOV_MCP_EXPANSION_WIDENS_ALLOWLIST']]) {
    for (const name of ['operator', 'human-admin', 'stub', 'codex-cio-2']) {
      const r = checkGovernance(mut((d) => { d.actors.push({ id: name, class: 'human', allowed_authorities: [auth] }); }));
      assert.equal(r.ok, false, `unpinned human ${name} holding ${auth} must be rejected`);
      assert.ok(capsOf(r).length > 0);
    }
  }
  assert.equal(checkGovernance(mut((d) => { d.actors.push({ id: 'operator', class: 'human', allowed_authorities: [] }); })).ok, false, 'even an empty unpinned human actor');
  assert.equal(checkGovernance(mut((d) => { actor(d, 'codex-cio').class = 'human'; actor(d, 'codex-cio').allowed_authorities.push('change_active_risk_policy'); })).ok, false, 'pinned actor promoted to human');
  assert.equal(checkGovernance(G()).ok, true, 'positive control');
});
