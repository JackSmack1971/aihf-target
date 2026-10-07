# aihf-target

Codex target repository for the AI Hedge Fund Control Plane (blueprint v1.1). Current scope: Phase 0 constitutional contracts and threat model, plus the Phase 1 Codex configuration layer (project agents, user profiles, managed requirements). There is no runtime, no key material, no network access, and no exchange connectivity here.

## Layout

- `AGENTS.md` - Codex operating contract.
- `.codex/` - reviewed project Codex surface only: `config.toml` (`[agents]` limits) and nine role files.
- `docs/` - architecture and threat model.
- `contracts/` - trust zones, threat model, state machines, forbidden-capability registry.
- `schemas/` - closed-shape schemas: TradeIntent, ExecutionPermit, RiskPolicy, SignerPolicy.
- `config/` - signer policy and the risk-policy template (numeric limits intentionally `null`).
- `config/codex/` - `fund-dev`/`fund-ops` profiles and the managed requirements for fund-ops; operator-installed (see its README).
- `src/contracts/` - zero-dependency schema validator, state-machine loader and Codex-config checker (fail closed).
- `tests/` - conformance and security denial tests; `tests/live/` holds the opt-in live Codex verifier (not run by `node --test`).

## Test

    node --test

Requires Node 22 or newer. No install step.
