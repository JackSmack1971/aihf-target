# aihf-target

Codex target repository for the AI Hedge Fund Control Plane (blueprint v1.1). Current scope: Phase 0, constitutional contracts and threat model. There is no runtime, no key material, no network access, and no exchange connectivity here.

## Layout

- `AGENTS.md` - Codex operating contract.
- `docs/` - architecture and threat model.
- `contracts/` - trust zones, threat model, state machines, forbidden-capability registry.
- `schemas/` - closed-shape schemas: TradeIntent, ExecutionPermit, RiskPolicy, SignerPolicy.
- `config/` - signer policy and the risk-policy template (numeric limits intentionally `null`).
- `src/contracts/` - zero-dependency schema validator and state-machine loader (fail closed).
- `tests/` - conformance and security denial tests.

## Test

    node --test

Requires Node 22 or newer. No install step.
