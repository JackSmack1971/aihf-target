# Architecture (Phase 0 contract)

Source: blueprint V1.1 sections 2, 3, 5, 12, 13, 16, 20, 21. Machine-readable zones: `contracts/trust-zones.json`.

## Principle

Models research, reason, propose, and monitor. Deterministic services authorize. The live-capital boundary is the deterministic authorization plus signer capability surface enforced outside model control. Codex permissions and prompt rules are defense in depth only.

## Six trust zones

| Zone | Name | Key facts |
|---|---|---|
| 0 | Human / custody root | Operator, hardware-backed master key. Funds, approves wallets, activates releases/policies, arms/disarms/halts. No AI control. |
| 1 | Codex intelligence plane | CIO and specialists, read-only data. No trading key, no raw exchange writes, no source writes, no custody actions. |
| 2 | Intent / control plane | fund-state, intent gateway, schema validation, provenance, idempotency, policy versioning. LLM output is hostile input. |
| 3 | Risk / authorization plane | riskd, reconciliation, exposure engine, breakers, ExecutionPermit issuer. |
| 4 | Execution plane | traderd, venue transport, order lifecycle, dead-man scheduling. No private key; acts only inside a permit. |
| 5 | Signing plane | signerd, agent-wallet key, nonce high-water mark, compile-time allowlist. No Codex, no MCP. |

## Flow

TradeIntent (zone 1 proposal, validated in zone 2) -> deterministic authorization in zone 3 produces a short-lived single-use ExecutionPermit -> zone 4 chooses execution details only inside the permit envelope -> zone 5 signs only canonical requests provable to be inside a valid, unexpired, unused permit.

## Contracts

- `schemas/trade-intent.schema.json`: closed shape; excludes asset index, tick/lot, nonce, cloid, raw action, final size, signature.
- `schemas/execution-permit.schema.json`: requires expiry, policy and activation hashes, single-use nonce, authorization, size and notional bounds; order types exclude market.
- `config/signer-policy.json` + `schemas/signer-policy.schema.json`: exactly SignOrder, SignCancelByCloid, SignCancelByOid, SignScheduleCancel; denied actions enumerated.
- `schemas/risk-policy.schema.json` + `config/risk-policy.template.json`: numeric limits required and unset; capability flags fixed.
- `contracts/runtime-state-machine.json`: exposure increase only in ARMED; SAFE_HALT has no edge to ARMED.
- `contracts/trade-intent-state-machine.json`: PERMITTED reachable only from AUTHORIZATION_PENDING.

## Operating modes

- Development mode: repository and Git writes; read-only market data; no intent submission; no signerd, riskd/traderd production endpoints, mainnet secret, or production ledger.
- Operations mode: read-only source and strategies; narrow-schema intent submission; no signer access, direct exchange writes, package installation, or arbitrary MCP servers.

## Non-goals

No third-party capital; no autonomous withdrawal/transfer or API-wallet/custody change; no runtime source mutation; no autonomous deployment or self-promotion; no generic exchange endpoint to Codex; no generic signer to traderd or MCP; no Co-Invest live execution in the production path.

## Out of scope for Phase 0

signerd, traderd, riskd, keys, connectivity, MCP servers, `.codex/` configuration, and numeric risk limits.
