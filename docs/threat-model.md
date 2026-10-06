# Threat model (Phase 0 contract)

Source: blueprint V1.1 section 31. Machine-readable form: `contracts/threat-model.json` (authoritative for tests).
Every threat maps to a deterministic expected safe state. Phase 0 defines the contract; the "Phase" column names where enforcement is built.

Safe states: `REJECT_INPUT`, `BLOCK_NEW_EXPOSURE`, `DEGRADED`, `SAFE_HALT`, `FAIL_CLOSED_REBUILD`, `DENY_CAPABILITY`, `RECONCILE_BEFORE_RETRY`.

## Prompt/data attacks

| ID | Threat | Expected safe state | Enforced in phase |
|---|---|---|---|
| PD-01 | Malicious news/article text instructing agents to call tools | `REJECT_INPUT` | 4 |
| PD-02 | Prompt injection returned by an MCP server | `REJECT_INPUT` | 2 |
| PD-03 | Model committee attempting to smuggle tool instructions | `REJECT_INPUT` | 5 |
| PD-04 | Malicious token metadata or symbol names | `REJECT_INPUT` | 2 |
| PD-05 | Oversized or malformed provider responses | `REJECT_INPUT` | 2 |
| PD-06 | Co-Invest response containing executable links/actions or tool-instruction injection | `REJECT_INPUT` | 2 |
| PD-07 | Upstream Co-Invest schema drift introducing a new state-changing method | `DENY_CAPABILITY` | 2 |
| PD-08 | False source-independence caused by two transports sharing one underlying market feed | `BLOCK_NEW_EXPOSURE` | 2 |

## Model failures

| ID | Threat | Expected safe state | Enforced in phase |
|---|---|---|---|
| MF-01 | Hallucinated account state | `BLOCK_NEW_EXPOSURE` | 3 |
| MF-02 | Stale prices | `BLOCK_NEW_EXPOSURE` | 7 |
| MF-03 | Contradictory agents | `BLOCK_NEW_EXPOSURE` | 4 |
| MF-04 | Role confusion | `DENY_CAPABILITY` | 1 |
| MF-05 | Infinite delegation loops | `DEGRADED` | 4 |
| MF-06 | Repeated TradeIntent spam | `REJECT_INPUT` | 7 |
| MF-07 | Committee collusion or consensus on wrong data | `BLOCK_NEW_EXPOSURE` | 5 |
| MF-08 | Malformed structured outputs | `REJECT_INPUT` | 0 |

## Local compromise

| ID | Threat | Expected safe state | Enforced in phase |
|---|---|---|---|
| LC-01 | fund-ops Codex process compromised | `DENY_CAPABILITY` | 1 |
| LC-02 | traderd compromised | `DENY_CAPABILITY` | 8 |
| LC-03 | One MCP server compromised | `DENY_CAPABILITY` | 1 |
| LC-04 | SQLite file tampering | `SAFE_HALT` | 3 |
| LC-05 | Log injection | `REJECT_INPUT` | 3 |
| LC-06 | Environment-variable leakage | `DENY_CAPABILITY` | 1 |
| LC-07 | Dependency compromise | `DENY_CAPABILITY` | 1 |
| LC-08 | Rogue project .codex configuration | `DENY_CAPABILITY` | 1 |
| LC-09 | Session launched with unsafe permissions | `DENY_CAPABILITY` | 1 |
| LC-10 | Direct fund-ops registration of an unrestricted Co-Invest endpoint | `DENY_CAPABILITY` | 1 |
| LC-11 | Bypass of the Co-Invest read-only proxy through shell/network egress | `DENY_CAPABILITY` | 1 |
| LC-12 | OAuth credential leakage from the Co-Invest proxy or paper adapter | `DENY_CAPABILITY` | 2 |
| LC-13 | Paper validation accidentally targeting live mode | `DENY_CAPABILITY` | 6 |

## Exchange/network failures

| ID | Threat | Expected safe state | Enforced in phase |
|---|---|---|---|
| EN-01 | REST timeout after accepted order | `RECONCILE_BEFORE_RETRY` | 8 |
| EN-02 | WebSocket loss | `BLOCK_NEW_EXPOSURE` | 2 |
| EN-03 | Duplicate response | `RECONCILE_BEFORE_RETRY` | 8 |
| EN-04 | Response reordering | `RECONCILE_BEFORE_RETRY` | 8 |
| EN-05 | Partial batch rejection | `RECONCILE_BEFORE_RETRY` | 8 |
| EN-06 | Rate limiting | `DEGRADED` | 8 |
| EN-07 | Clock skew | `BLOCK_NEW_EXPOSURE` | 8 |
| EN-08 | Nonce collision | `SAFE_HALT` | 8 |
| EN-09 | Scheduled-cancel refresh failure | `SAFE_HALT` | 9 |
| EN-10 | Protective order rejection | `SAFE_HALT` | 9 |
| EN-11 | Extreme spread or liquidity collapse | `BLOCK_NEW_EXPOSURE` | 7 |

## Rules

- On uncertainty, reject exposure increase.
- Risk-reducing emergency action must never depend on LLM availability or on Co-Invest availability.
- Research data never substitutes for authoritative execution-critical state.

## Limitations of the Phase-0 static scan

The repository-tree and source scans (`src/contracts/trust-zone-checker.mjs`, the import/pattern scanner in `tests/helpers.mjs`) are deterministic Phase-0 tripwires over text. They are not a containment control: obfuscation, string building, reflection and other loader tricks can evade regex matching, and new evasions are added only as they are found. Containment of live capability is the job of the later-phase runtime boundary (process separation, signer capability surface, no key in Codex or traderd), not of these scans.
