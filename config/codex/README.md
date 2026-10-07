# Codex configuration artifacts (Phase 1, slice P1-S1)

Version-controlled source for the Codex-side configuration layer. Written against `codex-cli 0.160.1`; re-ground against current official docs before changing any key.

| File | Installed to | Purpose |
|---|---|---|
| `fund-ops.config.toml` | `$CODEX_HOME/fund-ops.config.toml` (default `~/.codex/`) | constrained operational profile; launch with `codex --profile fund-ops` |
| `fund-dev.config.toml` | `$CODEX_HOME/fund-dev.config.toml` | development profile; launch with `codex --profile fund-dev` |
| `requirements.fund-ops.toml` | Windows `%ProgramData%\OpenAI\Codex\requirements.toml`; Unix `/etc/codex/requirements.toml` | managed, admin-owned policy for the fund-ops runtime |

The project `.codex/` directory (config + nine role files) is separate and ships with the repository.

## What this layer is and is not

- It is a restriction layer and defense in depth. The live-capital boundary is deterministic authorization plus the signer capability surface (see `AGENTS.md`).
- Profile files rank below project and CLI config, so they are defaults only. The managed requirements are what constrains a session's configured/selected permission mode, approval policy, web mode, browser/computer use, plugins/apps and which MCP servers may start (enforcement is documented behavior, not yet proven live here).
- Residual routes to unsandboxed execution this layer does NOT close (the Phase 1 exit gate stays open until the OS slice): (a) under `on-request`, a model can request an escalated command and a single operator approval runs it with that user's full privileges; (b) user-level `.rules` `allow` entries and a writable Codex home (`config.toml`, hooks, user agents shadowing the project roles) are outside this slice; (c) an approved MCP identity pins only the executable and arguments, not `cwd` or `env`, so launch-environment spoofing needs the protected Codex home and release ACLs; (d) `.agents/` (repo skills/plugins) is not yet denied by the repository tests.
- Not provided here (later Phase 1 slices): read-only release ACLs, `riskd`/`traderd`/`signerd` service identities, `fundctl`, outbound-network policy for the Codex process, protection of the operator's Codex home (`.rules` allow entries, writable config).
- MCP: identity authorization (managed `[mcp_servers]`, currently empty = all MCP disabled) is separate from per-tool exposure (`enabled_tools` in the profile). Codex has no managed `enabled_tools`; an approved server must itself enforce its closed tool surface (blueprint section 9).

## Installation is a deliberate operator action (Phase 1, P1-S2)

The canonical fund-ops runtime is a DEDICATED WSL2 Ubuntu distro (decision OD-1, D-0007); the requirements file is machine-wide for that distro, so it is never installed on a developer workstation. Nothing in the test suite installs anything. The reviewed provisioning path is `ops/provision/` (see its README and `docs/ops-runtime.md`):

1. `fund-ops-validate.sh` checks the pinned SHA-256 of the requirements, profile, WSL template and layout contract (no mutation).
2. `fund-ops-provision.sh plan|apply` creates the unprivileged `aihf-ops` identity, the root-owned toolchain/release/launcher, installs `/etc/codex/requirements.toml` byte-for-byte from the pinned artifact (refusing to replace a different file silently), pre-creates the protected Codex-home surface and installs the profile as `$CODEX_HOME/fund-ops.config.toml`.
3. `fund-ops-verify.sh` verifies the installed state and attempts the forbidden writes as the real ops identity.

The pinned hash lives in `ops/provision/canonical-artifacts.sha256`; changing the requirements or profile requires updating the pin in the same reviewed diff. Rollback is re-provisioning a previous release id and, for the requirements, an explicit `--replace-requirements` after reviewing the printed diff.

## Verification

Static (always, no Codex needed): `node --test` (parser, checker, mutation and conformance tests).

Live (installed Codex; no model call; scratch `CODEX_HOME`; never touches the real Codex home):

    set CODEX_EXE=<path to the native codex binary>
    node tests/live/verify-live.mjs --mode isolated   # runtime acceptance + negative controls; needs nothing installed
    node tests/live/verify-live.mjs --mode managed    # observes the installed requirements; fails closed if absent

`--mode managed` claims `LIVE ENFORCEMENT VERIFIED` only if the requirements are installed and every `MAN-*` check passes. Because the production template approves no MCP identity, run it twice: once with the production file, and once on a TEST machine with the output of `node tests/live/verify-live.mjs --emit-test-requirements <file>` (adds a dummy fixture identity) to exercise accepted-identity, drifted-identity and unlisted-server behavior. Never install the test variant on a production runtime.

## Adding an MCP server (Phase 2 and later)

1. Ground the server's tool schema; add its closed allowlist to `contracts/mcp-surface.json` (and the pinned checker) through a reviewed decision.
2. Add its managed identity to `requirements.fund-ops.toml` (structured exact `executable` + `args`, or an exact URL; never a bare command string, prefix or regex) and the matching entry with a non-empty `enabled_tools` to `fund-ops.config.toml`.
3. `node --test` must pass; then re-run both live managed passes.

## Open decisions

- OD-1 RESOLVED (D-0007): dedicated WSL2 Ubuntu distro.
- OD-2 RESOLVED (D-0007): scratch compute is `/var/lib/aihf/runtime/scratch` (OS-bounded, ops-owned); the `:read-only` Codex profile is NOT widened to write it. A managed custom profile that grants it is a later reviewed change.
- OD-3 unattended `never` approvals for fund-ops: still unresolved; `never` stays disallowed by the requirements.
- OD-4 per-role MCP narrowing for the nine agents (needs Phase 2 server definitions).
- OD-5 production Windows-account separation for the fund-ops distro (see `docs/ops-runtime.md` R1).
- OD-6 Codex credential storage mode for fund-ops (`cli_auth_credentials_store`).
