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

## Installation is a deliberate operator action

Nothing in this repository installs these files. A session must never write machine-wide Codex policy. To install on a fund-ops runtime:

1. Use an isolated runtime/host for fund-ops: the system requirements file is machine-wide, so every Codex user on that machine is bound by it (open decision OD-1). Do not install it on a developer workstation that must keep `fund-dev` working.
2. Review the diff and record the SHA-256 (line endings normalized to LF):

       node -e "console.log(require('crypto').createHash('sha256').update(require('fs').readFileSync('config/codex/requirements.fund-ops.toml','utf8').replace(/\r\n/g,'\n')).digest('hex'))"

3. As an administrator, copy the file to the system location above, keep it administrator-owned and not writable by the fund-ops OS account, and record who/when/hash in the operator log.
4. Copy the two profile files into the fund-ops / fund-dev account's `$CODEX_HOME`.
5. Verify (below). Rollback is deleting the system file and the profile copies.

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

## Open decisions (not decided here)

- OD-1 isolated runtime for fund-ops (machine-wide requirements on Windows).
- OD-2 location of fund-ops scratch compute (`:read-only` grants no writes).
- OD-3 unattended `never` approvals for fund-ops.
- OD-4 per-role MCP narrowing for the nine agents (needs Phase 2 server definitions).
