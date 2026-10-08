# Isolated fund-ops runtime: boundary, provisioning and threat review (Phase 1, slice P1-S2)

This document describes the OS boundary around the `fund-ops` Codex session and what has and has not been proven. It complements `docs/architecture.md` and `docs/threat-model.md`. Blueprint references: sections 3, 5, 6, 31, 33. Decisions: `builder-state` D-0007 (OD-1, OD-2, the provisioning exemption).

## Runtime model

The canonical v1 `fund-ops` runtime is a **dedicated WSL2 Ubuntu distro**, not the developer's ordinary environment. This is a runtime choice, not a claim that WSL is a security boundary. The properties come from managed Codex requirements, Unix identities and ownership, a root-owned release, service separation (later slices) and removal of the Windows interoperability routes.

```text
Windows host (operator = custody-adjacent trust, Zone 0 side)
  - developer environment: fund-dev, builder tooling
  - dedicated WSL2 distro for fund-ops
        root / operator-admin  : owns /etc/codex/requirements.toml, /opt/aihf/**, provisions releases
        aihf-ops (uid != 0)    : runs `/opt/aihf/bin/fund-ops`; no sudo, no secrets, no write to policy/release/toolchain
```

Layout (contract: `contracts/ops-runtime-layout.json`, checker: `src/contracts/ops-layout-checker.mjs`):

| Path | Owner / mode | Purpose |
|---|---|---|
| `/etc/codex/requirements.toml` | root 0644 | managed Codex requirements, byte-for-byte the pinned canonical artifact |
| `/opt/aihf/releases/<id>/` | root, read-only | immutable release (no Git working tree, no symlinks, `RELEASE-MANIFEST.sha256`) |
| `/opt/aihf/current` | root symlink | atomic activation (`ln -s` then `mv -T`) |
| `/opt/aihf/toolchain/codex/` | root | pinned Codex binary (0.160.1) |
| `/opt/aihf/bin/fund-ops` | root 0755 | launcher: refuses root, clean environment (`env -i`), absolute Codex path, `--profile fund-ops` |
| `/var/lib/aihf/ops/home` | root:aihf-ops 1770 | HOME of the ops identity: sticky like the Codex home because the documented user skill root `$HOME/.agents/skills`, `$HOME/.codex` and the shell startup files live here; those names are pre-created root-owned (review round 1, B2) |
| `/var/lib/aihf/ops/codex-home` | root:aihf-ops 1770 | `CODEX_HOME`: sticky and group-writable so Codex keeps its own mutable state; security-critical names are pre-created root-owned |
| `/var/lib/aihf/runtime/scratch` | aihf-ops 0700 | bounded agent scratch (decision OD-2); not granted to Codex's `:read-only` profile |
| `/var/lib/aihf/runtime/state` | aihf-ops 0700 | mutable runtime state, outside the release, policy and any secret path |

Protected Codex-home names (root-owned, not replaceable by the sticky-bit rule): `config.toml`, `.env`, `fund-ops.config.toml`, `hooks.json`, `AGENTS.md`, `AGENTS.override.md`, `rules/`, `skills/`, `agents/`, `prompts/`, `plugins/`. Protected HOME names: `.agents/`, `.codex/`, `.bashrc`, `.profile`, `.bash_profile`, `.bash_login`.

Protected names are installed through a root-only staging directory and an atomic move: the ops identity can never pre-create or race a staging name (review round 1, B1), and the provisioner refuses to run while ops processes are alive.

Provisioning is `ops/provision/` (validate, plan/apply, verify). Nothing is provisioned by tests or by running Codex.

## What is enforced by what

- **Codex authority clamp (managed requirements, live-verified in the scratch distro):** ordinary CLI flags, `-c` overrides, thread overrides, project `.codex/config.toml`, user profiles, user `config.toml` and user-defined permission profiles cannot widen the session beyond `read-only` + `on-request`; unlisted MCP servers expose no tools; features (apps, plugins, remote plugins, browser/computer use) stay off; hostile user/project hooks are not loaded.
- **OS identity boundary (verified as the real ops identity):** the ops identity cannot modify managed policy, the activated release, the toolchain, the launcher, the protected Codex-home names or the `current` symlink, and its writable set is exactly scratch, state, home, the Codex home's mutable names and the standard world-writable temp directories.
- **WSL interop routes:** closed by the per-distro `wsl.conf` (no automount, no interop, no Windows PATH), verified behaviorally including a Windows executable placed inside the Linux filesystem.

Evidence levels are never merged: `CONFIG_LOAD_VERIFIED`, `RUNTIME_ENFORCEMENT_VERIFIED`, `MODEL_TOOL_PATH_VERIFIED`. The model-driven tool path is **not** verified (no credentials, no model call).

## WSL boundary-leak review

| Route | Finding in the scratch distro (WSL 2.6.1, Ubuntu 24.04) | Treatment |
|---|---|---|
| `/mnt/c`, `/mnt/e` Windows drives | mounted read-write by default; developer checkout and host credential directories visible and writable | `[automount] enabled = false`; verified absent after restart. **Load-bearing:** when a drive IS mounted (tested by a manual root re-mount), the unprivileged ops uid could write the developer checkout path and read `.ssh`, `.codex`, `.claude` and `.gitconfig`, because DrvFS applies the Windows user's access to every Linux uid. Linux permissions do not protect Windows files |
| Windows executables from Linux | default interop live | `[interop] enabled = false`; a Windows executable in the Linux filesystem does not run for `aihf-ops` (the binfmt handler stays registered, so registration is informational and the behavioral probe is authoritative) |
| Windows PATH injection | 26 `/mnt/` PATH entries by default | `appendWindowsPath = false`; launcher PATH is `/usr/bin:/bin` |
| `WSLENV` / `WSL_INTEROP` | set in default sessions | launcher uses `env -i`; verified absent |
| Developer checkout via `/mnt/c` | visible and writable | unreachable once automount is off; provisioning uses a Linux-native source tree and refuses a Windows-mount source |
| Windows access to WSL files (`\\wsl.localhost\...`, `wsl -u root`, `wsl --export`) | works by design; the Windows operator account is root in the distro | **not closed** (R1) |
| Docker integration | `docker-desktop` distro exists on the host; no socket inside the scratch distro | verified absent in the dedicated distro; re-check per host |
| root / sudo | imported rootfs ships a cloud-init `NOPASSWD` sudoers entry for its default user | the ops account is not referenced in sudoers and has no groups; verified; the distro's other accounts are the operator's concern |
| Inherited environment secrets | default sessions inherit Windows variables | launcher clean environment; no credentials are passed |
| Shared SSH/Git credentials | host `.ssh`, `.gitconfig` visible through `/mnt/c` | gone with automount; the distro has no Git or SSH configuration for the ops identity |

## Residual risks and open items (the Phase 1 exit gate stays open)

- **R1 Windows operator account.** `wsl -d <distro> -u root` needs no password, and the vhdx is readable from Windows. A developer sharing that Windows account can reach root in the fund-ops distro. Production needs the fund-ops distro under a separate Windows account or on a separate host. This is a concrete blocker for the Phase 1 exit gate (open decision OD-5).
- **R10 Windows drive re-mount.** `automount = false` only prevents the automatic mount; root inside the distro can still `mount -t drvfs`, and any such mount exposes the host to the ops identity (see the table). Only the operator is root in the distro, but the verifier's `--expect-hardened-wsl` run (no read-write 9p/drvfs mount, `/mnt/c` empty) must be part of every launch gate, and a later slice should make the check continuous.
- **R11 Other WSL distros share the VM.** Every WSL2 distro on a host runs in one VM with one kernel and network namespace. Root in any other distro (the scratch rootfs ships a passwordless-sudo account, `docker-desktop` exists on the host) can likely reach the fund-ops disk, and localhost services in the fund-ops distro (future services) are reachable from other distros and from Windows. Untested; one more reason for OD-5 (separate Windows account or host).
- **R12 The protected home is defense in depth, not the clamp.** The ops identity can run the toolchain binary with any `CODEX_HOME` (the live battery does exactly that with hostile homes). Only `/etc/codex/requirements.toml` clamps those sessions. Not exercised: `-c model_provider`/`base_url`, `notify`, `shell_environment_policy`, `--add-dir`, `--dangerously-bypass-hook-trust`; a root-owned `.env` placeholder is pre-created because Codex may read `$CODEX_HOME/.env` (not confirmed against 0.160.1).
- **R13 Forgeable local state and unprotected HOME names.** Sessions, history, `shell_snapshots/`, `tmp/`, `auth.json`, extra profile files and `memories_*.sqlite` in the Codex home are ops-owned, and re-provisioning does not clean them (a concurrent ops process could tamper with them during a session; the "no concurrent ops process" rule is enforced only at provisioning time). HOME names outside the protected list (`.gitconfig`, `.config/`, `.ssh/config`, `.npmrc`, `.inputrc`, `.bash_logout`) are ops-creatable: persistence for one approved escalation, running only with ops authority, not an escalation route. The protected-name lists cover the Codex home AND HOME, are enumerated, and need re-grounding per Codex upgrade (R6). `features.memories` is pinned false in the managed requirements (OD-7, resolved in P1-S3A; documented requirements key, hash re-pinned, covered by tests). Existing `memories_*.sqlite` files remain ops-owned state, so the pin removes the feature, not the R13 tamper surface.
- **R14 Persistence routes** (user systemd units with linger, cron through setgid helpers) are not enumerated or tested.
- **R2 Interop behavior is WSL-version specific.** Re-run the PE probe after every WSL update.
- **R3 Standard world-writable directories** (`/tmp`, `/var/tmp`, `/var/crash`, `/dev/shm`) are writable by the ops identity at the OS level (not by Codex's read-only profile). Service-level sandboxing (private temp, noexec) belongs to the service-identity slice.
- **R4 No outbound network policy.** The ops identity can open connections; Codex command networking is off but Codex's own traffic and approved escalations are not constrained at the OS. Later Phase 1 slice.
- **R5 Approved escalations.** Under `on-request`, a single human approval runs a command with the ops identity's authority. That authority cannot touch policy, release or toolchain, but can write scratch/state/home/temp and use the network. Rules `allow` entries cannot be persisted (the rules directory is root-owned). Model-driven behavior is unverified.
- **R6 Codex-home names are an enumerated allow-surface.** A future Codex version that reads a new security-relevant top-level name from `CODEX_HOME` would let the ops identity create it until the pinned list is extended. Re-ground per Codex upgrade.
- **R7 Credentials.** If `codex login` is used, `auth.json` lands in the mutable Codex home, readable by the ops identity (and a compromised model). Storage mode (`cli_auth_credentials_store`) is an open decision (OD-6).
- **R8 Cosmetic log noise.** On Linux the shared requirements' `[windows]` table logs `Configured value for windows.sandbox is disallowed... falling back to Elevated`, and the root-owned `skills/` directory logs `failed to install system skills`. Both are harmless and expected; a Linux-specific requirements variant is a later cleanup.
- **R9 Scratch is not production.** The proof ran in a disposable Ubuntu 24.04 distro; the user's real distro is Ubuntu 26.04. The same provisioning must run on the real dedicated distro before it counts as the production identity.
- `--dangerously-bypass-hook-trust` and other Codex flags not listed in the live battery are clamped by system-wide requirements in principle but were not individually exercised.

## Not in this slice

Provisioning of the `riskd`, `traderd`, `signerd` identities and the `fundctl` executable (contracts only as of P1-S3A); real signer secret storage; production Hyperliquid connectivity; Phase 2 data/MCP integrations; the outbound-network policy. OD-3 (unattended `never` approvals) stays unresolved and `never` is not permitted by the requirements. OD-4 (per-role MCP narrowing) stays deferred.

## P1-S3A contracts (decisions D-0009; contracts only, nothing provisioned)

`contracts/ops-runtime-layout.json` now also defines, and `src/contracts/ops-layout-checker.mjs` pins:

- **Service identities** `aihf-riskd`, `aihf-traderd`, `aihf-signerd`: non-login (`/usr/sbin/nologin`), locked password, no sudo, no supplementary groups, one private group each, no group shared with `aihf-ops` or each other. Home is the identity's private state directory.
- **Private state** `/var/lib/aihf/{riskd,traderd,signerd}`: each `0700` and owned by its own `user:group`. The ops identity can traverse `/var/lib/aihf` (root `0755`) but cannot enter any of them.
- **Signer secret directory** `/var/lib/aihf/signerd/secrets` (`0700`) holding only a `0600` `sentinel` file. The sentinel is a fixed non-secret marker used by the later proof that `aihf-ops`, `aihf-riskd` and `aihf-traderd` cannot read signer-owned data. No real secret, key or seed exists in or is created from this contract.
- **`fundctl`** installed at `/usr/local/sbin/fundctl` (source `ops/fundctl/fundctl`, not yet written): `root:root` `0700` in a root-owned non-writable parent, so `aihf-ops` can neither execute nor replace it. It has no network, reads no secrets, and every one of the eight pinned commands (`status`, `arm`, `disarm`, `halt`, `flatten`, `activate-release`, `activate-policy`, `rotate-agent`) must fail closed with `NOT_IMPLEMENTED` and a non-zero exit. Operator controls remain unreachable through MCP.

Accepted trust statement (OD-5): the Windows administrator/operator is Zone 0 trust. The dedicated WSL distro stops `fund-ops` from escalating itself; it is not isolation from a Windows administrator.

Deferred, with triggers: IPC and socket semantics (a later Phase 1 provisioning slice must decide them before any service talks to another); the outbound-network policy for the Codex process (R4; **Phase 2 trigger: decide it when the Co-Invest proxy and upstream endpoints exist and are grounded, and before any MCP identity is approved in the requirements**); OD-3, OD-4 and OD-6; R10, R11, R12 and R14.
