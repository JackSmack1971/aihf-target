# ops/provision: human-run host provisioning for the isolated fund-ops runtime

`ops/provision/` is the **sole repository location authorized for human-run privileged host provisioning artifacts** (decision D-0007).
It is outside the model and runtime authority surface and does not create a general privileged-code exception.

- Operator/administrator use only. Codex `fund-ops`, `riskd`, `traderd`, `signerd`, MCP servers and any model-facing code must never invoke, import or reference these files; the repository tripwire rejects a reference from anywhere else.
- The file set is pinned in `src/contracts/trust-zone-checker.mjs` (`OPS_PROVISION_FILES`). Adding a file here is a review-visible change to checker code and its tests.
- The canonical runtime is a **dedicated WSL2 Ubuntu distro** (decision OD-1). WSL is the runtime choice, not the security boundary: the properties come from managed Codex requirements, Unix identities and ownership, a root-owned release, and the removal of Windows interoperability.

## Three separate steps

| Step | File | Mutates the system? |
|---|---|---|
| 1. generate/validate artifacts | `fund-ops-validate.sh` | no (offline; checks `canonical-artifacts.sha256`) |
| 2. provision | `fund-ops-provision.sh plan` (default) / `apply` | only with an explicit `apply` as root |
| 3. verify installed state | `fund-ops-verify.sh` | no (only removable probes inside ops-writable directories) |

Constants live in `fund-ops-layout.sh` and mirror `contracts/ops-runtime-layout.json` (parity is tested). `wsl.conf.fund-ops` is the hardened per-distro WSL configuration. `canonical-artifacts.sha256` pins the reviewed requirements, profile, WSL template and layout contract (SHA-256 over LF-normalized content). Changing any pinned artifact requires updating the pin in the same reviewed diff.

## Operator procedure (dedicated distro, run as root, source tree on the Linux filesystem)

    bash ops/provision/fund-ops-validate.sh
    bash ops/provision/fund-ops-provision.sh plan --release-id <id> --codex-dir <official codex dir>
    bash ops/provision/fund-ops-provision.sh apply --release-id <id> --codex-dir <official codex dir> --configure-wsl
    # from Windows: wsl --terminate <distro>      (applies wsl.conf)
    bash /opt/aihf/current/ops/provision/fund-ops-verify.sh --expect-hardened-wsl

`apply` installs `/etc/codex/requirements.toml` byte-for-byte from the pinned canonical artifact and refuses to replace a *different* installed file unless `--replace-requirements` is passed after reviewing the printed diff. Releases are immutable directories under `/opt/aihf/releases/<id>` activated by an atomic symlink switch of `/opt/aihf/current`; reusing an id with different content is refused.

## What this slice does not do

No `riskd`/`traderd`/`signerd` identities, no signer secret storage, no `fundctl`, no Hyperliquid connectivity, no outbound network policy. Those are later Phase 1 slices. A scratch or cloud environment run is not proof of the production identity until the same provisioning runs on the real dedicated distro.
